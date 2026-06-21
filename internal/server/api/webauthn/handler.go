package webauthn

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api/cacheutil"
	"github.com/homelab-tool/auth/internal/server/api/secondfactor"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/rs/zerolog/log"
)

const (
	maxDisplayNameLen = 256
	maxBodySize       = 1 << 20
	maxPasskeys       = 5
)

type Session struct {
	sessionData *webauthn.SessionData
	userID      int64
	purpose     service.CredentialPurpose
	name        string
}

type Handler struct {
	userService       *service.UserService
	credentialService *service.CredentialService
	cache             *ristretto.Cache[string, *Session]
	webAuthn          *auth.WebAuthnService
	jwtService        *auth.JWTService
	secondFactorSvc   service.SecondFactorService
	totpService       *service.TOTPService
	secondFactor      *secondfactor.Handler
}

func NewHandler(userService *service.UserService, credentialService *service.CredentialService,
	jwtService *auth.JWTService, secondFactorSvc service.SecondFactorService,
	totpService *service.TOTPService, secondFactor *secondfactor.Handler) (*Handler, error) {
	cache, err := cacheutil.NewCache[*Session]()
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn cache: %w", err)
	}

	return &Handler{
		userService:       userService,
		credentialService: credentialService,
		cache:             cache,
		webAuthn:          nil,
		jwtService:        jwtService,
		secondFactorSvc:   secondFactorSvc,
		totpService:       totpService,
		secondFactor:      secondFactor,
	}, nil
}

func (h *Handler) SetupRoutes(e *echo.Group, jwtMiddleware echo.MiddlewareFunc) {
	webAuthn, err := auth.NewWebAuthnService()
	if err != nil {
		log.Err(err).Msg("failed to create webauthn service")
		return
	}
	h.webAuthn = webAuthn

	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      5,
			Burst:     10,
			ExpiresIn: 3 * time.Minute,
		}),
	}))

	e.POST("/register/start", h.registerStart)
	e.POST("/register/finish", h.registerFinish)
	e.POST("/login/start", h.loginStart)
	e.POST("/login/finish", h.loginFinish)

	creds := e.Group("/credentials")
	creds.Use(jwtMiddleware)
	creds.POST("/add/start", h.addStart)
	creds.POST("/add/finish", h.addFinish)
}

type registerStartRequest struct {
	DisplayName string `json:"displayName"`
}

type addStartRequest struct {
	Purpose string `json:"purpose"`
	Name    string `json:"name"`
}

func validateDisplayName(name string) error {
	if name == "" {
		return fmt.Errorf("display name is empty")
	}
	if len(name) > maxDisplayNameLen {
		return fmt.Errorf("display name too long: %d bytes", len(name))
	}
	return nil
}

func (h *Handler) registerStart(c *echo.Context) error {
	var request registerStartRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind webauthn register start request")
		return c.String(400, "invalid request")
	}

	if err := validateDisplayName(request.DisplayName); err != nil {
		log.Err(err).Msg("invalid display name")
		return c.String(400, "invalid request")
	}

	userID, err := h.userService.Create(c.Request().Context(), request.DisplayName)
	if err != nil {
		log.Err(err).Msg("failed to insert user")
		return c.String(500, "server error")
	}

	user := &auth.WebAuthnUser{
		ID:          userID,
		DisplayName: request.DisplayName,
	}

	creation, sessionData, err := h.webAuthn.WebAuthn.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	)
	if err != nil {
		log.Err(err).Msg("failed to begin webauthn registration")

		if delErr := h.userService.Delete(c.Request().Context(), userID); delErr != nil {
			log.Err(delErr).Int64("userID", userID).Msg("failed to delete user after BeginRegistration failure")
		}

		return c.String(500, "server error")
	}

	h.cache.SetWithTTL(sessionData.Challenge, &Session{sessionData: sessionData, userID: userID}, 1, 2*time.Minute)
	h.cache.Wait()

	return c.JSON(200, creation)
}

func (h *Handler) registerFinish(c *echo.Context) error {
	body, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, maxBodySize))
	if err != nil {
		log.Err(err).Msg("failed to read request body")
		return c.String(400, "invalid request")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		log.Err(err).Msg("failed to parse credential creation response")
		return c.String(400, "invalid request")
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge
	if challenge == "" {
		return c.String(400, "invalid request")
	}

	s, found := h.cache.Get(challenge)
	if !found || s == nil || s.sessionData == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), s.userID)
	if err != nil {
		log.Err(err).Int64("userID", s.userID).Msg("failed to load user")
		h.cache.Del(challenge)
		return c.String(500, "server error")
	}

	credential, err := h.webAuthn.WebAuthn.CreateCredential(user, *s.sessionData, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to create credential")
		h.cache.Del(challenge)

		if delErr := h.userService.Delete(c.Request().Context(), s.userID); delErr != nil {
			log.Err(delErr).Int64("userID", s.userID).Msg("failed to delete user after failed registration")
		}

		return c.String(400, "invalid request")
	}

	if err := h.credentialService.Persist(c.Request().Context(), s.userID, credential, service.PurposeLogin, ""); err != nil {
		log.Err(err).Msg("failed to persist credential")
		h.cache.Del(challenge)

		if delErr := h.userService.Delete(c.Request().Context(), s.userID); delErr != nil {
			log.Err(delErr).Int64("userID", s.userID).Msg("failed to delete user after persist credential failure")
		}

		return c.String(500, "server error")
	}

	h.cache.Del(challenge)

	token, err := h.jwtService.GenerateToken(s.userID)
	if err != nil {
		log.Err(err).Msg("failed to generate jwt")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (h *Handler) loginStart(c *echo.Context) error {
	assertion, sessionData, err := h.webAuthn.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		log.Err(err).Msg("failed to begin discoverable login")
		return c.String(500, "server error")
	}

	h.cache.SetWithTTL(sessionData.Challenge, &Session{sessionData: sessionData}, 1, 2*time.Minute)
	h.cache.Wait()

	return c.JSON(200, assertion)
}

func (h *Handler) loginFinish(c *echo.Context) error {
	body, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, maxBodySize))
	if err != nil {
		log.Err(err).Msg("failed to read request body")
		return c.String(400, "invalid request")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		log.Err(err).Msg("failed to parse credential request response")
		return c.String(400, "invalid request")
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge
	if challenge == "" {
		return c.String(400, "invalid request")
	}

	s, found := h.cache.Get(challenge)
	if !found || s == nil || s.sessionData == nil {
		return c.String(400, "invalid request")
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, err := auth.UserIDFromWebAuthnID(userHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to decode user handle: %w", err)
		}

		user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), userID)
		if err != nil {
			return nil, fmt.Errorf("failed to load user: %w", err)
		}

		return user, nil
	}

	resolvedUser, validatedCredential, err := h.webAuthn.WebAuthn.ValidatePasskeyLogin(handler, *s.sessionData, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to validate passkey login")
		h.cache.Del(challenge)
		return c.String(401, "invalid credentials")
	}

	if err := h.credentialService.Update(c.Request().Context(), validatedCredential); err != nil {
		log.Err(err).Msg("failed to update credential")
		h.cache.Del(challenge)
		return c.String(500, "server error")
	}

	h.cache.Del(challenge)

	webAuthnUser := resolvedUser.(*auth.WebAuthnUser)

	purpose, err := h.credentialService.GetPurpose(c.Request().Context(), validatedCredential.ID)
	if err != nil {
		log.Err(err).Msg("failed to get credential purpose")
		return c.String(500, "server error")
	}

	if purpose.TwoFA && !purpose.Login {
		return c.String(401, "invalid credentials")
	}

	var methods []string

	if purpose.Login {
		totpOK, err := h.totpService.HasEnabled(c.Request().Context(), webAuthnUser.ID)
		if err != nil {
			log.Err(err).Int64("userID", webAuthnUser.ID).Msg("failed to check totp")
			return c.String(500, "server error")
		}
		if totpOK {
			methods = append(methods, "totp")
		}

		other2faCreds, err := h.credentialService.ListBy2FAPurpose(c.Request().Context(), webAuthnUser.ID)
		if err != nil {
			log.Err(err).Int64("userID", webAuthnUser.ID).Msg("failed to list 2fa credentials")
			return c.String(500, "server error")
		}

		for _, c2 := range other2faCreds {
			if !bytes.Equal(c2.CredentialID, validatedCredential.ID) {
				methods = append(methods, "webauthn")
				break
			}
		}
	}

	if len(methods) > 0 {
		result, err := h.secondFactor.CreatePendingSession(webAuthnUser.ID, methods)
		if err != nil {
			log.Err(err).Int64("userID", webAuthnUser.ID).Msg("failed to create 2fa session")
			return c.String(500, "server error")
		}

		return c.JSON(200, map[string]any{
			"status":     "2fa_required",
			"session_id": result.SessionID,
		})
	}

	token, err := h.jwtService.GenerateToken(webAuthnUser.ID)
	if err != nil {
		log.Err(err).Msg("failed to generate jwt")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (h *Handler) addStart(c *echo.Context) error {
	var request addStartRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind add webauthn start request")
		return c.String(400, "invalid request")
	}

	purpose, err := service.ParseCredentialPurpose(request.Purpose)
	if err != nil {
		return c.String(400, "invalid purpose")
	}

	claims, ok := c.Get(auth.ContextKeyClaims).(*auth.Claims)
	if !ok {
		return c.String(401, "unauthorized")
	}

	userID, err := auth.ParseUserID(claims.Subject)
	if err != nil {
		log.Err(err).Msg("failed to parse user id from claims")
		return c.String(500, "server error")
	}

	count, err := h.credentialService.Count(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to count credentials")
		return c.String(500, "server error")
	}
	if count >= maxPasskeys {
		return c.String(400, "maximum number of passkeys reached")
	}

	displayName, err := h.userService.GetDisplayName(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to query display name")
		return c.String(500, "server error")
	}

	user := &auth.WebAuthnUser{
		ID:          userID,
		DisplayName: displayName,
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	}
	if purpose.Login {
		opts = append(opts, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	}

	creation, sessionData, err := h.webAuthn.WebAuthn.BeginRegistration(user, opts...)
	if err != nil {
		log.Err(err).Msg("failed to begin webauthn registration")
		return c.String(500, "server error")
	}

	h.cache.SetWithTTL(sessionData.Challenge, &Session{sessionData: sessionData, userID: userID, purpose: purpose, name: request.Name}, 1, 2*time.Minute)
	h.cache.Wait()

	return c.JSON(200, creation)
}

func (h *Handler) addFinish(c *echo.Context) error {
	body, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, maxBodySize))
	if err != nil {
		log.Err(err).Msg("failed to read request body")
		return c.String(400, "invalid request")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		log.Err(err).Msg("failed to parse credential creation response")
		return c.String(400, "invalid request")
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge
	if challenge == "" {
		return c.String(400, "invalid request")
	}

	s, found := h.cache.Get(challenge)
	if !found || s == nil || s.sessionData == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), s.userID)
	if err != nil {
		log.Err(err).Int64("userID", s.userID).Msg("failed to load user")
		h.cache.Del(challenge)
		return c.String(500, "server error")
	}

	credential, err := h.webAuthn.WebAuthn.CreateCredential(user, *s.sessionData, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to create credential")
		h.cache.Del(challenge)
		return c.String(400, "invalid request")
	}

	purpose := s.purpose
	if !purpose.Login && !purpose.TwoFA {
		purpose = service.PurposeLogin
	}

	if err := h.credentialService.Persist(c.Request().Context(), s.userID, credential, purpose, s.name); err != nil {
		log.Err(err).Msg("failed to persist credential")
		h.cache.Del(challenge)
		return c.String(500, "server error")
	}

	h.cache.Del(challenge)

	return c.JSON(200, map[string]string{"status": "ok"})
}
