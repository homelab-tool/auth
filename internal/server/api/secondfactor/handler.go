package secondfactor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/homelab-tool/auth/internal/server/api/cacheutil"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

const maxBodySize = 1 << 20

type Pending2FAState struct {
	userID  int64
	methods []string
}

type Result struct {
	Requires2FA bool
	SessionID   string
	Methods     []string
}

type Handler struct {
	userService       *service.UserService
	credentialService *service.CredentialService
	jwtService        *auth.JWTService
	webAuthn          *auth.WebAuthnService
	secondFactorSvc   service.SecondFactorService
	totpService       *service.TOTPService
	pending2FA        *ristretto.Cache[string, *Pending2FAState]
	webauthn2FA       *ristretto.Cache[string, *webauthn.SessionData]
}

func NewHandler(userService *service.UserService, credentialService *service.CredentialService, jwtService *auth.JWTService, webAuthn *auth.WebAuthnService, svc service.SecondFactorService, totpSvc *service.TOTPService) (*Handler, error) {
	pending2FA, err := cacheutil.NewCache[*Pending2FAState]()
	if err != nil {
		return nil, fmt.Errorf("failed to create pending 2fa cache: %w", err)
	}

	webauthn2FA, err := cacheutil.NewCache[*webauthn.SessionData]()
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn 2fa cache: %w", err)
	}

	return &Handler{
		userService:       userService,
		credentialService: credentialService,
		jwtService:        jwtService,
		webAuthn:          webAuthn,
		secondFactorSvc:   svc,
		totpService:       totpSvc,
		pending2FA:        pending2FA,
		webauthn2FA:       webauthn2FA,
	}, nil
}

func (h *Handler) CheckPending(userID int64) (*Result, error) {
	if h.secondFactorSvc == nil {
		return &Result{}, nil
	}

	required, err := h.secondFactorSvc.Required(userID)
	if err != nil {
		return nil, err
	}
	if !required {
		return &Result{}, nil
	}

	methods, err := h.secondFactorSvc.Methods(userID)
	if err != nil {
		return nil, err
	}

	return h.createPendingSession(userID, methods)
}

func (h *Handler) CreatePendingSession(userID int64, methods []string) (*Result, error) {
	return h.createPendingSession(userID, methods)
}

func (h *Handler) createPendingSession(userID int64, methods []string) (*Result, error) {
	sessionID := generateSessionID()
	h.pending2FA.SetWithTTL(sessionID, &Pending2FAState{userID: userID, methods: methods}, 1, 5*time.Minute)
	h.pending2FA.Wait()

	return &Result{
		Requires2FA: true,
		SessionID:   sessionID,
	}, nil
}

func (h *Handler) GetPendingMethods(sessionID string) ([]string, error) {
	pending, found := h.pending2FA.Get(sessionID)
	if !found || pending == nil {
		return nil, fmt.Errorf("invalid session")
	}
	return pending.methods, nil
}

func (h *Handler) SetupRoutes(e *echo.Group, jwtMiddleware echo.MiddlewareFunc) {
	e.POST("/login/2fa/webauthn/start", h.login2FAStart)
	e.POST("/login/2fa/webauthn/finish", h.login2FAFinish)
	reg := e.Group("/register/2fa")
	reg.Use(jwtMiddleware)
	reg.POST("/webauthn/start", h.register2FAStart)
	reg.POST("/webauthn/finish", h.register2FAFinish)
}

func (h *Handler) login2FAStart(c *echo.Context) error {
	var request struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind 2fa webauthn start request")
		return c.String(400, "invalid request")
	}

	pending, found := h.pending2FA.Get(request.SessionID)
	if !found || pending == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), pending.userID)
	if err != nil {
		log.Err(err).Int64("userId", pending.userID).Msg("failed to load user for 2fa")
		return c.String(500, "server error")
	}

	assertion, session, err := h.webAuthn.WebAuthn.BeginLogin(user)
	if err != nil {
		log.Err(err).Msg("failed to begin webauthn login for 2fa")
		return c.String(500, "server error")
	}

	h.webauthn2FA.SetWithTTL(session.Challenge, session, 1, 2*time.Minute)
	h.webauthn2FA.Wait()

	return c.JSON(200, assertion)
}

func (h *Handler) login2FAFinish(c *echo.Context) error {
	sessionID := c.QueryParam("sessionId")
	if sessionID == "" {
		return c.String(400, "invalid request")
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, maxBodySize))
	if err != nil {
		log.Err(err).Msg("failed to read request body")
		return c.String(400, "invalid request")
	}

	pending, found := h.pending2FA.Get(sessionID)
	if !found || pending == nil {
		return c.String(400, "invalid request")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		log.Err(err).Msg("failed to parse credential request response for 2fa")
		return c.String(400, "invalid request")
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge
	if challenge == "" {
		return c.String(400, "invalid request")
	}

	session, found := h.webauthn2FA.Get(challenge)
	if !found || session == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), pending.userID)
	if err != nil {
		log.Err(err).Int64("userID", pending.userID).Msg("failed to load user for 2fa verification")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	validatedCredential, err := h.webAuthn.WebAuthn.ValidateLogin(user, *session, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to validate webauthn login for 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(401, "invalid credentials")
	}

	if err := h.credentialService.Update(c.Request().Context(), validatedCredential); err != nil {
		log.Err(err).Msg("failed to update credential after 2fa")
	}

	h.webauthn2FA.Del(challenge)
	h.pending2FA.Del(sessionID)

	token, err := h.jwtService.GenerateToken(pending.userID)
	if err != nil {
		log.Err(err).Msg("failed to generate jwt after 2fa")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (h *Handler) register2FAStart(c *echo.Context) error {
	claims, ok := c.Get(auth.ContextKeyClaims).(*auth.Claims)
	if !ok {
		return c.String(401, "unauthorized")
	}

	userID, err := auth.ParseUserID(claims.Subject)
	if err != nil {
		log.Err(err).Msg("failed to parse user id from claims")
		return c.String(500, "server error")
	}

	displayName, err := h.userService.GetDisplayName(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to query display name for 2fa registration")
		return c.String(500, "server error")
	}

	user := &auth.WebAuthnUser{
		ID:          userID,
		DisplayName: displayName,
	}

	creation, session, err := h.webAuthn.WebAuthn.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	)
	if err != nil {
		log.Err(err).Msg("failed to begin webauthn registration for 2fa")
		return c.String(500, "server error")
	}

	h.webauthn2FA.SetWithTTL(session.Challenge, session, 1, 2*time.Minute)
	h.webauthn2FA.Wait()

	return c.JSON(200, creation)
}

func (h *Handler) register2FAFinish(c *echo.Context) error {
	claims, ok := c.Get(auth.ContextKeyClaims).(*auth.Claims)
	if !ok {
		return c.String(401, "unauthorized")
	}

	userID, err := auth.ParseUserID(claims.Subject)
	if err != nil {
		log.Err(err).Msg("failed to parse user id from claims")
		return c.String(500, "server error")
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Response(), c.Request().Body, maxBodySize))
	if err != nil {
		log.Err(err).Msg("failed to read request body")
		return c.String(400, "invalid request")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		log.Err(err).Msg("failed to parse credential creation response for 2fa")
		return c.String(400, "invalid request")
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge
	if challenge == "" {
		return c.String(400, "invalid request")
	}

	session, found := h.webauthn2FA.Get(challenge)
	if !found || session == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to load user for 2fa registration finish")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	credential, err := h.webAuthn.WebAuthn.CreateCredential(user, *session, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to create credential for 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(400, "invalid request")
	}

	if err := h.credentialService.Persist(c.Request().Context(), userID, credential, "2fa", ""); err != nil {
		log.Err(err).Msg("failed to persist credential for 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	h.webauthn2FA.Del(challenge)

	return c.JSON(200, map[string]string{"status": "ok"})
}

func (h *Handler) ValidatePendingTOTP(ctx context.Context, sessionID, code string) (string, error) {
	pending, found := h.pending2FA.Get(sessionID)
	if !found || pending == nil {
		return "", fmt.Errorf("invalid session")
	}

	valid, err := h.totpService.ValidateCode(ctx, pending.userID, code)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", fmt.Errorf("invalid code")
	}

	h.pending2FA.Del(sessionID)

	token, err := h.jwtService.GenerateToken(pending.userID)
	if err != nil {
		return "", fmt.Errorf("failed to generate jwt: %w", err)
	}

	return token, nil
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}




