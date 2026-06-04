package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type pending2FAState struct {
	userID   int64
	clientID string
}

type secondFactorResult struct {
	Requires2FA bool
	SessionID   string
	Methods     []string
}

type secondFactorHandler struct {
	userService       *service.UserService
	credentialService *service.CredentialService
	jwtService        *auth.JWTService
	webAuthn          *auth.WebAuthnService
	secondFactorSvc   service.SecondFactorService
	pending2FA        *ristretto.Cache[string, *pending2FAState]
	webauthn2FA       *ristretto.Cache[string, *webauthnSession]
}

func newSecondFactorHandler(userService *service.UserService, credentialService *service.CredentialService, jwtService *auth.JWTService, webAuthn *auth.WebAuthnService, svc service.SecondFactorService) (*secondFactorHandler, error) {
	pending2FA, err := newDefaultCache[*pending2FAState]()
	if err != nil {
		return nil, fmt.Errorf("failed to create pending 2fa cache: %w", err)
	}

	webauthn2FA, err := newDefaultCache[*webauthnSession]()
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn 2fa cache: %w", err)
	}

	return &secondFactorHandler{
		userService:       userService,
		credentialService: credentialService,
		jwtService:        jwtService,
		webAuthn:          webAuthn,
		secondFactorSvc:   svc,
		pending2FA:        pending2FA,
		webauthn2FA:       webauthn2FA,
	}, nil
}

func (h *secondFactorHandler) checkPending(userID int64, clientID string) (*secondFactorResult, error) {
	if h.secondFactorSvc == nil {
		return &secondFactorResult{}, nil
	}

	required, err := h.secondFactorSvc.Required(userID)
	if err != nil {
		return nil, err
	}
	if !required {
		return &secondFactorResult{}, nil
	}

	methods, err := h.secondFactorSvc.Methods(userID)
	if err != nil {
		return nil, err
	}

	sessionID := generateSessionID()
	h.pending2FA.SetWithTTL(sessionID, &pending2FAState{userID: userID, clientID: clientID}, 1, 5*time.Minute)
	h.pending2FA.Wait()

	return &secondFactorResult{
		Requires2FA: true,
		SessionID:   sessionID,
		Methods:     methods,
	}, nil
}

func (h *secondFactorHandler) setupRoutes(e *echo.Group, jwtMiddleware echo.MiddlewareFunc) {
	e.POST("/login/2fa/webauthn/start", h.login2FAStart)
	e.POST("/login/2fa/webauthn/finish", h.login2FAFinish)

	reg := e.Group("/register/2fa")
	reg.Use(jwtMiddleware)
	reg.POST("/webauthn/start", h.register2FAStart)
	reg.POST("/webauthn/finish", h.register2FAFinish)
}

func (h *secondFactorHandler) login2FAStart(c *echo.Context) error {
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

	h.webauthn2FA.SetWithTTL(session.Challenge, &webauthnSession{session: session, userID: pending.userID}, 1, 2*time.Minute)
	h.webauthn2FA.Wait()

	return c.JSON(200, assertion)
}

func (h *secondFactorHandler) login2FAFinish(c *echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		log.Err(err).Msg("failed to read request body")
		return c.String(400, "invalid request")
	}

	var envelope struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		log.Err(err).Msg("failed to parse 2fa finish envelope")
		return c.String(400, "invalid request")
	}

	if envelope.SessionID == "" {
		return c.String(400, "invalid request")
	}

	pending, found := h.pending2FA.Get(envelope.SessionID)
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

	ws, found := h.webauthn2FA.Get(challenge)
	if !found || ws == nil || ws.session == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), ws.userID)
	if err != nil {
		log.Err(err).Int64("userID", ws.userID).Msg("failed to load user for 2fa verification")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	validatedCredential, err := h.webAuthn.WebAuthn.ValidateLogin(user, *ws.session, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to validate webauthn login for 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(401, "invalid credentials")
	}

	if err := h.credentialService.Update(c.Request().Context(), validatedCredential); err != nil {
		log.Err(err).Msg("failed to update credential after 2fa")
	}

	h.webauthn2FA.Del(challenge)
	h.pending2FA.Del(envelope.SessionID)

	token, err := h.jwtService.GenerateToken(pending.userID, pending.clientID)
	if err != nil {
		log.Err(err).Msg("failed to generate jwt after 2fa")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (h *secondFactorHandler) register2FAStart(c *echo.Context) error {
	claims, ok := c.Get(contextKeyClaims).(*auth.Claims)
	if !ok {
		return c.String(401, "unauthorized")
	}

	userID, err := parseUserID(claims.Subject)
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

	h.webauthn2FA.SetWithTTL(session.Challenge, &webauthnSession{session: session, userID: userID}, 1, 2*time.Minute)
	h.webauthn2FA.Wait()

	return c.JSON(200, creation)
}

func (h *secondFactorHandler) register2FAFinish(c *echo.Context) error {
	claims, ok := c.Get(contextKeyClaims).(*auth.Claims)
	if !ok {
		return c.String(401, "unauthorized")
	}

	userID, err := parseUserID(claims.Subject)
	if err != nil {
		log.Err(err).Msg("failed to parse user id from claims")
		return c.String(500, "server error")
	}

	body, err := io.ReadAll(c.Request().Body)
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

	ws, found := h.webauthn2FA.Get(challenge)
	if !found || ws == nil || ws.session == nil {
		return c.String(400, "invalid request")
	}

	user, err := h.userService.LoadWebAuthnUser(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to load user for 2fa registration finish")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	credential, err := h.webAuthn.WebAuthn.CreateCredential(user, *ws.session, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to create credential for 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(400, "invalid request")
	}

	if err := h.credentialService.Persist(c.Request().Context(), userID, credential); err != nil {
		log.Err(err).Msg("failed to persist credential for 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	if err := h.credentialService.EnableSecondFactor(c.Request().Context(), userID); err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to enable webauthn 2fa")
		h.webauthn2FA.Del(challenge)
		return c.String(500, "server error")
	}

	h.webauthn2FA.Del(challenge)

	return c.JSON(200, map[string]string{"status": "ok"})
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64Encoding.EncodeToString(b)
}

func parseUserID(subject string) (int64, error) {
	var userID int64
	_, err := fmt.Sscanf(subject, "%d", &userID)
	return userID, err
}
