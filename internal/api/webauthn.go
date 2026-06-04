package api

import (
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/rs/zerolog/log"
)

const maxDisplayNameLen = 256

type webauthnApi struct {
	db         *sql.DB
	cache      *ristretto.Cache[string, *webauthnSession]
	webAuthn   *auth.WebAuthnService
	jwtService *auth.JWTService
}

type webauthnSession struct {
	session *webauthn.SessionData
	userID  int64
}

func (a *Api) setupWebAuthn(db *sql.DB, e *echo.Group) error {
	webAuthn, err := auth.NewWebAuthnService()
	if err != nil {
		return fmt.Errorf("failed to create webauthn service: %w", err)
	}

	cache, err := ristretto.NewCache(&ristretto.Config[string, *webauthnSession]{
		NumCounters: 1e6,
		MaxCost:     1e4,
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("failed to create webauthn cache: %w", err)
	}

	wa := webauthnApi{
		db:         db,
		cache:      cache,
		webAuthn:   webAuthn,
		jwtService: a.JWT,
	}

	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      5,
			Burst:     10,
			ExpiresIn: 3 * time.Minute,
		}),
	}))

	e.POST("/register/start", wa.registerStart)
	e.POST("/register/finish", wa.registerFinish)
	e.POST("/login/start", wa.loginStart)
	e.POST("/login/finish", wa.loginFinish)

	return nil
}

type registerStartRequest struct {
	DisplayName string `json:"displayName"`
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

func (api *webauthnApi) registerStart(c *echo.Context) error {
	var request registerStartRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind webauthn register start request")
		return c.String(400, "invalid request")
	}

	if err := validateDisplayName(request.DisplayName); err != nil {
		log.Err(err).Msg("invalid display name")
		return c.String(400, "invalid request")
	}

	result, err := api.db.ExecContext(c.Request().Context(),
		"INSERT INTO users (auth_method, display_name) VALUES (?, ?)",
		"webauthn", request.DisplayName)
	if err != nil {
		log.Err(err).Msg("failed to insert user")
		return c.String(500, "server error")
	}

	userID, err := result.LastInsertId()
	if err != nil {
		log.Err(err).Msg("failed to get last insert id")
		return c.String(500, "server error")
	}

	user := &auth.WebAuthnUser{
		ID:          userID,
		DisplayName: request.DisplayName,
	}

	creation, session, err := api.webAuthn.WebAuthn.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	)
	if err != nil {
		log.Err(err).Msg("failed to begin webauthn registration")

		if _, delErr := api.db.ExecContext(c.Request().Context(), "DELETE FROM users WHERE id = ?", userID); delErr != nil {
			log.Err(delErr).Int64("userID", userID).Msg("failed to delete user after BeginRegistration failure")
		}

		return c.String(500, "server error")
	}

	api.cache.SetWithTTL(session.Challenge, &webauthnSession{session: session, userID: userID}, 1, 2*time.Minute)

	return c.JSON(200, creation)
}

func (api *webauthnApi) registerFinish(c *echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
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

	ws, found := api.cache.Get(challenge)
	if !found || ws == nil || ws.session == nil {
		return c.String(400, "invalid request")
	}

	user, err := api.loadWebAuthnUser(ws.userID)
	if err != nil {
		log.Err(err).Int64("userID", ws.userID).Msg("failed to load user")
		api.cache.Del(challenge)
		return c.String(500, "server error")
	}

	credential, err := api.webAuthn.WebAuthn.CreateCredential(user, *ws.session, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to create credential")
		api.cache.Del(challenge)

		_, delErr := api.db.ExecContext(c.Request().Context(), "DELETE FROM users WHERE id = ?", ws.userID)
		if delErr != nil {
			log.Err(delErr).Int64("userID", ws.userID).Msg("failed to delete user after failed registration")
		}

		return c.String(400, "invalid request")
	}

	if err := api.persistCredential(ws.userID, credential); err != nil {
		log.Err(err).Msg("failed to persist credential")
		api.cache.Del(challenge)

		_, delErr := api.db.ExecContext(c.Request().Context(), "DELETE FROM users WHERE id = ?", ws.userID)
		if delErr != nil {
			log.Err(delErr).Int64("userID", ws.userID).Msg("failed to delete user after persist credential failure")
		}

		return c.String(500, "server error")
	}

	api.cache.Del(challenge)

	token, err := api.jwtService.GenerateToken(ws.userID, "")
	if err != nil {
		log.Err(err).Msg("failed to generate jwt")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (api *webauthnApi) loginStart(c *echo.Context) error {
	assertion, session, err := api.webAuthn.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		log.Err(err).Msg("failed to begin discoverable login")
		return c.String(500, "server error")
	}

	api.cache.SetWithTTL(session.Challenge, &webauthnSession{session: session}, 1, 2*time.Minute)

	return c.JSON(200, assertion)
}

func (api *webauthnApi) loginFinish(c *echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
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

	ws, found := api.cache.Get(challenge)
	if !found || ws == nil || ws.session == nil {
		return c.String(400, "invalid request")
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, err := auth.UserIDFromWebAuthnID(userHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to decode user handle: %w", err)
		}

		user, err := api.loadWebAuthnUser(userID)
		if err != nil {
			return nil, fmt.Errorf("failed to load user: %w", err)
		}

		return user, nil
	}

	resolvedUser, validatedCredential, err := api.webAuthn.WebAuthn.ValidatePasskeyLogin(handler, *ws.session, parsedResponse)
	if err != nil {
		log.Err(err).Msg("failed to validate passkey login")
		api.cache.Del(challenge)
		return c.String(401, "invalid credentials")
	}

	if err := api.updateCredential(validatedCredential); err != nil {
		log.Err(err).Msg("failed to update credential")
		api.cache.Del(challenge)
		return c.String(500, "server error")
	}

	api.cache.Del(challenge)

	webAuthnUser := resolvedUser.(*auth.WebAuthnUser)

	token, err := api.jwtService.GenerateToken(webAuthnUser.ID, "")
	if err != nil {
		log.Err(err).Msg("failed to generate jwt")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (api *webauthnApi) loadWebAuthnUser(userID int64) (*auth.WebAuthnUser, error) {
	var displayName string
	err := api.db.QueryRow("SELECT display_name FROM users WHERE id = ?", userID).Scan(&displayName)
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	user := &auth.WebAuthnUser{
		ID:          userID,
		DisplayName: displayName,
	}

	rows, err := api.db.Query(
		`SELECT credential_id, public_key, attestation_type, transport, aaguid,
		        sign_count, clone_warning, backup_eligible, backup_state
		 FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var c webauthn.Credential
		var transportStr string
		var aaguid []byte
		var signCount int64
		var cloneWarning, backupEligible, backupState bool

		err := rows.Scan(
			&c.ID, &c.PublicKey, &c.AttestationType, &transportStr, &aaguid,
			&signCount, &cloneWarning, &backupEligible, &backupState)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		c.Authenticator.AAGUID = aaguid
		c.Authenticator.SignCount = uint32(signCount)
		c.Authenticator.CloneWarning = cloneWarning
		c.Flags = webauthn.CredentialFlags{
			UserPresent:    true,
			BackupEligible: backupEligible,
			BackupState:    backupState,
		}

		if transportStr != "" {
			for s := range strings.SplitSeq(transportStr, ",") {
				c.Transport = append(c.Transport, protocol.AuthenticatorTransport(s))
			}
		}

		user.Credentials = append(user.Credentials, c)
	}

	return user, rows.Err()
}

func (api *webauthnApi) persistCredential(userID int64, credential *webauthn.Credential) error {
	transportStrs := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transportStrs[i] = string(t)
	}
	transportStr := strings.Join(transportStrs, ",")

	_, err := api.db.Exec(
		`INSERT INTO webauthn_credentials
		 (user_id, credential_id, public_key, attestation_type, transport, aaguid,
		  sign_count, clone_warning, backup_eligible, backup_state)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		credential.ID,
		credential.PublicKey,
		credential.AttestationType,
		transportStr,
		credential.Authenticator.AAGUID,
		int64(credential.Authenticator.SignCount),
		credential.Authenticator.CloneWarning,
		credential.Flags.BackupEligible,
		credential.Flags.BackupState,
	)
	return err
}

func (api *webauthnApi) updateCredential(credential *webauthn.Credential) error {
	_, err := api.db.Exec(
		`UPDATE webauthn_credentials
		 SET sign_count = ?, clone_warning = ?, backup_state = ?, last_used_at = CURRENT_TIMESTAMP
		 WHERE credential_id = ? AND sign_count < ?`,
		int64(credential.Authenticator.SignCount),
		credential.Authenticator.CloneWarning,
		credential.Flags.BackupState,
		credential.ID,
		int64(credential.Authenticator.SignCount),
	)
	return err
}


