package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/bytemare/opaque"
	"github.com/dgraph-io/ristretto/v2"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/rs/zerolog/log"
)

const maxPayloadSize = 65536
const maxClientIdLen = 256

var base64Encoding = base64.RawURLEncoding

type opaqueApi struct {
	opaqueService *service.OpaqueService
	cache         *ristretto.Cache[string, []byte]
	loginCache    *ristretto.Cache[string, *loginState]
	opaqueServer  *opaque.Server
	fakeRecord    *opaque.ClientRecord
	jwtService    *auth.JWTService
	secondFactor  *secondFactorHandler
}

type loginState struct {
	serverOutput *opaque.ServerOutput
	userId       int64
}

func (a *Api) setupOpaque(e *echo.Group) error {
	opaqueServer, err := auth.CreateOpaqueServer(a.DB)
	if err != nil {
		log.Err(err).Msg("failed to setup opaque for server")
		return err
	}

	fakeRecord, err := auth.ServerConfig().GetFakeRecord([]byte("fake-client"))
	if err != nil {
		log.Err(err).Msg("failed to generate fake opaque record")
		return err
	}

	cache, err := newDefaultCache[[]byte]()
	if err != nil {
		log.Err(err).Msg("failed to create cache")
		return err
	}

	loginCache, err := newDefaultCache[*loginState]()
	if err != nil {
		log.Err(err).Msg("failed to create login cache")
		return err
	}

	sfHandler, err := newSecondFactorHandler(a.Users, a.Credentials, a.JWT, a.WebAuthn, a.SecondFactorSvc, a.TOTP)
	if err != nil {
		return err
	}

	api := opaqueApi{
		opaqueService: a.Opaque,
		cache:         cache,
		loginCache:    loginCache,
		opaqueServer:  opaqueServer,
		fakeRecord:    fakeRecord,
		jwtService:    a.JWT,
		secondFactor:  sfHandler,
	}

	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      5,
			Burst:     10,
			ExpiresIn: 3 * time.Minute,
		}),
	}))

	e.POST("/register/start", api.registerStart)
	e.POST("/register/finish", api.registerFinish)
	e.POST("/login/start", api.loginStart)
	e.POST("/login/finish", api.loginFinish)

	sfHandler.setupRoutes(e, jwtMiddleware(a.JWT))

	return nil
}

type RegisterRequest struct {
	ClientId string `json:"clientId"`
	Payload  string `json:"payload"`
}

func bindAndValidateOPAQUERequest(c *echo.Context) (string, []byte, error) {
	var request RegisterRequest
	if err := c.Bind(&request); err != nil {
		return "", nil, fmt.Errorf("failed to bind request: %w", err)
	}

	clientId := request.ClientId
	if err := validateClientId(clientId); err != nil {
		return "", nil, fmt.Errorf("invalid client id: %w", err)
	}

	if err := checkPayloadSize(request.Payload); err != nil {
		return "", nil, fmt.Errorf("payload too large: %w", err)
	}

	payload, err := base64Encoding.DecodeString(request.Payload)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	return clientId, payload, nil
}

func validateClientId(clientId string) error {
	if clientId == "" {
		return fmt.Errorf("client id is empty")
	}
	if !utf8.ValidString(clientId) {
		return fmt.Errorf("client id is not valid utf-8")
	}
	if len(clientId) > maxClientIdLen {
		return fmt.Errorf("client id too long: %d bytes", len(clientId))
	}
	return nil
}

func checkPayloadSize(raw string) error {
	if len(raw) > maxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes", len(raw))
	}
	return nil
}

func (api *opaqueApi) registerStart(c *echo.Context) error {
	clientId, payload, err := bindAndValidateOPAQUERequest(c)
	if err != nil {
		log.Err(err).Msg("failed to bind registration request")
		return c.String(400, "invalid request")
	}

	userExists, err := api.opaqueService.IsClientIDTaken(c.Request().Context(), clientId)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to check for taken client id")
		return c.String(500, "server error")
	}

	if userExists {
		return c.String(409, "client id is already taken")
	}

	registrationRequest, err := api.opaqueServer.Deserialize.RegistrationRequest(payload)
	if err != nil {
		log.Err(err).Msg("failed to deserialize registration request")
		return c.String(400, "invalid request")
	}

	credentialId := opaque.RandomBytes(64)
	api.cache.SetWithTTL(clientId, credentialId, 1, time.Minute)
	api.cache.Wait()

	registrationResponse, err := api.opaqueServer.RegistrationResponse(registrationRequest, credentialId, nil)
	if err != nil {
		log.Err(err).Msg("failed to generate registration response")
		return c.String(500, "server error")
	}

	responseBytes := registrationResponse.Serialize()
	encodedResponse := base64Encoding.EncodeToString(responseBytes)

	return c.String(200, encodedResponse)
}

func (api *opaqueApi) registerFinish(c *echo.Context) error {
	clientId, payload, err := bindAndValidateOPAQUERequest(c)
	if err != nil {
		log.Err(err).Msg("failed to bind registration finish request")
		return c.String(400, "invalid request")
	}

	credentialId, foundClientId := api.cache.Get(clientId)
	if !foundClientId || credentialId == nil {
		return c.String(400, "invalid request")
	}

	registrationRecord, err := api.opaqueServer.Deserialize.RegistrationRecord(payload)
	if err != nil {
		log.Err(err).Msg("failed to deserialize registration record")
		return c.String(400, "invalid request")
	}

	recordBytes := registrationRecord.Serialize()
	encodedRecord := base64Encoding.EncodeToString(recordBytes)
	encodedCredentialId := base64Encoding.EncodeToString(credentialId)

	_, err = api.opaqueService.CreateUser(c.Request().Context(), clientId, encodedCredentialId, encodedRecord)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to create opaque user")
		return c.String(500, "server error")
	}

	api.cache.Del(clientId)

	return c.String(200, "registered!")
}

func (api *opaqueApi) loginStart(c *echo.Context) error {
	clientId, payload, err := bindAndValidateOPAQUERequest(c)
	if err != nil {
		log.Err(err).Msg("failed to bind login start request")
		return c.String(400, "invalid request")
	}

	ke1, err := api.opaqueServer.Deserialize.KE1(payload)
	if err != nil {
		log.Err(err).Msg("failed to deserialize KE1")
		return c.String(400, "invalid request")
	}

	data, err := api.opaqueService.GetUserData(c.Request().Context(), clientId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ke2, serverOutput, err := api.opaqueServer.GenerateKE2(ke1, api.fakeRecord)
			if err != nil {
				log.Err(err).Str("clientId", clientId).Msg("failed to generate fake KE2")
				return c.String(500, "server error")
			}

			api.loginCache.SetWithTTL(clientId, &loginState{serverOutput: serverOutput}, 1, time.Minute)
			api.loginCache.Wait()

			ke2Bytes := ke2.Serialize()
			encodedResponse := base64Encoding.EncodeToString(ke2Bytes)

			return c.String(200, encodedResponse)
		}

		log.Err(err).Str("clientId", clientId).Msg("failed to query opaque user data")
		return c.String(500, "server error")
	}

	credentialId, err := base64Encoding.DecodeString(data.EncodedCredentialID)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to decode credential id")
		return c.String(500, "server error")
	}

	recordBytes, err := base64Encoding.DecodeString(data.EncodedRecord)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to decode registration record")
		return c.String(500, "server error")
	}

	registrationRecord, err := api.opaqueServer.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to deserialize registration record")
		return c.String(500, "server error")
	}

	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: credentialId,
		ClientIdentity:       []byte(clientId),
		RegistrationRecord:   registrationRecord,
	}

	ke2, serverOutput, err := api.opaqueServer.GenerateKE2(ke1, clientRecord)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to generate KE2")
		return c.String(500, "server error")
	}

	api.loginCache.SetWithTTL(clientId, &loginState{serverOutput: serverOutput, userId: data.UserID}, 1, time.Minute)
	api.loginCache.Wait()

	ke2Bytes := ke2.Serialize()
	encodedResponse := base64Encoding.EncodeToString(ke2Bytes)

	return c.String(200, encodedResponse)
}

func (api *opaqueApi) loginFinish(c *echo.Context) error {
	clientId, payload, err := bindAndValidateOPAQUERequest(c)
	if err != nil {
		log.Err(err).Msg("failed to bind login finish request")
		return c.String(400, "invalid request")
	}

	ke3, err := api.opaqueServer.Deserialize.KE3(payload)
	if err != nil {
		log.Err(err).Msg("failed to deserialize KE3")
		return c.String(400, "invalid request")
	}

	state, found := api.loginCache.Get(clientId)
	if !found || state == nil || state.serverOutput == nil {
		return c.String(400, "invalid request")
	}

	if err := api.opaqueServer.LoginFinish(ke3, state.serverOutput.ClientMAC); err != nil {
		log.Err(err).Str("clientId", clientId).Msg("login finish failed")
		return c.String(401, "invalid credentials")
	}

	api.loginCache.Del(clientId)

	if api.secondFactor != nil {
		result, err := api.secondFactor.checkPending(state.userId, clientId)
		if err != nil {
			log.Err(err).Int64("userId", state.userId).Msg("failed to check 2fa requirement")
			return c.String(500, "server error")
		}

		if result.Requires2FA {
			return c.JSON(200, map[string]any{
				"status":     "2fa_required",
				"session_id": result.SessionID,
				"methods":    result.Methods,
			})
		}
	}

	token, err := api.jwtService.GenerateToken(state.userId, clientId)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to generate jwt")
		return c.String(500, "server error")
	}

	return c.JSON(200, map[string]string{"token": token})
}
