package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/bytemare/opaque"
	"github.com/dgraph-io/ristretto/v2"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

const maxPayloadSize = 65536
const maxClientIdLen = 256

var base64Encoding = base64.RawURLEncoding

type opaqueApi struct {
	db           *sql.DB
	cache        *ristretto.Cache[string, []byte]
	loginCache   *ristretto.Cache[string, *opaque.ServerOutput]
	opaqueServer *opaque.Server
}

func (a *Api) setupOpaque(db *sql.DB, e *echo.Group) error {
	opaqueServer, err := auth.CreateOpaqueServer(a.DB)
	if err != nil {
		log.Err(err).Msg("failed to setup opaque for server")
		return err
	}

	cache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 1e6,
		MaxCost:     1e4,
		BufferItems: 64,
	})

	if err != nil {
		log.Err(err).Msg("failed to create cache")
		return err
	}

	loginCache, err := ristretto.NewCache(&ristretto.Config[string, *opaque.ServerOutput]{
		NumCounters: 1e6,
		MaxCost:     1e4,
		BufferItems: 64,
	})

	if err != nil {
		log.Err(err).Msg("failed to create login cache")
		return err
	}

	api := opaqueApi{
		db:           db,
		cache:        cache,
		loginCache:   loginCache,
		opaqueServer: opaqueServer,
	}

	e.POST("/register/start", api.registerStart)
	e.POST("/register/finish", api.registerFinish)
	e.POST("/login/start", api.loginStart)
	e.POST("/login/finish", api.loginFinish)

	return nil
}

type RegisterRequest struct {
	ClientId string `json:"clientId"`
	Payload  string `json:"payload"`
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

func isClientIdTaken(ctx context.Context, db *sql.DB, clientId string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM opaque_user_data WHERE client_id = ?", clientId).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (api *opaqueApi) registerStart(c *echo.Context) error {
	var request RegisterRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind registration request")
		return c.String(400, "invalid request")
	}

	clientId := request.ClientId
	if err := validateClientId(clientId); err != nil {
		log.Err(err).Msg("invalid client id")
		return c.String(400, "invalid request")
	}

	userExists, err := isClientIdTaken(c.Request().Context(), api.db, clientId)
	if err != nil {
		log.Err(err).Str("clientId", request.ClientId).Msg("failed to check for taken client id")
		return c.String(500, "server error")
	}

	if userExists {
		return c.String(409, "client id is already taken")
	}

	if err := checkPayloadSize(request.Payload); err != nil {
		log.Err(err).Msg("payload too large")
		return c.String(400, "invalid request")
	}

	payload, err := base64Encoding.DecodeString(request.Payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to decode payload")
		return c.String(400, "invalid request")
	}

	registrationRequest, err := api.opaqueServer.Deserialize.RegistrationRequest(payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to deserialize registartion request")
		return c.String(400, "invalid request")
	}

	credentialId := opaque.RandomBytes(64)
	api.cache.SetWithTTL(clientId, credentialId, 1, time.Minute)

	registrationResponse, err := api.opaqueServer.RegistrationResponse(registrationRequest, credentialId, nil)
	if err != nil {
		log.Err(err).Msg("failed to generate registartion resonse")
		return c.String(500, "server error")
	}

	responeBytes := registrationResponse.Serialize()
	encodedResponse := base64Encoding.EncodeToString(responeBytes)

	return c.String(200, encodedResponse)
}

func (api *opaqueApi) registerFinish(c *echo.Context) error {
	var request RegisterRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind registration request")
		return c.String(400, "invalid request")
	}

	clientId := request.ClientId
	if err := validateClientId(clientId); err != nil {
		log.Err(err).Msg("invalid client id")
		return c.String(400, "invalid request")
	}

	credentialId, foundClientId := api.cache.Get(clientId)
	if !foundClientId || credentialId == nil {
		return c.String(400, "invalid request")
	}

	if err := checkPayloadSize(request.Payload); err != nil {
		log.Err(err).Msg("payload too large")
		return c.String(400, "invalid request")
	}

	payload, err := base64Encoding.DecodeString(request.Payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to decode payload")
		return c.String(400, "invalid request")
	}

	registrationRecord, err := api.opaqueServer.Deserialize.RegistrationRecord(payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to deserialize registration record")
		return c.String(400, "invalid request")
	}

	recordBytes := registrationRecord.Serialize()
	encodedRecord := base64Encoding.EncodeToString(recordBytes)
	encodedCredentialId := base64Encoding.EncodeToString(credentialId)

	tx, err := api.db.BeginTx(c.Request().Context(), nil)
	if err != nil {
		log.Err(err).Msg("failed to begin transaction")
		return c.String(500, "server error")
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(c.Request().Context(),
		"INSERT INTO users (auth_method, display_name) VALUES (?, ?)",
		"pass-opaque", clientId)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to insert user")
		return c.String(500, "server error")
	}

	userId, err := result.LastInsertId()
	if err != nil {
		log.Err(err).Msg("failed to get last insert id")
		return c.String(500, "server error")
	}

	_, err = tx.ExecContext(c.Request().Context(),
		"INSERT INTO opaque_user_data (client_id, credential_id, registration_record, user_id) VALUES (?, ?, ?, ?)",
		clientId, encodedCredentialId, encodedRecord, userId)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to insert opaque user data")
		return c.String(500, "server error")
	}

	if err := tx.Commit(); err != nil {
		log.Err(err).Msg("failed to commit transaction")
		return c.String(500, "server error")
	}

	api.cache.Del(clientId)

	return c.String(200, "registered!")
}

func (api *opaqueApi) loginStart(c *echo.Context) error {
	var request RegisterRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind login start request")
		return c.String(400, "invalid request")
	}

	clientId := request.ClientId
	if err := validateClientId(clientId); err != nil {
		log.Err(err).Msg("invalid client id")
		return c.String(400, "invalid request")
	}

	if err := checkPayloadSize(request.Payload); err != nil {
		log.Err(err).Msg("payload too large")
		return c.String(400, "invalid request")
	}

	payload, err := base64Encoding.DecodeString(request.Payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to decode payload")
		return c.String(400, "invalid request")
	}

	ke1, err := api.opaqueServer.Deserialize.KE1(payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to deserialize KE1")
		return c.String(400, "invalid request")
	}

	var encodedCredentialId string
	var encodedRecord string
	err = api.db.QueryRowContext(c.Request().Context(),
		"SELECT credential_id, registration_record FROM opaque_user_data WHERE client_id = ?", clientId).
		Scan(&encodedCredentialId, &encodedRecord)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.String(401, "invalid credentials")
		}

		log.Err(err).Str("clientId", clientId).Msg("failed to query opaque user data")
		return c.String(500, "server error")
	}

	credentialId, err := base64Encoding.DecodeString(encodedCredentialId)
	if err != nil {
		log.Err(err).Str("clientId", clientId).Msg("failed to decode credential id")
		return c.String(500, "server error")
	}

	recordBytes, err := base64Encoding.DecodeString(encodedRecord)
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

	api.loginCache.SetWithTTL(clientId, serverOutput, 1, time.Minute)

	ke2Bytes := ke2.Serialize()
	encodedResponse := base64Encoding.EncodeToString(ke2Bytes)

	return c.String(200, encodedResponse)
}

func (api *opaqueApi) loginFinish(c *echo.Context) error {
	var request RegisterRequest
	if err := c.Bind(&request); err != nil {
		log.Err(err).Msg("failed to bind login finish request")
		return c.String(400, "invalid request")
	}

	clientId := request.ClientId
	if err := validateClientId(clientId); err != nil {
		log.Err(err).Msg("invalid client id")
		return c.String(400, "invalid request")
	}

	if err := checkPayloadSize(request.Payload); err != nil {
		log.Err(err).Msg("payload too large")
		return c.String(400, "invalid request")
	}

	payload, err := base64Encoding.DecodeString(request.Payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to decode payload")
		return c.String(400, "invalid request")
	}

	ke3, err := api.opaqueServer.Deserialize.KE3(payload)
	if err != nil {
		log.Err(err).Str("base64", request.Payload).Msg("failed to deserialize KE3")
		return c.String(400, "invalid request")
	}

	serverOutput, found := api.loginCache.Get(clientId)
	if !found || serverOutput == nil {
		return c.String(400, "invalid request")
	}

	if err := api.opaqueServer.LoginFinish(ke3, serverOutput.ClientMAC); err != nil {
		log.Err(err).Str("clientId", clientId).Msg("login finish failed")
		return c.String(401, "invalid credentials")
	}

	api.loginCache.Del(clientId)

	return c.String(200, "authenticated!")
}
