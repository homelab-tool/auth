package testutil

import (
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/homelab-tool/auth/internal"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api"
	"github.com/homelab-tool/auth/internal/server/api/secondfactor"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/homelab-tool/auth/internal/testhelpers"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/require"
)

type NewTestServerOpts struct {
	RPID            string
	RPOrigins       string
	SecondFactorSvc service.SecondFactorService
}

func NewTestServer(t *testing.T, db *sql.DB, opts *NewTestServerOpts) *echo.Echo {
	t.Helper()

	rpID := "localhost"
	rpOrigins := "http://localhost:1337"
	var secondFactorSvc service.SecondFactorService

	if opts != nil {
		if opts.RPID != "" {
			rpID = opts.RPID
		}
		if opts.RPOrigins != "" {
			rpOrigins = opts.RPOrigins
		}
		secondFactorSvc = opts.SecondFactorSvc
	}

	t.Setenv("WEBAUTHN_RPID", rpID)
	t.Setenv("WEBAUTHN_RP_ORIGINS", rpOrigins)

	svcs, err := internal.InitServices(db, secondFactorSvc)
	require.NoError(t, err)

	e := echo.New()
	a := &api.Api{
		DB:              db,
		JWT:             svcs.JWT,
		WebAuthn:        svcs.WebAuthn,
		Users:           svcs.Users,
		Opaque:          svcs.Opaque,
		Credentials:     svcs.Credentials,
		SecondFactorSvc: svcs.SecondFactor,
		TOTP:            svcs.TOTP,
		SiteConfigs:     svcs.SiteConfigs,
	}
	sfHandler, err := secondfactor.NewHandler(
		a.Users, a.Credentials, a.JWT, a.WebAuthn,
		a.SecondFactorSvc, a.TOTP,
	)
	require.NoError(t, err)

	err = a.SetupRoutes(e.Group("/api"), svcs.OpaqueServer, sfHandler)
	require.NoError(t, err)
	return e
}

func OpaqueRegister(t *testing.T, srv *echo.Echo, clientID, password string) {
	t.Helper()
	client := testhelpers.NewOpaqueClient(t)

	regInit, err := client.RegistrationInit([]byte(password))
	require.NoError(t, err)

	body := `{"clientId":"` + clientID + `","payload":"` + testhelpers.B64.EncodeToString(regInit.Serialize()) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var startResp struct {
		RegistrationResponse string `json:"registrationResponse"`
		KSF                  struct {
			Algorithm string `json:"algorithm"`
			Params    string `json:"params"`
			OutputLen int    `json:"outputLen"`
		} `json:"ksf"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &startResp))
	def := auth.DefaultKSF()
	defParams, _ := def.ParamsJSON()
	require.Equal(t, def.AlgorithmName(), startResp.KSF.Algorithm)
	require.Equal(t, defParams, startResp.KSF.Params)
	require.Equal(t, def.OutputLen, startResp.KSF.OutputLen)
	regRespBytes, err := testhelpers.B64.DecodeString(startResp.RegistrationResponse)
	require.NoError(t, err)
	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	require.NoError(t, err)

	opts := auth.DefaultKSF().ClientOptions()
	record, _, err := client.RegistrationFinalize(regResp, []byte(clientID), nil, opts)
	require.NoError(t, err)

	body = `{"clientId":"` + clientID + `","payload":"` + testhelpers.B64.EncodeToString(record.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
}

func OpaqueRegisterAndLogin(t *testing.T, srv *echo.Echo, clientID, password string) string {
	t.Helper()
	OpaqueRegister(t, srv, clientID, password)
	return OpaqueLogin(t, srv, clientID, []byte(password))
}

func OpaqueLoginRaw(t *testing.T, srv *echo.Echo, clientID string, password []byte) *httptest.ResponseRecorder {
	t.Helper()

	loginClient := testhelpers.NewOpaqueClient(t)
	ke1, err := loginClient.GenerateKE1(password)
	require.NoError(t, err)

	body := `{"clientId":"` + clientID + `","payload":"` + testhelpers.B64.EncodeToString(ke1.Serialize()) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/login/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var loginStartResp struct {
		LoginResponse string `json:"loginResponse"`
		KSF           struct {
			Algorithm string `json:"algorithm"`
			Params    string `json:"params"`
			OutputLen int    `json:"outputLen"`
		} `json:"ksf"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &loginStartResp))
	def := auth.DefaultKSF()
	defParams, _ := def.ParamsJSON()
	require.Equal(t, def.AlgorithmName(), loginStartResp.KSF.Algorithm)
	require.Equal(t, defParams, loginStartResp.KSF.Params)
	require.Equal(t, def.OutputLen, loginStartResp.KSF.OutputLen)
	ke2Bytes, err := testhelpers.B64.DecodeString(loginStartResp.LoginResponse)
	require.NoError(t, err)
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	opts := auth.DefaultKSF().ClientOptions()
	ke3, _, _, err := loginClient.GenerateKE3(ke2, []byte(clientID), nil, opts)
	require.NoError(t, err)

	body = `{"clientId":"` + clientID + `","payload":"` + testhelpers.B64.EncodeToString(ke3.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	return rec
}

func ExtractPublicKey(t *testing.T, response string) string {
	t.Helper()
	var wrapped map[string]json.RawMessage
	err := json.Unmarshal([]byte(response), &wrapped)
	require.NoError(t, err)
	pk, ok := wrapped["publicKey"]
	require.True(t, ok, "response should contain publicKey field")
	return string(pk)
}

func AddUserHandle(t *testing.T, assertionResponse string, userID int64) string {
	t.Helper()
	var resp map[string]any
	err := json.Unmarshal([]byte(assertionResponse), &resp)
	require.NoError(t, err)

	response, ok := resp["response"].(map[string]any)
	require.True(t, ok)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(userID))
	response["userHandle"] = base64.RawURLEncoding.EncodeToString(buf[:])

	patched, err := json.Marshal(resp)
	require.NoError(t, err)
	return string(patched)
}

func OpaqueLogin(t *testing.T, srv *echo.Echo, clientID string, password []byte) string {
	t.Helper()
	rec := OpaqueLoginRaw(t, srv, clientID, password)

	var resp map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.NotEmpty(t, resp["token"])

	return resp["token"]
}
