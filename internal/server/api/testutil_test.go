package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/server/api"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/homelab-tool/auth/internal/testhelpers"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testhelpers.NewTestDB(t)
}

type testServerOpts struct {
	RPID            string
	RPOrigins       string
	SecondFactorSvc service.SecondFactorService
}

func newTestServer(t *testing.T, db *sql.DB, opts *testServerOpts) *echo.Echo {
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

	jwtService, err := auth.NewJWTService(db)
	require.NoError(t, err)

	webAuthnSvc, err := auth.NewWebAuthnService()
	require.NoError(t, err)

	userSvc := service.NewUserService(db)
	opaqueSvc := service.NewOpaqueService(db)
	credentialSvc := service.NewCredentialService(db)
	totpSvc := service.NewTOTPService(db)
	siteConfigSvc := service.NewSiteConfigService(db)

	e := echo.New()
	a := &api.Api{
		DB:              db,
		JWT:             jwtService,
		WebAuthn:        webAuthnSvc,
		Users:           userSvc,
		Opaque:          opaqueSvc,
		Credentials:     credentialSvc,
		SecondFactorSvc: secondFactorSvc,
		TOTP:            totpSvc,
		SiteConfigs:     siteConfigSvc,
	}
	err = a.SetupRoutes(e.Group("/api"))
	require.NoError(t, err)
	return e
}

// opaqueRegister performs the OPAQUE registration flow.
func opaqueRegister(t *testing.T, srv *echo.Echo, clientID, password string) {
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

	regRespBytes, err := testhelpers.B64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	require.NoError(t, err)

	record, _, err := client.RegistrationFinalize(regResp, []byte(clientID), nil)
	require.NoError(t, err)

	body = `{"clientId":"` + clientID + `","payload":"` + testhelpers.B64.EncodeToString(record.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
}

// opaqueRegisterAndLogin performs the full OPAQUE register + login flow
// and returns the JWT token from the server.
func opaqueRegisterAndLogin(t *testing.T, srv *echo.Echo, clientID, password string) string {
	t.Helper()
	opaqueRegister(t, srv, clientID, password)
	return opaqueLogin(t, srv, clientID, []byte(password))
}

// opaqueLoginRaw performs the KE1→KE2→KE3 login handshake and returns the raw response recorder.
func opaqueLoginRaw(t *testing.T, srv *echo.Echo, clientID string, password []byte) *httptest.ResponseRecorder {
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

	ke2Bytes, err := testhelpers.B64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	ke3, _, _, err := loginClient.GenerateKE3(ke2, []byte(clientID), nil)
	require.NoError(t, err)

	body = `{"clientId":"` + clientID + `","payload":"` + testhelpers.B64.EncodeToString(ke3.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	return rec
}

// opaqueLogin performs the OPAQUE login handshake and returns the JWT token.
func opaqueLogin(t *testing.T, srv *echo.Echo, clientID string, password []byte) string {
	t.Helper()
	rec := opaqueLoginRaw(t, srv, clientID, password)

	var resp map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.NotEmpty(t, resp["token"])

	return resp["token"]
}
