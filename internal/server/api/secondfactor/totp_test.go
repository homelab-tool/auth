package secondfactor_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apitest "github.com/homelab-tool/auth/internal/server/api/testutil"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/homelab-tool/auth/internal/testhelpers"
)

func TestTOTPRegisterFlow(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	token := apitest.OpaqueRegisterAndLogin(t, srv, "totp-user", "super-secret-password")

	// Generate TOTP secret
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/generate", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var genResp struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &genResp)
	require.NoError(t, err)
	assert.NotEmpty(t, genResp.Secret)
	assert.Contains(t, genResp.URI, "otpauth://totp/")

	// Verify TOTP with valid code
	code, err := totp.GenerateCode(genResp.Secret, time.Now())
	require.NoError(t, err)

	body := `{"code":"` + code + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var verifyResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &verifyResp)
	require.NoError(t, err)
	assert.Equal(t, "ok", verifyResp["status"])

	// Verify TOTP is enabled in DB
	var enabled int
	err = db.QueryRow("SELECT enabled FROM totp_secrets WHERE user_id = 1").Scan(&enabled)
	require.NoError(t, err)
	assert.Equal(t, 1, enabled)
}

func TestTOTPLoginFlow(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	token := apitest.OpaqueRegisterAndLogin(t, srv, "totp-user2", "super-secret-password")

	// Enable TOTP 2FA
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/generate", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var genResp struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &genResp)
	require.NoError(t, err)

	code, err := totp.GenerateCode(genResp.Secret, time.Now())
	require.NoError(t, err)

	body := `{"code":"` + code + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	// Login with OPAQUE — should trigger 2FA
	rec = apitest.OpaqueLoginRaw(t, srv, "totp-user2", []byte("super-secret-password"))

	var loginResp map[string]any
	err = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	assert.Equal(t, "2fa_required", loginResp["status"])
	sessionID, ok := loginResp["session_id"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, sessionID)

	// Complete 2FA with TOTP
	code, err = totp.GenerateCode(genResp.Secret, time.Now())
	require.NoError(t, err)

	body = `{"sessionId":"` + sessionID + `","code":"` + code + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/2fa/totp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var finalResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &finalResp)
	require.NoError(t, err)
	assert.NotEmpty(t, finalResp["token"])
}

func TestTOTPLoginInvalidCode(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	token := apitest.OpaqueRegisterAndLogin(t, srv, "totp-user3", "super-secret-password")

	// Enable TOTP
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/generate", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var genResp struct {
		Secret string `json:"secret"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &genResp)
	require.NoError(t, err)

	code, err := totp.GenerateCode(genResp.Secret, time.Now())
	require.NoError(t, err)

	body := `{"code":"` + code + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	// Login to get 2FA session
	rec = apitest.OpaqueLoginRaw(t, srv, "totp-user3", []byte("super-secret-password"))

	var loginResp map[string]any
	err = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	sessionID, ok := loginResp["session_id"].(string)
	require.True(t, ok)

	// Submit wrong TOTP code
	body = `{"sessionId":"` + sessionID + `","code":"000000"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/2fa/totp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestTOTPRegisterErrors(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	// Generate without JWT
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/generate", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)

	// Verify without JWT
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/verify", strings.NewReader(`{"code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)

	// Verify with JWT but no active secret
	token := apitest.OpaqueRegisterAndLogin(t, srv, "totp-error-user", "super-secret-password")
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/verify", strings.NewReader(`{"code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 400, rec.Code)

	// Empty code
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/totp/verify", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 400, rec.Code)
}

func TestTOTPLoginInvalidSession(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	body := `{"sessionId":"invalid","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/login/2fa/totp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 400, rec.Code)
}
