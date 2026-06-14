package secondfactor_test

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apitest "github.com/homelab-tool/auth/internal/server/api/testutil"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/homelab-tool/auth/internal/testhelpers"
)

func extractPublicKey(t *testing.T, response string) string {
	t.Helper()
	var wrapped map[string]json.RawMessage
	err := json.Unmarshal([]byte(response), &wrapped)
	require.NoError(t, err)
	pk, ok := wrapped["publicKey"]
	require.True(t, ok, "response should contain publicKey field")
	return string(pk)
}

func addUserHandle(t *testing.T, assertionResponse string, userID int64) string {
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

func TestSecondFactorRegisterFullFlow(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	rp := virtualwebauthn.RelyingParty{
		Name:   "Homelab Auth",
		ID:     "localhost",
		Origin: "http://localhost:1337",
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	token := apitest.OpaqueRegisterAndLogin(t, srv, "2fa-user", "super-secret-password")

	// Register WebAuthn 2FA start
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/webauthn/start", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk := extractPublicKey(t, rec.Body.String())
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(pk)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	require.NotEmpty(t, attestationResponse)

	// Register WebAuthn 2FA finish
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/webauthn/finish", strings.NewReader(attestationResponse))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var finishResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &finishResp)
	require.NoError(t, err)
	assert.Equal(t, "ok", finishResp["status"])

	// Verify 2FA is enabled in DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM user_second_factors WHERE user_id = 1 AND method = 'webauthn' AND enabled = 1").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	authenticator.AddCredential(cred)
}

func TestSecondFactorLoginFullFlow(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	rp := virtualwebauthn.RelyingParty{
		Name:   "Homelab Auth",
		ID:     "localhost",
		Origin: "http://localhost:1337",
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register OPAQUE user + login to get JWT
	token := apitest.OpaqueRegisterAndLogin(t, srv, "2fa-user2", "super-secret-password")

	// Register WebAuthn 2FA
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/webauthn/start", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk := extractPublicKey(t, rec.Body.String())
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(pk)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/webauthn/finish", strings.NewReader(attestationResponse))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	authenticator.AddCredential(cred)

	// Now login with OPAQUE — should trigger 2FA
	rec = apitest.OpaqueLoginRaw(t, srv, "2fa-user2", []byte("super-secret-password"))

	var loginResp map[string]any
	err = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	assert.Equal(t, "2fa_required", loginResp["status"])
	sessionID, ok := loginResp["session_id"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, sessionID)

	// Complete 2FA with WebAuthn
	body := `{"sessionId":"` + sessionID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/2fa/webauthn/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk = extractPublicKey(t, rec.Body.String())
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(pk)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	assertionResponse = addUserHandle(t, assertionResponse, 1)

	body = `{` + assertionResponse[1:]
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/2fa/webauthn/finish?sessionId="+sessionID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var finalResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &finalResp)
	require.NoError(t, err)
	assert.NotEmpty(t, finalResp["token"])
}

func TestSecondFactorRegister2FAFinishErrors(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:            "localhost",
		RPOrigins:       "http://localhost:1337",
		SecondFactorSvc: service.NewDefaultSecondFactorService(db),
	})

	// Missing JWT should return 401
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/webauthn/finish", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 401, rec.Code)

	// With JWT but no active 2FA session should return 400
	token := apitest.OpaqueRegisterAndLogin(t, srv, "2fa-error-user", "super-secret-password")

	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/2fa/webauthn/finish", strings.NewReader(`{"id":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 400, rec.Code)
}
