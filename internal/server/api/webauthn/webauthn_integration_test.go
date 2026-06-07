package webauthn_test

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

func TestWebAuthnFullFlowEC2(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:      "localhost",
		RPOrigins: "http://localhost:1337",
	})

	rp := virtualwebauthn.RelyingParty{
		Name:   "Homelab Auth",
		ID:     "localhost",
		Origin: "http://localhost:1337",
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// === REGISTER ===

	body := `{"displayName":"testuser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk := extractPublicKey(t, rec.Body.String())
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(pk)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attestationOptions)
	require.NotEmpty(t, attestationResponse)

	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/register/finish", strings.NewReader(attestationResponse))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var regResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &regResp)
	require.NoError(t, err)
	assert.NotEmpty(t, regResp["token"])

	authenticator.AddCredential(credential)

	// === LOGIN ===

	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/login/start", nil)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk = extractPublicKey(t, rec.Body.String())
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(pk)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertionOptions)
	// First registered user gets userID=1
	assertionResponse = addUserHandle(t, assertionResponse, 1)

	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/login/finish", strings.NewReader(assertionResponse))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var loginResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	assert.NotEmpty(t, loginResp["token"])
}

func TestWebAuthnFullFlowRSA(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:      "localhost",
		RPOrigins: "http://localhost:1337",
	})

	rp := virtualwebauthn.RelyingParty{
		Name:   "Homelab Auth",
		ID:     "localhost",
		Origin: "http://localhost:1337",
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeRSA)

	body := `{"displayName":"rsauser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk := extractPublicKey(t, rec.Body.String())
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(pk)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attestationOptions)
	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/register/finish", strings.NewReader(attestationResponse))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	authenticator.AddCredential(credential)

	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/login/start", nil)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk = extractPublicKey(t, rec.Body.String())
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(pk)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *assertionOptions)
	assertionResponse = addUserHandle(t, assertionResponse, 1)
	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/login/finish", strings.NewReader(assertionResponse))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var loginResp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	assert.NotEmpty(t, loginResp["token"])
}

func TestWebAuthnLoginFinishInvalidCredential(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{
		RPID:      "localhost",
		RPOrigins: "http://localhost:1337",
	})

	rp := virtualwebauthn.RelyingParty{
		Name:   "Homelab Auth",
		ID:     "localhost",
		Origin: "http://localhost:1337",
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	body := `{"displayName":"testuser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk := extractPublicKey(t, rec.Body.String())
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(pk)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *attestationOptions)
	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/register/finish", strings.NewReader(attestationResponse))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	authenticator.AddCredential(credential)

	evilCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/login/start", nil)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	pk = extractPublicKey(t, rec.Body.String())
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(pk)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, evilCred, *assertionOptions)
	req = httptest.NewRequest(http.MethodPost, "/api/webauthn/login/finish", strings.NewReader(assertionResponse))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 401, rec.Code)
}
