package webauthn_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apitest "github.com/homelab-tool/auth/internal/server/api/testutil"
	"github.com/homelab-tool/auth/internal/testhelpers"
)

func TestWebAuthnBadPayloads(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{RPID: "example.org", RPOrigins: "https://example.org"})

	tests := []struct {
		name   string
		path   string
		body   string
		status int
	}{
		{
			name:   "register start no body",
			path:   "/api/webauthn/register/start",
			status: 400,
		},
		{
			name:   "register start empty display name",
			path:   "/api/webauthn/register/start",
			body:   `{"displayName":""}`,
			status: 400,
		},
		{
			name:   "register start missing display name",
			path:   "/api/webauthn/register/start",
			body:   `{}`,
			status: 400,
		},
		{
			name:   "register finish no session",
			path:   "/api/webauthn/register/finish",
			body:   `{"id":"test","type":"public-key","response":{"clientDataJSON":"dGVzdA","attestationObject":"dGVzdA"}}`,
			status: 400,
		},
		{
			name:   "login finish no session",
			path:   "/api/webauthn/login/finish",
			body:   `{"id":"test","type":"public-key","response":{"clientDataJSON":"dGVzdA","authenticatorData":"dGVzdA","signature":"dGVzdA"}}`,
			status: 400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body == "" {
				req = httptest.NewRequest(http.MethodPost, tc.path, nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			}
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			require.Equal(t, tc.status, rec.Code, tc.name)
		})
	}
}

func TestWebAuthnRegisterStart(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{RPID: "example.org", RPOrigins: "https://example.org"})

	body := `{"displayName":"testuser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var creation map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &creation)
	require.NoError(t, err)
	_, ok := creation["publicKey"]
	assert.True(t, ok, "response should contain publicKey field")

	var rowCount int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE auth_method = 'webauthn'").Scan(&rowCount)
	require.NoError(t, err)
	assert.Equal(t, 1, rowCount)
}

func TestWebAuthnLoginStart(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{RPID: "example.org", RPOrigins: "https://example.org"})

	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/login/start", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var assertion map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &assertion)
	require.NoError(t, err)
	_, ok := assertion["publicKey"]
	assert.True(t, ok, "response should contain publicKey field")
}

func TestWebAuthnRegisterStartDisplayNameTooLong(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := apitest.NewTestServer(t, db, &apitest.NewTestServerOpts{RPID: "example.org", RPOrigins: "https://example.org"})

	longName := strings.Repeat("a", 300)
	body := `{"displayName":"` + longName + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 400, rec.Code)
}

func TestWebAuthnFullFlow(t *testing.T) {
	// Registration test vectors from W3C spec (None ES256)
	// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
	credentialIDHex := "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
	credentialPubKeyHex := "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	attestationObjectHex := "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	clientDataJSONHex := "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
	challengeHex := "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"

	credentialID, err := hex.DecodeString(credentialIDHex)
	require.NoError(t, err)
	credPubKey, err := hex.DecodeString(credentialPubKeyHex)
	require.NoError(t, err)
	challengeRaw, err := hex.DecodeString(challengeHex)
	require.NoError(t, err)
	challenge := base64.RawURLEncoding.EncodeToString(challengeRaw)

	attObj := base64.RawURLEncoding.EncodeToString(func() []byte {
		b, _ := hex.DecodeString(attestationObjectHex)
		return b
	}())
	cdj := base64.RawURLEncoding.EncodeToString(func() []byte {
		b, _ := hex.DecodeString(clientDataJSONHex)
		return b
	}())
	id := base64.RawURLEncoding.EncodeToString(credentialID)

	response := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": attObj,
			"clientDataJSON":    cdj,
		},
	}
	body, err := json.Marshal(response)
	require.NoError(t, err)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	require.NoError(t, err)

	w, err := webauthn.New(&webauthn.Config{
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
		RPDisplayName: "Test",
	})
	require.NoError(t, err)

	userID := []byte("test-user-id")
	session := webauthn.SessionData{
		Challenge:  challenge,
		UserID:     userID,
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
	}
	user := &testWebAuthnUser{id: userID}

	credential, err := w.CreateCredential(user, session, parsedResponse)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, credentialID, credential.ID)
	assert.Equal(t, "none", credential.AttestationType)
	assert.Equal(t, "none", credential.AttestationFormat)

	// Login test vectors from W3C spec (None ES256)
	// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
	loginChallengeHex := "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	loginAuthenticatorDataHex := "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	loginClientDataJSONHex := "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	loginSignatureHex := "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"

	loginChallenge := base64.RawURLEncoding.EncodeToString(func() []byte {
		b, _ := hex.DecodeString(loginChallengeHex)
		return b
	}())
	loginAuthenticatorData := base64.RawURLEncoding.EncodeToString(func() []byte {
		b, _ := hex.DecodeString(loginAuthenticatorDataHex)
		return b
	}())
	loginClientDataJSON := base64.RawURLEncoding.EncodeToString(func() []byte {
		b, _ := hex.DecodeString(loginClientDataJSONHex)
		return b
	}())
	loginSignature := base64.RawURLEncoding.EncodeToString(func() []byte {
		b, _ := hex.DecodeString(loginSignatureHex)
		return b
	}())

	loginResp := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": loginAuthenticatorData,
			"clientDataJSON":    loginClientDataJSON,
			"signature":         loginSignature,
		},
	}
	loginBody, err := json.Marshal(loginResp)
	require.NoError(t, err)

	loginParsed, err := protocol.ParseCredentialRequestResponseBytes(loginBody)
	require.NoError(t, err)

	loginSession := webauthn.SessionData{
		Challenge: loginChallenge,
		UserID:    userID,
	}

	loginUser := &testWebAuthnUser{
		id: userID,
		credentials: []webauthn.Credential{{
			ID:        credentialID,
			PublicKey: credPubKey,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				BackupEligible: true,
			},
		}},
	}

	verifiedCred, err := w.ValidateLogin(loginUser, loginSession, loginParsed)
	require.NoError(t, err)
	require.NotNil(t, verifiedCred)
	assert.Equal(t, credentialID, verifiedCred.ID)
}

type testWebAuthnUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *testWebAuthnUser) WebAuthnID() []byte                    { return u.id }
func (u *testWebAuthnUser) WebAuthnName() string                  { return "test" }
func (u *testWebAuthnUser) WebAuthnDisplayName() string           { return "Test" }
func (u *testWebAuthnUser) WebAuthnIcon() string                  { return "" }
func (u *testWebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
