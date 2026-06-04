package api_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal"
	"github.com/homelab-tool/auth/internal/api"
	"github.com/homelab-tool/auth/internal/auth"
)

var b64 = base64.RawURLEncoding

func newTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := internal.MigrateDB("sqlite3://" + dbPath)
	require.NoError(t, err)

	db, err := sql.Open("sqlite3", dbPath+"?cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)

	return db, dbPath
}

func newTestServer(t *testing.T, db *sql.DB) *echo.Echo {
	t.Helper()
	jwtService, err := auth.NewJWTService(db)
	require.NoError(t, err)
	e := echo.New()
	a := &api.Api{DB: db, JWT: jwtService}
	err = a.SetupRoutes(e.Group("/api"))
	require.NoError(t, err)
	return e
}

func newOpaqueClient(t *testing.T) *opaque.Client {
	t.Helper()
	c, err := auth.ServerConfig().Client()
	require.NoError(t, err)
	return c
}

func TestOpaqueFullFlow(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)
	client := newOpaqueClient(t)
	clientId := "testuser"
	password := []byte("super-secret-password")

	// === REGISTRATION ===

	regInit, err := client.RegistrationInit(password)
	require.NoError(t, err)

	body := `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(regInit.Serialize()) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	regRespBytes, err := b64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	require.NoError(t, err)

	clientID := []byte(clientId)

	record, exportKey, err := client.RegistrationFinalize(regResp, clientID, nil)
	require.NoError(t, err)
	require.NotNil(t, exportKey)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(record.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	assert.Equal(t, "registered!", rec.Body.String())

	// === DUPLICATE REGISTRATION ===

	dupClient := newOpaqueClient(t)
	regInit2, err := dupClient.RegistrationInit(password)
	require.NoError(t, err)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(regInit2.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 409, rec.Code)

	// === LOGIN ===

	loginClient := newOpaqueClient(t)

	ke1, err := loginClient.GenerateKE1(password)
	require.NoError(t, err)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(ke1.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	ke2Bytes, err := b64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	ke3, sessionKey, _, err := loginClient.GenerateKE3(ke2, clientID, nil)
	require.NoError(t, err)
	require.NotNil(t, sessionKey)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(ke3.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["token"])
}

func TestOpaqueLoginUnknownUser(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)
	loginClient := newOpaqueClient(t)

	ke1, err := loginClient.GenerateKE1([]byte("password"))
	require.NoError(t, err)

	// loginStart returns 200 with a fake KE2 to prevent client enumeration
	body := `{"clientId":"nonexistent","payload":"` + b64.EncodeToString(ke1.Serialize()) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/login/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	require.NotEmpty(t, rec.Body.String())

	// loginFinish eventually rejects the fake session with 401
	ke2Bytes, err := b64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	// Client will fail to generate KE3 because the fake record's keys
	// don't match the server's actual key material.
	_, _, _, err = loginClient.GenerateKE3(ke2, nil, nil)
	require.Error(t, err)

	// Send a fabricated KE3 to loginFinish
	fakeKE3 := make([]byte, 64)
	for i := range fakeKE3 {
		fakeKE3[i] = byte(i)
	}
	body = `{"clientId":"nonexistent","payload":"` + b64.EncodeToString(fakeKE3) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 401, rec.Code)
}

func TestOpaqueLoginWrongPassword(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	regClient := newOpaqueClient(t)
	clientId := "testuser"

	// Register with correct password
	regInit, err := regClient.RegistrationInit([]byte("correct-password"))
	require.NoError(t, err)

	body := `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(regInit.Serialize()) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	regRespBytes, _ := b64.DecodeString(rec.Body.String())
	regResp, _ := regClient.Deserialize.RegistrationResponse(regRespBytes)
	record, _, _ := regClient.RegistrationFinalize(regResp, nil, nil)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(record.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	// Login with wrong password
	wrongClient := newOpaqueClient(t)
	ke1Wrong, err := wrongClient.GenerateKE1([]byte("wrong-password"))
	require.NoError(t, err)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(ke1Wrong.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	ke2Bytes, _ := b64.DecodeString(rec.Body.String())
	ke2, err := wrongClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	// Client should fail to verify KE3 due to password mismatch
	_, _, _, err = wrongClient.GenerateKE3(ke2, nil, nil)
	require.Error(t, err)

	// Server should reject a non-zero KE3 with wrong content
	fakeKE3 := make([]byte, 64)
	for i := range fakeKE3 {
		fakeKE3[i] = byte(i)
	}
	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(fakeKE3) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 401, rec.Code)
}

func TestOpaqueBadPayloads(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	tests := []struct {
		name   string
		path   string
		body   string
		status int
	}{
		{
			name:   "register start invalid base64",
			path:   "/api/opaque/register/start",
			body:   `{"clientId":"test","payload":"!!!invalid-b64!!!"}`,
			status: 400,
		},
		{
			name:   "register start short payload",
			path:   "/api/opaque/register/start",
			body:   `{"clientId":"test","payload":"` + b64.EncodeToString([]byte{1, 2, 3}) + `"}`,
			status: 400,
		},
		{
			name:   "login start invalid base64",
			path:   "/api/opaque/login/start",
			body:   `{"clientId":"test","payload":"!!!invalid-b64!!!"}`,
			status: 400,
		},
		{
			name:   "register start empty client id",
			path:   "/api/opaque/register/start",
			body:   `{"clientId":"","payload":"dGVzdA=="}`,
			status: 400,
		},
		{
			name:   "login start empty client id",
			path:   "/api/opaque/login/start",
			body:   `{"clientId":"","payload":"dGVzdA=="}`,
			status: 400,
		},
		{
			name:   "register finish empty client id",
			path:   "/api/opaque/register/finish",
			body:   `{"clientId":"","payload":"dGVzdA=="}`,
			status: 400,
		},
		{
			name:   "login finish empty client id",
			path:   "/api/opaque/login/finish",
			body:   `{"clientId":"","payload":"dGVzdA=="}`,
			status: 400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			require.Equal(t, tc.status, rec.Code)
		})
	}
}

func TestOpaqueClientIdTooLong(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	longId := strings.Repeat("a", 300)
	body := `{"clientId":"` + longId + `","payload":"dGVzdA=="}`

	for _, path := range []string{
		"/api/opaque/register/start",
		"/api/opaque/register/finish",
		"/api/opaque/login/start",
		"/api/opaque/login/finish",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			require.Equal(t, 400, rec.Code)
		})
	}
}

func TestOpaquePayloadTooLarge(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	largePayload := strings.Repeat("a", 70000)
	body := `{"clientId":"test","payload":"` + largePayload + `"}`

	for _, path := range []string{
		"/api/opaque/register/start",
		"/api/opaque/register/finish",
		"/api/opaque/login/start",
		"/api/opaque/login/finish",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			require.Equal(t, 400, rec.Code)
		})
	}
}
