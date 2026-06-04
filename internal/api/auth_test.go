package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registerAndLogin(t *testing.T, srv *echo.Echo, clientId string) string {
	t.Helper()
	client := newOpaqueClient(t)
	password := []byte("super-secret-password")

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

	record, _, err := client.RegistrationFinalize(regResp, []byte(clientId), nil)
	require.NoError(t, err)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(record.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

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

	ke3, _, _, err := loginClient.GenerateKE3(ke2, []byte(clientId), nil)
	require.NoError(t, err)

	body = `{"clientId":"` + clientId + `","payload":"` + b64.EncodeToString(ke3.Serialize()) + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.NotEmpty(t, resp["token"])

	return resp["token"]
}

func TestWhoamiSuccess(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)
	token := registerAndLogin(t, srv, "whoami-user")

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var resp map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "1", resp["user_id"])
}

func TestWhoamiNoAuth(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestWhoamiInvalidToken(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestWhoamiWrongScheme(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}
