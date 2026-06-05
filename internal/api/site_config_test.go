package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func authToken(t *testing.T, srv *echo.Echo, clientID, password string) string {
	t.Helper()
	client := newOpaqueClient(t)

	regInit, err := client.RegistrationInit([]byte(password))
	require.NoError(t, err)

	body := fmt.Sprintf(`{"clientId":"%s","payload":"%s"}`, clientID, b64.EncodeToString(regInit.Serialize()))
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	regRespBytes, err := b64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	require.NoError(t, err)

	record, _, err := client.RegistrationFinalize(regResp, []byte(clientID), nil)
	require.NoError(t, err)

	body = fmt.Sprintf(`{"clientId":"%s","payload":"%s"}`, clientID, b64.EncodeToString(record.Serialize()))
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	loginClient := newOpaqueClient(t)
	ke1, err := loginClient.GenerateKE1([]byte(password))
	require.NoError(t, err)

	body = fmt.Sprintf(`{"clientId":"%s","payload":"%s"}`, clientID, b64.EncodeToString(ke1.Serialize()))
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	ke2Bytes, err := b64.DecodeString(rec.Body.String())
	require.NoError(t, err)
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	ke3, _, _, err := loginClient.GenerateKE3(ke2, []byte(clientID), nil)
	require.NoError(t, err)

	body = fmt.Sprintf(`{"clientId":"%s","payload":"%s"}`, clientID, b64.EncodeToString(ke3.Serialize()))
	req = httptest.NewRequest(http.MethodPost, "/api/opaque/login/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var result map[string]string
	err = json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	token, ok := result["token"]
	require.True(t, ok)
	require.NotEmpty(t, token)
	return token
}

func TestSiteConfigAPICreate(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := authToken(t, srv, "create-test-user", "password")

	body := `{"hostname":"app1.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 201, rec.Code)

	var cfg service.SiteConfig
	err := json.NewDecoder(rec.Body).Decode(&cfg)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cfg.ID)
	assert.Equal(t, "app1.example.com", cfg.Hostname)
	assert.False(t, cfg.CreatedAt.IsZero())
}

func TestSiteConfigAPICreateDuplicate(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := authToken(t, srv, "dup-test-user", "password")

	body := `{"hostname":"app1.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 201, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 409, rec.Code)
}

func TestSiteConfigAPICreateUnauthenticated(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db, nil)

	body := `{"hostname":"app1.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestSiteConfigAPIList(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := authToken(t, srv, "list-test-user", "password")

	for _, host := range []string{"app2.example.com", "app1.example.com"} {
		body := fmt.Sprintf(`{"hostname":"%s"}`, host)
		req := httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		require.Equal(t, 201, rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/site-configs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var configs []service.SiteConfig
	err := json.NewDecoder(rec.Body).Decode(&configs)
	require.NoError(t, err)
	require.Len(t, configs, 2)
	assert.Equal(t, "app1.example.com", configs[0].Hostname)
	assert.Equal(t, "app2.example.com", configs[1].Hostname)
}

func TestSiteConfigAPIDelete(t *testing.T) {
	db, _ := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := authToken(t, srv, "delete-test-user", "password")

	body := `{"hostname":"app1.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 201, rec.Code)

	var cfg service.SiteConfig
	err := json.NewDecoder(rec.Body).Decode(&cfg)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/site-configs/%d", cfg.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 204, rec.Code)
}
