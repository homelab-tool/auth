package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestSiteConfigAPICreate(t *testing.T) {
	db := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := opaqueRegisterAndLogin(t, srv, "create-test-user", "password")

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
	db := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := opaqueRegisterAndLogin(t, srv, "dup-test-user", "password")

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
	db := newTestDB(t)
	srv := newTestServer(t, db, nil)

	body := `{"hostname":"app1.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/site-configs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestSiteConfigAPIList(t *testing.T) {
	db := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := opaqueRegisterAndLogin(t, srv, "list-test-user", "password")

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
	db := newTestDB(t)
	srv := newTestServer(t, db, nil)
	token := opaqueRegisterAndLogin(t, srv, "delete-test-user", "password")

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
