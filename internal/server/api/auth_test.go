package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/homelab-tool/auth/internal/server/api/testutil"
	"github.com/homelab-tool/auth/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoamiSuccess(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := testutil.NewTestServer(t, db, nil)
	token := testutil.OpaqueRegisterAndLogin(t, srv, "whoami-user", "super-secret-password")

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	var resp map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "1", resp["userId"])
}

func TestWhoamiNoAuth(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := testutil.NewTestServer(t, db, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestWhoamiInvalidToken(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := testutil.NewTestServer(t, db, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}

func TestWhoamiWrongScheme(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	srv := testutil.NewTestServer(t, db, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, 401, rec.Code)
}
