package caddy_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/caddy"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := internal.MigrateDB("sqlite3://" + dbPath)
	require.NoError(t, err)
	db, err := sql.Open("sqlite3", dbPath+"?cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	return db
}

func setupTest(t *testing.T) (*echo.Echo, *auth.JWTService) {
	t.Helper()
	db := newTestDB(t)
	jwtSvc, err := auth.NewJWTService(db)
	require.NoError(t, err)
	e := echo.New()
	h := caddy.NewHandler(jwtSvc)
	h.SetupRoutes(e.Group("/caddy"))
	return e, jwtSvc
}

func TestForwardAuthValidToken(t *testing.T) {
	srv, jwtSvc := setupTest(t)
	token, err := jwtSvc.GenerateToken(1, "test-user")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
}

func TestForwardAuthValidTokenCookie(t *testing.T) {
	srv, jwtSvc := setupTest(t)
	token, err := jwtSvc.GenerateToken(2, "cookie-user")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
}

func TestForwardAuthNoAuth(t *testing.T) {
	srv, _ := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	assert.Equal(t, 401, rec.Code)
}

func TestForwardAuthInvalidToken(t *testing.T) {
	srv, _ := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-valid-jwt")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	assert.Equal(t, 401, rec.Code)
}

func TestForwardAuthBearerTakesPriority(t *testing.T) {
	srv, jwtSvc := setupTest(t)
	validToken, err := jwtSvc.GenerateToken(3, "header-user")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.AddCookie(&http.Cookie{Name: "token", Value: "some-invalid-cookie-jwt"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
}
