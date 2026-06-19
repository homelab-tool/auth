package caddy_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api/caddy"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/homelab-tool/auth/internal/testhelpers"
)

const testHost = "test.example.com"

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testhelpers.NewTestDB(t)
}

type testFixture struct {
	srv          *echo.Echo
	allowedToken string
}

func setupTest(t *testing.T) *testFixture {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()

	jwtSvc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	siteConfigSvc := service.NewSiteConfigService(db)
	site, err := siteConfigSvc.Create(ctx, testHost)
	require.NoError(t, err)

	userSvc := service.NewUserService(db)
	groupSvc := service.NewGroupService(db)

	adminGroup, err := groupSvc.Create(ctx, "Admin", "", true)
	require.NoError(t, err)
	err = groupSvc.GrantGroupSiteAccess(ctx, adminGroup.ID, site.ID)
	require.NoError(t, err)

	userID, err := userSvc.Create(ctx, "allowed-user")
	require.NoError(t, err)
	err = groupSvc.AddUser(ctx, userID, adminGroup.ID)
	require.NoError(t, err)

	token, err := jwtSvc.GenerateToken(userID)
	require.NoError(t, err)

	e := echo.New()
	h := caddy.NewHandler(jwtSvc, siteConfigSvc, groupSvc)
	h.SetupRoutes(e.Group("/caddy"))

	return &testFixture{srv: e, allowedToken: token}
}

func TestForwardAuthValidToken(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer "+f.allowedToken)
	req.Header.Set("X-Forwarded-Host", testHost)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
}

func TestForwardAuthValidTokenCookie(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: f.allowedToken})
	req.Header.Set("X-Forwarded-Host", testHost)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
}

func TestForwardAuthNoAuth(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("X-Forwarded-Host", testHost)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	assert.Equal(t, 401, rec.Code)
}

func TestForwardAuthInvalidToken(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-valid-jwt")
	req.Header.Set("X-Forwarded-Host", testHost)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	assert.Equal(t, 401, rec.Code)
}

func TestForwardAuthBearerTakesPriority(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer "+f.allowedToken)
	req.AddCookie(&http.Cookie{Name: "token", Value: "some-invalid-cookie-jwt"})
	req.Header.Set("X-Forwarded-Host", testHost)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
}

func TestForwardAuthHostNotConfigured(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer "+f.allowedToken)
	req.Header.Set("X-Forwarded-Host", "unknown.example.com")
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	assert.Equal(t, 401, rec.Code)
}

func TestForwardAuthMissingHost(t *testing.T) {
	f := setupTest(t)

	req := httptest.NewRequest(http.MethodGet, "/caddy/forward_auth", nil)
	req.Header.Set("Authorization", "Bearer "+f.allowedToken)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	assert.Equal(t, 401, rec.Code)
}
