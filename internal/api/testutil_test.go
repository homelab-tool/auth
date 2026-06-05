package api_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal"
	"github.com/homelab-tool/auth/internal/api"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
)

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

type testServerOpts struct {
	RPID            string
	RPOrigins       string
	SecondFactorSvc service.SecondFactorService
}

func newTestServer(t *testing.T, db *sql.DB, opts *testServerOpts) *echo.Echo {
	t.Helper()

	rpID := "localhost"
	rpOrigins := "http://localhost:1337"
	var secondFactorSvc service.SecondFactorService

	if opts != nil {
		if opts.RPID != "" {
			rpID = opts.RPID
		}
		if opts.RPOrigins != "" {
			rpOrigins = opts.RPOrigins
		}
		secondFactorSvc = opts.SecondFactorSvc
	}

	t.Setenv("WEBAUTHN_RPID", rpID)
	t.Setenv("WEBAUTHN_RP_ORIGINS", rpOrigins)

	jwtService, err := auth.NewJWTService(db)
	require.NoError(t, err)

	webAuthnSvc, err := auth.NewWebAuthnService()
	require.NoError(t, err)

	userSvc := service.NewUserService(db)
	opaqueSvc := service.NewOpaqueService(db)
	credentialSvc := service.NewCredentialService(db)
	totpSvc := service.NewTOTPService(db)
	siteConfigSvc := service.NewSiteConfigService(db)

	e := echo.New()
	a := &api.Api{
		DB:              db,
		JWT:             jwtService,
		WebAuthn:        webAuthnSvc,
		Users:           userSvc,
		Opaque:          opaqueSvc,
		Credentials:     credentialSvc,
		SecondFactorSvc: secondFactorSvc,
		TOTP:            totpSvc,
		SiteConfigs:     siteConfigSvc,
	}
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
