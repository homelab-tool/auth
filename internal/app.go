package internal

import (
	"database/sql"
	"io/fs"
	"log/slog"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api"
	"github.com/homelab-tool/auth/internal/server/api/caddy"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/server/pages/login"
	"github.com/homelab-tool/auth/internal/server/pages/profile"
	"github.com/homelab-tool/auth/internal/server/pages/register"
	"github.com/homelab-tool/auth/internal/server/pages/static"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type App struct {
	Router *echo.Echo
	DB     *sql.DB
}

func CreateApp() (*App, error) {
	var e = echo.New()
	var handler = zerolog.NewSlogHandler(log.Logger)
	e.Logger = slog.New(handler)

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogMethod:    true,
		LogLatency:   true,
		LogRequestID: true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			log.Info().
				Str("method", v.Method).
				Str("uri", v.URI).
				Int("status", v.Status).
				Dur("latency", v.Latency).
				Str("request_id", v.RequestID).
				Msg("request")
			return nil
		},
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	e.GET("/health", func(c *echo.Context) error {
		return c.String(200, "ok")
	})

	var db, err = InitializeDb()
	if err != nil {
		return nil, err
	}

	jwtService, err := auth.NewJWTService(db)
	if err != nil {
		return nil, err
	}

	webAuthnSvc, err := auth.NewWebAuthnService()
	if err != nil {
		return nil, err
	}

	userSvc := service.NewUserService(db)
	opaqueSvc := service.NewOpaqueService(db)
	credentialSvc := service.NewCredentialService(db)
	secondFactorSvc := service.NewDefaultSecondFactorService(db)
	totpSvc := service.NewTOTPService(db)
	siteConfigSvc := service.NewSiteConfigService(db)

	opaqueServer, err := auth.CreateOpaqueServer(db)
	if err != nil {
		return nil, err
	}

	if err := BootstrapAdminUser(db, opaqueSvc, opaqueServer); err != nil {
		return nil, err
	}

	api := api.Api{
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

	if err = api.SetupRoutes(e.Group("/api"), opaqueServer); err != nil {
		return nil, err
	}

	caddyHandler := caddy.NewHandler(jwtService, siteConfigSvc)
	caddyHandler.SetupRoutes(e.Group("/caddy"))

	subFS, err := fs.Sub(static.Files, "dist")
	if err != nil {
		return nil, err
	}
	e.StaticFS("/static", subFS)

	e.GET("/login", login.PageHandler)
	e.GET("/register", register.PageHandler)
	e.GET("/profile", profile.PageHandler(jwtService, userSvc, secondFactorSvc))

	enrollHandler := register.NewEnrollmentHandler(jwtService, userSvc, totpSvc)
	e.GET("/register/2fa", enrollHandler.PageHandler)
	e.POST("/register/2fa/totp/generate", enrollHandler.HandleTOTPGenerate)
	e.POST("/register/2fa/totp/verify", enrollHandler.HandleTOTPVerify)
	e.POST("/auth/set-cookie", layout.SetCookieHandler(jwtService))
	e.POST("/auth/logout", layout.LogoutHandler)

	app := &App{
		Router: e,
		DB:     db,
	}

	return app, nil
}
