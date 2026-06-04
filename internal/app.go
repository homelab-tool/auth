package internal

import (
	"database/sql"
	"log/slog"

	"github.com/homelab-tool/auth/internal/api"
	"github.com/homelab-tool/auth/internal/auth"
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

	api := api.Api{
		DB:              db,
		JWT:             jwtService,
		WebAuthn:        webAuthnSvc,
		Users:           userSvc,
		Opaque:          opaqueSvc,
		Credentials:     credentialSvc,
		SecondFactorSvc: secondFactorSvc,
	}

	if err = api.SetupRoutes(e.Group("/api")); err != nil {
		return nil, err
	}

	app := &App{
		Router: e,
		DB:     db,
	}

	return app, nil
}
