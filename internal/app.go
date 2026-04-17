package internal

import (
	"database/sql"
	"log/slog"

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

	var db, err = InitializeDb()
	if err != nil {
		return nil, err
	}

	app := &App{
		Router: e,
		DB:     db,
	}

	e.POST("/auth", app.AuthHandler)

	return app, nil
}

func (a *App) AuthHandler(c *echo.Context) error {
	return c.String(500, "todo")
}
