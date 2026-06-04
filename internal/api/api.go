package api

import (
	"database/sql"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
)

type Api struct {
	DB              *sql.DB
	JWT             *auth.JWTService
	WebAuthn        *auth.WebAuthnService
	SecondFactorSvc SecondFactorService
}

func (api *Api) SetupRoutes(e *echo.Group) error {
	if err := api.setupOpaque(api.DB, e.Group("/opaque"), api.WebAuthn, api.SecondFactorSvc); err != nil {
		return err
	}

	if err := api.setupWebAuthn(api.DB, e.Group("/webauthn")); err != nil {
		return err
	}

	e.GET("/whoami", api.whoami, jwtMiddleware(api.JWT))

	return nil
}
