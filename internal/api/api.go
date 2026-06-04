package api

import (
	"database/sql"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
)

type Api struct {
	DB              *sql.DB
	JWT             *auth.JWTService
	WebAuthn        *auth.WebAuthnService
	Users           *service.UserService
	Opaque          *service.OpaqueService
	Credentials     *service.CredentialService
	SecondFactorSvc service.SecondFactorService
	TOTP            *service.TOTPService
}

func (api *Api) SetupRoutes(e *echo.Group) error {
	if err := api.setupOpaque(e.Group("/opaque")); err != nil {
		return err
	}

	if err := api.setupWebAuthn(e.Group("/webauthn")); err != nil {
		return err
	}

	e.GET("/whoami", api.whoami, jwtMiddleware(api.JWT))

	return nil
}
