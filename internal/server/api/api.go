package api

import (
	"database/sql"

	bytemareopaque "github.com/bytemare/opaque"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api/opaque"
	"github.com/homelab-tool/auth/internal/server/api/secondfactor"
	"github.com/homelab-tool/auth/internal/server/api/siteconfig"
	"github.com/homelab-tool/auth/internal/server/api/webauthn"
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
	SiteConfigs     *service.SiteConfigService
}

func (api *Api) SetupRoutes(e *echo.Group, opaqueServer *bytemareopaque.Server, sfHandler *secondfactor.Handler) error {
	opaqueHandler, err := opaque.NewHandler(
		opaqueServer, api.Opaque, api.JWT, sfHandler,
	)
	if err != nil {
		return err
	}

	webAuthnHandler, err := webauthn.NewHandler(api.Users, api.Credentials, api.JWT, api.SecondFactorSvc, api.TOTP, sfHandler)
	if err != nil {
		return err
	}

	siteConfigHandler := siteconfig.NewHandler(api.SiteConfigs)

	opaqueHandler.SetupRoutes(e.Group("/opaque"), jwtMiddleware(api.JWT))
	webAuthnHandler.SetupRoutes(e.Group("/webauthn"), jwtMiddleware(api.JWT))
	siteConfigHandler.SetupRoutes(e.Group("/site-configs"), jwtMiddleware(api.JWT))

	e.GET("/whoami", api.whoami, jwtMiddleware(api.JWT))

	return nil
}
