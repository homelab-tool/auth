package api

import (
	"database/sql"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
)

type Api struct {
	DB  *sql.DB
	JWT *auth.JWTService
}

func (api *Api) SetupRoutes(e *echo.Group) error {
	if err := api.setupOpaque(api.DB, e.Group("/opaque")); err != nil {
		return err
	}

	e.GET("/whoami", api.whoami, jwtMiddleware(api.JWT))

	return nil
}
