package api

import (
	"database/sql"
	"github.com/labstack/echo/v5"
)

type Api struct {
	DB *sql.DB
}

func (api *Api) SetupRoutes(e *echo.Group) error {
	return api.setupOpaque(api.DB, e.Group("/opaque"))
}
