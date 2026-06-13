package profile

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type ProfileData struct {
	User           *service.User
	EnabledMethods []string
}

func PageHandler(jwt *auth.JWTService, users *service.UserService, svc service.SecondFactorService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, err := layout.UserIDFromCookie(c, jwt)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		user, err := users.GetUser(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to load user")
			return c.String(500, "server error")
		}

		methods, err := svc.Methods(userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to query 2fa methods")
			return c.String(500, "server error")
		}

		return Page(&ProfileData{
			User:           user,
			EnabledMethods: methods,
		}).Render(c.Request().Context(), c.Response())
	}
}
