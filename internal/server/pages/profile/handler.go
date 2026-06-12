package profile

import (
	"fmt"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

func PageHandler(jwt *auth.JWTService, users *service.UserService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		cookie, err := c.Cookie("token")
		if err != nil || cookie.Value == "" {
			return c.Redirect(302, "/login")
		}

		claims, err := jwt.ValidateToken(cookie.Value)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		var userID int64
		if _, err := fmt.Sscanf(claims.Subject, "%d", &userID); err != nil {
			log.Err(err).Msg("failed to parse user id from claims")
			return c.Redirect(302, "/login")
		}

		user, err := users.GetUser(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to load user")
			return c.String(500, "server error")
		}

		return Page(user).Render(c.Request().Context(), c.Response())
	}
}
