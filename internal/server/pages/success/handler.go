package success

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
)

func PageHandler(jwt *auth.JWTService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		cookie, err := c.Cookie("token")
		if err != nil || cookie.Value == "" {
			return c.Redirect(302, "/login")
		}
		if _, err := jwt.ValidateToken(cookie.Value); err != nil {
			return c.Redirect(302, "/login")
		}
		return Page().Render(c.Request().Context(), c.Response())
	}
}
