package middleware

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
)

func AdminMiddleware(jwt *auth.JWTService, groups *service.GroupService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			userID, err := jwt.UserIDFromCookie(c.Request())
			if err != nil {
				return c.Redirect(302, "/login")
			}
			isAdmin, err := groups.IsAdmin(c.Request().Context(), userID)
			if err != nil || !isAdmin {
				return c.Redirect(302, "/login")
			}
			return next(c)
		}
	}
}
