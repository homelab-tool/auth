package layout

import (
	"net/http"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

func SetCookieHandler(jwt *auth.JWTService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		token := c.FormValue("token")
		if token == "" {
			return c.String(400, "missing token")
		}

		claims, err := jwt.ValidateToken(token)
		if err != nil {
			log.Err(err).Msg("invalid token in set-cookie")
			return c.HTML(400, `<div>Invalid token</div>`)
		}

		c.SetCookie(&http.Cookie{
			Name:     "token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Expires:  claims.ExpiresAt.Time,
		})

		c.Response().Header().Set("HX-Redirect", "/profile")
		return c.NoContent(200)
	}
}

func UserIDFromCookie(c *echo.Context, jwt *auth.JWTService) (int64, error) {
	userID, err := jwt.UserIDFromCookie(c.Request())
	if err != nil {
		return 0, echo.NewHTTPError(401, "unauthorized")
	}
	return userID, nil
}

func LogoutHandler(c *echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	return c.Redirect(302, "/login")
}
