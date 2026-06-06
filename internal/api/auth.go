package api

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

const contextKeyClaims = "claims"

func jwtMiddleware(jwtService *auth.JWTService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			token := extractJWT(c)
			if token == "" {
				return c.String(401, "unauthorized")
			}

			claims, err := jwtService.ValidateToken(token)
			if err != nil {
				log.Err(err).Msg("jwt validation failed")
				return c.String(401, "unauthorized")
			}

			c.Set(contextKeyClaims, claims)
			return next(c)
		}
	}
}

func extractJWT(c *echo.Context) string {
	const bearerLen = len("Bearer ")
	authHeader := c.Request().Header.Get("Authorization")
	if len(authHeader) > bearerLen && authHeader[:bearerLen] == "Bearer " {
		return authHeader[bearerLen:]
	}

	if cookie, err := c.Cookie("token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

func (api *Api) whoami(c *echo.Context) error {
	claims, ok := c.Get(contextKeyClaims).(*auth.Claims)
	if !ok {
		return c.String(401, "unauthorized")
	}
	return c.JSON(200, map[string]string{"user_id": claims.Subject})
}
