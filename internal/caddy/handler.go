package caddy

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	JWT *auth.JWTService
}

func NewHandler(jwt *auth.JWTService) *Handler {
	return &Handler{JWT: jwt}
}

func (h *Handler) SetupRoutes(g *echo.Group) {
	g.GET("/forward_auth", h.forwardAuth)
}

func (h *Handler) forwardAuth(c *echo.Context) error {
	token := extractToken(c)
	if token == "" {
		return c.String(401, "unauthorized")
	}

	claims, err := h.JWT.ValidateToken(token)
	if err != nil {
		log.Debug().Err(err).Msg("forward_auth: jwt validation failed")
		return c.String(401, "unauthorized")
	}

	log.Debug().
		Str("user_id", claims.Subject).
		Str("client_id", claims.ClientID).
		Str("target_host", c.Request().Header.Get("X-Forwarded-Host")).
		Msg("forward_auth: authorized")

	return c.NoContent(200)
}

func extractToken(c *echo.Context) string {
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
