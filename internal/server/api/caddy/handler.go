package caddy

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	JWT         *auth.JWTService
	SiteConfigs *service.SiteConfigService
}

func NewHandler(jwt *auth.JWTService, siteConfigs *service.SiteConfigService) *Handler {
	return &Handler{JWT: jwt, SiteConfigs: siteConfigs}
}

func (h *Handler) SetupRoutes(g *echo.Group) {
	g.GET("/forward_auth", h.forwardAuth)
}

func (h *Handler) forwardAuth(c *echo.Context) error {
	token := api.ExtractJWT(c)
	if token == "" {
		return c.String(401, "unauthorized")
	}

	claims, err := h.JWT.ValidateToken(token)
	if err != nil {
		log.Debug().Err(err).Msg("forward_auth: jwt validation failed")
		return c.String(401, "unauthorized")
	}

	host := c.Request().Header.Get("X-Forwarded-Host")
	if host == "" {
		log.Debug().Msg("forward_auth: missing X-Forwarded-Host")
		return c.String(401, "unauthorized")
	}

	exists, err := h.SiteConfigs.Exists(c.Request().Context(), host)
	if err != nil {
		log.Debug().Err(err).Str("host", host).Msg("forward_auth: site config lookup failed")
		return c.String(401, "unauthorized")
	}
	if !exists {
		log.Debug().Str("host", host).Msg("forward_auth: host not configured")
		return c.String(401, "unauthorized")
	}

	log.Debug().
		Str("user_id", claims.Subject).
		Str("target_host", host).
		Msg("forward_auth: authorized")

	return c.NoContent(200)
}


