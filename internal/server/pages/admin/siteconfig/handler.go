package siteconfig

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	JWT *auth.JWTService
	Svc *service.SiteConfigService
}

func NewHandler(jwt *auth.JWTService, svc *service.SiteConfigService) *Handler {
	return &Handler{JWT: jwt, Svc: svc}
}

func (h *Handler) PageHandler(c *echo.Context) error {
	_, err := layout.UserIDFromCookie(c, h.JWT)
	if err != nil {
		return c.Redirect(http.StatusFound, "/login")
	}

	configs, err := h.Svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(http.StatusInternalServerError, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return Page(configs).Render(c.Request().Context(), c.Response())
}

func (h *Handler) CreateHandler(c *echo.Context) error {
	_, err := layout.UserIDFromCookie(c, h.JWT)
	if err != nil {
		return c.Redirect(http.StatusFound, "/login")
	}

	hostname := strings.TrimSpace(c.FormValue("hostname"))
	if hostname == "" {
		return c.String(http.StatusBadRequest, "hostname is required")
	}

	if _, err := h.Svc.Create(c.Request().Context(), hostname); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return c.String(http.StatusConflict, "hostname already exists")
		}
		log.Err(err).Str("hostname", hostname).Msg("failed to create site config")
		return c.String(http.StatusInternalServerError, "server error")
	}

	configs, err := h.Svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(http.StatusInternalServerError, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return SiteConfigList(configs).Render(c.Request().Context(), c.Response())
}

func (h *Handler) DeleteHandler(c *echo.Context) error {
	_, err := layout.UserIDFromCookie(c, h.JWT)
	if err != nil {
		return c.Redirect(http.StatusFound, "/login")
	}

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}

	if err := h.Svc.Delete(c.Request().Context(), id); err != nil {
		log.Err(err).Int64("id", id).Msg("failed to delete site config")
		return c.String(http.StatusInternalServerError, "server error")
	}

	configs, err := h.Svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(http.StatusInternalServerError, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return SiteConfigList(configs).Render(c.Request().Context(), c.Response())
}
