package siteconfig

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	svc *service.SiteConfigService
}

func NewHandler(svc *service.SiteConfigService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) SetupRoutes(e *echo.Group, jwtMiddleware echo.MiddlewareFunc) {
	e.Use(jwtMiddleware)
	e.POST("", h.create)
	e.GET("", h.list)
	e.DELETE("/:id", h.delete)
}

type createSiteConfigRequest struct {
	Hostname string `json:"hostname"`
}

func (h *Handler) create(c *echo.Context) error {
	var req createSiteConfigRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request")
	}

	req.Hostname = strings.TrimSpace(req.Hostname)
	if req.Hostname == "" {
		return c.String(http.StatusBadRequest, "hostname is required")
	}

	cfg, err := h.svc.Create(c.Request().Context(), req.Hostname)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return c.String(http.StatusConflict, "hostname already exists")
		}
		log.Err(err).Str("hostname", req.Hostname).Msg("failed to create site config")
		return c.String(http.StatusInternalServerError, "server error")
	}

	return c.JSON(http.StatusCreated, cfg)
}

func (h *Handler) list(c *echo.Context) error {
	configs, err := h.svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(http.StatusInternalServerError, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return c.JSON(http.StatusOK, configs)
}

func (h *Handler) delete(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}

	if err := h.svc.Delete(c.Request().Context(), id); err != nil {
		log.Err(err).Int64("id", id).Msg("failed to delete site config")
		return c.String(http.StatusInternalServerError, "server error")
	}

	return c.NoContent(http.StatusNoContent)
}
