package siteconfig

import (
	"strconv"
	"strings"

	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	Svc    *service.SiteConfigService
	Groups *service.GroupService
	Users  *service.UserService
}

func NewHandler(svc *service.SiteConfigService, groups *service.GroupService, users *service.UserService) *Handler {
	return &Handler{Svc: svc, Groups: groups, Users: users}
}

func (h *Handler) PageHandler(c *echo.Context) error {
	configs, err := h.Svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(500, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return Page(configs).Render(c.Request().Context(), c.Response())
}

func (h *Handler) CreateHandler(c *echo.Context) error {
	hostname := strings.TrimSpace(c.FormValue("hostname"))
	if hostname == "" {
		return c.String(400, "hostname is required")
	}

	if _, err := h.Svc.Create(c.Request().Context(), hostname); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return c.String(409, "hostname already exists")
		}
		log.Err(err).Str("hostname", hostname).Msg("failed to create site config")
		return c.String(500, "server error")
	}

	configs, err := h.Svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(500, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return Page(configs).Render(c.Request().Context(), c.Response())
}

func (h *Handler) DeleteHandler(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	if err := h.Svc.Delete(c.Request().Context(), id); err != nil {
		log.Err(err).Int64("id", id).Msg("failed to delete site config")
		return c.String(500, "server error")
	}

	configs, err := h.Svc.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list site configs")
		return c.String(500, "server error")
	}

	if configs == nil {
		configs = []service.SiteConfig{}
	}

	return Page(configs).Render(c.Request().Context(), c.Response())
}

func (h *Handler) ManageHandler(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	site, err := h.Svc.GetByID(c.Request().Context(), id)
	if err != nil {
		log.Err(err).Int64("id", id).Msg("failed to get site config")
		return c.String(500, "server error")
	}

	allGroups, err := h.Groups.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	allUsers, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	siteGroups, err := h.Groups.GroupsForSite(c.Request().Context(), id)
	if err != nil {
		log.Err(err).Int64("id", id).Msg("failed to list groups for site")
		return c.String(500, "server error")
	}

	siteUsers, err := h.Groups.UsersForSite(c.Request().Context(), id)
	if err != nil {
		log.Err(err).Int64("id", id).Msg("failed to list users for site")
		return c.String(500, "server error")
	}

	return SiteAccessSection(site, allGroups, allUsers, siteGroups, siteUsers).Render(c.Request().Context(), c.Response())
}

func (h *Handler) GrantGroupHandler(c *echo.Context) error {
	siteID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	groupID, err := strconv.ParseInt(c.FormValue("group_id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid group")
	}

	if err := h.Groups.GrantGroupSiteAccess(c.Request().Context(), groupID, siteID); err != nil {
		log.Err(err).Int64("siteID", siteID).Int64("groupID", groupID).Msg("failed to grant group access")
		return c.String(409, "group already has access")
	}

	return h.renderAccessSection(c, siteID)
}

func (h *Handler) RevokeGroupHandler(c *echo.Context) error {
	siteID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	groupID, err := strconv.ParseInt(c.Param("groupID"), 10, 64)
	if err != nil {
		return c.String(400, "invalid group")
	}

	if err := h.Groups.RevokeGroupSiteAccess(c.Request().Context(), groupID, siteID); err != nil {
		log.Err(err).Int64("siteID", siteID).Int64("groupID", groupID).Msg("failed to revoke group access")
		return c.String(500, "server error")
	}

	return h.renderAccessSection(c, siteID)
}

func (h *Handler) GrantUserHandler(c *echo.Context) error {
	siteID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	userID, err := strconv.ParseInt(c.FormValue("user_id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid user")
	}

	if err := h.Groups.GrantUserSiteAccess(c.Request().Context(), userID, siteID); err != nil {
		log.Err(err).Int64("siteID", siteID).Int64("userID", userID).Msg("failed to grant user access")
		return c.String(409, "user already has access")
	}

	return h.renderAccessSection(c, siteID)
}

func (h *Handler) RevokeUserHandler(c *echo.Context) error {
	siteID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	userID, err := strconv.ParseInt(c.Param("userID"), 10, 64)
	if err != nil {
		return c.String(400, "invalid user")
	}

	if err := h.Groups.RevokeUserSiteAccess(c.Request().Context(), userID, siteID); err != nil {
		log.Err(err).Int64("siteID", siteID).Int64("userID", userID).Msg("failed to revoke user access")
		return c.String(500, "server error")
	}

	return h.renderAccessSection(c, siteID)
}

func (h *Handler) renderAccessSection(c *echo.Context, siteID int64) error {
	site, err := h.Svc.GetByID(c.Request().Context(), siteID)
	if err != nil {
		return c.String(500, "server error")
	}

	allGroups, err := h.Groups.List(c.Request().Context())
	if err != nil {
		return c.String(500, "server error")
	}

	allUsers, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		return c.String(500, "server error")
	}

	siteGroups, err := h.Groups.GroupsForSite(c.Request().Context(), siteID)
	if err != nil {
		return c.String(500, "server error")
	}

	siteUsers, err := h.Groups.UsersForSite(c.Request().Context(), siteID)
	if err != nil {
		return c.String(500, "server error")
	}

	return SiteAccessSection(site, allGroups, allUsers, siteGroups, siteUsers).Render(c.Request().Context(), c.Response())
}
