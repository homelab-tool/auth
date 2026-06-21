package groups

import (
	"strconv"

	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	Groups *service.GroupService
	Users  *service.UserService
}

func NewHandler(groups *service.GroupService, users *service.UserService) *Handler {
	return &Handler{Groups: groups, Users: users}
}

func (h *Handler) PageHandler(c *echo.Context) error {
	allGroups, members, err := h.Groups.ListWithMembers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	users, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	return GroupsPage(allGroups, members, users).Render(c.Request().Context(), c.Response())
}

func (h *Handler) GroupFormHandler(c *echo.Context) error {
	return GroupForm().Render(c.Request().Context(), c.Response())
}

func (h *Handler) CreateHandler(c *echo.Context) error {
	name := c.FormValue("name")
	description := c.FormValue("description")
	isAdmin := c.FormValue("is_admin") == "true"

	if _, err := h.Groups.Create(c.Request().Context(), name, description, isAdmin); err != nil {
		log.Err(err).Str("name", name).Msg("failed to create group")
		return c.String(409, "group name already exists")
	}

	allGroups, members, err := h.Groups.ListWithMembers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	users, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	return GroupList(allGroups, members, users).Render(c.Request().Context(), c.Response())
}

func (h *Handler) DeleteHandler(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	if err := h.Groups.Delete(c.Request().Context(), id); err != nil {
		log.Err(err).Int64("id", id).Msg("failed to delete group")
		return c.String(409, err.Error())
	}

	allGroups, members, err := h.Groups.ListWithMembers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	users, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	return GroupList(allGroups, members, users).Render(c.Request().Context(), c.Response())
}

func (h *Handler) AddMemberHandler(c *echo.Context) error {
	groupID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	userID, err := strconv.ParseInt(c.FormValue("user_id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid user")
	}

	if err := h.Groups.AddUser(c.Request().Context(), userID, groupID); err != nil {
		log.Err(err).Int64("groupID", groupID).Int64("userID", userID).Msg("failed to add member")
		return c.String(409, "user is already a member")
	}

	return h.renderGroupArticle(c, groupID)
}

func (h *Handler) RemoveMemberHandler(c *echo.Context) error {
	groupID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	userID, err := strconv.ParseInt(c.Param("userID"), 10, 64)
	if err != nil {
		return c.String(400, "invalid user")
	}

	if err := h.Groups.RemoveUser(c.Request().Context(), userID, groupID); err != nil {
		log.Err(err).Int64("groupID", groupID).Int64("userID", userID).Msg("failed to remove member")
		return c.String(409, err.Error())
	}

	return h.renderGroupArticle(c, groupID)
}

func (h *Handler) renderGroupArticle(c *echo.Context, groupID int64) error {
	group, err := h.Groups.GetByID(c.Request().Context(), groupID)
	if err != nil {
		log.Err(err).Int64("id", groupID).Msg("failed to get group")
		return c.String(500, "server error")
	}

	members, err := h.Groups.UsersInGroup(c.Request().Context(), groupID)
	if err != nil {
		log.Err(err).Int64("id", groupID).Msg("failed to list members")
		return c.String(500, "server error")
	}

	allUsers, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	return GroupArticle(*group, members, allUsers).Render(c.Request().Context(), c.Response())
}
