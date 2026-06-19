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
	allGroups, err := h.Groups.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	users, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	summaries := make([]GroupSummary, 0, len(allGroups))
	for _, g := range allGroups {
		count, err := h.Groups.MemberCount(c.Request().Context(), g.ID)
		if err != nil {
			log.Err(err).Int64("groupID", g.ID).Msg("failed to get member count")
			count = 0
		}
		summaries = append(summaries, GroupSummary{Group: g, MemberCount: count})
	}

	return GroupsPage(&GroupsPageData{Groups: summaries, Users: users}).Render(c.Request().Context(), c.Response())
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

	allGroups, err := h.Groups.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	summaries := make([]GroupSummary, 0, len(allGroups))
	for _, g := range allGroups {
		count, _ := h.Groups.MemberCount(c.Request().Context(), g.ID)
		summaries = append(summaries, GroupSummary{Group: g, MemberCount: count})
	}

	return GroupList(summaries).Render(c.Request().Context(), c.Response())
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

	allGroups, err := h.Groups.List(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list groups")
		return c.String(500, "server error")
	}

	summaries := make([]GroupSummary, 0, len(allGroups))
	for _, g := range allGroups {
		count, _ := h.Groups.MemberCount(c.Request().Context(), g.ID)
		summaries = append(summaries, GroupSummary{Group: g, MemberCount: count})
	}

	return GroupList(summaries).Render(c.Request().Context(), c.Response())
}

func (h *Handler) ManageHandler(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(400, "invalid id")
	}

	group, err := h.Groups.GetByID(c.Request().Context(), id)
	if err != nil {
		log.Err(err).Int64("id", id).Msg("failed to get group")
		return c.String(500, "server error")
	}

	members, err := h.Groups.UsersInGroup(c.Request().Context(), id)
	if err != nil {
		log.Err(err).Int64("id", id).Msg("failed to list members")
		return c.String(500, "server error")
	}

	allUsers, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		log.Err(err).Msg("failed to list users")
		return c.String(500, "server error")
	}

	return GroupDetail(group, members, allUsers).Render(c.Request().Context(), c.Response())
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

	group, err := h.Groups.GetByID(c.Request().Context(), groupID)
	if err != nil {
		return c.String(500, "server error")
	}

	members, err := h.Groups.UsersInGroup(c.Request().Context(), groupID)
	if err != nil {
		return c.String(500, "server error")
	}

	allUsers, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		return c.String(500, "server error")
	}

	return GroupDetail(group, members, allUsers).Render(c.Request().Context(), c.Response())
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

	group, err := h.Groups.GetByID(c.Request().Context(), groupID)
	if err != nil {
		return c.String(500, "server error")
	}

	members, err := h.Groups.UsersInGroup(c.Request().Context(), groupID)
	if err != nil {
		return c.String(500, "server error")
	}

	allUsers, err := h.Users.ListUsers(c.Request().Context())
	if err != nil {
		return c.String(500, "server error")
	}

	return GroupDetail(group, members, allUsers).Render(c.Request().Context(), c.Response())
}
