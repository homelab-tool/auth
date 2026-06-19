package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestGroupServiceEnsureAdminGroup(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	id, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), id)

	group, err := svc.GetByID(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "Admin", group.Name)
	assert.True(t, group.IsAdmin)

	id2, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, id, id2, "EnsureAdminGroup should be idempotent")
}

func TestGroupServiceCreate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	group, err := svc.Create(context.Background(), "Family", "Family members", false)
	require.NoError(t, err)
	assert.Equal(t, int64(1), group.ID)
	assert.Equal(t, "Family", group.Name)
	assert.Equal(t, "Family members", group.Description)
	assert.False(t, group.IsAdmin)
	assert.NotEmpty(t, group.CreatedAt)
}

func TestGroupServiceCreateDuplicate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	_, err := svc.Create(context.Background(), "Family", "", false)
	require.NoError(t, err)

	_, err = svc.Create(context.Background(), "Family", "", false)
	assert.ErrorContains(t, err, "UNIQUE constraint")
}

func TestGroupServiceList(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	adminID, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)

	_, err = svc.Create(context.Background(), "Family", "", false)
	require.NoError(t, err)

	groups, err := svc.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, groups, 2)

	assert.Equal(t, "Admin", groups[0].Name)
	assert.True(t, groups[0].IsAdmin)
	assert.Equal(t, adminID, groups[0].ID)
}

func TestGroupServiceGetByID(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	created, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	group, err := svc.GetByID(context.Background(), created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, group.ID)
	assert.Equal(t, "Test", group.Name)
}

func TestGroupServiceDelete(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	group, err := svc.Create(context.Background(), "Temp", "", false)
	require.NoError(t, err)

	err = svc.Delete(context.Background(), group.ID)
	require.NoError(t, err)

	groups, err := svc.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestGroupServiceDeleteLastAdminGroup(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	adminID, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)

	err = svc.Delete(context.Background(), adminID)
	assert.ErrorContains(t, err, "cannot delete the last admin group")
}

func TestGroupServiceDeleteAdminGroupWhenMultipleExist(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	adminID, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)

	_, err = svc.Create(context.Background(), "Super Admins", "", true)
	require.NoError(t, err)

	err = svc.Delete(context.Background(), adminID)
	require.NoError(t, err)
}

func TestGroupServiceAddUser(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	err = svc.AddUser(context.Background(), userID, group.ID)
	require.NoError(t, err)

	members, err := svc.UsersInGroup(context.Background(), group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, userID, members[0].ID)
	assert.Equal(t, "testuser", members[0].DisplayName)
}

func TestGroupServiceAddUserDuplicate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	err = svc.AddUser(context.Background(), userID, group.ID)
	require.NoError(t, err)

	err = svc.AddUser(context.Background(), userID, group.ID)
	assert.ErrorContains(t, err, "UNIQUE constraint")
}

func TestGroupServiceRemoveUser(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	err = svc.AddUser(context.Background(), userID, group.ID)
	require.NoError(t, err)

	err = svc.RemoveUser(context.Background(), userID, group.ID)
	require.NoError(t, err)

	members, err := svc.UsersInGroup(context.Background(), group.ID)
	require.NoError(t, err)
	assert.Empty(t, members)
}

func TestGroupServiceRemoveUserLastAdminGroup(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	adminID, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "adminuser")
	require.NoError(t, err)

	err = svc.AddUser(context.Background(), userID, adminID)
	require.NoError(t, err)

	err = svc.RemoveUser(context.Background(), userID, adminID)
	assert.ErrorContains(t, err, "cannot remove user from their only admin group")
}

func TestGroupServiceRemoveUserFromNonAdminGroupWhenOnlyMembership(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Family", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	err = svc.AddUser(context.Background(), userID, group.ID)
	require.NoError(t, err)

	err = svc.RemoveUser(context.Background(), userID, group.ID)
	require.NoError(t, err)
}

func TestGroupServiceUsersInGroup(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	uid1, err := userSvc.Create(context.Background(), "alice")
	require.NoError(t, err)
	uid2, err := userSvc.Create(context.Background(), "bob")
	require.NoError(t, err)

	svc.AddUser(context.Background(), uid1, group.ID)
	svc.AddUser(context.Background(), uid2, group.ID)

	members, err := svc.UsersInGroup(context.Background(), group.ID)
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "alice", members[0].DisplayName)
	assert.Equal(t, "bob", members[1].DisplayName)
}

func TestGroupServiceGroupsForUser(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	g1, err := svc.Create(context.Background(), "Family", "", false)
	require.NoError(t, err)
	g2, err := svc.Create(context.Background(), "Friends", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	svc.AddUser(context.Background(), userID, g1.ID)
	svc.AddUser(context.Background(), userID, g2.ID)

	groups, err := svc.GroupsForUser(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, groups, 2)
	assert.Equal(t, "Family", groups[0].Name)
	assert.Equal(t, "Friends", groups[1].Name)
}

func TestGroupServiceIsAdmin(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	adminID, err := svc.EnsureAdminGroup(context.Background())
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "adminuser")
	require.NoError(t, err)

	svc.AddUser(context.Background(), userID, adminID)

	isAdmin, err := svc.IsAdmin(context.Background(), userID)
	require.NoError(t, err)
	assert.True(t, isAdmin)
}

func TestGroupServiceIsAdminNotAdmin(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Family", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "regular")
	require.NoError(t, err)

	svc.AddUser(context.Background(), userID, group.ID)

	isAdmin, err := svc.IsAdmin(context.Background(), userID)
	require.NoError(t, err)
	assert.False(t, isAdmin)
}

func TestGroupServiceIsAdminNoGroups(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	userID, err := userSvc.Create(context.Background(), "lonely")
	require.NoError(t, err)

	isAdmin, err := svc.IsAdmin(context.Background(), userID)
	require.NoError(t, err)
	assert.False(t, isAdmin)
}

func TestGroupServiceMemberCount(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	count, err := svc.MemberCount(context.Background(), group.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	uid1, err := userSvc.Create(context.Background(), "alice")
	require.NoError(t, err)
	svc.AddUser(context.Background(), uid1, group.ID)

	count, err = svc.MemberCount(context.Background(), group.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGroupServiceGrantGroupSiteAccess(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	err = svc.GrantGroupSiteAccess(context.Background(), group.ID, site.ID)
	require.NoError(t, err)

	sites, err := svc.SitesForGroup(context.Background(), group.ID)
	require.NoError(t, err)
	require.Len(t, sites, 1)
	assert.Equal(t, "app.example.com", sites[0].Hostname)
}

func TestGroupServiceRevokeGroupSiteAccess(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	group, err := svc.Create(context.Background(), "Test", "", false)
	require.NoError(t, err)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	err = svc.GrantGroupSiteAccess(context.Background(), group.ID, site.ID)
	require.NoError(t, err)

	err = svc.RevokeGroupSiteAccess(context.Background(), group.ID, site.ID)
	require.NoError(t, err)

	sites, err := svc.SitesForGroup(context.Background(), group.ID)
	require.NoError(t, err)
	assert.Empty(t, sites)
}

func TestGroupServiceGrantUserSiteAccess(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	err = svc.GrantUserSiteAccess(context.Background(), userID, site.ID)
	require.NoError(t, err)

	users, err := svc.UsersForSite(context.Background(), site.ID)
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "testuser", users[0].DisplayName)
}

func TestGroupServiceRevokeUserSiteAccess(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	err = svc.GrantUserSiteAccess(context.Background(), userID, site.ID)
	require.NoError(t, err)

	err = svc.RevokeUserSiteAccess(context.Background(), userID, site.ID)
	require.NoError(t, err)

	users, err := svc.UsersForSite(context.Background(), site.ID)
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestGroupServiceGroupsForSite(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	g1, err := svc.Create(context.Background(), "Alpha", "", false)
	require.NoError(t, err)
	g2, err := svc.Create(context.Background(), "Beta", "", false)
	require.NoError(t, err)

	svc.GrantGroupSiteAccess(context.Background(), g1.ID, site.ID)
	svc.GrantGroupSiteAccess(context.Background(), g2.ID, site.ID)

	groups, err := svc.GroupsForSite(context.Background(), site.ID)
	require.NoError(t, err)
	require.Len(t, groups, 2)
	assert.Equal(t, "Alpha", groups[0].Name)
	assert.Equal(t, "Beta", groups[1].Name)
}

func TestGroupServiceCanAccessSiteViaGroup(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	group, err := svc.Create(context.Background(), "Family", "", false)
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	svc.AddUser(context.Background(), userID, group.ID)
	svc.GrantGroupSiteAccess(context.Background(), group.ID, site.ID)

	ok, err := svc.CanAccessSite(context.Background(), userID, site.ID)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestGroupServiceCanAccessSiteViaDirectUser(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	svc.GrantUserSiteAccess(context.Background(), userID, site.ID)

	ok, err := svc.CanAccessSite(context.Background(), userID, site.ID)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestGroupServiceCanAccessSiteDenied(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewGroupService(db)
	userSvc := service.NewUserService(db)

	siteSvc := service.NewSiteConfigService(db)
	site, err := siteSvc.Create(context.Background(), "app.example.com")
	require.NoError(t, err)

	userID, err := userSvc.Create(context.Background(), "testuser")
	require.NoError(t, err)

	ok, err := svc.CanAccessSite(context.Background(), userID, site.ID)
	require.NoError(t, err)
	assert.False(t, ok)
}
