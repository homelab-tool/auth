package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestUserServiceCreate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	id, err := svc.Create(context.Background(), "webauthn", "testuser")
	require.NoError(t, err)
	assert.Equal(t, int64(1), id)

	var displayName string
	err = db.QueryRow("SELECT display_name FROM users WHERE id = ?", id).Scan(&displayName)
	require.NoError(t, err)
	assert.Equal(t, "testuser", displayName)
}

func TestUserServiceCreateInvalidAuthMethod(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	_, err := svc.Create(context.Background(), "invalid-method", "testuser")
	assert.ErrorContains(t, err, "CHECK constraint")
}

func TestUserServiceDelete(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	id, err := svc.Create(context.Background(), "webauthn", "testuser")
	require.NoError(t, err)

	err = svc.Delete(context.Background(), id)
	require.NoError(t, err)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestUserServiceDeleteNonExistent(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	err := svc.Delete(context.Background(), 999)
	require.NoError(t, err)
}

func TestUserServiceGetDisplayName(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	id, err := svc.Create(context.Background(), "webauthn", "testuser")
	require.NoError(t, err)

	name, err := svc.GetDisplayName(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "testuser", name)
}

func TestUserServiceGetDisplayNameNotFound(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	_, err := svc.GetDisplayName(context.Background(), 999)
	assert.ErrorContains(t, err, "no rows in result set")
}

func TestUserServiceLoadWebAuthnUserNoCredentials(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	id, err := svc.Create(context.Background(), "webauthn", "testuser")
	require.NoError(t, err)

	user, err := svc.LoadWebAuthnUser(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, id, user.ID)
	assert.Equal(t, "testuser", user.DisplayName)
	assert.Empty(t, user.Credentials)
}

func TestUserServiceLoadWebAuthnUserNotFound(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewUserService(db)

	_, err := svc.LoadWebAuthnUser(context.Background(), 999)
	assert.Error(t, err)
}
