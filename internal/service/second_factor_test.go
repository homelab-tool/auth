package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestDefaultSecondFactorRequiredTrue(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	_, err := db.Exec("INSERT INTO user_second_factors (user_id, method, enabled) VALUES (?, 'webauthn', 1)", userID)
	require.NoError(t, err)

	required, err := svc.Required(userID)
	require.NoError(t, err)
	assert.True(t, required)
}

func TestDefaultSecondFactorRequiredFalse(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	required, err := svc.Required(userID)
	require.NoError(t, err)
	assert.False(t, required)
}

func TestDefaultSecondFactorRequiredDisabled(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	_, err := db.Exec("INSERT INTO user_second_factors (user_id, method, enabled) VALUES (?, 'webauthn', 0)", userID)
	require.NoError(t, err)

	required, err := svc.Required(userID)
	require.NoError(t, err)
	assert.False(t, required)
}

func TestDefaultSecondFactorMethods(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	_, err := db.Exec("INSERT INTO user_second_factors (user_id, method, enabled) VALUES (?, 'webauthn', 1)", userID)
	require.NoError(t, err)

	methods, err := svc.Methods(userID)
	require.NoError(t, err)
	assert.Equal(t, []string{"webauthn"}, methods)
}

func TestDefaultSecondFactorMethodsMultiple(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	_, err := db.Exec("INSERT INTO user_second_factors (user_id, method, enabled) VALUES (?, 'webauthn', 1)", userID)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO user_second_factors (user_id, method, enabled) VALUES (?, 'totp', 1)", userID)
	require.NoError(t, err)

	methods, err := svc.Methods(userID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"webauthn", "totp"}, methods)
}

func TestDefaultSecondFactorMethodsNone(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	methods, err := svc.Methods(userID)
	require.NoError(t, err)
	assert.Empty(t, methods)
}
