package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestDefaultSecondFactorRequiredWithWebAuthn(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "testuser")

	_, err := db.Exec(
		"INSERT INTO webauthn_credentials (user_id, credential_id, public_key, attestation_type, transport, sign_count, clone_warning, backup_eligible, backup_state, purpose, name) VALUES (?, ?, ?, ?, '', 0, 0, 0, 0, '2fa', '')",
		userID, []byte("cred-1"), []byte("pk"), "none")
	require.NoError(t, err)

	required, err := svc.Required(userID)
	require.NoError(t, err)
	assert.True(t, required)
}

func TestDefaultSecondFactorRequiredWithTOTP(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "testuser")

	_, err := db.Exec(
		"INSERT INTO totp_secrets (user_id, secret, enabled) VALUES (?, 'secret', 1)",
		userID)
	require.NoError(t, err)

	required, err := svc.Required(userID)
	require.NoError(t, err)
	assert.True(t, required)
}

func TestDefaultSecondFactorRequiredFalse(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "testuser")

	required, err := svc.Required(userID)
	require.NoError(t, err)
	assert.False(t, required)
}

func TestDefaultSecondFactorMethods(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "testuser")

	_, err := db.Exec(
		"INSERT INTO totp_secrets (user_id, secret, enabled) VALUES (?, 'secret', 1)",
		userID)
	require.NoError(t, err)

	methods, err := svc.Methods(userID)
	require.NoError(t, err)
	assert.Equal(t, []string{"totp"}, methods)
}

func TestDefaultSecondFactorMethodsNone(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "testuser")

	methods, err := svc.Methods(userID)
	require.NoError(t, err)
	assert.Empty(t, methods)
}

func TestDefaultSecondFactorDisableTOTP(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewDefaultSecondFactorService(db)
	userID := insertTestUser(t, db, "testuser")

	_, err := db.Exec(
		"INSERT INTO totp_secrets (user_id, secret, enabled) VALUES (?, 'secret', 1)",
		userID)
	require.NoError(t, err)

	err = svc.Disable(userID, "totp")
	require.NoError(t, err)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM totp_secrets WHERE user_id = ?", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
