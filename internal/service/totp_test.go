package service_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestTOTPGenerateSecret(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	result, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Secret)
	assert.NotEmpty(t, result.URI)
	assert.Contains(t, result.URI, "otpauth://totp/")
	assert.Contains(t, result.URI, "secret="+result.Secret)
}

func TestTOTPVerifyAndEnableValidCode(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	result, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)

	code, err := totp.GenerateCode(result.Secret, time.Now())
	require.NoError(t, err)

	ok, err := svc.VerifyAndEnable(t.Context(), userID, code)
	require.NoError(t, err)
	assert.True(t, ok)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM user_second_factors WHERE user_id = ? AND method = 'totp' AND enabled = 1", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	var enabled int
	err = db.QueryRow("SELECT enabled FROM totp_secrets WHERE user_id = ?", userID).Scan(&enabled)
	require.NoError(t, err)
	assert.Equal(t, 1, enabled)
}

func TestTOTPVerifyAndEnableInvalidCode(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	_, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)

	ok, err := svc.VerifyAndEnable(t.Context(), userID, "000000")
	require.NoError(t, err)
	assert.False(t, ok)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM user_second_factors WHERE user_id = ? AND method = 'totp'", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestTOTPVerifyAndEnableNoSecret(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	ok, err := svc.VerifyAndEnable(t.Context(), userID, "123456")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestTOTPValidateCodeEnabled(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	result, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)

	code, err := totp.GenerateCode(result.Secret, time.Now())
	require.NoError(t, err)

	ok, err := svc.VerifyAndEnable(t.Context(), userID, code)
	require.NoError(t, err)
	require.True(t, ok)

	code, err = totp.GenerateCode(result.Secret, time.Now())
	require.NoError(t, err)

	valid, err := svc.ValidateCode(t.Context(), userID, code)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestTOTPValidateCodeDisabled(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	_, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)

	valid, err := svc.ValidateCode(t.Context(), userID, "123456")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTOTPValidateCodeNotFound(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	valid, err := svc.ValidateCode(t.Context(), userID, "123456")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTOTPGenerateSecretReplace(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewTOTPService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	result1, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)

	result2, err := svc.GenerateSecret(t.Context(), userID, "testuser", "auth")
	require.NoError(t, err)

	assert.NotEqual(t, result1.Secret, result2.Secret)

	code, err := totp.GenerateCode(result2.Secret, time.Now())
	require.NoError(t, err)

	ok, err := svc.VerifyAndEnable(t.Context(), userID, code)
	require.NoError(t, err)
	assert.True(t, ok)
}
