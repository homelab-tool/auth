package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
)

func TestOpaqueServiceIsClientIDTaken(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)

	taken, err := svc.IsClientIDTaken(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.False(t, taken)
}

func TestOpaqueServiceIsClientIDTakenTrue(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)
	ksf := auth.DefaultKSF()
	params, _ := ksf.ParamsJSON()

	_, err := svc.CreateUser(context.Background(), "testuser", "cred123", "record123",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	require.NoError(t, err)

	taken, err := svc.IsClientIDTaken(context.Background(), "testuser")
	require.NoError(t, err)
	assert.True(t, taken)
}

func TestOpaqueServiceGetUserDataFound(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)
	ksf := auth.DefaultKSF()
	params, _ := ksf.ParamsJSON()

	userID, err := svc.CreateUser(context.Background(), "testuser", "cred123", "record123",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	require.NoError(t, err)

	data, err := svc.GetUserData(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", data.ClientID)
	assert.Equal(t, "cred123", data.EncodedCredentialID)
	assert.Equal(t, "record123", data.EncodedRecord)
	assert.Equal(t, userID, data.UserID)
	assert.Equal(t, ksf.AlgorithmName(), data.KSFAlgorithm)
	assert.Equal(t, params, data.KSFParams)
	assert.Equal(t, ksf.OutputLen, data.KSFOutputLen)
}

func TestOpaqueServiceGetUserDataNotFound(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)

	_, err := svc.GetUserData(context.Background(), "nonexistent")
	assert.ErrorContains(t, err, "no rows in result set")
}

func TestOpaqueServiceCreateUser(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)
	ksf := auth.DefaultKSF()
	params, _ := ksf.ParamsJSON()

	userID, err := svc.CreateUser(context.Background(), "testuser", "cred123", "record123",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	require.NoError(t, err)
	assert.Equal(t, int64(1), userID)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	err = db.QueryRow("SELECT COUNT(*) FROM opaque_user_data WHERE client_id = 'testuser'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestOpaqueServiceCreateUserDuplicateClientID(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)
	ksf := auth.DefaultKSF()
	params, _ := ksf.ParamsJSON()

	_, err := svc.CreateUser(context.Background(), "testuser", "cred123", "record123",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	require.NoError(t, err)

	_, err = svc.CreateUser(context.Background(), "testuser", "cred456", "record456",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	assert.Error(t, err)
}

func TestOpaqueServiceCreateUserRollsBackOnError(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewOpaqueService(db)
	ksf := auth.DefaultKSF()
	params, _ := ksf.ParamsJSON()

	_, err := svc.CreateUser(context.Background(), "testuser", "cred123", "record123",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	require.NoError(t, err)

	_, err = svc.CreateUser(context.Background(), "testuser2", "cred123", "record456",
		ksf.AlgorithmName(), ksf.Salt, params, ksf.OutputLen)
	assert.Error(t, err)

	var userCount int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	require.NoError(t, err)

	var dataCount int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_user_data").Scan(&dataCount)
	require.NoError(t, err)
	assert.Equal(t, 1, dataCount)
	assert.Equal(t, 1, userCount)
}
