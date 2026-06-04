package service_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func insertTestUser(t *testing.T, db *sql.DB, authMethod, displayName string) int64 {
	t.Helper()
	result, err := db.Exec("INSERT INTO users (auth_method, display_name) VALUES (?, ?)", authMethod, displayName)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	return id
}

func TestCredentialServicePersist(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "webauthn", "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("credential-id-1"),
		PublicKey:       []byte("public-key-bytes"),
		AttestationType: "none",
	}

	err := svc.Persist(context.Background(), userID, cred)
	require.NoError(t, err)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestCredentialServicePersistDuplicateCredentialID(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "webauthn", "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("same-cred-id"),
		PublicKey:       []byte("public-key-bytes"),
		AttestationType: "none",
	}

	err := svc.Persist(context.Background(), userID, cred)
	require.NoError(t, err)

	err = svc.Persist(context.Background(), userID, cred)
	assert.ErrorContains(t, err, "UNIQUE constraint")
}

func TestCredentialServicePersistMissingUser(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)

	cred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("public-key"),
		AttestationType: "none",
	}

	err := svc.Persist(context.Background(), 999, cred)
	assert.ErrorContains(t, err, "FOREIGN KEY constraint")
}

func TestCredentialServiceUpdate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "webauthn", "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
	}
	err := svc.Persist(context.Background(), userID, cred)
	require.NoError(t, err)

	cred.Authenticator.SignCount = 5
	err = svc.Update(context.Background(), cred)
	require.NoError(t, err)

	var signCount int64
	err = db.QueryRow("SELECT sign_count FROM webauthn_credentials WHERE credential_id = ?", cred.ID).Scan(&signCount)
	require.NoError(t, err)
	assert.Equal(t, int64(5), signCount)
}

func TestCredentialServiceUpdateStaleSignCount(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "webauthn", "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
	}
	cred.Authenticator.SignCount = 10
	err := svc.Persist(context.Background(), userID, cred)
	require.NoError(t, err)

	cred.Authenticator.SignCount = 5
	err = svc.Update(context.Background(), cred)
	require.NoError(t, err)

	var signCount int64
	err = db.QueryRow("SELECT sign_count FROM webauthn_credentials WHERE credential_id = ?", cred.ID).Scan(&signCount)
	require.NoError(t, err)
	assert.Equal(t, int64(10), signCount, "sign count should not decrease")
}

func TestCredentialServiceEnableSecondFactor(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	err := svc.EnableSecondFactor(context.Background(), userID)
	require.NoError(t, err)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM user_second_factors WHERE user_id = ? AND method = 'webauthn' AND enabled = 1", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestCredentialServiceEnableSecondFactorIdempotent(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "pass-opaque", "testuser")

	err := svc.EnableSecondFactor(context.Background(), userID)
	require.NoError(t, err)

	err = svc.EnableSecondFactor(context.Background(), userID)
	require.NoError(t, err)
}
