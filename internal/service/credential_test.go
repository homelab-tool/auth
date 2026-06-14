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

func insertTestUser(t *testing.T, db *sql.DB, displayName string) int64 {
	t.Helper()
	result, err := db.Exec("INSERT INTO users (display_name) VALUES (?)", displayName)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	return id
}

func TestCredentialServicePersist(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("credential-id-1"),
		PublicKey:       []byte("public-key-bytes"),
		AttestationType: "none",
	}

	err := svc.Persist(context.Background(), userID, cred, "login", "test passkey")
	require.NoError(t, err)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestCredentialServicePersistDuplicateCredentialID(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("same-cred-id"),
		PublicKey:       []byte("public-key-bytes"),
		AttestationType: "none",
	}

	err := svc.Persist(context.Background(), userID, cred, "login", "")
	require.NoError(t, err)

	err = svc.Persist(context.Background(), userID, cred, "login", "")
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

	err := svc.Persist(context.Background(), 999, cred, "login", "")
	assert.ErrorContains(t, err, "FOREIGN KEY constraint")
}

func TestCredentialServiceUpdate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
	}
	err := svc.Persist(context.Background(), userID, cred, "login", "")
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
	userID := insertTestUser(t, db, "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
	}
	cred.Authenticator.SignCount = 10
	err := svc.Persist(context.Background(), userID, cred, "login", "")
	require.NoError(t, err)

	cred.Authenticator.SignCount = 5
	err = svc.Update(context.Background(), cred)
	require.NoError(t, err)

	var signCount int64
	err = db.QueryRow("SELECT sign_count FROM webauthn_credentials WHERE credential_id = ?", cred.ID).Scan(&signCount)
	require.NoError(t, err)
	assert.Equal(t, int64(10), signCount, "sign count should not decrease")
}

func TestCredentialServiceGetPurpose(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "testuser")

	cred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
	}
	err := svc.Persist(context.Background(), userID, cred, "login", "")
	require.NoError(t, err)

	purpose, err := svc.GetPurpose(context.Background(), cred.ID)
	require.NoError(t, err)
	assert.Equal(t, "login", purpose)
}

func TestCredentialServiceListBy2FAPurpose(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewCredentialService(db)
	userID := insertTestUser(t, db, "testuser")

	cred1 := &webauthn.Credential{ID: []byte("cred-1"), PublicKey: []byte("pk1"), AttestationType: "none"}
	cred2 := &webauthn.Credential{ID: []byte("cred-2"), PublicKey: []byte("pk2"), AttestationType: "none"}

	require.NoError(t, svc.Persist(context.Background(), userID, cred1, "login", ""))
	require.NoError(t, svc.Persist(context.Background(), userID, cred2, "2fa", ""))

	creds, err := svc.ListBy2FAPurpose(context.Background(), userID)
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, "2fa", creds[0].Purpose)
}
