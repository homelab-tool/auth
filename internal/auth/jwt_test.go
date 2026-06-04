package auth_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal"
	"github.com/homelab-tool/auth/internal/auth"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := internal.MigrateDB("sqlite3://" + dbPath)
	require.NoError(t, err)
	db, err := sql.Open("sqlite3", dbPath+"?cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	return db
}

func TestJWTServiceGenerateAndValidate(t *testing.T) {
	db := newTestDB(t)
	svc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	token, err := svc.GenerateToken(1, "testuser")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "1", claims.Subject)
	assert.Equal(t, "testuser", claims.ClientID)
	assert.Equal(t, "auth", claims.Issuer)
}

func TestJWTServiceValidateExpiredToken(t *testing.T) {
	db := newTestDB(t)
	svc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	var secret []byte
	err = db.QueryRow("SELECT value FROM secrets WHERE name = 'jwt_secret'").Scan(&secret)
	require.NoError(t, err)

	claims := &auth.Claims{
		ClientID: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "1",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
			Issuer:    "auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(secret)
	require.NoError(t, err)

	_, err = svc.ValidateToken(tokenStr)
	assert.ErrorContains(t, err, "token is expired")
}

func TestJWTServiceValidateWrongSigningMethod(t *testing.T) {
	db := newTestDB(t)
	svc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	claims := &auth.Claims{
		ClientID: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "1",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	// Sign with "none" algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenStr, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = svc.ValidateToken(tokenStr)
	assert.Error(t, err)
}

func TestJWTServiceValidateMalformedToken(t *testing.T) {
	db := newTestDB(t)
	svc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	_, err = svc.ValidateToken("not-a-jwt-token")
	assert.Error(t, err)
}

func TestJWTServiceValidateEmptyToken(t *testing.T) {
	db := newTestDB(t)
	svc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	_, err = svc.ValidateToken("")
	assert.Error(t, err)
}

func TestJWTServiceGenerateMultipleTokens(t *testing.T) {
	db := newTestDB(t)
	svc, err := auth.NewJWTService(db)
	require.NoError(t, err)

	t1, err := svc.GenerateToken(1, "user1")
	require.NoError(t, err)
	t2, err := svc.GenerateToken(2, "user2")
	require.NoError(t, err)
	assert.NotEqual(t, t1, t2)

	c1, err := svc.ValidateToken(t1)
	require.NoError(t, err)
	assert.Equal(t, "1", c1.Subject)
	assert.Equal(t, "user1", c1.ClientID)

	c2, err := svc.ValidateToken(t2)
	require.NoError(t, err)
	assert.Equal(t, "2", c2.Subject)
	assert.Equal(t, "user2", c2.ClientID)
}

func TestJWTServiceCrossDBValidation(t *testing.T) {
	db1 := newTestDB(t)
	svc1, err := auth.NewJWTService(db1)
	require.NoError(t, err)

	db2 := newTestDB(t)
	svc2, err := auth.NewJWTService(db2)
	require.NoError(t, err)

	token, err := svc1.GenerateToken(1, "testuser")
	require.NoError(t, err)

	// Different DB has different secret
	_, err = svc2.ValidateToken(token)
	assert.ErrorContains(t, err, "signature is invalid")
}

func TestJWTServiceSecretPersistence(t *testing.T) {
	db := newTestDB(t)

	svc1, err := auth.NewJWTService(db)
	require.NoError(t, err)
	token, err := svc1.GenerateToken(1, "testuser")
	require.NoError(t, err)

	svc2, err := auth.NewJWTService(db)
	require.NoError(t, err)
	claims, err := svc2.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "1", claims.Subject)
}
