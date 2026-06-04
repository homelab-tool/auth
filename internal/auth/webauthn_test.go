package auth_test

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/auth"
)

func TestUserIDFromWebAuthnID(t *testing.T) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], 42)

	id, err := auth.UserIDFromWebAuthnID(buf[:])
	require.NoError(t, err)
	assert.Equal(t, int64(42), id)
}

func TestUserIDFromWebAuthnIDInvalidLength(t *testing.T) {
	_, err := auth.UserIDFromWebAuthnID([]byte{1, 2, 3})
	assert.ErrorContains(t, err, "invalid webauthn user id length")

	_, err = auth.UserIDFromWebAuthnID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	assert.ErrorContains(t, err, "invalid webauthn user id length")
}

func TestUserIDFromWebAuthnIDZero(t *testing.T) {
	var buf [8]byte

	id, err := auth.UserIDFromWebAuthnID(buf[:])
	require.NoError(t, err)
	assert.Equal(t, int64(0), id)
}

func TestUserIDFromWebAuthnIDMaxInt64(t *testing.T) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], 1<<63-1)

	id, err := auth.UserIDFromWebAuthnID(buf[:])
	require.NoError(t, err)
	assert.Equal(t, int64(1<<63-1), id)
}

func TestNewWebAuthnServiceMissingRPID(t *testing.T) {
	t.Setenv("WEBAUTHN_RPID", "")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")

	_, err := auth.NewWebAuthnService()
	assert.ErrorContains(t, err, "WEBAUTHN_RPID")
}

func TestNewWebAuthnServiceMissingRPOrigins(t *testing.T) {
	t.Setenv("WEBAUTHN_RPID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "")

	_, err := auth.NewWebAuthnService()
	assert.ErrorContains(t, err, "WEBAUTHN_RP_ORIGINS")
}

func TestNewWebAuthnServiceSuccess(t *testing.T) {
	t.Setenv("WEBAUTHN_RPID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")
	t.Setenv("WEBAUTHN_RP_DISPLAY_NAME", "Test RP")

	svc, err := auth.NewWebAuthnService()
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.NotNil(t, svc.WebAuthn)
}

func TestNewWebAuthnServiceDefaultDisplayName(t *testing.T) {
	t.Setenv("WEBAUTHN_RPID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")

	svc, err := auth.NewWebAuthnService()
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestWebAuthnUserMethods(t *testing.T) {
	user := &auth.WebAuthnUser{
		ID:          42,
		DisplayName: "Test User",
	}

	id := user.WebAuthnID()
	assert.Len(t, id, 8)
	assert.Equal(t, "Test User", user.WebAuthnDisplayName())
	assert.Equal(t, "42", user.WebAuthnName())
	assert.Equal(t, "", user.WebAuthnIcon())
	assert.Empty(t, user.WebAuthnCredentials())
}
