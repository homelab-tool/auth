package auth_test

import (
	"testing"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/auth"
)

func TestServerConfig(t *testing.T) {
	cfg := auth.ServerConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, opaque.RistrettoSha512, cfg.OPRF)
	assert.Equal(t, opaque.RistrettoSha512, cfg.AKE)
	assert.Equal(t, ksf.Argon2id, cfg.KSF)
}

func TestCreateOpaqueServerGeneratesKeyMaterial(t *testing.T) {
	db := newTestDB(t)

	srv, err := auth.CreateOpaqueServer(db)
	require.NoError(t, err)
	require.NotNil(t, srv)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM secrets WHERE name = 'opaque_skm'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestCreateOpaqueServerStoresKeyMaterial(t *testing.T) {
	db := newTestDB(t)

	srv, err := auth.CreateOpaqueServer(db)
	require.NoError(t, err)
	require.NotNil(t, srv)

	var storedBytes []byte
	err = db.QueryRow("SELECT value FROM secrets WHERE name = 'opaque_skm'").Scan(&storedBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, storedBytes)
}

func TestServerConfigClient(t *testing.T) {
	client, err := auth.ServerConfig().Client()
	require.NoError(t, err)
	require.NotNil(t, client)
}
