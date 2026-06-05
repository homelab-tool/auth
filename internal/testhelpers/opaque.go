package testhelpers

import (
	"encoding/base64"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/auth"
)

var B64 = base64.RawURLEncoding

func NewOpaqueClient(t *testing.T) *opaque.Client {
	t.Helper()
	c, err := auth.ServerConfig().Client()
	require.NoError(t, err)
	return c
}
