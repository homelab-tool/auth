package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bytemare/opaque"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/homelab-tool/auth/internal/auth"
)

var b64 = base64.RawURLEncoding

const caddyfile = `{
    debug
    local_certs
}

auth.mydomain.test {
    tls internal
    reverse_proxy auth:1337
}

app1.mydomain.test {
    tls internal
    forward_auth auth:1337 {
        uri /caddy/forward_auth
    }
    respond "Hello World from caddy!"
}

app2.mydomain.test {
    tls internal
    forward_auth auth:1337 {
        uri /caddy/forward_auth
    }
    respond "App 2"
}`

type e2eEnv struct {
	authURL    string
	caddyURL   string
	client     *opaque.Client
	httpClient *http.Client
}

func setupE2E(t *testing.T) *e2eEnv {
	t.Helper()
	ctx := context.Background()

	netName := "e2e-" + uuid.NewString()
	net, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           netName,
			CheckDuplicate: true,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { net.Remove(ctx) })

	authC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "homelab-auth:e2e",
			Env: map[string]string{
				"WEBAUTHN_RPID":       "localhost",
				"WEBAUTHN_RP_ORIGINS": "http://localhost:1337",
			},
			ExposedPorts:  []string{"1337/tcp"},
			Networks:      []string{netName},
			NetworkAliases: map[string][]string{netName: {"auth"}},
			WaitingFor: wait.ForHTTP("/health").
				WithPort("1337/tcp").
				WithStartupTimeout(120 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { authC.Terminate(ctx) })

	authPort, err := authC.MappedPort(ctx, "1337/tcp")
	require.NoError(t, err)

	caddyC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "caddy:2-alpine",
			Files: []testcontainers.ContainerFile{
				{
					Reader:            strings.NewReader(caddyfile),
					ContainerFilePath: "/etc/caddy/Caddyfile",
					FileMode:          0o644,
				},
			},
			ExposedPorts:  []string{"443/tcp"},
			Networks:      []string{netName},
			NetworkAliases: map[string][]string{netName: {"caddy"}},
			WaitingFor: wait.ForHTTP("/health").
				WithPort("443/tcp").
				WithTLS(true, &tls.Config{ServerName: "auth.mydomain.test", InsecureSkipVerify: true}).
				WithHeaders(map[string]string{"Host": "auth.mydomain.test"}).
				WithStartupTimeout(120 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { caddyC.Terminate(ctx) })

	caddyPort, err := caddyC.MappedPort(ctx, "443/tcp")
	require.NoError(t, err)

	opaqueClient, err := auth.ServerConfig().Client()
	require.NoError(t, err)

	return &e2eEnv{
		authURL:  fmt.Sprintf("http://127.0.0.1:%s", authPort.Port()),
		caddyURL: fmt.Sprintf("https://127.0.0.1:%s", caddyPort.Port()),
		client:   opaqueClient,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					ServerName:         "app1.mydomain.test",
					InsecureSkipVerify: true,
				},
			},
			Timeout: 10 * time.Second,
		},
	}
}

func (env *e2eEnv) caddyRequest(t *testing.T, method, path, host string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, env.caddyURL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := env.httpClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (env *e2eEnv) authAPI(t *testing.T, method, path string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, env.authURL+path, strings.NewReader(body))
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (env *e2eEnv) configureSite(t *testing.T, token, hostname string) {
	t.Helper()
	body := `{"hostname":"` + hostname + `"}`
	resp := env.authAPI(t, "POST", "/api/site-configs",
		map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + token,
		}, body)
	require.Equal(t, 201, resp.StatusCode)
}

func (env *e2eEnv) opaqueRegister(t *testing.T, clientID, password string) {
	t.Helper()

	regInit, err := env.client.RegistrationInit([]byte(password))
	require.NoError(t, err)

	payload := b64.EncodeToString(regInit.Serialize())
	body := `{"clientId":"` + clientID + `","payload":"` + payload + `"}`
	resp := env.authAPI(t, "POST", "/api/opaque/register/start",
		map[string]string{"Content-Type": "application/json"}, body)
	require.Equal(t, 200, resp.StatusCode)

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(t, err)

	regRespBytes, err := b64.DecodeString(strings.TrimSpace(buf.String()))
	require.NoError(t, err)
	regResp, err := env.client.Deserialize.RegistrationResponse(regRespBytes)
	require.NoError(t, err)

	record, _, err := env.client.RegistrationFinalize(regResp, []byte(clientID), nil)
	require.NoError(t, err)

	recordPayload := b64.EncodeToString(record.Serialize())
	body = `{"clientId":"` + clientID + `","payload":"` + recordPayload + `"}`
	resp = env.authAPI(t, "POST", "/api/opaque/register/finish",
		map[string]string{"Content-Type": "application/json"}, body)
	require.Equal(t, 200, resp.StatusCode)
}

func (env *e2eEnv) opaqueLogin(t *testing.T, clientID, password string) string {
	t.Helper()

	loginClient, err := auth.ServerConfig().Client()
	require.NoError(t, err)

	ke1, err := loginClient.GenerateKE1([]byte(password))
	require.NoError(t, err)

	payload := b64.EncodeToString(ke1.Serialize())
	body := `{"clientId":"` + clientID + `","payload":"` + payload + `"}`
	resp := env.authAPI(t, "POST", "/api/opaque/login/start",
		map[string]string{"Content-Type": "application/json"}, body)
	require.Equal(t, 200, resp.StatusCode)

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(t, err)
	ke2Bytes, err := b64.DecodeString(strings.TrimSpace(buf.String()))
	require.NoError(t, err)
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	require.NoError(t, err)

	ke3, _, _, err := loginClient.GenerateKE3(ke2, []byte(clientID), nil)
	require.NoError(t, err)

	ke3Payload := b64.EncodeToString(ke3.Serialize())
	body = `{"clientId":"` + clientID + `","payload":"` + ke3Payload + `"}`
	resp = env.authAPI(t, "POST", "/api/opaque/login/finish",
		map[string]string{"Content-Type": "application/json"}, body)
	require.Equal(t, 200, resp.StatusCode)

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	token, ok := result["token"]
	require.True(t, ok)
	require.NotEmpty(t, token)
	return token
}

func TestE2EForwardAuth(t *testing.T) {
	t.Parallel()
	env := setupE2E(t)

	clientID := "e2e-test-user"
	password := "super-secret-password"

	env.opaqueRegister(t, clientID, password)
	token := env.opaqueLogin(t, clientID, password)
	env.configureSite(t, token, "app1.mydomain.test")

	t.Run("authorized request returns 200", func(t *testing.T) {
		resp := env.caddyRequest(t, "GET", "/", "app1.mydomain.test",
			map[string]string{"Authorization": "Bearer " + token}, "")
		assert.Equal(t, 200, resp.StatusCode)

		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "Hello World from caddy!", strings.TrimSpace(buf.String()))
	})

	t.Run("unauthorized request returns 401", func(t *testing.T) {
		resp := env.caddyRequest(t, "GET", "/", "app1.mydomain.test", nil, "")
		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("unconfigured site returns 401 even with valid token", func(t *testing.T) {
		resp := env.caddyRequest(t, "GET", "/", "app2.mydomain.test",
			map[string]string{"Authorization": "Bearer " + token}, "")
		assert.Equal(t, 401, resp.StatusCode)
	})
}

func TestE2EForwardAuthConcurrent(t *testing.T) {
	t.Parallel()

	t.Run("user1", func(t *testing.T) {
		t.Parallel()
		env := setupE2E(t)

		env.opaqueRegister(t, "user1", "pass1")
		token := env.opaqueLogin(t, "user1", "pass1")
		env.configureSite(t, token, "app1.mydomain.test")

		resp := env.caddyRequest(t, "GET", "/", "app1.mydomain.test",
			map[string]string{"Authorization": "Bearer " + token}, "")
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("user2", func(t *testing.T) {
		t.Parallel()
		env := setupE2E(t)

		env.opaqueRegister(t, "user2", "pass2")
		token := env.opaqueLogin(t, "user2", "pass2")
		env.configureSite(t, token, "app1.mydomain.test")

		resp := env.caddyRequest(t, "GET", "/", "app1.mydomain.test",
			map[string]string{"Authorization": "Bearer " + token}, "")
		assert.Equal(t, 200, resp.StatusCode)
	})
}
