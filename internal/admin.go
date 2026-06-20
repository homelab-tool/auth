package internal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"

	"github.com/bytemare/opaque"
	"github.com/rs/zerolog/log"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/service"
)

const adminBootstrappedKey = "admin_bootstrapped"

var passwordChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func generatePassword() (string, error) {
	pw := make([]byte, 32)
	for i := range pw {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordChars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random password: %w", err)
		}
		pw[i] = passwordChars[n.Int64()]
	}
	return string(pw), nil
}

func BootstrapAdminUser(db *sql.DB, opaqueSvc *service.OpaqueService, opaqueServer *opaque.Server, groups *service.GroupService) error {
	ctx := context.Background()

	adminGroupID, err := groups.EnsureAdminGroup(ctx)
	if err != nil {
		return fmt.Errorf("failed to ensure admin group: %w", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM secrets WHERE name = ?", adminBootstrappedKey).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check admin bootstrap status: %w", err)
	}
	if count > 0 {
		log.Debug().Msg("admin user already bootstrapped, skipping")
		return nil
	}

	username := os.Getenv("ADMIN_USERNAME")
	usernameFromEnv := username != ""
	if username == "" {
		username = "admin"
	}

	password := os.Getenv("ADMIN_PASSWORD")
	passwordFromEnv := password != ""
	if password == "" {
		pwd, err := generatePassword()
		if err != nil {
			return fmt.Errorf("failed to generate admin password: %w", err)
		}
		password = pwd
	}

	client, err := auth.ServerConfig().Client()
	if err != nil {
		return fmt.Errorf("failed to create opaque client: %w", err)
	}
	defer client.ClearState()

	regInit, err := client.RegistrationInit([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to initialize opaque registration: %w", err)
	}

	credentialID := opaque.RandomBytes(64)

	regResp, err := opaqueServer.RegistrationResponse(regInit, credentialID, nil)
	if err != nil {
		return fmt.Errorf("failed to process opaque registration response: %w", err)
	}

	ksf := auth.DefaultKSF()
	regRecord, _, err := client.RegistrationFinalize(regResp, []byte(username), nil, ksf.ClientOptions())
	if err != nil {
		return fmt.Errorf("failed to finalize opaque registration: %w", err)
	}

	encodedRecord := base64.RawURLEncoding.EncodeToString(regRecord.Serialize())
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(credentialID)

	ksfParams, _ := ksf.ParamsJSON()
	userID, err := opaqueSvc.CreateUser(ctx, username, encodedCredentialID, encodedRecord,
		ksf.AlgorithmName(), ksf.Salt, ksfParams, ksf.OutputLen)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	if err := groups.AddUser(ctx, userID, adminGroupID); err != nil {
		return fmt.Errorf("failed to add admin user to admin group: %w", err)
	}

	_, err = db.Exec("INSERT INTO secrets (name, value) VALUES (?, ?)", adminBootstrappedKey, []byte("1"))
	if err != nil {
		return fmt.Errorf("failed to mark admin bootstrap as done: %w", err)
	}

	if !usernameFromEnv && !passwordFromEnv {
		log.Info().Str("username", username).Str("password", password).Msg("admin user created")
	}

	return nil
}
