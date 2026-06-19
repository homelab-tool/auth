package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/homelab-tool/auth/internal/auth"
)

type User struct {
	ID          int64
	DisplayName string
	CreatedAt   string
}

type UserService struct {
	db *sql.DB
}

func NewUserService(db *sql.DB) *UserService {
	return &UserService{db: db}
}

func (s *UserService) Create(ctx context.Context, displayName string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO users (display_name) VALUES (?)",
		displayName)
	if err != nil {
		return 0, fmt.Errorf("failed to insert user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return id, nil
}

func (s *UserService) Delete(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID)
	return err
}

func (s *UserService) GetDisplayName(ctx context.Context, userID int64) (string, error) {
	var displayName string
	err := s.db.QueryRowContext(ctx, "SELECT display_name FROM users WHERE id = ?", userID).Scan(&displayName)
	if err != nil {
		return "", fmt.Errorf("failed to query display name: %w", err)
	}
	return displayName, nil
}

func (s *UserService) GetUser(ctx context.Context, userID int64) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		"SELECT id, display_name, created_at FROM users WHERE id = ?", userID).
		Scan(&u.ID, &u.DisplayName, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &u, nil
}

func (s *UserService) HasPassword(ctx context.Context, userID int64) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM opaque_user_data WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check password: %w", err)
	}
	return count > 0, nil
}

func (s *UserService) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, display_name, created_at FROM users ORDER BY display_name")
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *UserService) LoadWebAuthnUser(ctx context.Context, userID int64) (*auth.WebAuthnUser, error) {
	displayName, err := s.GetDisplayName(ctx, userID)
	if err != nil {
		return nil, err
	}

	user := &auth.WebAuthnUser{
		ID:          userID,
		DisplayName: displayName,
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id, public_key, attestation_type, transport, aaguid,
		        sign_count, clone_warning, backup_eligible, backup_state
		 FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var c webauthn.Credential
		var transportStr string
		var aaguid []byte
		var signCount int64
		var cloneWarning, backupEligible, backupState bool

		err := rows.Scan(
			&c.ID, &c.PublicKey, &c.AttestationType, &transportStr, &aaguid,
			&signCount, &cloneWarning, &backupEligible, &backupState)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		c.Authenticator.AAGUID = aaguid
		c.Authenticator.SignCount = uint32(signCount)
		c.Authenticator.CloneWarning = cloneWarning
		c.Flags = webauthn.CredentialFlags{
			UserPresent:    true,
			BackupEligible: backupEligible,
			BackupState:    backupState,
		}

		if transportStr != "" {
			for s := range strings.SplitSeq(transportStr, ",") {
				c.Transport = append(c.Transport, protocol.AuthenticatorTransport(s))
			}
		}

		user.Credentials = append(user.Credentials, c)
	}

	return user, rows.Err()
}
