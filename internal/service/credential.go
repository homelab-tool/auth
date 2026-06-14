package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

type CredentialInfo struct {
	ID        int64
	Name      string
	Purpose   string
	CreatedAt string
}

type CredentialService struct {
	db *sql.DB
}

func NewCredentialService(db *sql.DB) *CredentialService {
	return &CredentialService{db: db}
}

func (s *CredentialService) Persist(ctx context.Context, userID int64, credential *webauthn.Credential, purpose, name string) error {
	transportStrs := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transportStrs[i] = string(t)
	}
	transportStr := strings.Join(transportStrs, ",")

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
		 (user_id, credential_id, public_key, attestation_type, transport, aaguid,
		  sign_count, clone_warning, backup_eligible, backup_state, purpose, name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		credential.ID,
		credential.PublicKey,
		credential.AttestationType,
		transportStr,
		credential.Authenticator.AAGUID,
		int64(credential.Authenticator.SignCount),
		credential.Authenticator.CloneWarning,
		credential.Flags.BackupEligible,
		credential.Flags.BackupState,
		purpose,
		name,
	)
	return err
}

func (s *CredentialService) Update(ctx context.Context, credential *webauthn.Credential) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials
		 SET sign_count = ?, clone_warning = ?, backup_state = ?, last_used_at = CURRENT_TIMESTAMP
		 WHERE credential_id = ? AND sign_count < ?`,
		int64(credential.Authenticator.SignCount),
		credential.Authenticator.CloneWarning,
		credential.Flags.BackupState,
		credential.ID,
		int64(credential.Authenticator.SignCount),
	)
	return err
}

func (s *CredentialService) GetPurpose(ctx context.Context, credentialID []byte) (string, error) {
	var purpose string
	err := s.db.QueryRowContext(ctx,
		"SELECT purpose FROM webauthn_credentials WHERE credential_id = ?", credentialID).Scan(&purpose)
	if err != nil {
		return "", err
	}
	return purpose, nil
}

func (s *CredentialService) List(ctx context.Context, userID int64) ([]CredentialInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, purpose, created_at
		 FROM webauthn_credentials WHERE user_id = ?
		 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	var creds []CredentialInfo
	for rows.Next() {
		var c CredentialInfo
		if err := rows.Scan(&c.ID, &c.Name, &c.Purpose, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *CredentialService) ListBy2FAPurpose(ctx context.Context, userID int64) ([]CredentialInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, purpose, created_at
		 FROM webauthn_credentials WHERE user_id = ? AND purpose IN ('2fa', 'login,2fa')
		 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query 2fa credentials: %w", err)
	}
	defer rows.Close()

	var creds []CredentialInfo
	for rows.Next() {
		var c CredentialInfo
		if err := rows.Scan(&c.ID, &c.Name, &c.Purpose, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *CredentialService) UpdatePurpose(ctx context.Context, credentialID int64, purpose string) error {
	result, err := s.db.ExecContext(ctx,
		"UPDATE webauthn_credentials SET purpose = ? WHERE id = ?",
		purpose, credentialID)
	if err != nil {
		return fmt.Errorf("failed to update purpose: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

func (s *CredentialService) UpdateName(ctx context.Context, credentialID int64, name string) error {
	result, err := s.db.ExecContext(ctx,
		"UPDATE webauthn_credentials SET name = ? WHERE id = ?",
		name, credentialID)
	if err != nil {
		return fmt.Errorf("failed to update name: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

func (s *CredentialService) Delete(ctx context.Context, credentialID int64) error {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM webauthn_credentials WHERE id = ?", credentialID)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

func (s *CredentialService) Count(ctx context.Context, userID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count credentials: %w", err)
	}
	return count, nil
}
