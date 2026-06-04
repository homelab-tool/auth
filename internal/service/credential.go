package service

import (
	"context"
	"database/sql"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

type CredentialService struct {
	db *sql.DB
}

func NewCredentialService(db *sql.DB) *CredentialService {
	return &CredentialService{db: db}
}

func (s *CredentialService) Persist(ctx context.Context, userID int64, credential *webauthn.Credential) error {
	transportStrs := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transportStrs[i] = string(t)
	}
	transportStr := strings.Join(transportStrs, ",")

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
		 (user_id, credential_id, public_key, attestation_type, transport, aaguid,
		  sign_count, clone_warning, backup_eligible, backup_state)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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

func (s *CredentialService) EnableSecondFactor(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_second_factors (user_id, method, enabled) VALUES (?, 'webauthn', 1)
		 ON CONFLICT(user_id, method) DO UPDATE SET enabled = 1`,
		userID)
	return err
}
