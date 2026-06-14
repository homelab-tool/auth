package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pquerna/otp/totp"
)

type TOTPService struct {
	db *sql.DB
}

func NewTOTPService(db *sql.DB) *TOTPService {
	return &TOTPService{db: db}
}

type TOTPSecretResult struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

func (s *TOTPService) GenerateSecret(ctx context.Context, userID int64, displayName, issuer string) (*TOTPSecretResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: displayName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate totp key: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO totp_secrets (user_id, secret, enabled) VALUES (?, ?, 0)
		 ON CONFLICT(user_id) DO UPDATE SET secret = ?, enabled = 0`,
		userID, key.Secret(), key.Secret())
	if err != nil {
		return nil, fmt.Errorf("failed to store totp secret: %w", err)
	}

	return &TOTPSecretResult{Secret: key.Secret(), URI: key.URL()}, nil
}

func (s *TOTPService) VerifyAndEnable(ctx context.Context, userID int64, code string) (bool, error) {
	var secret string
	err := s.db.QueryRowContext(ctx,
		"SELECT secret FROM totp_secrets WHERE user_id = ?", userID).Scan(&secret)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to query totp secret: %w", err)
	}

	valid := totp.Validate(code, secret)
	if !valid {
		return false, nil
	}

	_, err = s.db.ExecContext(ctx,
		"UPDATE totp_secrets SET enabled = 1 WHERE user_id = ?", userID)
	if err != nil {
		return false, fmt.Errorf("failed to enable totp secret: %w", err)
	}

	return true, nil
}

func (s *TOTPService) ValidateCode(ctx context.Context, userID int64, code string) (bool, error) {
	var secret string
	err := s.db.QueryRowContext(ctx,
		"SELECT secret FROM totp_secrets WHERE user_id = ? AND enabled = 1", userID).Scan(&secret)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to query totp secret: %w", err)
	}

	return totp.Validate(code, secret), nil
}

func (s *TOTPService) HasEnabled(ctx context.Context, userID int64) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM totp_secrets WHERE user_id = ? AND enabled = 1", userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
