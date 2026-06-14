package service

import (
	"database/sql"
	"fmt"
)

type SecondFactorService interface {
	Required(userID int64) (bool, error)
	Methods(userID int64) ([]string, error)
	Disable(userID int64, method string) error
}

type DefaultSecondFactorService struct {
	db *sql.DB
}

func NewDefaultSecondFactorService(db *sql.DB) *DefaultSecondFactorService {
	return &DefaultSecondFactorService{db: db}
}

func (s *DefaultSecondFactorService) Required(userID int64) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM (
		   SELECT 1 FROM totp_secrets WHERE user_id = ? AND enabled = 1
		   UNION ALL
		   SELECT 1 FROM webauthn_credentials WHERE user_id = ? AND purpose IN ('2fa', 'login,2fa')
		 )`, userID, userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *DefaultSecondFactorService) Methods(userID int64) ([]string, error) {
	var methods []string

	var totpCount int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM totp_secrets WHERE user_id = ? AND enabled = 1", userID).Scan(&totpCount)
	if err != nil {
		return nil, err
	}
	if totpCount > 0 {
		methods = append(methods, "totp")
	}

	var webauthnCount int
	err = s.db.QueryRow(
		"SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ? AND purpose IN ('2fa', 'login,2fa')",
		userID).Scan(&webauthnCount)
	if err != nil {
		return nil, err
	}
	if webauthnCount > 0 {
		methods = append(methods, "webauthn")
	}

	return methods, nil
}

func (s *DefaultSecondFactorService) Disable(userID int64, method string) error {
	switch method {
	case "totp":
		result, err := s.db.Exec(
			"DELETE FROM totp_secrets WHERE user_id = ?", userID)
		if err != nil {
			return fmt.Errorf("failed to disable totp: %w", err)
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			return fmt.Errorf("second factor not found")
		}
		return nil

	case "webauthn":
		result, err := s.db.Exec(
			`UPDATE webauthn_credentials
			 SET purpose = CASE
			   WHEN purpose = '2fa' THEN ''
			   WHEN purpose = 'login,2fa' THEN 'login'
			   ELSE purpose
			 END
			 WHERE user_id = ?`,
			userID)
		if err != nil {
			return fmt.Errorf("failed to disable webauthn 2fa: %w", err)
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			return fmt.Errorf("second factor not found")
		}
		return nil
	}

	return fmt.Errorf("unknown method: %s", method)
}
