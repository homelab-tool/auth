package service

import (
	"context"
	"database/sql"
	"fmt"
)

type OpaqueService struct {
	db *sql.DB
}

func NewOpaqueService(db *sql.DB) *OpaqueService {
	return &OpaqueService{db: db}
}

func (s *OpaqueService) IsClientIDTaken(ctx context.Context, clientID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM opaque_user_data WHERE client_id = ?", clientID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

type OpaqueUserData struct {
	ClientID            string
	EncodedCredentialID string
	EncodedRecord       string
	UserID              int64
	KSFAlgorithm        string
	KSFSalt             []byte
	KSFParams           string
	KSFOutputLen        int
}

func (s *OpaqueService) GetUserData(ctx context.Context, clientID string) (*OpaqueUserData, error) {
	var data OpaqueUserData
	err := s.db.QueryRowContext(ctx,
		"SELECT client_id, credential_id, registration_record, user_id, ksf_algorithm, ksf_salt, ksf_params, ksf_output_len FROM opaque_user_data WHERE client_id = ?", clientID).
		Scan(&data.ClientID, &data.EncodedCredentialID, &data.EncodedRecord, &data.UserID,
			&data.KSFAlgorithm, &data.KSFSalt, &data.KSFParams, &data.KSFOutputLen)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func (s *OpaqueService) HasPassword(ctx context.Context, userID int64) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM opaque_user_data WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *OpaqueService) CreateUser(ctx context.Context, clientID, encodedCredentialID, encodedRecord string,
	ksfAlgorithm string, ksfSalt []byte, ksfParams string, ksfOutputLen int) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		"INSERT INTO users (display_name) VALUES (?)",
		clientID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert user: %w", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO opaque_user_data (client_id, credential_id, registration_record, user_id, ksf_algorithm, ksf_salt, ksf_params, ksf_output_len) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		clientID, encodedCredentialID, encodedRecord, userID,
		ksfAlgorithm, ksfSalt, ksfParams, ksfOutputLen); err != nil {
		return 0, fmt.Errorf("failed to insert opaque user data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return userID, nil
}

func (s *OpaqueService) AddPasswordToUser(ctx context.Context, userID int64, clientID, encodedCredentialID, encodedRecord string,
	ksfAlgorithm string, ksfSalt []byte, ksfParams string, ksfOutputLen int) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO opaque_user_data (client_id, credential_id, registration_record, user_id, ksf_algorithm, ksf_salt, ksf_params, ksf_output_len) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		clientID, encodedCredentialID, encodedRecord, userID,
		ksfAlgorithm, ksfSalt, ksfParams, ksfOutputLen)
	if err != nil {
		return fmt.Errorf("failed to insert opaque user data: %w", err)
	}
	return nil
}
