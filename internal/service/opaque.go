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
	ClientID           string
	EncodedCredentialID string
	EncodedRecord      string
	UserID             int64
}

func (s *OpaqueService) GetUserData(ctx context.Context, clientID string) (*OpaqueUserData, error) {
	var data OpaqueUserData
	err := s.db.QueryRowContext(ctx,
		"SELECT client_id, credential_id, registration_record, user_id FROM opaque_user_data WHERE client_id = ?", clientID).
		Scan(&data.ClientID, &data.EncodedCredentialID, &data.EncodedRecord, &data.UserID)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func (s *OpaqueService) CreateUser(ctx context.Context, clientID, encodedCredentialID, encodedRecord string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		"INSERT INTO users (auth_method, display_name) VALUES (?, ?)",
		"pass-opaque", clientID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert user: %w", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO opaque_user_data (client_id, credential_id, registration_record, user_id) VALUES (?, ?, ?, ?)",
		clientID, encodedCredentialID, encodedRecord, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert opaque user data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return userID, nil
}
