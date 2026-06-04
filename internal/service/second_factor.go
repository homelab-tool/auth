package service

import "database/sql"

type SecondFactorService interface {
	Required(userID int64) (bool, error)
	Methods(userID int64) ([]string, error)
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
		"SELECT COUNT(*) FROM user_second_factors WHERE user_id = ? AND enabled = 1", userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *DefaultSecondFactorService) Methods(userID int64) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT method FROM user_second_factors WHERE user_id = ? AND enabled = 1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var methods []string
	for rows.Next() {
		var method string
		if err := rows.Scan(&method); err != nil {
			return nil, err
		}
		methods = append(methods, method)
	}
	return methods, rows.Err()
}
