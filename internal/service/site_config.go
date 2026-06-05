package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type SiteConfig struct {
	ID        int64     `json:"id"`
	Hostname  string    `json:"hostname"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SiteConfigService struct {
	db *sql.DB
}

func NewSiteConfigService(db *sql.DB) *SiteConfigService {
	return &SiteConfigService{db: db}
}

func (s *SiteConfigService) Create(ctx context.Context, hostname string) (*SiteConfig, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO site_configs (hostname, created_at, updated_at) VALUES (?, ?, ?)",
		hostname, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to insert site config: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return &SiteConfig{
		ID:        id,
		Hostname:  hostname,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}, nil
}

func (s *SiteConfigService) GetByHostname(ctx context.Context, hostname string) (*SiteConfig, error) {
	var cfg SiteConfig
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, hostname, created_at, updated_at FROM site_configs WHERE hostname = ?",
		hostname).Scan(&cfg.ID, &cfg.Hostname, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to query site config: %w", err)
	}

	cfg.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	cfg.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &cfg, nil
}

func (s *SiteConfigService) List(ctx context.Context) ([]SiteConfig, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, hostname, created_at, updated_at FROM site_configs ORDER BY hostname")
	if err != nil {
		return nil, fmt.Errorf("failed to list site configs: %w", err)
	}
	defer rows.Close()

	var configs []SiteConfig
	for rows.Next() {
		var cfg SiteConfig
		var createdAt, updatedAt string
		if err := rows.Scan(&cfg.ID, &cfg.Hostname, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan site config: %w", err)
		}
		cfg.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		cfg.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		configs = append(configs, cfg)
	}

	return configs, rows.Err()
}

func (s *SiteConfigService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM site_configs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete site config: %w", err)
	}
	return nil
}

func (s *SiteConfigService) Exists(ctx context.Context, hostname string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM site_configs WHERE hostname = ?", hostname).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check site config existence: %w", err)
	}
	return count > 0, nil
}
