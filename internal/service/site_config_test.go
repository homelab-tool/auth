package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal/service"
)

func TestSiteConfigServiceCreate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	cfg, err := svc.Create(context.Background(), "app1.example.com")
	require.NoError(t, err)
	assert.Equal(t, int64(1), cfg.ID)
	assert.Equal(t, "app1.example.com", cfg.Hostname)
	assert.False(t, cfg.CreatedAt.IsZero())
	assert.False(t, cfg.UpdatedAt.IsZero())
}

func TestSiteConfigServiceCreateDuplicate(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	_, err := svc.Create(context.Background(), "app1.example.com")
	require.NoError(t, err)

	_, err = svc.Create(context.Background(), "app1.example.com")
	assert.ErrorContains(t, err, "UNIQUE constraint")
}

func TestSiteConfigServiceGetByHostname(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	created, err := svc.Create(context.Background(), "app1.example.com")
	require.NoError(t, err)

	cfg, err := svc.GetByHostname(context.Background(), "app1.example.com")
	require.NoError(t, err)
	assert.Equal(t, created.ID, cfg.ID)
	assert.Equal(t, "app1.example.com", cfg.Hostname)
}

func TestSiteConfigServiceGetByHostnameNotFound(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	_, err := svc.GetByHostname(context.Background(), "nonexistent.example.com")
	assert.ErrorContains(t, err, "no rows in result set")
}

func TestSiteConfigServiceList(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	_, err := svc.Create(context.Background(), "app2.example.com")
	require.NoError(t, err)
	_, err = svc.Create(context.Background(), "app1.example.com")
	require.NoError(t, err)

	configs, err := svc.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, configs, 2)
	assert.Equal(t, "app1.example.com", configs[0].Hostname)
	assert.Equal(t, "app2.example.com", configs[1].Hostname)
}

func TestSiteConfigServiceListEmpty(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	configs, err := svc.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, configs)
}

func TestSiteConfigServiceDelete(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	cfg, err := svc.Create(context.Background(), "app1.example.com")
	require.NoError(t, err)

	err = svc.Delete(context.Background(), cfg.ID)
	require.NoError(t, err)

	exists, err := svc.Exists(context.Background(), "app1.example.com")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestSiteConfigServiceDeleteNonExistent(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	err := svc.Delete(context.Background(), 999)
	require.NoError(t, err)
}

func TestSiteConfigServiceExists(t *testing.T) {
	db := newTestDB(t)
	svc := service.NewSiteConfigService(db)

	_, err := svc.Create(context.Background(), "app1.example.com")
	require.NoError(t, err)

	exists, err := svc.Exists(context.Background(), "app1.example.com")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = svc.Exists(context.Background(), "other.example.com")
	require.NoError(t, err)
	assert.False(t, exists)
}
