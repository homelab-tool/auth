package service_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/homelab-tool/auth/internal"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := internal.MigrateDB("sqlite3://" + dbPath)
	require.NoError(t, err)
	db, err := sql.Open("sqlite3", dbPath+"?cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	return db
}
