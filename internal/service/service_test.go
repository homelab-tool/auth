package service_test

import (
	"database/sql"
	"testing"

	"github.com/homelab-tool/auth/internal/testhelpers"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testhelpers.NewTestDB(t)
}
