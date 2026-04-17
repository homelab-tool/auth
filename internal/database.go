package internal

import (
	"database/sql"
	"embed"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/*.sql
var fs embed.FS

func InitializeDb() (*sql.DB, error) {
	log.Debug().Msg("initializing database")

	err := runMigration()
	if err != nil {
		log.Error().Err(err).Msg("migration failed")
		return nil, err
	}

	db, err := sql.Open("sqlite3", "file:Database.sqlite?cache=shared")
	if err != nil {
		return nil, err
	}

	// https://www.sqlite.org/pragma.html#pragma_journal_mode
	// Use write-ahead log instead of a rollback journal to implement transactions.
	if _, err = db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		_ = db.Close()
		return nil, err
	}

	// https://www.sqlite.org/pragma.html#pragma_foreign_keys
	// Enable the enforcement of foreign key constraints.
	if _, err = db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, err
	}

	// https://www.sqlite.org/pragma.html#pragma_encoding
	// Set the text encoding to UTF-8.
	if _, err = db.Exec("PRAGMA encoding = 'UTF-8'"); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func runMigration() error {
	log.Debug().Msg("running migrations")

	const sourceName = "iofs"
	sourceDriver, err := iofs.New(fs, "migrations")
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance(sourceName, sourceDriver, "sqlite3://Database.sqlite")
	if err != nil {
		return err
	}

	if err = m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			return nil
		}

		return err
	}

	return nil
}
