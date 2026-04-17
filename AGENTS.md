# Agent Instructions for homelab-auth

## Overview
Go 1.26 auth service for the homelab, built with Echo and SQLite.

## Architecture
- **Entrypoint**: `cmd/auth/main.go` (server on `:1337`).
- **Core Logic**: `internal/`
    - `app.go`: App struct, router setup, `/auth` POST route.
    - `database.go`: SQLite init, WAL/foreign-key/UTF-8 pragmas, embedded migration runner.
- **Module**: `github.com/homelab-tool/auth`.
- **Database**: SQLite (`Database.sqlite`, ignored by git) with migrations in `internal/migrations/` applied at startup via `golang-migrate` + `embed.FS`.

## Development Commands
- **Run**: `go run cmd/auth/main.go`
- **Build**: `go build -o auth cmd/auth/main.go`

