# homelab-auth — AGENTS.md

## What this is

Go + TypeScript monorepo. Echo v5 HTTP server (SQLite-backed). Vite frontend at `frontend/`.

## Commands

| What | Command |
|---|---|
| All Go tests | `make test` (runs `go test -v -count=1 ./...`) |
| Single pkg tests | `go test -v -count=1 ./internal/service/...` |
| Run server | `go run ./cmd/auth/...` |
| Frontend dev | `pnpm --filter frontend dev` (via Vite) |
| Frontend lint | `pnpm --filter frontend oxlint` (correctness errors only) |
| Frontend format | `pnpm --filter frontend oxfmt` |
| Install all deps | `pnpm install` (root) |

## Architecture

- **`cmd/auth/main.go`** — entrypoint, listens on `:1337`
- **`internal/app.go`** — wires Echo, DB, services, routes at `/api`
- **`internal/database.go`** — SQLite, embedded migrations, WAL journal + foreign keys
- **`internal/api/`** — HTTP handlers
- **`internal/auth/`** — crypto/low-level
- **`internal/service/`** — business logic layer
- **`internal/migrations/`** — SQLite migrations
- **`frontend/`** — Vite + TypeScript

## Required env vars (WebAuthn)

- `WEBAUTHN_RPID` — e.g. `localhost`
- `WEBAUTHN_RP_ORIGINS` — comma-separated, e.g. `http://localhost:1337`
- `WEBAUTHN_RP_DISPLAY_NAME` — optional, defaults to `Homelab Auth`

## Testing quirks

- Tests create a fresh SQLite DB per test via `t.TempDir()` + `internal.MigrateDB()`
- Use `testify/require` throughout
- API tests use in-memory Echo (no real HTTP server), tests in `api_test` / `service_test` external packages
- `WEBAUTHN_*` env vars are set in test helpers with `t.Setenv()`
- `-count=1` to disable caching

