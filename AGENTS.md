# homelab-auth — AGENTS.md

## What this is

Go + TypeScript monorepo. Echo v5 HTTP server (SQLite-backed). Vite frontend at `frontend/`.

## Commands

| What | Command |
|---|---|
| All Go tests | `make test` (uses `gotestsum`) |
| All tests (verbose) | `make test-verbose` |
| With race detector | `make test-race` |
| Single pkg | `gotestsum -- ./internal/service/...` |
| E2E tests (Docker) | `make e2e` (builds image + runs testcontainers-go) |
| Run server | `go run ./cmd/auth/...` |
| Frontend dev | `pnpm --filter frontend dev` (via Vite) |
| Frontend lint | `pnpm --filter frontend oxlint` (correctness errors only) |
| Frontend format | `pnpm --filter frontend oxfmt` |
| Install all deps | `pnpm install` (root) |

## Architecture

- **`cmd/auth/main.go`** — entrypoint, listens on `:1337`
- **`internal/app.go`** — wires Echo, DB, services, routes at `/api`
- **`internal/database.go`** — SQLite, embedded migrations, WAL journal + foreign keys
- **`internal/api/`** — HTTP handlers for `/api` routes
- **`internal/caddy/`** — Caddy `forward_auth` endpoint at `/caddy/forward_auth`
- **`internal/auth/`** — crypto/low-level (JWT, OPAQUE, WebAuthn)
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

