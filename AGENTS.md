# homelab-auth — AGENTS.md

## What this is

Go + JavaScript monorepo. Echo v5 HTTP server (SQLite-backed). templ + HTMX frontend.

## Commands

| What | Command |
|---|---|
| All Go tests | `make test` (uses `gotestsum`) |
| All tests (verbose) | `make test-verbose` |
| With race detector | `make test-race` |
| Single pkg | `gotestsum -- ./internal/service/...` |
| E2E tests (Docker) | `make e2e` (builds image + runs testcontainers-go) |
| Run server | `make run` (builds templ + frontend first) |
| Build all | `make build` (builds templ + frontend + Go binary) |
| Regenerate templates | `make templ-gen` |
| Build JS bundle | `make js-build` |
| JS watch | `make js-watch` |
| Full generate | `make generate` (templ + rolldown) |
| Dev mode | `make dev` (generate + run server + watch) |
| Frontend lint | `pnpm oxlint` |
| Frontend format | `pnpm oxfmt` |
| Install all deps | `pnpm install` |

## Architecture

- **`cmd/auth/main.go`** — entrypoint, listens on `:1337`
- **`internal/app.go`** — wires Echo, DB, services, routes
- **`internal/database.go`** — SQLite, embedded migrations, WAL journal + foreign keys
- **`internal/api/`** — HTTP handlers for `/api` routes
- **`internal/caddy/`** — Caddy `forward_auth` endpoint at `/caddy/forward_auth`
- **`internal/auth/`** — crypto/low-level (JWT, OPAQUE, WebAuthn)
- **`internal/service/`** — business logic layer
- **`internal/migrations/`** — SQLite migrations
- **`internal/layout/`** — shared page layout (templ) + auth handlers + JS bundle source (OPAQUE client, WebAuthn client, cookie helpers)
- **`internal/login/`** — login page (templ + Go handler)
- **`internal/register/`** — register page (templ + Go handler)
- **`internal/success/`** — post-login landing page (templ + Go handler)
- **`internal/static/`** — embedded static assets (HTMX, built auth.js)

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

