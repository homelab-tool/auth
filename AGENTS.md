# homelab-auth

Go + JavaScript monorepo. Echo v5 HTTP server (SQLite-backed). templ + HTMX frontend. Playwright E2E via testcontainers.

## Commands

| What                 | Command             |
| -------------------- | ------------------- |
| All Go tests         | `make test`         |
| Go tests (verbose)   | `make test-verbose` |
| Go tests (race)      | `make test-race`    |
| E2E tests            | `make e2e`          |
| E2E tests (UI mode)  | `make e2e-ui`       |
| Run server           | `make run`          |
| Build all            | `make build`        |
| Regenerate templates | `make templ-gen`    |
| Build JS bundle      | `make js-build`     |
| Dev mode (watch)     | `make dev`          |
| Frontend lint        | `pnpm lint`         |
| Frontend format      | `pnpm format`       |
| Type check           | `pnpm typecheck`    |

## Architecture

- **`cmd/auth/main.go`** — entrypoint, listens on `:1337`
- **`internal/app.go`** — wires Echo, DB, services, routes
- **`internal/database.go`** — SQLite, embedded migrations, WAL + foreign keys
- **`internal/auth/`** — crypto (JWT, OPAQUE, WebAuthn)
- **`internal/service/`** — business logic
- **`internal/migrations/`** — SQLite schema
- **`internal/server/api/`** — HTTP handlers for `/api` routes
- **`internal/server/api/caddy/`** — Caddy `forward_auth` endpoint
- **`internal/server/pages/layout/`** — shared templ layout + JS bundle source (OPAQUE, WebAuthn, TOTP, cookie)
- **`internal/server/pages/login/`**, **`internal/server/pages/register/`**, **`internal/server/pages/success/`** — page handlers (templ + Go)
- **`internal/server/pages/static/`** — embedded static assets (HTMX, bundled auth.js)
- **`test/e2e/`** — Playwright E2E specs + fixtures + testcontainers orchestration
- **`playwright.config.ts`** — Playwright config (chromium, TLS ignore, host resolver rules)

## Required env vars (WebAuthn)

- `WEBAUTHN_RPID` — e.g. `localhost`
- `WEBAUTHN_RP_ORIGINS` — comma-separated, e.g. `http://localhost:1337`
- `WEBAUTHN_RP_DISPLAY_NAME` — optional, defaults to `Homelab Auth`
