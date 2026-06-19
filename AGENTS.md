# homelab-auth

Go + TypeScript monorepo for an authentication service.

## Commands

Commands such as building, testing, formatting, linting, typechecking can be found in `./Makefile` and `./package.json`.

- When changing server code: **Always** run `make vet` and `make test` to validate changes
- When changing frontend code: **Always** run `pnpm run typecheck && pnpm run lint` to validate changes

E2E tests can be run with `make e2e` which handles everything and runs Playwright. Alternatively run `make e2e-build` to build the containers and then execute Playwright normally with `pnpm exec playwright test`. The latter should be used when fixing individual tests without changing server or frontend code since those changes don't require container rebuild.

E2E tests should **always** be run after making frontend or other UX changes. When an E2E test fails, **always** read the error context. If more details are needed, read the produced trace (need to read the ZIP file).

## Documentation

Use the following links to download extensive documentation for major libraries and algorithms used in this project. **NEVER** read the entire contents as these single files are too large. Instead, download the desired documentation to a temporary file and grep for headings first to find the sections that are important to the user query.

- HTMX: https://raw.githubusercontent.com/bigskysoftware/htmx/refs/heads/master/www/content/docs.md
- Templ: https://templ.guide/llms.md
- OPAQUE (RFC9807): https://www.rfc-editor.org/rfc/rfc9807.txt

## Dependencies

### Go

Managed through `./go.mod`. To find the source files for them use `go env GOMODCACHE` to find the directory.

### JavaScript/TypeScript

Found in `./node_modules/` managed through `./pnpm-workspace.yaml` and `./package.json`. Dependencies should always be added with `pnpm add`.
