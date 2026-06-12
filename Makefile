test:
	go tool gotestsum -- -count=1 ./internal/... ./cmd/...

test-race:
	go tool gotestsum -- -race -count=1 ./internal/... ./cmd/...

test-verbose:
	go tool gotestsum --format standard-verbose -- -count=1 ./internal/... ./cmd/...

vet:
	go vet ./...

run: generate
	go run ./cmd/auth/...

build: generate
	go build -o bin/auth ./cmd/auth/...

e2e-build:
	docker build -t homelab-auth:e2e .

e2e: e2e-build
	pnpm exec playwright test --config=playwright.config.ts

e2e-ui: e2e-build
	pnpm exec playwright test --config=playwright.config.ts --ui

templ-gen:
	go tool templ generate

copy-htmx:
	cp node_modules/htmx.org/dist/htmx.min.js \
		internal/server/pages/static/dist/htmx.min.js

js-build:
	pnpm build

js-watch:
	pnpm watch

generate: copy-htmx templ-gen js-build

.PHONY: test test-race test-verbose vet run build e2e e2e-ui e2e-build templ-gen copy-htmx js-build js-watch generate dev
