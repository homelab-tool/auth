GOTESTSUM = $(shell go env GOPATH)/bin/gotestsum

test:
	$(GOTESTSUM) -- -count=1 ./internal/... ./cmd/...

test-race:
	$(GOTESTSUM) -- -race -count=1 ./internal/... ./cmd/...

test-verbose:
	$(GOTESTSUM) --format standard-verbose -- -count=1 ./internal/... ./cmd/...

vet:
	go vet ./...

run:
	go run ./cmd/auth/...

build:
	go build -o bin/auth ./cmd/auth/...

e2e-build:
	docker build -f test/e2e/Dockerfile -t homelab-auth:e2e .

e2e: e2e-build
	go test -v -count=1 -timeout 10m ./test/e2e/...

.PHONY: test test-race test-verbose vet run build e2e e2e-build
