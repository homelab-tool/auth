GOTESTSUM = $(shell go env GOPATH)/bin/gotestsum

test:
	$(GOTESTSUM) -- -count=1 ./...

test-race:
	$(GOTESTSUM) -- -race -count=1 ./...

test-verbose:
	$(GOTESTSUM) --format standard-verbose -- -count=1 ./...

vet:
	go vet ./...

run:
	go run ./cmd/auth/...

build:
	go build -o bin/auth ./cmd/auth/...

.PHONY: test test-race test-verbose vet run build
