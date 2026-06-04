test:
	go test -v -count=1 ./...

test-race:
	go test -race -count=1 ./ ...

.PHONY: test
