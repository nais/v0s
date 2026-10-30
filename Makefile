.PHONY: generate check build

generate:
	buf generate

check:
	buf lint
	go vet ./...
	go tool staticcheck ./...
	go test ./...

build:
	go build -o bin/v0s ./cmd/v0s
