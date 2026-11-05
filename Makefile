.PHONY: generate check build

generate:
	buf generate
	buf generate third_party/naisapi --template buf.gen.naisapi.yaml

check:
	buf lint
	go vet ./...
	go tool staticcheck ./...
	go test ./...

build:
	go build -o bin/v0s ./cmd/v0s
