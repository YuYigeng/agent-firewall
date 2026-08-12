.PHONY: fmt vet test test-race build preflight

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

build:
	go build -trimpath -o bin/agent-firewall ./cmd/agent-firewall

preflight:
	test -z "$$(gofmt -l .)"
	go mod tidy
	git diff --exit-code -- go.mod go.sum
	go vet ./...
	go test ./...
	go test -race ./...
	go build -trimpath ./cmd/agent-firewall
