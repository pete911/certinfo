VERSION ?= dev

.DEFAULT_GOAL := build

test:
	go fmt ./...
	go vet ./...
	go clean -testcache && go test -cover ./...
.PHONY:test

build: test
	go build -ldflags "-X main.Version=${VERSION}" -mod vendor
.PHONY:build

install: test
	go install -ldflags "-X main.Version=${VERSION}" -mod vendor
.PHONY:install
