NAME := certinfo
IMAGE := pete911/${NAME}
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

image:
	docker build --build-arg version=${VERSION} -t ${IMAGE}:${VERSION} .
	docker tag ${IMAGE}:${VERSION} ${IMAGE}:latest
.PHONY:image

push-image:
	docker push ${IMAGE}:${VERSION}
	docker push ${IMAGE}:latest
.PHONY:push-image

