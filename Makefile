NAME := certinfo
IMAGE := pete911/${NAME}
VERSION ?= dev

.DEFAULT_GOAL := build

test:
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

release:
	# amd64
	for GOOS in "linux" "darwin" "windows"; do \
		BUILD_CMD="GOOS=$$GOOS GOARCH=amd64 go build -ldflags \"-X main.Version=${VERSION}\" -o releases/${NAME}" ; \
		TAR_CMD="tar -czvf releases/${NAME}_$${GOOS}_amd64.tar.gz -C releases/ ${NAME} && rm releases/${NAME}" ; \
		docker run --rm -it -v "${PWD}":/usr/src/app -w /usr/src/app -e CGO_ENABLED=0 golang:1.16-alpine sh -c "$$BUILD_CMD && $$TAR_CMD" ; \
	done
	# arm64
	for GOOS in "darwin"; do \
		BUILD_CMD="GOOS=$$GOOS GOARCH=arm64 go build -ldflags \"-X main.Version=${VERSION}\" -o releases/${NAME}" ; \
		TAR_CMD="tar -czvf releases/${NAME}_$${GOOS}_arm64.tar.gz -C releases/ ${NAME} && rm releases/${NAME}" ; \
		docker run --rm -it -v "${PWD}":/usr/src/app -w /usr/src/app -e CGO_ENABLED=0 golang:1.16-alpine sh -c "$$BUILD_CMD && $$TAR_CMD" ; \
	done
.PHONY:release
