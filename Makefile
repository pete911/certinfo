IMAGE := pete911/certinfo
VERSION ?= dev

test:
	go clean -testcache && go test -cover ./...

build: test
	go build -mod vendor

install: test
	go install -mod vendor

image:
	docker build -t ${IMAGE}:${VERSION} .
	docker tag ${IMAGE}:${VERSION} ${IMAGE}:latest

push-image:
	docker push ${IMAGE}:${VERSION}
	docker push ${IMAGE}:latest

release:
	docker build -t certinfo-releases -f Releases.Dockerfile .
	docker create -ti --name certinfo-releases certinfo-releases sh
	docker cp certinfo-releases:/releases/certinfo_linux.tar.gz releases/
	docker cp certinfo-releases:/releases/certinfo_darwin.tar.gz releases/
	docker cp certinfo-releases:/releases/certinfo_windows.tar.gz releases/
	docker rm certinfo-releases
	docker rmi certinfo-releases
