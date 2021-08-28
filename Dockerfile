FROM golang:1.17.0-alpine AS build
RUN apk add --no-cache gcc libc-dev

WORKDIR /go/src/app
COPY . .
RUN go test ./...
ARG version=dev
RUN go build -ldflags "-X main.Version=$version" -o /bin/certinfo

FROM alpine:3.14.2

COPY --from=build /bin/certinfo /usr/local/bin/certinfo
ENTRYPOINT ["certinfo"]
