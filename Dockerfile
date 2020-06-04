FROM golang:1.14-alpine AS build
RUN apk add --no-cache gcc libc-dev

WORKDIR /go/src/app
COPY . .
RUN go test ./...
RUN go build -o /bin/certinfo

FROM alpine:3.12

COPY --from=build /bin/certinfo /usr/local/bin/certinfo
ENTRYPOINT ["certinfo"]
