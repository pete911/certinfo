FROM golang:1.14-alpine AS build
RUN apk add --no-cache gcc libc-dev

WORKDIR /go/src/app
COPY . .
RUN go test ./...
RUN mkdir /releases

RUN GOOS=linux go build -o /releases/certinfo
RUN tar -czvf /releases/certinfo_linux.tar.gz -C /releases/ certinfo
RUN rm /releases/certinfo

RUN GOOS=darwin go build -o /releases/certinfo
RUN tar -czvf /releases/certinfo_darwin.tar.gz -C /releases/ certinfo
RUN rm /releases/certinfo

RUN GOOS=windows go build -o /releases/certinfo.exe
RUN tar -czvf /releases/certinfo_windows.tar.gz -C /releases/ certinfo.exe
RUN rm /releases/certinfo.exe
