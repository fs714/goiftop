.PHONY: build

default: build

BINARY=goiftop
GIT_VERSION := $(shell git rev-parse HEAD)
GO_VERSION := $(shell go version)
BUILD_TIME := $(shell date +%FT%T%z)

LDFLAGS=-ldflags '-s -X "github.com/fs714/goiftop/utils/version.GitVersion=${GIT_VERSION}" -X "github.com/fs714/goiftop/utils/.GoVersion=${GO_VERSION}" -X "github.com/fs714/goiftop/utils/version.BuildTime=${BUILD_TIME}"'

build:
	env GOOS=linux GOARCH=amd64 go build -o bin/${BINARY} ${LDFLAGS}
clean:
	rm -rf bin/
