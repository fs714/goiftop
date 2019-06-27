.PHONY: build

default: build

BINARY=goiftop
BUILD_TIME=`date +%FT%T%z`

LDFLAGS=-ldflags "-s -X main.BuildTime=${BUILD_TIME}"

bindata:
	go-bindata-assetfs  static/...
build:
	go-bindata-assetfs  static/...
	env GOOS=linux GOARCH=amd64 go build -o bin/${BINARY} ${LDFLAGS}
clean:
	rm bindata.go
	rm -rf bin/
