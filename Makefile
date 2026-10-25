BINARY := lanclip
VERSION ?= $(shell date -u +%Y%m%d 2>/dev/null || date +%Y%m%d)

.PHONY: build test vet release clean run

build:
	go build -ldflags "-s -w -X main.appVersion=$(VERSION)" -o $(BINARY) ./cmd/lanclip

vet:
	go vet ./...

test: vet
	go test ./...

release: clean
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-s -w" -o dist/lanclip-darwin-arm64       ./cmd/lanclip
	GOOS=darwin  GOARCH=amd64 go build -ldflags "-s -w" -o dist/lanclip-darwin-amd64       ./cmd/lanclip
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/lanclip-windows-amd64.exe  ./cmd/lanclip
	GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w" -o dist/lanclip-linux-amd64        ./cmd/lanclip

run: build
	./$(BINARY) serve

clean:
	rm -rf dist $(BINARY) $(BINARY).exe
