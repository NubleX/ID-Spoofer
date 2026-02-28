BINARY     := idspoof
MODULE     := github.com/NubleX/ID-Spoofer/idspoof
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -X $(MODULE)/internal/config.Version=$(VERSION) \
              -X $(MODULE)/internal/config.Commit=$(COMMIT) \
              -X $(MODULE)/internal/config.BuildDate=$(BUILD_DATE)

BIN_DIR    := bin
CMD_DIR    := ./cmd/idspoof

.PHONY: all build build-all clean test lint install

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)
	@echo "Built $(BIN_DIR)/$(BINARY)"

build-all:
	@mkdir -p $(BIN_DIR)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-linux-amd64   $(CMD_DIR)
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-linux-arm64   $(CMD_DIR)
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-darwin-amd64  $(CMD_DIR)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-darwin-arm64  $(CMD_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-windows-amd64.exe $(CMD_DIR)
	@echo "Cross-compiled all targets"

test:
	go test -race ./...

test-integration:
	go test -race -tags integration ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR)

install: build
	@echo "Installing to /usr/local/bin/$(BINARY)"
	install -m 755 $(BIN_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
