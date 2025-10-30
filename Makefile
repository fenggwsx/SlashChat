GO ?= go
BINDIR ?= build
SERVER_BIN ?= $(BINDIR)/goslash-server
CLIENT_BIN ?= $(BINDIR)/goslash-client

.PHONY: help build build-server build-client clean

help:
	@echo "Available targets:"
	@echo "  make build         Build server and client binaries."
	@echo "  make build-server  Build only the server binary."
	@echo "  make build-client  Build only the client binary."
	@echo "  make clean         Remove build artifacts."

build: build-server build-client

build-server:
	@mkdir -p $(BINDIR)
	$(GO) build -o $(SERVER_BIN) ./cmd/server

build-client:
	@mkdir -p $(BINDIR)
	$(GO) build -o $(CLIENT_BIN) ./cmd/client

clean:
	@rm -rf $(BINDIR)
