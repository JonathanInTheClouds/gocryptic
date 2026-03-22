# GoCryptic Makefile
# ─────────────────────────────────────────────────────────────────────────────
BINARY   := gocryptic
PKG      := github.com/gocryptic/gocryptic
GOFLAGS  := -trimpath -ldflags="-s -w"
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build install test lint clean cross-build

all: build

## build: Compile the binary for the host OS/arch
build:
	go build $(GOFLAGS) -o $(BINARY) .

## install: Install gocryptic to $GOPATH/bin (or $GOBIN)
install:
	go install $(GOFLAGS) .

## run-demo: Quick smoke-test of all sub-commands
run-demo: build
	@echo "=== AES-GCM encrypt/decrypt ==="
	./$(BINARY) encrypt --algo aes-gcm --input "Hello, GoCryptic!" --key "demo-password"
	@echo ""
	@echo "=== SHA-256 hash ==="
	./$(BINARY) hash --input "Hello, GoCryptic!"
	@echo ""
	@echo "=== All hashes ==="
	./$(BINARY) hash --algo all --input "Hello, GoCryptic!"
	@echo ""
	@echo "=== Base64 encode/decode ==="
	./$(BINARY) encode --format base64 --input "Hello, GoCryptic!"
	@echo ""
	@echo "=== Keygen: password ==="
	./$(BINARY) keygen --type password --length 20 --special
	@echo ""
	@echo "=== Keygen: AES-256 ==="
	./$(BINARY) keygen --type aes --bits 256

## test: Run the test suite
test:
	go test ./... -v -race -count=1

## lint: Run golangci-lint (install separately: https://golangci-lint.run)
lint:
	golangci-lint run ./...

## cross-build: Build binaries for all supported platforms
cross-build:
	@mkdir -p dist
	$(foreach platform, $(PLATFORMS), \
		$(eval GOOS   = $(word 1, $(subst /, ,$(platform)))) \
		$(eval GOARCH = $(word 2, $(subst /, ,$(platform)))) \
		GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) \
			-o dist/$(BINARY)-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe,) ./... ; \
	)
	ls -lh dist/

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf dist/
