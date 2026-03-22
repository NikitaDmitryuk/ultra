.PHONY: build build-install test vet lint format install build-linux-amd64 build-install-linux-amd64 build-linux-arm64 clean

BINARY=ultra-relay
INSTALL_BINARY=ultra-install

# Pin tool versions (align with reproducible CI-style runs)
GOIMPORTS_PKG=golang.org/x/tools/cmd/goimports@v0.30.0
GOLANGCI_LINT_VERSION=v2.10.1

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/ultra-relay

build-install:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY) ./cmd/ultra-install

test:
	CGO_ENABLED=0 go test ./...

vet:
	go vet ./...

format:
	@echo "Running goimports..."
	go run $(GOIMPORTS_PKG) -w .
	@echo "Running gofmt -s..."
	gofmt -s -w .
	@if command -v golines >/dev/null 2>&1; then \
		echo "Running golines..."; \
		golines --max-len=140 -w .; \
	else \
		echo "golines not installed; skip (optional: go install github.com/segmentio/golines@latest)"; \
	fi
	go mod tidy

lint:
	@echo "Running golangci-lint ($(GOLANGCI_LINT_VERSION))..."
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

install:
	@bash "$(CURDIR)/scripts/install.sh"

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-amd64 ./cmd/ultra-relay

build-install-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY)-linux-amd64 ./cmd/ultra-install

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-arm64 ./cmd/ultra-relay

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(INSTALL_BINARY) $(INSTALL_BINARY)-linux-amd64
