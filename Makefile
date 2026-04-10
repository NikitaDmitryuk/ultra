.PHONY: build build-install build-bot test vet lint format install bot-cert relay-logs verify-relay latency-profile build-linux-amd64 build-install-linux-amd64 build-bot-linux-amd64 build-linux-arm64 clean

BINARY=ultra-relay
INSTALL_BINARY=ultra-install
BOT_BINARY=ultra-bot

# Pin tool versions (align with reproducible CI-style runs)
GOIMPORTS_PKG=golang.org/x/tools/cmd/goimports@v0.30.0
GOLANGCI_LINT_VERSION=v2.10.1

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/ultra-relay

build-install:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY) ./cmd/ultra-install

build-bot:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BOT_BINARY) ./cmd/ultra-bot

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
	@# ultra-install fetches geo bundles on the bridge unless skipped; see install.config.sample (SKIP_GEO_DOWNLOAD)
	@bash "$(CURDIR)/scripts/install.sh"

# Получить (или обновить) TLS-сертификат для ultra-bot локально через acme.sh и загрузить на bridge.
# Требует DUCKDNS_TOKEN в .env и настроенного install.config (BOT_DOMAIN, BRIDGE, IDENTITY).
bot-cert:
	@bash "$(CURDIR)/scripts/bot-cert.sh"

# С journalctl: либо BRIDGE и EXIT, либо корневой install.config (см. install.config.sample).
# Опции: IDENTITY, SSH_USER, LINES, INSTALL_CONFIG (путь к конфигу вместо install.config).
relay-logs:
	@if [ -n "$(BRIDGE)" ] && [ -n "$(EXIT)" ]; then \
		bash "$(CURDIR)/scripts/collect-relay-logs.sh" \
			$(if $(IDENTITY),-i '$(IDENTITY)',) \
			$(if $(SSH_USER),-u '$(SSH_USER)',) \
			$(if $(LINES),-n '$(LINES)',) \
			"$(BRIDGE)" "$(EXIT)"; \
	else \
		bash "$(CURDIR)/scripts/collect-relay-logs.sh" \
			$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
			$(if $(IDENTITY),-i '$(IDENTITY)',) \
			$(if $(SSH_USER),-u '$(SSH_USER)',) \
			$(if $(LINES),-n '$(LINES)',); \
	fi

# Интеграционная проверка (локальный xray + SOCKS). Нужен VERIFY_IP_URL. См. README.
# Опции: VERIFY_USER_UUID, VERIFY_SOCKS_PORT, VERIFY_IP_URL (передайте make … VAR=…).
verify-relay:
	@export VERIFY_USER_UUID="$(VERIFY_USER_UUID)"; \
	export VERIFY_IP_URL="$(VERIFY_IP_URL)"; \
	export VERIFY_SPLIT_ROUTING="$(VERIFY_SPLIT_ROUTING)"; \
	export VERIFY_PROBE_EXIT_URL="$(VERIFY_PROBE_EXIT_URL)"; \
	export VERIFY_PROBE_EXIT_PLAIN_URL="$(VERIFY_PROBE_EXIT_PLAIN_URL)"; \
	if [ -n "$(BRIDGE)" ] && [ -n "$(EXIT)" ]; then \
		bash "$(CURDIR)/scripts/verify-relay.sh" \
			$(if $(IDENTITY),-i '$(IDENTITY)',) \
			$(if $(SSH_USER),-u '$(SSH_USER)',) \
			$(if $(VERIFY_SOCKS_PORT),-p '$(VERIFY_SOCKS_PORT)',) \
			"$(BRIDGE)" "$(EXIT)"; \
	else \
		bash "$(CURDIR)/scripts/verify-relay.sh" \
			$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
			$(if $(IDENTITY),-i '$(IDENTITY)',) \
			$(if $(SSH_USER),-u '$(SSH_USER)',) \
			$(if $(VERIFY_SOCKS_PORT),-p '$(VERIFY_SOCKS_PORT)',); \
	fi

# Hop-by-hop latency profiling: bridge→exit TCP, WARP overhead, session traces, E2E SOCKS.
# Включи трейсинг: "trace_latency": true в /etc/ultra-relay/spec.json на bridge, затем перезапусти.
latency-profile:
	@bash "$(CURDIR)/scripts/latency-profile.sh" \
		$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
		$(if $(IDENTITY),-i '$(IDENTITY)',) \
		$(if $(SSH_USER),-u '$(SSH_USER)',) \
		$(if $(VERIFY_SOCKS_PORT),-p '$(VERIFY_SOCKS_PORT)',) \
		$(if $(BRIDGE),"$(BRIDGE)",) \
		$(if $(EXIT),"$(EXIT)",)

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-amd64 ./cmd/ultra-relay

build-install-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY)-linux-amd64 ./cmd/ultra-install

build-bot-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BOT_BINARY)-linux-amd64 ./cmd/ultra-bot

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-arm64 ./cmd/ultra-relay

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 \
	      $(INSTALL_BINARY) $(INSTALL_BINARY)-linux-amd64 \
	      $(BOT_BINARY) $(BOT_BINARY)-linux-amd64
