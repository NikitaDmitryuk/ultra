.PHONY: build build-install build-bot test vet lint format install bot-cert relay-logs verify-relay benchmark-relay verify-miniapp build-linux-amd64 build-install-linux-amd64 build-bot-linux-amd64 build-linux-arm64 build-install-linux-arm64 build-bot-linux-arm64 release-dist clean

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

# Проверка DNS и HTTPS Mini App (BOT_DOMAIN → bridge, не exit). См. README «Домен для Mini App».
verify-miniapp:
	@bash "$(CURDIR)/scripts/verify-miniapp.sh" $(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',)

# С journalctl: bridge + exit-ноды из install.config (EXIT, EXIT2).
# Недоступные exit пропускаются с WARNING; код выхода 1 только если недоступен bridge.
# Опции: IDENTITY, SSH_USER, LINES, INSTALL_CONFIG, SINCE_RESTART=1 (-s).
relay-logs:
	@bash "$(CURDIR)/scripts/collect-relay-logs.sh" \
		$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
		$(if $(IDENTITY),-i '$(IDENTITY)',) \
		$(if $(SSH_USER),-u '$(SSH_USER)',) \
		$(if $(LINES),-n '$(LINES)',) \
		$(if $(filter 1 y Y yes true,$(SINCE_RESTART)),-s,) \
		$(if $(BRIDGE),"$(BRIDGE)",) \
		$(if $(EXIT),"$(EXIT)",) \
		$(if $(EXIT2),"$(EXIT2)",)

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

# Read-only benchmark: локальный xray + SOCKS, /v1/health, bridge→exit TCP,
# exit direct vs WARP curl. Опции: BENCH_USER_UUID, BENCH_SOCKS_PORT,
# BENCH_DOWNLOAD_URL, BENCH_DOWNLOAD_URLS, BENCH_UPLOAD_URL, BENCH_UPLOAD_BYTES.
benchmark-relay:
	@export BENCH_USER_UUID="$(BENCH_USER_UUID)"; \
	export BENCH_DOWNLOAD_URL="$(BENCH_DOWNLOAD_URL)"; \
	export BENCH_DOWNLOAD_URLS="$(BENCH_DOWNLOAD_URLS)"; \
	export BENCH_UPLOAD_URL="$(BENCH_UPLOAD_URL)"; \
	export BENCH_UPLOAD_BYTES="$(BENCH_UPLOAD_BYTES)"; \
	export BENCH_IP_URL="$(BENCH_IP_URL)"; \
	export BENCH_SOCKS_PORT="$(BENCH_SOCKS_PORT)"; \
	bash "$(CURDIR)/scripts/benchmark-relay.sh" \
		$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
		$(if $(IDENTITY),-i '$(IDENTITY)',) \
		$(if $(SSH_USER),-u '$(SSH_USER)',) \
		$(if $(BENCH_SOCKS_PORT),-p '$(BENCH_SOCKS_PORT)',)

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-amd64 ./cmd/ultra-relay

build-install-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY)-linux-amd64 ./cmd/ultra-install

build-bot-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BOT_BINARY)-linux-amd64 ./cmd/ultra-bot

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-arm64 ./cmd/ultra-relay

build-install-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY)-linux-arm64 ./cmd/ultra-install

build-bot-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BOT_BINARY)-linux-arm64 ./cmd/ultra-bot

release-dist: build-linux-amd64 build-install-linux-amd64 build-bot-linux-amd64 build-linux-arm64 build-install-linux-arm64 build-bot-linux-arm64
	mkdir -p dist
	cp $(BINARY)-linux-amd64 $(INSTALL_BINARY)-linux-amd64 $(BOT_BINARY)-linux-amd64 \
	   $(BINARY)-linux-arm64 $(INSTALL_BINARY)-linux-arm64 $(BOT_BINARY)-linux-arm64 \
	   deploy/mobile-bootstrap.sh dist/
	(cd dist && sha256sum \
	   $(BINARY)-linux-amd64 $(INSTALL_BINARY)-linux-amd64 $(BOT_BINARY)-linux-amd64 \
	   $(BINARY)-linux-arm64 $(INSTALL_BINARY)-linux-arm64 $(BOT_BINARY)-linux-arm64 \
	   mobile-bootstrap.sh > checksums.txt)
	scripts/build-release-manifest.sh dist "$$(git describe --tags --always --dirty 2>/dev/null || true)"

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 \
	      $(INSTALL_BINARY) $(INSTALL_BINARY)-linux-amd64 $(INSTALL_BINARY)-linux-arm64 \
	      $(BOT_BINARY) $(BOT_BINARY)-linux-amd64 $(BOT_BINARY)-linux-arm64
	rm -rf dist
