.PHONY: build build-install build-bot test vet lint format format-check install bot-cert relay-logs verify-relay benchmark-relay verify-miniapp build-linux-amd64 build-install-linux-amd64 build-bot-linux-amd64 build-linux-arm64 build-install-linux-arm64 build-bot-linux-arm64 release-dist clean harness-check generate-db

BINARY=ultra-relay
INSTALL_BINARY=ultra-install
BOT_BINARY=ultra-bot

# Pin tool versions here; CI invokes these same Make targets.
GOIMPORTS_PKG=golang.org/x/tools/cmd/goimports@v0.50.0
GOLINES_PKG=github.com/segmentio/golines@v0.13.0
GOLANGCI_LINT_VERSION=v2.14.0
SQLC_VERSION=v1.31.1

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/ultra-relay

build-install:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(INSTALL_BINARY) ./cmd/ultra-install

build-bot:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BOT_BINARY) ./cmd/ultra-bot

test:
	CGO_ENABLED=0 go test ./...

generate-db:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

harness-check:
	go run ./tools/harnesscheck

vet:
	go vet ./...

format:
	@echo "Running goimports..."
	go run $(GOIMPORTS_PKG) -w .
	@echo "Running gofmt -s..."
	gofmt -s -w .
	@echo "Running golines..."
	go run $(GOLINES_PKG) --max-len=140 -w .
	go mod tidy

format-check:
	$(MAKE) format
	git diff --exit-code

lint:
	@echo "Running golangci-lint ($(GOLANGCI_LINT_VERSION))..."
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout 5m ./...

install: build-install
	@bash "$(CURDIR)/scripts/install.sh"

# Получить (или обновить) TLS-сертификат для ultra-bot локально через acme.sh и загрузить на bridge.
# Требует DUCKDNS_TOKEN в .env и настроенного install.config (BOT_DOMAIN, BRIDGE_IP, BRIDGE_SSH_KEY).
bot-cert:
	@bash "$(CURDIR)/scripts/bot-cert.sh"

# Проверка DNS и HTTPS Mini App (BOT_DOMAIN → bridge, не exit). См. README «Домен для Mini App».
verify-miniapp:
	@bash "$(CURDIR)/scripts/verify-miniapp.sh" $(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',)

# С journalctl: bridge + exit-ноды из install.config (MAIN_EXIT_IP).
# Недоступные exit пропускаются с WARNING; код выхода 1 только если недоступен bridge.
# Опции: SSH_USER, LINES, INSTALL_CONFIG, SINCE_RESTART=1 (-s).
relay-logs:
	@bash "$(CURDIR)/scripts/collect-relay-logs.sh" \
		$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
		$(if $(SSH_USER),-u '$(SSH_USER)',) \
		$(if $(LINES),-n '$(LINES)',) \
		$(if $(filter 1 y Y yes true,$(SINCE_RESTART)),-s,) \
		$(if $(BRIDGE_IP),"$(BRIDGE_IP)",) \
		$(if $(MAIN_EXIT_IP),"$(MAIN_EXIT_IP)",)

# Интеграционная проверка (локальный xray + SOCKS). Нужен VERIFY_IP_URL. См. README.
# Опции: VERIFY_USER_UUID, VERIFY_SOCKS_PORT, VERIFY_IP_URL (передайте make … VAR=…).
verify-relay:
	@export VERIFY_USER_UUID="$(VERIFY_USER_UUID)"; \
	export VERIFY_IP_URL="$(VERIFY_IP_URL)"; \
	export VERIFY_SPLIT_ROUTING="$(VERIFY_SPLIT_ROUTING)"; \
	export VERIFY_PROBE_EXIT_URL="$(VERIFY_PROBE_EXIT_URL)"; \
	export VERIFY_PROBE_EXIT_PLAIN_URL="$(VERIFY_PROBE_EXIT_PLAIN_URL)"; \
	if [ -n "$(BRIDGE_IP)" ] && [ -n "$(MAIN_EXIT_IP)" ]; then \
		bash "$(CURDIR)/scripts/verify-relay.sh" \
			$(if $(SSH_USER),-u '$(SSH_USER)',) \
			$(if $(VERIFY_SOCKS_PORT),-p '$(VERIFY_SOCKS_PORT)',) \
			"$(BRIDGE_IP)" "$(MAIN_EXIT_IP)"; \
	else \
		bash "$(CURDIR)/scripts/verify-relay.sh" \
			$(if $(INSTALL_CONFIG),-c '$(INSTALL_CONFIG)',) \
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

release-dist: ansible-dist build-client-release build-linux-amd64 build-install-linux-amd64 build-bot-linux-amd64 build-linux-arm64 build-install-linux-arm64 build-bot-linux-arm64
	mkdir -p dist
	cp $(BINARY)-linux-amd64 $(INSTALL_BINARY)-linux-amd64 $(BOT_BINARY)-linux-amd64 \
	   $(BINARY)-linux-arm64 $(INSTALL_BINARY)-linux-arm64 $(BOT_BINARY)-linux-arm64 \
	   ultra-client-linux-amd64 ultra-client-linux-arm64 deploy/mobile-bootstrap.sh dist/
	tar -czf dist/ultra-recovery.tar.gz -C deploy/recovery $$(cd deploy/recovery && find . -maxdepth 1 -type f \( -name "*.py" -o -name "*.service" -o -name "*.timer" \) ! -name "test_*" ! -name "vm_*" ! -name "test-*" -printf "%f\n" | sort)
	(cd dist && sha256sum \
	   $(BINARY)-linux-amd64 $(INSTALL_BINARY)-linux-amd64 $(BOT_BINARY)-linux-amd64 \
	   $(BINARY)-linux-arm64 $(INSTALL_BINARY)-linux-arm64 $(BOT_BINARY)-linux-arm64 \
	   ultra-client-linux-amd64 ultra-client-linux-arm64 ultra-recovery.tar.gz mobile-bootstrap.sh \
	   ultra-ansible.tar.gz ultra-ansible-runtime-linux-amd64.tar.gz ultra-ansible-runtime-linux-arm64.tar.gz > checksums.txt)
	scripts/build-release-manifest.sh dist "$$(git describe --tags --always --dirty 2>/dev/null || true)"

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 \
	      $(INSTALL_BINARY) $(INSTALL_BINARY)-linux-amd64 $(INSTALL_BINARY)-linux-arm64 \
	      $(BOT_BINARY) $(BOT_BINARY)-linux-amd64 $(BOT_BINARY)-linux-arm64 \
	      ultra-client-linux-amd64 ultra-client-linux-arm64
	rm -rf dist

.PHONY: build-client
build-client:
	go build -o ultra-client ./cmd/ultra-client

.PHONY: build-bench
build-bench:
	go build -o ultra-bench ./cmd/ultra-bench

# Vision still requires the existing VLESS-only checkptr workaround on Go 1.27.
# Race instrumentation and all transport tests remain enabled.
.PHONY: test-race

.PHONY: test-ui
test-ui:
	python3 scripts/test-mobile-bootstrap.py
	python3 scripts/test-ansible-release-contracts.py
	python3 scripts/test-controller-enforcement.py
	python3 scripts/test-database-preservation.py
	python3 scripts/test-ansible-upgrade-baseline.py
	python3 scripts/test-verify-miniapp.py
	python3 scripts/test-ingress-ssh.py
	python3 scripts/test-bridge-subscription.py
	python3 scripts/test-reality-reserve.py
	node --test scripts/test-happ-import.cjs scripts/test-cabinet.cjs scripts/test-miniapp-preview.cjs

test-race:
	go test -race -gcflags='github.com/xtls/xray-core/proxy/vless/...=-d=checkptr=0' ./...

.PHONY: build-client-release
build-client-release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ultra-client-linux-amd64 ./cmd/ultra-client
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ultra-client-linux-arm64 ./cmd/ultra-client

.PHONY: ansible-dist test-ansible test-ansible-exit

ansible-dist:
	mkdir -p dist
	tar --exclude=__pycache__ --exclude=\*.pyc -czf dist/ultra-ansible.tar.gz -C deploy/ansible ansible.cfg requirements.txt controller.py playbooks roles library callback_plugins
	python3 scripts/manual-deploy-runtime.py --architecture amd64 --output dist/ultra-ansible-runtime-linux-amd64.tar.gz
	python3 scripts/manual-deploy-runtime.py --architecture arm64 --output dist/ultra-ansible-runtime-linux-arm64.tar.gz

test-ansible:
	python3 scripts/test-ansible-controller-process.py
	python3 scripts/test-upgrade-worker-drain.py
	python3 scripts/test-ansible-release-contracts.py
	python3 scripts/test-controller-enforcement.py
	python3 scripts/test-ansible-db-tunnel-authorization.py
	python3 scripts/test-db-tunnel-reuse.py
	python3 scripts/test-ansible-safe-diagnostic.py
	python3 scripts/test-release-ci.py
	python3 scripts/test-ansible-owned-file.py
	python3 scripts/test-ansible-input-types.py
	python3 scripts/test-relay-environment.py
	python3 scripts/test-ansible-operation-mapping.py
	python3 scripts/test-retained-primary-gates.py
	python3 scripts/test-subscription-key-projection.py
	python3 scripts/test-recovery-tools-bootstrap.py
	python3 scripts/test-ansible-dns-migration.py
	python3 scripts/test-ansible-upgrade-runtime.py
	python3 scripts/test-ansible-accepted-resume.py
	python3 scripts/test-ansible-upgrade-domain.py
	python3 scripts/test-ansible-runtime-effects.py
	python3 scripts/test-ansible-lifecycle-retry.py
	python3 scripts/test-ansible-release-identity.py
	python3 scripts/test-ansible-upgrade-baseline.py
	python3 scripts/test-ansible-release-retention.py
	python3 scripts/test-ansible-ingress.py
	python3 scripts/test-ansible-retire-experiment.py
	python3 scripts/test-ansible-ingress-probe.py
	python3 scripts/test-ansible-adopt-baseline.py
	python3 scripts/test-ansible-adoption.py
	python3 scripts/test-ansible-adoption-tls.py
	python3 scripts/test-ansible-forward.py
	python3 scripts/test-ansible-exit-pin-rebind.py
	ANSIBLE_CONFIG="$(CURDIR)/deploy/ansible/ansible.cfg" ansible-lint --offline deploy/ansible/playbooks deploy/ansible/roles

# Disposable container: real SSH/Ansible with a simulated service manager.
test-ansible-exit: build-install
	python3 scripts/test-ansible-exit.py --installer "$(CURDIR)/ultra-install" --ansible-playbook "$$(command -v ansible-playbook)"

# Explicit operator action: builds committed HEAD in isolation, then rolls out.
.PHONY: deploy deploy-build test-manual-deploy
deploy:
	python3 scripts/manual-deploy.py $(if $(INSTALL_CONFIG),--config "$(INSTALL_CONFIG)",) $(if $(filter 1,$(RETRY_FAILED)),--retry-failed,) $(if $(SUBSCRIPTION_PROBE_ENV_FILE),--subscription-probe-env-file "$(SUBSCRIPTION_PROBE_ENV_FILE)",)

deploy-build:
	python3 scripts/manual-deploy.py --build-only

test-manual-deploy:
	python3 scripts/test-manual-deploy.py
