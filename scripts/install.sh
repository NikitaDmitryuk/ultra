#!/usr/bin/env bash
# Интерактивная или неинтерактивная установка (если есть install.config).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=install-config.sh
source "$ROOT/scripts/install-config.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Требуется команда в PATH: $1" >&2
		exit 1
	fi
}

need go
need ssh
need scp

# check_port HOST PORT LABEL
# Returns 0 if the port is reachable (open or refused quickly), 1 if filtered (timeout).
# Uses nc; silently skips the check if nc is not available.
check_port() {
	local host="$1" port="$2" label="$3"
	if ! command -v nc >/dev/null 2>&1; then
		echo "  ? $port/tcp ($label) — nc не найден, проверка пропущена"
		return 0
	fi
	local t0 t1 elapsed rc
	t0=$(date +%s)
	nc -zw 3 "$host" "$port" >/dev/null 2>&1; rc=$?
	t1=$(date +%s)
	elapsed=$(( t1 - t0 ))
	# rc=0  → кто-то слушает (порт открыт)
	# rc!=0, elapsed<2 → connection refused (firewall пропускает, но сервис ещё не запущен — нормально)
	# rc!=0, elapsed>=2 → timeout — скорее всего заблокирован firewall / security group
	if [[ $rc -eq 0 ]] || [[ $elapsed -lt 2 ]]; then
		echo "  ✓ $port/tcp ($label)"
		return 0
	else
		echo "  ✗ $port/tcp ($label) — timeout: порт заблокирован firewall или security group" >&2
		return 1
	fi
}

FROM_CONFIG=0
CONFIG_FILE=""
if [[ -n "${ULTRA_INSTALL_CONFIG:-}" ]]; then
	CONFIG_FILE="$ULTRA_INSTALL_CONFIG"
	if [[ ! -f "$CONFIG_FILE" ]]; then
		echo "ultra: файл ULTRA_INSTALL_CONFIG=$CONFIG_FILE не найден." >&2
		exit 1
	fi
	load_install_config "$CONFIG_FILE"
	FROM_CONFIG=1
elif [[ -f "$(install_config_default_path)" ]]; then
	CONFIG_FILE="$(install_config_default_path)"
	load_install_config "$CONFIG_FILE"
	FROM_CONFIG=1
fi

if [[ "$FROM_CONFIG" -eq 1 ]]; then
	echo "=== ultra: установка из конфига $CONFIG_FILE ==="
	FRONT="${BRIDGE:-${FRONT:-}}"
	BACK="${EXIT:-${BACK:-}}"
	SSH_USER=${SSH_USER:-root}
	PUB=${PUBLIC_HOST:-}
	PUB=${PUB:-$FRONT}
	VLESS_PORT=${VLESS_PORT:-443}
	TUNNEL_PORT=${TUNNEL_PORT:-}
	VERIFY_AFTER_INSTALL=${VERIFY_AFTER_INSTALL:-n}
	VERIFY_USER_UUID=${VERIFY_USER_UUID:-}
	VERIFY_SOCKS_PORT=${VERIFY_SOCKS_PORT:-}
	VERIFY_IP_URL=${VERIFY_IP_URL:-}
	VERIFY_FAIL_LOG_LINES=${VERIFY_FAIL_LOG_LINES:-400}
	LOG_LEVEL=${LOG_LEVEL:-info}
	case "${GENERATE_EXIT_TLS:-y}" in
	n | N | false | no | 0) GEN_FLAG=(-generate-exit-tls=false) ;;
	*) GEN_FLAG=() ;;
	esac
	REALITY_DEST=${REALITY_DEST:-}
	REALITY_SNI=${REALITY_SNI:-}
	IDENTITY=${IDENTITY:-}
	reuse_spec=0
	case "${REUSE_BRIDGE_SPEC:-y}" in
	y | Y | true | 1 | yes) reuse_spec=1 ;;
	esac
	if [[ "$reuse_spec" -ne 1 && -z "${REALITY_DEST// }" ]]; then
		echo "ultra: в install.config укажите REALITY_DEST=host:443 (цель TLS handshape) или REUSE_BRIDGE_SPEC=y." >&2
		exit 1
	fi
	if [[ -n "$IDENTITY" && "$IDENTITY" == ~/* ]]; then
		IDENTITY="$HOME/${IDENTITY#~/}"
	fi
	# Database variables (all optional; DB_ENABLE=y activates automatic PostgreSQL setup)
	DB_ENABLE="${DB_ENABLE:-n}"
	DB_HOST="${DB_HOST:-}"
	DB_REPLICA="${DB_REPLICA:-}"
	DB_SSH_USER="${DB_SSH_USER:-}"
	DB_NAME="${DB_NAME:-ultra_db}"
	DB_USER="${DB_USER:-ultra}"
	# Bot variables
	BOT_ENABLE="${BOT_ENABLE:-n}"
	BOT_DOMAIN="${BOT_DOMAIN:-}"
	BOT_PORT="${BOT_PORT:-8444}"
else
	echo "=== ultra: установка пары узлов (bridge / exit) ==="
	echo "Нужен SSH-доступ по ключу к обоим хостам (пароли сюда не вводятся)."
	echo "Подсказка: скопируйте install.config.sample → install.config для автоматического режима."
	echo

	read -r -p "Front node — хост или IP (SSH, роль bridge): " FRONT
	read -r -p "Back node — хост или IP (SSH, роль exit): " BACK
	read -r -p "SSH user [root]: " SSH_USER
	SSH_USER=${SSH_USER:-root}

	read -r -p "Путь к приватному SSH-ключу (пусто = ssh-agent): " IDENTITY

	read -r -p "Публичный адрес входа (public-host) [${FRONT}]: " PUB
	PUB=${PUB:-$FRONT}

	read -r -p "Публичный TLS handshape, host:port (обязательно): " REALITY_DEST
	if [[ -z "${REALITY_DEST// }" ]]; then
		echo "Параметр host:port обязателен." >&2
		exit 1
	fi
	read -r -p "SNI для этого handshape [пусто = host из dest]: " REALITY_SNI

	read -r -p "TCP-порт публичного inbound на bridge (vless_port) [443]: " VLESS_PORT
	VLESS_PORT=${VLESS_PORT:-443}
	read -r -p "Порт splithttp на exit (если 443 занят только там; пусто = тот же): " TUNNEL_PORT

	echo "Уровень логов на обоих узлах (slog + Xray): debug, info, warning, error, none [info]"
	read -r -p "log-level [info]: " LOG_LEVEL
	LOG_LEVEL=${LOG_LEVEL:-info}

	read -r -p "Генерировать self-signed TLS на back? [Y/n]: " GEN_TLS
	case "${GEN_TLS:-y}" in
	n | N) GEN_FLAG=(-generate-exit-tls=false) ;;
	*) GEN_FLAG=() ;;
	esac

	echo "Локальная интеграционная проверка: xray, jq или python3; также VERIFY_IP_URL (HTTPS GET через SOCKS)."
	read -r -p "Запустить проверку цепочки после установки? [y/N]: " RUN_VERIFY_INTERACTIVE
	RUN_VERIFY_INTERACTIVE=${RUN_VERIFY_INTERACTIVE:-n}
	case "${RUN_VERIFY_INTERACTIVE:-n}" in
	y | Y | true | 1 | yes)
		read -r -p "VERIFY_IP_URL (HTTPS, GET через SOCKS): " VERIFY_IP_URL
		;;
	esac

	echo
	echo "База данных PostgreSQL: ultra-install может автоматически установить и настроить"
	echo "PostgreSQL на bridge-хосте (primary) и exit-хосте (streaming replica)."
	read -r -p "Настроить PostgreSQL автоматически? [y/N]: " DB_ENABLE_INTERACTIVE
	DB_ENABLE="${DB_ENABLE_INTERACTIVE:-n}"
	DB_HOST=""
	DB_REPLICA=""
	DB_SSH_USER=""
	DB_NAME="ultra_db"
	DB_USER="ultra"
	case "${DB_ENABLE}" in
	y | Y | true | 1 | yes)
		read -r -p "Хост PostgreSQL primary (Enter = тот же, что bridge): " DB_HOST
		read -r -p "Хост PostgreSQL replica (Enter = тот же, что exit): " DB_REPLICA
		read -r -p "SSH-пользователь для DB-хостов (Enter = ${SSH_USER}): " DB_SSH_USER
		read -r -p "Имя базы данных [ultra_db]: " DB_NAME
		DB_NAME=${DB_NAME:-ultra_db}
		read -r -p "Имя роли приложения [ultra]: " DB_USER
		DB_USER=${DB_USER:-ultra}
		;;
	esac
fi

PRESET=${PRESET:-apijson}
SPLITHTTP_HOST=${SPLITHTTP_HOST:-}
SPLITHTTP_PATH=${SPLITHTTP_PATH:-}

if [[ -z "${FRONT// }" || -z "${BACK// }" ]]; then
	echo "Нужны непустые BRIDGE и EXIT (или FRONT и BACK) в install.config либо ответы в интерактиве." >&2
	exit 1
fi

EXIT_DIAL=${EXIT_DIAL:-}

BOT_ENABLE="${BOT_ENABLE:-n}"
BOT_DOMAIN="${BOT_DOMAIN:-}"
BOT_PORT="${BOT_PORT:-8444}"

# Получить TLS-сертификат для ultra-bot через certbot HTTP-01 на сервере.
# Пропускает, если сертификат уже свежий (>7 дней до истечения).
# Certbot сам настраивает cron-автообновление на сервере.
# Использует глобальные: _ssh_base FRONT
# Возвращает 0 при успехе, 1 при ошибке.
obtain_bot_cert() {
	local domain="$1"

	# Пропустить если сертификат свежий (>7 дней).
	if "${_ssh_base[@]}" "
		cert=/etc/letsencrypt/live/${domain}/fullchain.pem
		[[ -f \"\$cert\" ]] && openssl x509 -checkend 604800 -noout -in \"\$cert\" >/dev/null 2>&1
	" 2>/dev/null; then
		echo "  Сертификат на сервере свежий — пропускаю."
		return 0
	fi

	echo "  Запрашиваю сертификат через certbot HTTP-01 на ${FRONT}…"
	if "${_ssh_base[@]}" "certbot certonly --standalone -d '${domain}' \
		--non-interactive --agree-tos --email 'admin@${domain}' 2>&1"; then
		echo "  Сертификат получен."
		return 0
	fi

	echo >&2
	echo "ultra: certbot не смог получить сертификат для ${domain}." >&2
	echo "  Проверьте:" >&2
	echo "    • DNS A-запись для ${domain} указывает на IP exit-ноды ${BACK}" >&2
	echo "    • Порт 80/tcp открыт на exit-ноде ${BACK}" >&2
	echo "  После исправления запустите: make bot-cert" >&2
	return 1
}

echo
echo "Сборка бинарников…"
BUILD_TARGETS="build-linux-amd64 build-install"
case "${BOT_ENABLE:-n}" in
y | Y | true | 1 | yes) BUILD_TARGETS="$BUILD_TARGETS build-bot-linux-amd64" ;;
esac
# shellcheck disable=SC2086
make $BUILD_TARGETS

INSTALLER="$ROOT/ultra-install"
RELAY_BIN="$ROOT/ultra-relay-linux-amd64"
BOT_BIN="$ROOT/ultra-bot-linux-amd64"
if [[ ! -x "$INSTALLER" ]]; then
	echo "Не найден исполняемый $INSTALLER после сборки." >&2
	exit 1
fi
if [[ ! -f "$RELAY_BIN" ]]; then
	echo "Не найден $RELAY_BIN (нужен для загрузки на Linux VPS)." >&2
	exit 1
fi

ARGS=(
	-bridge "$FRONT"
	-exit "$BACK"
	-ssh-user "$SSH_USER"
	-public-host "$PUB"
	-vless-port "$VLESS_PORT"
	-project-root "$ROOT"
	-binary "$RELAY_BIN"
)

if [[ -n "${REALITY_DEST// }" ]]; then
	ARGS+=(-reality-dest "$REALITY_DEST")
fi
if [[ -n "${REALITY_SNI// }" ]]; then
	ARGS+=(-reality-sni "$REALITY_SNI")
fi

if [[ -n "${TUNNEL_PORT// }" ]]; then
	ARGS+=(-tunnel-port "$TUNNEL_PORT")
fi

if [[ -n "${EXIT_DIAL// }" ]]; then
	ARGS+=(-exit-dial "$EXIT_DIAL")
fi

case "${REUSE_BRIDGE_SPEC:-y}" in
y | Y | true | 1 | yes) ARGS+=(-reuse-bridge-spec) ;;
esac

if [[ -n "${IDENTITY// }" ]]; then
	ARGS+=(-identity "$IDENTITY")
fi

ARGS+=("${GEN_FLAG[@]}")
ARGS+=(-log-level "$LOG_LEVEL")
ARGS+=(-preset "$PRESET")
if [[ -n "${SPLITHTTP_HOST// }" ]]; then
	ARGS+=(-splithttp-host "$SPLITHTTP_HOST")
fi
if [[ -n "${SPLITHTTP_PATH// }" ]]; then
	ARGS+=(-splithttp-path "$SPLITHTTP_PATH")
fi

ROUTING_MODE="${ROUTING_MODE:-}"
if [[ -n "${ROUTING_MODE// }" ]]; then
	ARGS+=(-routing-mode "$ROUTING_MODE")
fi
GEOSITE_BLOCK_TAGS="${GEOSITE_BLOCK_TAGS:-}"
if [[ -n "${GEOSITE_BLOCK_TAGS// }" ]]; then
	ARGS+=(-geosite-block-tags "$GEOSITE_BLOCK_TAGS")
fi

case "${SKIP_GEO_DOWNLOAD:-${SKIP_RUNETFREEDOM_GEO:-n}}" in
y | Y | true | 1 | yes) ARGS+=(-skip-geo-download) ;;
esac
# Пусто = ultra-install сам берёт latest с GitHub API на bridge; иначе зафиксировать тег релиза.
GEO_RELEASE_TAG="${GEO_RELEASE_TAG:-}"
if [[ -n "${GEO_RELEASE_TAG// }" ]]; then
	ARGS+=(-geo-release-tag "$GEO_RELEASE_TAG")
fi

# ── WARP: Cloudflare proxy на exit-ноде ──────────────────────────────────────
# WARP_ENABLE=y — установить warp-cli на exit-ноде и проксировать через Cloudflare.
# При включении destination-сайты видят IP Cloudflare вместо IP датацентра.
case "${WARP_ENABLE:-n}" in
y | Y | true | 1 | yes) ARGS+=(-warp) ;;
esac
WARP_PORT="${WARP_PORT:-40000}"
if [[ "${WARP_PORT}" != "40000" ]]; then
	ARGS+=(-warp-port "$WARP_PORT")
fi

# ── DNS over HTTPS (включён по умолчанию) ────────────────────────────────────
# DOH_DISABLE=y — отключить DoH в Xray (использовать системный DNS).
case "${DOH_DISABLE:-n}" in
y | Y | true | 1 | yes) ARGS+=(-disable-doh) ;;
esac

# ── Transport: bridge→exit tunnel protocol ───────────────────────────────────
# TRANSPORT=grpc     — HTTP/2 gRPC persistent stream (по умолчанию; меньше накладных расходов).
# TRANSPORT=splithttp — HTTP chunked transfer; для сетей, где gRPC блокируется промежуточными узлами.
TRANSPORT="${TRANSPORT:-grpc}"
if [[ "${TRANSPORT}" == "splithttp" ]]; then
	ARGS+=(-transport splithttp)
fi

# ── Connection tuning options ────────────────────────────────────────────────
# FRAGMENT_DISABLE=y — отключить фрагментацию TLS ClientHello (по умолчанию включена).
case "${FRAGMENT_DISABLE:-n}" in
y | Y | true | 1 | yes) ARGS+=(-no-fragment) ;;
esac
# SPLITHTTP_PADDING — диапазон байт случайного паддинга для каждого чанка, напр. "100-1000" (по умолч.); "0" отключает.
SPLITHTTP_PADDING="${SPLITHTTP_PADDING:-}"
if [[ -n "${SPLITHTTP_PADDING// }" ]]; then
	ARGS+=(-splithttp-padding "$SPLITHTTP_PADDING")
fi
# SPLITHTTP_MAX_CHUNK_KB — ограничить размер каждого POST-запроса (0 = умолч. Xray ~1 МБ).
SPLITHTTP_MAX_CHUNK_KB="${SPLITHTTP_MAX_CHUNK_KB:-0}"
if [[ "${SPLITHTTP_MAX_CHUNK_KB}" -gt 0 ]] 2>/dev/null; then
	ARGS+=(-splithttp-max-chunk-kb "$SPLITHTTP_MAX_CHUNK_KB")
fi
# REALITY_FINGERPRINTS — через запятую: chrome,firefox,safari,ios,android (по умолч. ротация из всех).
REALITY_FINGERPRINTS="${REALITY_FINGERPRINTS:-}"
if [[ -n "${REALITY_FINGERPRINTS// }" ]]; then
	ARGS+=(-reality-fingerprints "$REALITY_FINGERPRINTS")
fi

# ── PostgreSQL automatic setup ────────────────────────────────────────────────
case "${DB_ENABLE:-n}" in
y | Y | true | 1 | yes)
	# Default DB_HOST to bridge, DB_REPLICA to exit when not explicitly set.
	_db_host="${DB_HOST:-$FRONT}"
	_db_replica="${DB_REPLICA:-$BACK}"
	ARGS+=(-db-host "$_db_host")
	[[ -n "${_db_replica// }" ]] && ARGS+=(-db-replica "$_db_replica")
	[[ -n "${DB_SSH_USER// }" ]] && ARGS+=(-db-ssh-user "$DB_SSH_USER")
	[[ -n "${DB_NAME:-}" ]] && ARGS+=(-db-name "$DB_NAME")
	[[ -n "${DB_USER:-}" ]] && ARGS+=(-db-user "$DB_USER")
	;;
esac

RUN_VERIFY=0
if [[ "$FROM_CONFIG" -eq 1 ]]; then
	case "${VERIFY_AFTER_INSTALL:-n}" in
	y | Y | true | 1 | yes) RUN_VERIFY=1 ;;
	esac
else
	case "${RUN_VERIFY_INTERACTIVE:-n}" in
	y | Y | true | 1 | yes) RUN_VERIFY=1 ;;
	esac
fi

if [[ "$RUN_VERIFY" -eq 1 ]]; then
	if [[ -z "${VERIFY_IP_URL// }" ]]; then
		echo "ultra: для проверки задайте VERIFY_IP_URL (HTTPS) в install.config или в интерактиве." >&2
		exit 1
	fi
	export VERIFY_IP_URL
fi

echo "Запуск: $INSTALLER ${ARGS[*]}"
if ! "$INSTALLER" "${ARGS[@]}"; then
	exit 1
fi

# ── Bot deployment ────────────────────────────────────────────────────────────
case "${BOT_ENABLE:-n}" in
y | Y | true | 1 | yes)
	if [[ -z "${BOT_DOMAIN// }" ]]; then
		echo >&2
		echo "ultra: ошибка — BOT_ENABLE=y, но BOT_DOMAIN не задан." >&2
		echo >&2
		echo "  Telegram Mini App требует публичного домена с HTTPS (Let's Encrypt)." >&2
		echo "  Как получить домен — см. раздел «Домен для Mini App» в README.md." >&2
		echo >&2
		echo "  Укажите в install.config:" >&2
		echo "    BOT_DOMAIN=bot.example.com   # FQDN с DNS A-записью на bridge ($FRONT)" >&2
		echo >&2
		echo "  Затем повторите: make install" >&2
		exit 1
	elif [[ ! -f "$BOT_BIN" ]]; then
		echo "ultra: не найден $BOT_BIN — пропускаю деплой бота." >&2
	else
		# ── Проверка портов ───────────────────────────────────────────────────
		# Mini App доступна через exit-ноду (nginx TCP-прокси → bridge).
		# Let's Encrypt HTTP-01 также идёт через exit (nginx → bridge:80).
		echo
		echo "Проверка доступности портов на exit ($BACK) для Mini App…"
		_ports_ok=1
		check_port "$BACK" 80 "Let's Encrypt ACME HTTP-01 (через exit)" || _ports_ok=0
		check_port "$BACK" "${BOT_PORT}" "Mini App HTTPS (через exit)" || _ports_ok=0
		if [[ "$_ports_ok" -eq 0 ]]; then
			echo >&2
			echo "ultra: ошибка — необходимые порты недоступны на exit ($BACK)." >&2
			echo >&2
			echo "  Откройте входящие правила в firewall / security group:" >&2
			echo "    80/tcp          — для получения TLS-сертификата (Let's Encrypt HTTP-01)" >&2
			echo "    ${BOT_PORT}/tcp — для Mini App HTTPS" >&2
			echo >&2
			echo "  После открытия портов повторите: make install" >&2
			exit 1
		fi

		echo
		echo "=== Деплой ultra-bot на bridge ($FRONT) ==="
		_ssh_id_args=()
		if [[ -n "${IDENTITY// }" ]]; then
			_ssh_id_args=(-i "$IDENTITY")
		fi
		_ssh_base=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${_ssh_id_args[@]}" "${SSH_USER}@${FRONT}")
		_scp_base=(scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${_ssh_id_args[@]}")
		_ssh_exit_bot=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${_ssh_id_args[@]}" "${SSH_USER}@${BACK}")

		# ── nginx TCP-прокси на exit для Mini App ─────────────────────────────
		# Mini App (HTTPS) и Let's Encrypt HTTP-01 проходят через exit-ноду:
		#   exit:BOT_PORT  → TCP passthrough → bridge:BOT_PORT  (TLS на bridge)
		#   exit:80 (/.well-known/acme-challenge/) → HTTP proxy → bridge:80  (certbot standalone)
		# Это позволяет держать DNS A-запись на exit и работать в сетях,
		# которые не могут напрямую достучаться до bridge (напр. Cloudflare WARP → Yandex Cloud).
		echo
		echo "Настройка nginx на exit ($BACK) для Mini App…"
		if "${_ssh_exit_bot[@]}" "
			set -e
			# Установить nginx и модуль stream, если отсутствуют.
			if ! command -v nginx >/dev/null 2>&1; then
				DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx libnginx-mod-stream
			elif ! dpkg -l libnginx-mod-stream 2>/dev/null | grep -q '^ii'; then
				DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libnginx-mod-stream
			fi
			# Добавить блок stream в nginx.conf, если его ещё нет.
			grep -q 'stream\.d' /etc/nginx/nginx.conf || printf '\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n' >> /etc/nginx/nginx.conf
			mkdir -p /etc/nginx/stream.d

			# TCP passthrough: BOT_PORT → bridge.
			cat > /etc/nginx/stream.d/bot-proxy.conf << 'EOSTREAM'
server {
    listen ${BOT_PORT};
    listen [::]:${BOT_PORT};
    proxy_pass ${FRONT}:${BOT_PORT};
    proxy_connect_timeout 10s;
    proxy_timeout 300s;
}
EOSTREAM

			# HTTP proxy для ACME HTTP-01 certbot renewal на bridge.
			cat > /etc/nginx/conf.d/acme-proxy.conf << 'EOACME'
server {
    listen 80;
    listen [::]:80;
    server_name ${BOT_DOMAIN};

    location /.well-known/acme-challenge/ {
        proxy_pass http://${FRONT}:80;
        proxy_set_header Host \$host;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }

    location / {
        return 301 https://\$host:${BOT_PORT}\$request_uri;
    }
}
EOACME

			nginx -t && systemctl enable nginx && { systemctl reload nginx 2>/dev/null || systemctl start nginx; }
		"; then
			echo "  nginx на exit настроен."
		else
			echo "ultra: ошибка настройки nginx на exit — Mini App будет доступна только напрямую через bridge ($FRONT)." >&2
		fi

		# Stop the bot before replacing the binary (running process locks the file on Linux).
		"${_ssh_base[@]}" "systemctl stop ultra-bot 2>/dev/null || true"

		# Copy bot binary.
		"${_scp_base[@]}" "$BOT_BIN" "${SSH_USER}@${FRONT}:/usr/local/bin/ultra-bot"
		"${_ssh_base[@]}" "chmod 755 /usr/local/bin/ultra-bot"

		# bot.env contains only TELEGRAM_BOT_TOKEN; everything else comes from
		# /etc/ultra-relay/environment (admin token) and spec.json (DB DSN).
		_bot_env_src="${BOT_ENV_FILE:-${ROOT}/.env}"
		if [[ -f "$_bot_env_src" ]]; then
			"${_scp_base[@]}" "$_bot_env_src" "${SSH_USER}@${FRONT}:/etc/ultra-relay/bot.env"
			"${_ssh_base[@]}" "chmod 600 /etc/ultra-relay/bot.env"
		else
			echo "ultra: файл .env не найден ($ROOT/.env)." >&2
			echo "ultra: создайте /etc/ultra-relay/bot.env на сервере с содержимым:" >&2
			echo "       TELEGRAM_BOT_TOKEN=<ваш токен>" >&2
		fi

		# Write ULTRA_BOT_DOMAIN and ULTRA_BOT_PORT into the shared environment file.
		"${_ssh_base[@]}" "
			grep -v '^ULTRA_BOT_' /etc/ultra-relay/environment > /tmp/env.tmp 2>/dev/null || true
			printf 'ULTRA_BOT_DOMAIN=%s\nULTRA_BOT_PORT=%s\n' '${BOT_DOMAIN}' '${BOT_PORT}' >> /tmp/env.tmp
			mv /tmp/env.tmp /etc/ultra-relay/environment
			chmod 600 /etc/ultra-relay/environment
		"

		# ── TLS-сертификат ───────────────────────────────────────────────────
		echo
		echo "Получение TLS-сертификата для ${BOT_DOMAIN}…"
		_cert_ok=1
		obtain_bot_cert "$BOT_DOMAIN" || _cert_ok=0

		# Install systemd unit.
		"${_scp_base[@]}" "$ROOT/deploy/systemd/ultra-bot.service" "${SSH_USER}@${FRONT}:/etc/systemd/system/ultra-bot.service"
		"${_ssh_base[@]}" "
			mkdir -p /var/lib/ultra-bot
			systemctl daemon-reload
			systemctl enable ultra-bot
			systemctl restart ultra-bot
		"

		if [[ "$_cert_ok" -eq 1 ]]; then
			echo "ultra-bot запущен. Mini App: https://${BOT_DOMAIN}:${BOT_PORT}/"
		else
			echo >&2
			echo "ultra: ultra-bot запущен, но TLS-сертификат не получен." >&2
			echo "  Бот (polling) работает, Mini App недоступна." >&2
			echo "  После устранения проблемы с DNS/портами запустите: make bot-cert" >&2
		fi
		echo
		echo "╔══════════════════════════════════════════════════════════════════╗"
		echo "║                    DNS ДЛЯ MINI APP                             ║"
		echo "╠══════════════════════════════════════════════════════════════════╣"
		echo "║  Укажите A-запись для домена Mini App на IP exit-ноды:          ║"
		echo "║                                                                  ║"
		printf  "║    %-62s║\n" "${BOT_DOMAIN}  →  ${BACK}"
		echo "║                                                                  ║"
		echo "║  Mini App доступна через exit (nginx TCP-прокси → bridge).      ║"
		echo "╚══════════════════════════════════════════════════════════════════╝"
		echo

		# Generate an initial admin invite token and store it in the DB on the server.
		# ultra-install has already run PostgreSQL setup, so psql is available and spec.json exists.
		_INVITE_TOKEN=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
		"${_ssh_base[@]}" "
			_dsn=\$(python3 -c \"import json,sys; d=json.load(open('/etc/ultra-relay/spec.json')); print(d.get('database',{}).get('dsn',''))\" 2>/dev/null || true)
			if [[ -n \"\$_dsn\" ]]; then
				psql \"\$_dsn\" -c \"INSERT INTO bot_invite_tokens(token) VALUES('${_INVITE_TOKEN}') ON CONFLICT DO NOTHING\" >/dev/null 2>&1 || true
			fi
		" 2>/dev/null || true

		echo "╔══════════════════════════════════════════════════════════════════╗"
		echo "║          ТОКЕН АДМИНИСТРАТОРА TELEGRAM-БОТА                     ║"
		echo "╠══════════════════════════════════════════════════════════════════╣"
		echo "║  Отправьте боту эту команду, чтобы стать администратором:       ║"
		echo "║                                                                  ║"
		printf  "║  /start %-57s║\n" "${_INVITE_TOKEN}"
		echo "║                                                                  ║"
		echo "║  Токен однократного использования. Не передавайте третьим.      ║"
		echo "╚══════════════════════════════════════════════════════════════════╝"
		echo
	fi
	;;
esac

if [[ "$RUN_VERIFY" -eq 1 ]]; then
	echo
	echo "=== Интеграционная проверка (Admin API → локальный xray → SOCKS → GET) ==="
	export VERIFY_USER_UUID="${VERIFY_USER_UUID:-}"
	export VERIFY_SOCKS_PORT="${VERIFY_SOCKS_PORT:-}"
	export VERIFY_IP_URL="${VERIFY_IP_URL:-}"
	export VERIFY_SPLIT_ROUTING="${VERIFY_SPLIT_ROUTING:-}"
	export VERIFY_PROBE_EXIT_URL="${VERIFY_PROBE_EXIT_URL:-}"
	export VERIFY_PROBE_EXIT_PLAIN_URL="${VERIFY_PROBE_EXIT_PLAIN_URL:-}"
	verify_ok=0
	if [[ "$FROM_CONFIG" -eq 1 && -n "${CONFIG_FILE:-}" ]]; then
		if bash "$ROOT/scripts/verify-relay.sh" -c "$CONFIG_FILE"; then
			verify_ok=1
		fi
	else
		VERIFY_ARGS=(-u "$SSH_USER")
		if [[ -n "${IDENTITY// }" ]]; then
			VERIFY_ARGS+=(-i "$IDENTITY")
		fi
		if [[ -n "${VERIFY_SOCKS_PORT// }" ]]; then
			VERIFY_ARGS+=(-p "$VERIFY_SOCKS_PORT")
		fi
		if bash "$ROOT/scripts/verify-relay.sh" "${VERIFY_ARGS[@]}" "$FRONT" "$BACK"; then
			verify_ok=1
		fi
	fi
	if [[ "$verify_ok" -ne 1 ]]; then
		echo >&2
		echo "ultra: проверка цепочки не прошла — журнал ultra-relay с момента последнего запуска сервиса на bridge и exit (-s в collect-relay-logs.sh):" >&2
		LOG_ARGS=(-s -n "${VERIFY_FAIL_LOG_LINES:-400}")
		if [[ "$FROM_CONFIG" -eq 1 && -n "${CONFIG_FILE:-}" ]]; then
			LOG_ARGS+=(-c "$CONFIG_FILE")
		else
			LOG_ARGS+=(-u "$SSH_USER")
			if [[ -n "${IDENTITY// }" ]]; then
				LOG_ARGS+=(-i "$IDENTITY")
			fi
		fi
		bash "$ROOT/scripts/collect-relay-logs.sh" "${LOG_ARGS[@]}" "$FRONT" "$BACK" >&2 || true
		exit 1
	fi
fi
