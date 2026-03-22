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
	case "${REUSE_BRIDGE_SPEC:-n}" in
	y | Y | true | 1 | yes) reuse_spec=1 ;;
	esac
	if [[ "$reuse_spec" -ne 1 && -z "${REALITY_DEST// }" ]]; then
		echo "ultra: в install.config укажите REALITY_DEST=host:443 или REUSE_BRIDGE_SPEC=y." >&2
		exit 1
	fi
	if [[ -n "$IDENTITY" && "$IDENTITY" == ~/* ]]; then
		IDENTITY="$HOME/${IDENTITY#~/}"
	fi
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

	read -r -p "REALITY dest (host:port), обязательно: " REALITY_DEST
	if [[ -z "${REALITY_DEST// }" ]]; then
		echo "REALITY dest обязателен." >&2
		exit 1
	fi
	read -r -p "REALITY SNI [пусто = host из dest]: " REALITY_SNI

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
fi

if [[ -z "${FRONT// }" || -z "${BACK// }" ]]; then
	echo "Нужны непустые BRIDGE и EXIT (или FRONT и BACK) в install.config либо ответы в интерактиве." >&2
	exit 1
fi

EXIT_DIAL=${EXIT_DIAL:-}

echo
echo "Сборка: ultra-relay-linux-amd64 (для серверов) и ultra-install под эту машину…"
make build-linux-amd64 build-install

INSTALLER="$ROOT/ultra-install"
RELAY_BIN="$ROOT/ultra-relay-linux-amd64"
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

case "${REUSE_BRIDGE_SPEC:-n}" in
y | Y | true | 1 | yes) ARGS+=(-reuse-bridge-spec) ;;
esac

if [[ -n "${IDENTITY// }" ]]; then
	ARGS+=(-identity "$IDENTITY")
fi

ARGS+=("${GEN_FLAG[@]}")
ARGS+=(-log-level "$LOG_LEVEL")

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

if [[ "$RUN_VERIFY" -eq 1 ]]; then
	echo
	echo "=== Интеграционная проверка (Admin API → локальный xray → SOCKS → GET) ==="
	export VERIFY_USER_UUID="${VERIFY_USER_UUID:-}"
	export VERIFY_SOCKS_PORT="${VERIFY_SOCKS_PORT:-}"
	export VERIFY_IP_URL="${VERIFY_IP_URL:-}"
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
