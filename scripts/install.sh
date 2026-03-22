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
	LOG_LEVEL=${LOG_LEVEL:-info}
	case "${GENERATE_EXIT_TLS:-y}" in
	n | N | false | no | 0) GEN_FLAG=(-generate-exit-tls=false) ;;
	*) GEN_FLAG=() ;;
	esac
	REALITY_DEST=${REALITY_DEST:-}
	REALITY_SNI=${REALITY_SNI:-}
	IDENTITY=${IDENTITY:-}
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

	read -r -p "Адрес для клиентов (public-host) [${FRONT}]: " PUB
	PUB=${PUB:-$FRONT}

	read -r -p "Другой внешний TLS-пир dest host:port [пусто = значение по умолчанию установщика]: " REALITY_DEST
	read -r -p "Другой SNI [пусто = значение по умолчанию установщика]: " REALITY_SNI

	read -r -p "Публичный порт VLESS на bridge [443]: " VLESS_PORT
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
fi

if [[ -z "${FRONT// }" || -z "${BACK// }" ]]; then
	echo "Нужны непустые BRIDGE и EXIT (или FRONT и BACK) в install.config либо ответы в интерактиве." >&2
	exit 1
fi

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

if [[ -n "${IDENTITY// }" ]]; then
	ARGS+=(-identity "$IDENTITY")
fi

ARGS+=("${GEN_FLAG[@]}")
ARGS+=(-log-level "$LOG_LEVEL")

echo "Запуск: $INSTALLER ${ARGS[*]}"
exec "$INSTALLER" "${ARGS[@]}"
