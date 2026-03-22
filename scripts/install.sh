#!/usr/bin/env bash
# Interactive deploy: builds Linux amd64 binaries and runs ultra-install (SSH key auth only).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Требуется команда в PATH: $1" >&2
    exit 1
  fi
}

need go
need ssh
need scp

echo "=== ultra: установка пары узлов (bridge / exit) ==="
echo "Нужен SSH-доступ по ключу к обоим хостам (пароли сюда не вводятся)."
echo

read -r -p "Front node — хост или IP (SSH, роль bridge): " FRONT
read -r -p "Back node — хост или IP (SSH, роль exit): " BACK
if [[ -z "${FRONT// }" || -z "${BACK// }" ]]; then
  echo "Оба хоста обязательны." >&2
  exit 1
fi

read -r -p "SSH user [root]: " SSH_USER
SSH_USER=${SSH_USER:-root}

read -r -p "Путь к приватному SSH-ключу (пусто = ssh-agent): " IDENTITY

read -r -p "Адрес для клиентов (public-host) [${FRONT}]: " PUB
PUB=${PUB:-$FRONT}

read -r -p "Другой внешний TLS-пир dest host:port [пусто = значение по умолчанию установщика]: " REALITY_DEST
read -r -p "Другой SNI [пусто = значение по умолчанию установщика]: " REALITY_SNI

read -r -p "VLESS / splithttp порт [443]: " VLESS_PORT
VLESS_PORT=${VLESS_PORT:-443}

read -r -p "Генерировать self-signed TLS на back? [Y/n]: " GEN_TLS
case "${GEN_TLS:-y}" in
  n|N) GEN_FLAG=(-generate-exit-tls=false) ;;
  *) GEN_FLAG=() ;;
esac

echo
echo "Сборка ultra-relay-linux-amd64 и ultra-install-linux-amd64..."
make build-linux-amd64 build-install-linux-amd64

INSTALLER="$ROOT/ultra-install-linux-amd64"
if [[ ! -x "$INSTALLER" ]]; then
  echo "Не найден $INSTALLER после сборки." >&2
  exit 1
fi

ARGS=(
  -bridge "$FRONT"
  -exit "$BACK"
  -ssh-user "$SSH_USER"
  -public-host "$PUB"
  -vless-port "$VLESS_PORT"
  -project-root "$ROOT"
  -binary "$ROOT/ultra-relay-linux-amd64"
)

if [[ -n "${REALITY_DEST// }" ]]; then
  ARGS+=(-reality-dest "$REALITY_DEST")
fi
if [[ -n "${REALITY_SNI// }" ]]; then
  ARGS+=(-reality-sni "$REALITY_SNI")
fi

if [[ -n "${IDENTITY// }" ]]; then
  ARGS+=(-identity "$IDENTITY")
fi

ARGS+=("${GEN_FLAG[@]}")

echo "Запуск: $INSTALLER ${ARGS[*]}"
exec "$INSTALLER" "${ARGS[@]}"
