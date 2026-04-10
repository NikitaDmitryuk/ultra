#!/usr/bin/env bash
# Получить (или обновить) TLS-сертификат для ultra-bot через certbot HTTP-01
# и перезапустить сервис.
# Запускается локально с машины разработчика — подключается к bridge по SSH.
#
# Использует: install.config (BOT_DOMAIN, BRIDGE, SSH_USER, IDENTITY)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=install-config.sh
source "$ROOT/scripts/install-config.sh"

if [[ -n "${ULTRA_INSTALL_CONFIG:-}" ]]; then
	load_install_config "$ULTRA_INSTALL_CONFIG"
elif [[ -f "$(install_config_default_path)" ]]; then
	load_install_config "$(install_config_default_path)"
else
	echo "ultra: install.config не найден. Скопируйте install.config.sample → install.config." >&2
	exit 1
fi

FRONT="${BRIDGE:-${FRONT:-}}"
SSH_USER="${SSH_USER:-root}"
BOT_DOMAIN="${BOT_DOMAIN:-}"
BOT_PORT="${BOT_PORT:-8444}"
IDENTITY="${IDENTITY:-}"
if [[ -n "$IDENTITY" && "$IDENTITY" == ~/* ]]; then
	IDENTITY="$HOME/${IDENTITY#~/}"
fi

if [[ -z "${BOT_DOMAIN:-}" ]]; then
	echo "ultra: BOT_DOMAIN не задан в install.config." >&2; exit 1
fi
if [[ -z "${FRONT:-}" ]]; then
	echo "ultra: BRIDGE не задан в install.config." >&2; exit 1
fi

_ssh_id_args=()
if [[ -n "${IDENTITY:-}" ]]; then
	_ssh_id_args=(-i "$IDENTITY")
fi
_ssh_base=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${_ssh_id_args[@]}" "${SSH_USER}@${FRONT}")

echo "Запрашиваю сертификат для ${BOT_DOMAIN} через certbot HTTP-01 на ${FRONT}…"
"${_ssh_base[@]}" "certbot certonly --standalone -d '${BOT_DOMAIN}' \
	--non-interactive --agree-tos --email 'admin@${BOT_DOMAIN}' 2>&1"

echo "Перезапускаю ultra-bot…"
"${_ssh_base[@]}" "systemctl restart ultra-bot"

echo
echo "Готово. Mini App: https://${BOT_DOMAIN}:${BOT_PORT}/"
echo "Certbot настроил автообновление — сертификат продлится автоматически."
