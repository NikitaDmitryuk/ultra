#!/usr/bin/env bash
# Проверка публичного HTTPS-входа и backend bridge по отдельности.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-config.sh
source "$SCRIPT_DIR/install-config.sh"

CONFIG_FILE=""
while getopts "c:h" opt; do
	case "$opt" in
	c) CONFIG_FILE=$OPTARG ;;
	h)
		echo "Использование: $0 [-c install.config]" >&2
		exit 2
		;;
	*) exit 2 ;;
	esac
done

if [[ -n "$CONFIG_FILE" ]]; then
	load_install_config "$CONFIG_FILE"
elif [[ -f "$(install_config_default_path)" ]]; then
	load_install_config "$(install_config_default_path)"
fi

BRIDGE="${BRIDGE:-${FRONT:-}}"
BOT_DOMAIN="${BOT_DOMAIN:-}"
BOT_PORT="${BOT_PORT:-8444}"

if [[ -z "${BRIDGE// }" || -z "${BOT_DOMAIN// }" ]]; then
	echo "verify-miniapp: задайте BRIDGE и BOT_DOMAIN в install.config" >&2
	exit 2
fi

exec python3 "$SCRIPT_DIR/verify-miniapp.py" "$BRIDGE" "$BOT_DOMAIN" "$BOT_PORT" "${BOT_PUBLIC_URL:-}" "${BOT_INGRESS_IP:-}"
