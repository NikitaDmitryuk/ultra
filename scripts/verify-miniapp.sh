#!/usr/bin/env bash
# Проверка Mini App: DNS A-запись → bridge, HTTPS на BOT_DOMAIN:BOT_PORT.
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

fail=0
dns_ok=0
resolved=""
bridge_tcp_ok=0
https_ok=0

echo "=== verify-miniapp: ${BOT_DOMAIN} (bridge ${BRIDGE}) ==="

if command -v dig >/dev/null 2>&1; then
	resolved=$(dig +timeout=5 +tries=2 +short "$BOT_DOMAIN" A 2>/dev/null | head -1 || true)
	resolved=${resolved// /}
	if [[ -z "$resolved" ]]; then
		echo "DNS: ✗ A-запись для $BOT_DOMAIN не найдена"
		fail=1
	elif [[ "$resolved" == "$BRIDGE" ]]; then
		echo "DNS: ✓ $BOT_DOMAIN → $resolved"
		dns_ok=1
	else
		echo "DNS: ✗ $BOT_DOMAIN → $resolved (ожидался bridge $BRIDGE)"
		echo "  Исправьте A-запись в DNS (afraid.org и т.п.). Mini App ходит по домену, не по IP exit."
		fail=1
	fi
else
	echo "DNS: ? dig не найден — пропуск"
fi

if command -v nc >/dev/null 2>&1; then
	if nc -zw 5 "$BRIDGE" "$BOT_PORT" >/dev/null 2>&1; then
		echo "TCP: ✓ ${BRIDGE}:${BOT_PORT} (bridge IP)"
		bridge_tcp_ok=1
	else
		echo "TCP: ✗ ${BRIDGE}:${BOT_PORT} — timeout (firewall/security group?)"
		fail=1
	fi
	if [[ "$dns_ok" -eq 1 && "$bridge_tcp_ok" -eq 1 ]]; then
		echo "TCP: ✓ ${BOT_DOMAIN}:${BOT_PORT} — не проверялся (DNS → bridge, порт на IP OK)"
	elif [[ -n "${resolved:-}" ]]; then
		if nc -zw 5 "$BOT_DOMAIN" "$BOT_PORT" >/dev/null 2>&1; then
			echo "TCP: ✓ ${BOT_DOMAIN}:${BOT_PORT} (по hostname)"
		else
			echo "TCP: ? ${BOT_DOMAIN}:${BOT_PORT} — timeout по hostname (на macOS часто ложный negative при верном DNS)"
		fi
	fi
fi

if command -v curl >/dev/null 2>&1; then
	url="https://${BOT_DOMAIN}:${BOT_PORT}/"
	if code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 --resolve "${BOT_DOMAIN}:${BOT_PORT}:${BRIDGE}" "$url" 2>/dev/null); then
		echo "HTTPS (ultra-bot на bridge): ✓ HTTP $code"
		https_ok=1
	else
		echo "HTTPS (ultra-bot на bridge): ✗ не удалось подключиться к ${BRIDGE}:${BOT_PORT}"
		fail=1
	fi
	if [[ "$dns_ok" -eq 1 && "$https_ok" -eq 1 ]]; then
		echo "HTTPS (по DNS resolver): ✓ достаточно проверки с корректным IP (Telegram резолвит так же)"
	elif [[ "${resolved:-}" == "$BRIDGE" ]]; then
		if code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 "$url" 2>/dev/null); then
			echo "HTTPS (по DNS resolver): ✓ HTTP $code"
		else
			echo "HTTPS (по DNS resolver): ? timeout (локальный resolver; при OK выше Mini App должен работать)"
		fi
	fi
fi

if [[ "$fail" -ne 0 ]]; then
	echo
	echo "verify-miniapp: FAILED — исправьте DNS (A → bridge) и/или откройте ${BOT_PORT}/tcp на bridge."
	exit 1
fi
echo "=== verify-miniapp: OK ==="
