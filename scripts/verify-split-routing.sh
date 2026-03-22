#!/usr/bin/env bash
# verify-split-routing.sh — проверка split-routing на мосту через локальный SOCKS5 клиента Xray.
# Клиент может быть на любой ОС; ultra-relay в проде — на Linux. Трафик: клиент → мост (РФ) →
# при blocklist direct или to-exit; удалённый сервис видит либо IP моста, либо IP exit.
#
# Требует: curl с поддержкой --socks5-hostname.
#
# Переменные:
#   ULTRA_SOCKS5            host:port SOCKS (по умолчанию 127.0.0.1:10808)
#   SPLIT_PROBE_DIRECT_URL  HTTPS; ответ должен содержать видимый IPv4; SNI/CONNECT-хост
#                           обычно НЕ в ru-blocked (уходит в direct на мосту).
#   SPLIT_PROBE_EXIT_URL    HTTPS; CONNECT-хост обычно в ru-blocked (уходит на exit).
#   SPLIT_STRICT=1          завершить с ошибкой, если оба IP совпали.
#   SPLIT_EXPECT_DIRECT_IP  если задано — IP с DIRECT_URL должен совпасть.
#   SPLIT_EXPECT_EXIT_IP    если задано — IP с EXIT_URL должен совпасть.
#
# Подбор URL зависит от актуальных списков runetfreedom; при ложных срабатываниях смените зонды.
#
set -euo pipefail

SOCKS="${ULTRA_SOCKS5:-127.0.0.1:10808}"
DIRECT_URL="${SPLIT_PROBE_DIRECT_URL:-https://ifconfig.me/ip}"
EXIT_URL="${SPLIT_PROBE_EXIT_URL:-https://icanhazip.com}"

extract_ipv4() {
	grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1
}

ip_for_url() {
	local url="$1"
	curl -fsS --max-time 35 --socks5-hostname "$SOCKS" "$url" | tr -d '\r\n\t ' | extract_ipv4
}

if ! command -v curl >/dev/null 2>&1; then
	echo "split-check: нужен curl" >&2
	exit 2
fi

set +e
IP_D="$(ip_for_url "$DIRECT_URL")"
IP_X="$(ip_for_url "$EXIT_URL")"
set -e

if [[ -z "$IP_D" || -z "$IP_X" ]]; then
	echo "split-check: не удалось извлечь IPv4 (direct=${IP_D:-empty} exit=${IP_X:-empty})" >&2
	echo "split-check: проверьте SOCKS (${SOCKS}), URL и что клиент Xray запущен." >&2
	exit 1
fi

echo "split-check: IP для CONNECT likely-direct ($DIRECT_URL) → $IP_D"
echo "split-check: IP для CONNECT likely-exit   ($EXIT_URL) → $IP_X"

if [[ -n "${SPLIT_EXPECT_DIRECT_IP:-}" && "$IP_D" != "$SPLIT_EXPECT_DIRECT_IP" ]]; then
	echo "split-check: ожидали direct IP ${SPLIT_EXPECT_DIRECT_IP}, получили $IP_D" >&2
	exit 1
fi
if [[ -n "${SPLIT_EXPECT_EXIT_IP:-}" && "$IP_X" != "$SPLIT_EXPECT_EXIT_IP" ]]; then
	echo "split-check: ожидали exit IP ${SPLIT_EXPECT_EXIT_IP}, получили $IP_X" >&2
	exit 1
fi

if [[ "$IP_D" == "$IP_X" ]]; then
	echo "split-check: предупреждение: оба зонда дали один IP — маршрутизация может не различаться или зонды неверны." >&2
	if [[ "${SPLIT_STRICT:-0}" == "1" ]]; then
		exit 1
	fi
fi

echo "split-check: OK"
exit 0
