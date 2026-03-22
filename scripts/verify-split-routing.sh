#!/usr/bin/env bash
# verify-split-routing.sh — проверка split-routing на мосту через локальный SOCKS5 клиента Xray.
# Клиент может быть на любой ОС; ultra-relay в проде — на Linux. Трафик: клиент → мост (РФ) →
# при blocklist direct или to-exit; удалённый сервис видит либо IP моста, либо IP exit.
#
# Требует: curl с поддержкой --socks5-hostname.
#
# Переменные:
#   ULTRA_SOCKS5            host:port SOCKS (по умолчанию 127.0.0.1:10808)
#   SPLIT_PROBE_DIRECT_URL  HTTPS; ответ — видимый IPv4; CONNECT обычно НЕ в ru-blocked-all (direct).
#   SPLIT_PROBE_EXIT_URL    HTTPS; CONNECT в ru-blocked-all (через exit). Пусто — встроенный перебор
#                           (cdn-cgi/trace на доменах Meta/X и т.п.).
#   SPLIT_STRICT=1          завершить с ошибкой, если оба IP совпали (relay-check задаёт по умолчанию).
#   SPLIT_EXPECT_DIRECT_IP  если задано — IP с DIRECT_URL должен совпасть.
#   SPLIT_EXPECT_EXIT_IP    если задано — IP с EXIT_URL должен совпасть.
# Из install.config verify-relay прокидывает VERIFY_PROBE_* в SPLIT_PROBE_*.
#
# Подбор URL зависит от актуальных списков runetfreedom; при ложных срабатываниях задайте SPLIT_PROBE_EXIT_URL.
#
set -euo pipefail

SOCKS="${ULTRA_SOCKS5:-127.0.0.1:10808}"
# ipify часто остаётся в direct на bridge с ru-blocked-all (сервис не в блоклисте).
DIRECT_URL="${SPLIT_PROBE_DIRECT_URL:-https://api.ipify.org}"
USER_EXIT_URL="${SPLIT_PROBE_EXIT_URL:-}"

# Запасные зонды: SNI обычно в geosite:ru-blocked-all; тело — Cloudflare trace (строка ip=…).
DEFAULT_EXIT_TRACE_URLS=(
	"https://www.facebook.com/cdn-cgi/trace"
	"https://www.instagram.com/cdn-cgi/trace"
	"https://www.threads.net/cdn-cgi/trace"
	"https://x.com/cdn-cgi/trace"
)

CURL_BASE=(curl -fsS --max-time 35 --socks5-hostname "$SOCKS" -A "Mozilla/5.0 (compatible; ultra-relay-verify/1.0)")

extract_ipv4() {
	grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1
}

# Ответ вида Cloudflare cdn-cgi/trace: строка ip=1.2.3.4 или ip=2a00:…
trace_ipv4_from_body() {
	grep -E '^ip=' | head -1 | sed 's/^ip=//' | tr -d '\r' | extract_ipv4
}

ip_direct_plain() {
	"${CURL_BASE[@]}" "$1" | tr -d '\r\n\t ' | extract_ipv4
}

ip_exit_trace() {
	"${CURL_BASE[@]}" "$1" | trace_ipv4_from_body
}

# Пользовательский EXIT URL: trace по пути или «голый» IPv4 в теле.
ip_exit_user() {
	local url=$1
	case "$url" in
	*cdn-cgi/trace*) ip_exit_trace "$url" ;;
	*) "${CURL_BASE[@]}" "$url" | tr -d '\r\n\t ' | extract_ipv4 ;;
	esac
}

if ! command -v curl >/dev/null 2>&1; then
	echo "split-check: нужен curl" >&2
	exit 2
fi

set +e
IP_D="$(ip_direct_plain "$DIRECT_URL")"
set -e

if [[ -z "$IP_D" ]]; then
	echo "split-check: не удалось IPv4 для direct-зонда ($DIRECT_URL)" >&2
	echo "split-check: проверьте SOCKS (${SOCKS}) и SPLIT_PROBE_DIRECT_URL." >&2
	exit 1
fi

IP_X=""
EXIT_URL=""
if [[ -n "$USER_EXIT_URL" ]]; then
	EXIT_URL="$USER_EXIT_URL"
	set +e
	IP_X="$(ip_exit_user "$EXIT_URL")"
	set -e
else
	for u in "${DEFAULT_EXIT_TRACE_URLS[@]}"; do
		set +e
		cand="$(ip_exit_trace "$u")"
		set -e
		if [[ -n "$cand" && "$cand" != "$IP_D" ]]; then
			IP_X="$cand"
			EXIT_URL="$u"
			break
		fi
		if [[ -n "$cand" ]]; then
			IP_X="$cand"
			EXIT_URL="$u"
		fi
	done
fi

if [[ -z "$IP_X" ]]; then
	echo "split-check: не удалось IPv4 для exit-зонда (direct=${IP_D})" >&2
	if [[ -n "$USER_EXIT_URL" ]]; then
		echo "split-check: проверьте SPLIT_PROBE_EXIT_URL (или cdn-cgi/trace на домене из ru-blocked-all)." >&2
	else
		echo "split-check: ни один встроенный trace-URL не сработал; задайте SPLIT_PROBE_EXIT_URL вручную." >&2
	fi
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
	echo "split-check: оба зонда дали один IP ($IP_D) — CONNECT для exit-зонда, скорее всего, всё ещё в direct; смените SPLIT_PROBE_EXIT_URL (домен из ru-blocked-all, ответ с IPv4 или cdn-cgi/trace)." >&2
	if [[ "${SPLIT_STRICT:-0}" == "1" ]]; then
		exit 1
	fi
fi

echo "split-check: OK"
exit 0
