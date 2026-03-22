#!/usr/bin/env bash
# verify-split-routing.sh — дополнительная проверка после установки: один HTTPS-зонд на маршрут exit
# (клиент → bridge → exit → интернет). IP bridge/direct не проверяем.
#
# Требует: curl с --socks5-hostname.
#
# Переменные:
#   ULTRA_SOCKS5            host:port SOCKS (по умолчанию 127.0.0.1:10808)
#   ULTRA_ROUTING_MODE      blocklist | ru_direct (verify-relay выставляет из spec.json на bridge)
#   SPLIT_PROBE_EXIT_URL    HTTPS; явный зонд exit (если задан — только он, без запасных trace)
#   SPLIT_PROBE_EXIT_PLAIN_URL  при ru_direct без EXIT_URL: по умолчанию https://api.ipify.org
#   SPLIT_EXPECT_EXIT_IP    ожидаемый IPv4 для exit-зонда (опционально)
# Из install.config verify-relay прокидывает VERIFY_PROBE_* в SPLIT_PROBE_*.
#
set -euo pipefail

SOCKS="${ULTRA_SOCKS5:-127.0.0.1:10808}"
ULTRA_RM="${ULTRA_ROUTING_MODE:-blocklist}"
USER_EXIT_URL="${SPLIT_PROBE_EXIT_URL:-}"
EXIT_PLAIN_DEFAULT="${SPLIT_PROBE_EXIT_PLAIN_URL:-https://api.ipify.org}"

DEFAULT_EXIT_TRACE_URLS=(
	"https://www.facebook.com/cdn-cgi/trace"
	"https://www.instagram.com/cdn-cgi/trace"
	"https://www.threads.net/cdn-cgi/trace"
	"https://x.com/cdn-cgi/trace"
)

UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
CURL_BASE=(curl -fsS --compressed --max-time 35 --socks5-hostname "$SOCKS" -A "$UA")

extract_ipv4() {
	grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1
}

trace_ipv4_from_body() {
	grep -E '^ip=' | head -1 | sed 's/^ip=//' | tr -d '\r' | extract_ipv4
}

ip_exit_trace() {
	"${CURL_BASE[@]}" "$1" | trace_ipv4_from_body
}

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

IP_X=""
EXIT_URL=""

if [[ -n "$USER_EXIT_URL" ]]; then
	EXIT_URL="$USER_EXIT_URL"
	set +e
	IP_X="$(ip_exit_user "$USER_EXIT_URL")"
	set -e
elif [[ "$ULTRA_RM" == "ru_direct" ]]; then
	EXIT_URL="$EXIT_PLAIN_DEFAULT"
	set +e
	IP_X="$(ip_exit_user "$EXIT_PLAIN_DEFAULT")"
	set -e
fi

if [[ -z "$IP_X" ]] && [[ -z "$USER_EXIT_URL" ]]; then
	for u in "${DEFAULT_EXIT_TRACE_URLS[@]}"; do
		set +e
		cand="$(ip_exit_trace "$u")"
		set -e
		if [[ -n "$cand" ]]; then
			IP_X="$cand"
			EXIT_URL="$u"
			break
		fi
	done
fi

if [[ -z "$IP_X" ]]; then
	echo "split-check: не удалось IPv4 для exit-зонды" >&2
	if [[ -n "$USER_EXIT_URL" ]]; then
		echo "split-check: проверьте SPLIT_PROBE_EXIT_URL и SOCKS (${SOCKS})." >&2
	else
		echo "split-check: задайте SPLIT_PROBE_EXIT_URL или SPLIT_PROBE_EXIT_PLAIN_URL; либо проверьте доступ к встроенным trace-URL." >&2
	fi
	exit 1
fi

echo "split-check: IP для exit-зонды ($EXIT_URL) → $IP_X"

if [[ -n "${SPLIT_EXPECT_EXIT_IP:-}" && "$IP_X" != "$SPLIT_EXPECT_EXIT_IP" ]]; then
	echo "split-check: ожидали exit IP ${SPLIT_EXPECT_EXIT_IP}, получили $IP_X" >&2
	exit 1
fi

echo "split-check: OK"
exit 0
