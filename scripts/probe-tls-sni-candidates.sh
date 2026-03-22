#!/usr/bin/env bash
# Quick TLS probe: TLS 1.3 and server certificate with DNS SAN. Use to short-list public handshake targets.
# Does not replace end-to-end checks — after choosing a host use make verify-relay and VERIFY_IP_URL.
#
# Prefer running from the same egress as the front node (e.g. SSH to that host) so paths and IPs match production.
#
# Requires: openssl, head; time limit: timeout(1) on Linux or gtimeout (brew install coreutils on macOS).
set -euo pipefail

usage() {
	echo "Usage:" >&2
	echo "  $0 [-p PORT] HOST [HOST ...]" >&2
	echo "  $0 [-p PORT] -           # one host per line on stdin" >&2
	echo "Default PORT=443. Example: $0 host1.example.org host2.example.org" >&2
	exit 2
}

PORT=443
HOSTS=()

while [ $# -gt 0 ]; do
	case "$1" in
	-p)
		PORT="${2:?}"
		shift 2
		;;
	-h | --help)
		usage
		;;
	--)
		shift
		HOSTS+=("$@")
		break
		;;
	-)
		shift
		while IFS= read -r line || [ -n "$line" ]; do
			line="${line%%#*}"
			line="${line#"${line%%[![:space:]]*}"}"
			line="${line%"${line##*[![:space:]]}"}"
			[ -n "$line" ] && HOSTS+=("$line")
		done
		break
		;;
	-*)
		echo "Unknown flag: $1" >&2
		usage
		;;
	*)
		HOSTS+=("$1")
		shift
		;;
	esac
done

if [ ${#HOSTS[@]} -eq 0 ]; then
	usage
fi

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

run_s_client() {
	local host="$1"
	local port="$2"
	local sec=15
	local to_cmd=""
	if have_cmd timeout; then
		to_cmd=timeout
	elif have_cmd gtimeout; then
		to_cmd=gtimeout
	fi
	if [ -z "$to_cmd" ]; then
		echo "Need timeout(1) (Linux) or gtimeout (brew install coreutils). Prefer running from the front node." >&2
		return 1
	fi
	"$to_cmd" "$sec" sh -c 'echo | openssl s_client -connect "$1" -servername "$2" 2>&1 | head -n 500' _ "${host}:${port}" "$host"
	return 0
}

first_server_pem() {
	awk '/-----BEGIN CERTIFICATE-----/{t=1} t{print} /-----END CERTIFICATE-----/{if(t) exit}'
}

probe_one() {
	local host="$1"
	local port="$2"
	local raw pem ext san_text tls13=0 has_san=0 reason=""

	if [[ ! "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]]; then
		echo "${host}:${port}  FAIL  invalid hostname (allowed: letters, digits, . -)"
		return 0
	fi
	if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
		echo "${host}:${port}  FAIL  invalid port"
		return 0
	fi

	if ! raw="$(run_s_client "$host" "$port")"; then
		echo "${host}:${port}  FAIL  openssl probe failed (no timeout/gtimeout?)"
		return 0
	fi

	if echo "$raw" | grep -qiE 'handshake failure|alert (handshake|protocol|internal|decode)|connect:errno=|Connection refused|Name or service not known|No route to host|getaddrinfo|Could not connect'; then
		echo "${host}:${port}  FAIL  handshake or network error in output"
		return 0
	fi

	if echo "$raw" | grep -qE 'TLSv1\.3|Protocol[[:space:]]*:[[:space:]]*TLSv1\.3|New,[[:space:]]*TLSv1\.3'; then
		tls13=1
	else
		reason="no TLS 1.3 in handshake summary"
	fi

	pem="$(echo "$raw" | first_server_pem)"
	if [ -z "$pem" ]; then
		echo "${host}:${port}  FAIL  no certificate PEM in handshake output"
		return 0
	fi

	ext="$(echo "$pem" | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)"
	if echo "$ext" | grep -q "DNS:"; then
		has_san=1
	else
		san_text="$(echo "$pem" | openssl x509 -noout -text 2>/dev/null || true)"
		if echo "$san_text" | grep -q "DNS:"; then
			has_san=1
		else
			[ -z "$reason" ] && reason="no SAN (DNS) in certificate" || reason="${reason}; no SAN (DNS) in certificate"
		fi
	fi

	if [ "$tls13" -eq 1 ] && [ "$has_san" -eq 1 ]; then
		echo "${host}:${port}  PASS  TLS 1.3, SAN present"
	else
		[ -z "$reason" ] && reason="TLS 1.3 or SAN check failed"
		echo "${host}:${port}  FAIL  ${reason}"
	fi
	return 0
}

for h in "${HOSTS[@]}"; do
	probe_one "$h" "$PORT"
done
