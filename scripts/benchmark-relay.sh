#!/usr/bin/env bash
# Read-only speed diagnostics for bridge→exit:
# - local client → bridge → exit → WARP download/upload via exported Xray config
# - Admin API /v1/health latency snapshot
# - bridge → each exit TCP connect timing
# - each exit direct vs WARP download timing
#
# Does not install packages or change relay configuration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-config.sh
source "$SCRIPT_DIR/install-config.sh"

SOCKS_PORT="${BENCH_SOCKS_PORT:-10808}"
DOWNLOAD_URL="${BENCH_DOWNLOAD_URL:-https://speed.cloudflare.com/__down?bytes=25000000}"
DOWNLOAD_URLS="${BENCH_DOWNLOAD_URLS:-$DOWNLOAD_URL}"
UPLOAD_URL="${BENCH_UPLOAD_URL:-https://speed.cloudflare.com/__up}"
UPLOAD_BYTES="${BENCH_UPLOAD_BYTES:-5000000}"
IP_URL="${BENCH_IP_URL:-https://api.ipify.org}"
REMOTE_SPEC="${BENCH_SPEC_PATH:-/etc/ultra-relay/spec.json}"
WARP_PORT="${WARP_PORT:-40000}"
WARN_WARP_MBPS="${BENCH_WARN_WARP_MBPS:-25}"

usage() {
	echo "Использование:" >&2
	echo "  $0 [-c install.config] [-i identity] [-u ssh_user] [-p socks_port]" >&2
	echo "Переменные:" >&2
	echo "  BENCH_DOWNLOAD_URL     HTTPS URL для download (default speed.cloudflare.com 25MB)" >&2
	echo "  BENCH_DOWNLOAD_URLS    comma-separated HTTPS URLs для нескольких download-зондов" >&2
	echo "  BENCH_UPLOAD_URL       HTTPS URL для upload POST (default speed.cloudflare.com/__up)" >&2
	echo "  BENCH_UPLOAD_BYTES     upload payload bytes (default 5000000)" >&2
	echo "  BENCH_IP_URL           URL, возвращающий внешний IP (default https://api.ipify.org)" >&2
	echo "  BENCH_USER_UUID        UUID пользователя; иначе первый из /v1/users" >&2
	echo "  BENCH_SOCKS_PORT       локальный SOCKS порт (default 10808)" >&2
	exit 2
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

json_users_first_uuid() {
	if have_cmd jq; then
		jq -r '.[0].uuid // empty' "$1"
	else
		python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d[0].get("uuid", "") if isinstance(d, list) and d else "")
PY
	fi
}

json_client_b64() {
	if have_cmd jq; then
		jq -r '.full_xray_config_base64 // empty' "$1"
	else
		python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("full_xray_config_base64", "") if isinstance(d, dict) else "")
PY
	fi
}

patch_socks_port() {
	local f=$1
	local p=$2
	if have_cmd jq; then
		jq --argjson port "$p" '(.inbounds |= map(if (.protocol == "socks") then .port = $port else . end))' "$f" >"${f}.tmp"
		mv "${f}.tmp" "$f"
	else
		python3 - "$f" "$p" <<'PY'
import json, sys
path, port = sys.argv[1], int(sys.argv[2])
cfg = json.load(open(path))
for ib in cfg.get("inbounds", []):
    if ib.get("protocol") == "socks":
        ib["port"] = port
json.dump(cfg, open(path, "w"), indent=2)
PY
	fi
}

port_open() {
	local host=$1
	local port=$2
	if have_cmd nc; then
		nc -z "$host" "$port" 2>/dev/null
		return $?
	fi
	if echo 2>/dev/null >/dev/tcp/"$host"/"$port"; then
		return 0
	fi
	return 1
}

mbps_from_curl() {
	awk -v bps="${1:-0}" 'BEGIN { printf "%.2f", (bps * 8) / 1000000 }'
}

split_csv() {
	local s=$1
	local old_ifs=$IFS
	IFS=,
	read -r -a _split_csv_out <<<"$s"
	IFS=$old_ifs
}

curl_download_line() {
	local label=$1
	shift
	local url=$1
	shift
	local line
	line=$(curl "$@" -o /dev/null -sS -w 'time_total=%{time_total} speed_download=%{speed_download} remote_ip=%{remote_ip}' --max-time 60 "$url" || true)
	local bps
	bps=$(printf '%s\n' "$line" | sed -n 's/.*speed_download=\([0-9.]*\).*/\1/p')
	echo "${label}: ${line} mbps=$(mbps_from_curl "${bps:-0}") url=${url}"
}

CONFIG_FILE=""
SSH_EXTRA=()
SSH_USER=root

while getopts "c:i:u:p:h" opt; do
	case "$opt" in
	c) CONFIG_FILE=$OPTARG ;;
	i) SSH_EXTRA=(-i "$OPTARG") ;;
	u) SSH_USER="$OPTARG" ;;
	p) SOCKS_PORT="$OPTARG" ;;
	h) usage ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

if [[ -n "$CONFIG_FILE" ]]; then
	if [[ ! -f "$CONFIG_FILE" ]]; then
		echo "benchmark-relay: config not found: $CONFIG_FILE" >&2
		exit 1
	fi
	load_install_config "$CONFIG_FILE"
else
	def="$(install_config_default_path)"
	if [[ -f "$def" ]]; then
		load_install_config "$def"
	fi
fi

BRIDGE="${BRIDGE:-${FRONT:-}}"
EXIT="${EXIT:-${BACK:-}}"
if [[ -z "${BRIDGE// }" || -z "${EXIT// }" ]]; then
	echo "benchmark-relay: BRIDGE and EXIT are required (install.config or env)." >&2
	exit 1
fi

if [[ -n "${IDENTITY:-}" && ${#SSH_EXTRA[@]} -eq 0 ]]; then
	id="$IDENTITY"
	if [[ "$id" == ~/* ]]; then
		id="$HOME/${id#~/}"
	fi
	SSH_EXTRA=(-i "$id")
fi

for x in ssh curl xray; do
	if ! have_cmd "$x"; then
		echo "benchmark-relay: required command missing: $x" >&2
		exit 1
	fi
done
if ! have_cmd jq && ! have_cmd python3; then
	echo "benchmark-relay: jq or python3 is required for JSON parsing." >&2
	exit 1
fi

# shellcheck disable=SC2206
ssh_base=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${SSH_EXTRA[@]}" "${SSH_USER}@${BRIDGE}")

remote_curl_api() {
	local api_path=$1
	"${ssh_base[@]}" bash -s "$api_path" <<'EOS'
set -euo pipefail
path=${1:?}
ENV=/etc/ultra-relay/environment
tok=$(sed -n 's/^ULTRA_RELAY_ADMIN_TOKEN=//p' "$ENV" | head -1)
test -n "$tok"
exec curl -sS -g -H "Authorization: Bearer ${tok}" "http://127.0.0.1:8443${path}"
EOS
}

TMPDIR_BENCH=""
XRAY_PID=""
cleanup() {
	if [[ -n "${XRAY_PID:-}" ]] && kill -0 "$XRAY_PID" 2>/dev/null; then
		kill "$XRAY_PID" 2>/dev/null || true
		wait "$XRAY_PID" 2>/dev/null || true
	fi
	if [[ -n "${TMPDIR_BENCH:-}" && -d "$TMPDIR_BENCH" ]]; then
		rm -rf "$TMPDIR_BENCH"
	fi
}
trap cleanup EXIT INT TERM

echo "=== benchmark-relay: bridge=${BRIDGE}, exits=${EXIT}${EXIT2:+,$EXIT2} ==="

TMPDIR_BENCH=$(mktemp -d)
USERS_JSON="${TMPDIR_BENCH}/users.json"
CLIENT_JSON="${TMPDIR_BENCH}/client.json.raw"
CFG="${TMPDIR_BENCH}/client.json"
PAYLOAD="${TMPDIR_BENCH}/upload.bin"
SCORES="${TMPDIR_BENCH}/scores.tsv"

echo "--- bridge health ---"
if remote_curl_api "/v1/health" >"${TMPDIR_BENCH}/health.json"; then
	if have_cmd jq; then
		jq '{active_exit_id, bridge, exit, exits}' "${TMPDIR_BENCH}/health.json"
	else
		cat "${TMPDIR_BENCH}/health.json"
		echo
	fi
else
	echo "health: failed" >&2
fi

echo "--- bridge spec transport ---"
if "${ssh_base[@]}" "test -r $(printf '%q' "$REMOTE_SPEC") && jq -r '{tunnel_transport,vless_port,splithttp_host,splithttp_path,routing_mode,anti_censor}' $(printf '%q' "$REMOTE_SPEC")" 2>/dev/null; then
	:
else
	echo "bridge spec: unavailable or jq missing remotely"
fi

echo "--- local client via bridge→exit→WARP ---"
remote_curl_api "/v1/users" >"$USERS_JSON"
UUID="${BENCH_USER_UUID:-}"
if [[ -z "$UUID" ]]; then
	UUID="$(json_users_first_uuid "$USERS_JSON")"
fi
if [[ -z "$UUID" ]]; then
	echo "benchmark-relay: no user UUID found; create a user or set BENCH_USER_UUID." >&2
	exit 1
fi
echo "user_uuid=${UUID}"

remote_curl_api "/v1/users/${UUID}/client" >"$CLIENT_JSON"
B64="$(json_client_b64 "$CLIENT_JSON")"
if [[ -z "$B64" ]]; then
	echo "benchmark-relay: full_xray_config_base64 missing in client export." >&2
	exit 1
fi
if ! printf '%s' "$B64" | base64 -d >"$CFG" 2>/dev/null; then
	if ! printf '%s' "$B64" | base64 --decode >"$CFG" 2>/dev/null; then
		printf '%s' "$B64" | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.standard_b64decode(sys.stdin.buffer.read()))' >"$CFG"
	fi
fi
chmod 600 "$CFG"
if [[ "$SOCKS_PORT" != "10808" ]]; then
	patch_socks_port "$CFG" "$SOCKS_PORT"
fi
if port_open 127.0.0.1 "$SOCKS_PORT"; then
	echo "benchmark-relay: local port ${SOCKS_PORT} is already in use." >&2
	exit 1
fi
xray run -c "$CFG" >/dev/null 2>"${TMPDIR_BENCH}/xray.log" &
XRAY_PID=$!
ready=0
for _ in $(seq 1 50); do
	if port_open 127.0.0.1 "$SOCKS_PORT"; then
		ready=1
		break
	fi
	if ! kill -0 "$XRAY_PID" 2>/dev/null; then
		echo "benchmark-relay: local xray exited early:" >&2
		tail -50 "${TMPDIR_BENCH}/xray.log" >&2 || true
		exit 1
	fi
	sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
	echo "benchmark-relay: timeout waiting for local SOCKS on ${SOCKS_PORT}." >&2
	exit 1
fi

echo "--- local route identity ---"
system_ip="$(curl -fsS --max-time 20 "$IP_URL" 2>/dev/null | tr -d '\r\n\t ' | head -c 128 || true)"
socks_ip="$(curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -fsS --max-time 30 "$IP_URL" 2>/dev/null | tr -d '\r\n\t ' | head -c 128 || true)"
echo "local_system_ip=${system_ip:-unavailable} url=${IP_URL}"
echo "local_socks_xray_ip=${socks_ip:-unavailable} url=${IP_URL}"
if [[ -n "${system_ip:-}" && -n "${socks_ip:-}" && "$system_ip" == "$socks_ip" ]]; then
	echo "note: local system path and exported Xray SOCKS show the same IP; system VPN may already be active."
fi

echo "--- local download matrix ---"
split_csv "$DOWNLOAD_URLS"
for raw_url in "${_split_csv_out[@]}"; do
	url="$(printf '%s' "$raw_url" | xargs)"
	[[ -z "$url" ]] && continue
	curl_download_line "local_system_download" "$url"
	curl_download_line "local_socks_xray_download" "$url" --socks5-hostname "127.0.0.1:${SOCKS_PORT}"
done

dd if=/dev/zero of="$PAYLOAD" bs="$UPLOAD_BYTES" count=1 >/dev/null 2>&1
up_line=$(curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -o /dev/null -sS -X POST --data-binary @"$PAYLOAD" -w 'time_total=%{time_total} speed_upload=%{speed_upload} remote_ip=%{remote_ip}' --max-time 60 "$UPLOAD_URL" || true)
up_bps=$(printf '%s\n' "$up_line" | sed -n 's/.*speed_upload=\([0-9.]*\).*/\1/p')
echo "local_socks_xray_upload: ${up_line} mbps=$(mbps_from_curl "${up_bps:-0}") bytes=${UPLOAD_BYTES} url=${UPLOAD_URL}"

remote_exit_bench() {
	local host=$1
	local label=$2
	echo "--- exit ${label} (${host}) direct-vs-WARP ---"
	ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${SSH_EXTRA[@]}" "${SSH_USER}@${host}" bash -s "$DOWNLOAD_URL" "$WARP_PORT" <<'EOS'
set -euo pipefail
url=${1:?}
warp_port=${2:?}
printf 'service='
systemctl is-active ultra-relay 2>/dev/null || true
printf 'iperf3='
if command -v iperf3 >/dev/null 2>&1; then echo available; else echo missing; fi
printf 'warp_status='
if command -v warp-cli >/dev/null 2>&1; then
	warp_status=$(warp-cli --accept-tos status 2>&1 || true)
	printf '%s' "${warp_status:-empty}" | tr '\n' ';'
else
	printf 'warp-cli-missing'
fi
echo
measure() {
	local name=$1
	shift
	local line
	line=$(curl "$@" -o /dev/null -sS -w 'time_total=%{time_total} speed_download=%{speed_download} remote_ip=%{remote_ip}' --max-time 45 "$url" || true)
	local bps
	bps=$(printf '%s\n' "$line" | sed -n 's/.*speed_download=\([0-9.]*\).*/\1/p')
	local total
	total=$(printf '%s\n' "$line" | sed -n 's/.*time_total=\([0-9.]*\).*/\1/p')
	local mbps
	mbps=$(awk -v bps="${bps:-0}" 'BEGIN { printf "%.2f", (bps * 8) / 1000000 }')
	echo "${name}: ${line} mbps=${mbps}"
	if [[ "$name" == "warp" ]]; then
		printf 'SCORE_DOWNLOAD_BPS=%s\n' "${bps:-0}"
		printf 'SCORE_WARP_TIME=%s\n' "${total:-0}"
	fi
}
measure direct
measure warp -x "socks5h://127.0.0.1:${warp_port}"
EOS
}

bridge_tcp_probe() {
	local host=$1
	local port=$2
	local label=$3
	echo "--- bridge→${label} TCP (${host}:${port}) ---"
	"${ssh_base[@]}" bash -s "$host" "$port" <<'EOS'
set -euo pipefail
host=${1:?}
port=${2:?}
if command -v python3 >/dev/null 2>&1; then
	python3 - "$host" "$port" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
t0 = time.time()
try:
    s = socket.create_connection((host, port), timeout=5)
    s.close()
    ms = (time.time() - t0) * 1000
    print("tcp_connect_ms=%.1f" % ms)
    print("SCORE_TCP_MS=%.1f" % ms)
except Exception as e:
    print("tcp_connect_error=%s" % e)
PY
elif command -v nc >/dev/null 2>&1; then
	if nc -z -w 5 "$host" "$port" >/dev/null 2>&1; then echo "tcp_connect=ok"; else echo "tcp_connect=failed"; fi
else
	echo "tcp_connect=skipped_no_python3_or_nc"
fi
EOS
}

bridge_direct_bench() {
	local url=$1
	echo "--- bridge direct download ---"
	"${ssh_base[@]}" bash -s "$url" <<'EOS'
set -euo pipefail
url=${1:?}
line=$(curl -o /dev/null -sS -w 'time_total=%{time_total} speed_download=%{speed_download} remote_ip=%{remote_ip}' --max-time 45 "$url" || true)
bps=$(printf '%s\n' "$line" | sed -n 's/.*speed_download=\([0-9.]*\).*/\1/p')
mbps=$(awk -v bps="${bps:-0}" 'BEGIN { printf "%.2f", (bps * 8) / 1000000 }')
echo "bridge_direct: ${line} mbps=${mbps} url=${url}"
EOS
}

score_exit() {
	local host=$1
	local label=$2
	local tcp_ms=$3
	local out
	out="$(remote_exit_bench "$host" "$label")"
	printf '%s\n' "$out" | grep -v '^SCORE_' || true
	local score
	score="$(printf '%s\n' "$out" | sed -n 's/^SCORE_DOWNLOAD_BPS=//p' | tail -1)"
	local warp_time
	warp_time="$(printf '%s\n' "$out" | sed -n 's/^SCORE_WARP_TIME=//p' | tail -1)"
	printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$host" "${score:-0}" "${tcp_ms:-0}" "${warp_time:-0}" >>"$SCORES"
}

TUNNEL_PORT_REMOTE="${TUNNEL_PORT:-51001}"
bridge_direct_bench "$DOWNLOAD_URL"
primary_tcp_out="$(bridge_tcp_probe "${EXIT_DIAL:-$EXIT}" "$TUNNEL_PORT_REMOTE" "primary")"
printf '%s\n' "$primary_tcp_out" | grep -v '^SCORE_' || true
primary_tcp_ms="$(printf '%s\n' "$primary_tcp_out" | sed -n 's/^SCORE_TCP_MS=//p' | tail -1)"
score_exit "$EXIT" "primary" "$primary_tcp_ms"

if [[ -n "${EXIT2:-}" ]]; then
	backup_tcp_out="$(bridge_tcp_probe "${EXIT2_DIAL:-$EXIT2}" "$TUNNEL_PORT_REMOTE" "backup")"
	printf '%s\n' "$backup_tcp_out" | grep -v '^SCORE_' || true
	backup_tcp_ms="$(printf '%s\n' "$backup_tcp_out" | sed -n 's/^SCORE_TCP_MS=//p' | tail -1)"
	score_exit "$EXIT2" "backup" "$backup_tcp_ms"
fi

echo "--- diagnostic recommendation ---"
if [[ -s "$SCORES" ]]; then
	awk -F '\t' -v warn_warp_mbps="$WARN_WARP_MBPS" '
		{
			mbps=($3*8)/1000000
			tcp_ms=$4+0
			warp_ms=($5+0)*1000
			latency_penalty=1 + ((tcp_ms + warp_ms) / 100)
			diag_score=mbps / latency_penalty
			printf "%s (%s): warp_download_mbps=%.2f tunnel_tcp_ms=%.1f warp_time_ms=%.1f diagnostic_score=%.2f\n", $1, $2, mbps, tcp_ms, warp_ms, diag_score
			if (mbps > 0 && mbps < warn_warp_mbps) {
				printf "WARNING: %s WARP throughput below %.2f Mbps; keep it out of active failover until fixed.\n", $1, warn_warp_mbps
			}
		}
		diag_score > best { best=diag_score; best_label=$1; best_host=$2; best_mbps=mbps }
		END {
			if (best_label != "") {
				printf "recommended_exit_by_score=%s (%s), warp_download_mbps=%.2f, score=%.2f\n", best_label, best_host, best_mbps, best
			}
		}
	' "$SCORES"
else
	echo "no remote WARP scores collected"
fi

echo "=== benchmark-relay: done ==="
