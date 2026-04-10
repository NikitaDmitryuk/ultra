#!/usr/bin/env bash
# Latency profiling for the ultra relay pipeline.
#
# Measures each hop independently and prints a formatted breakdown:
#   1. bridge → exit raw TCP RTT   (via Admin API /v1/latency/probe)
#   2. exit  → WARP → Cloudflare  (via SSH to exit node)
#   3. per-connection stage timing  (via Admin API /v1/latency/sessions)
#   4. full SOCKS5 end-to-end TTFB (via local xray client)
#
# Usage:
#   scripts/latency-profile.sh [-c install.config] [-i identity] [-u ssh_user] [-p socks_port] [BRIDGE] [EXIT]
#   make latency-profile
#
# Dependencies: ssh, curl, xray (in PATH), jq or python3.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/install-config.sh"

SOCKS_PORT="${VERIFY_SOCKS_PORT:-10808}"
IDENTITY=""
SSH_USER=""

usage() {
	echo "Usage: $0 [-c install.config] [-i identity] [-u ssh_user] [-p socks_port] [BRIDGE [EXIT]]" >&2
	exit 2
}

# ── Parse arguments ────────────────────────────────────────────────────────────
while getopts ":c:i:u:p:h" opt; do
	case $opt in
		c) load_install_config "$OPTARG" ;;
		i) IDENTITY="$OPTARG" ;;
		u) SSH_USER="$OPTARG" ;;
		p) SOCKS_PORT="$OPTARG" ;;
		h) usage ;;
		*) usage ;;
	esac
done
shift $((OPTIND - 1))

[[ -z "${BRIDGE:-}" ]] && { load_install_config 2>/dev/null || true; }

BRIDGE_HOST="${1:-${BRIDGE:-}}"
EXIT_HOST="${2:-${EXIT:-}}"
SSH_USER="${SSH_USER:-${SSH_USER:-root}}"
IDENTITY="${IDENTITY:-${IDENTITY:-}}"

if [[ -z "$BRIDGE_HOST" ]]; then
	echo "latency-profile: BRIDGE host required (set in install.config or pass as arg)" >&2
	exit 1
fi

# ── SSH helper ────────────────────────────────────────────────────────────────
ssh_cmd() {
	local host=$1; shift
	local id_args=()
	[[ -n "$IDENTITY" ]] && id_args=(-i "$IDENTITY")
	ssh "${id_args[@]}" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
		"${SSH_USER}@${host}" "$@"
}

# ── Admin API helper (SSH tunnel) ─────────────────────────────────────────────
TUNNEL_PORT=28443
TUNNEL_PID=""

start_tunnel() {
	local id_args=()
	[[ -n "$IDENTITY" ]] && id_args=(-i "$IDENTITY")
	ssh "${id_args[@]}" -f -N -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
		-L "${TUNNEL_PORT}:127.0.0.1:8443" "${SSH_USER}@${BRIDGE_HOST}" 2>/dev/null &
	TUNNEL_PID=$!
	sleep 1
}

stop_tunnel() {
	[[ -n "$TUNNEL_PID" ]] && kill "$TUNNEL_PID" 2>/dev/null || true
}
trap stop_tunnel EXIT

api_get() {
	local path=$1
	curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
		"http://127.0.0.1:${TUNNEL_PORT}${path}"
}

# ── JSON helpers ──────────────────────────────────────────────────────────────
jq_or_python() {
	local filter=$1 input=$2
	if command -v jq >/dev/null 2>&1; then
		echo "$input" | jq -r "$filter" 2>/dev/null || echo "n/a"
	else
		echo "$input" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # simple key access only
    key = '${filter}'.lstrip('.')
    print(d.get(key, 'n/a'))
except: print('n/a')
" 2>/dev/null || echo "n/a"
	fi
}

sessions_table() {
	local json=$1
	if command -v jq >/dev/null 2>&1; then
		echo "$json" | jq -r '
			.[] |
			"  session \(.session_id)  \(.destination // "?")  [\(.outbound_tag // "?")]" ,
			(.stages_ms | to_entries | sort_by(.value) |
			 .[] | "    +" + (.value|tostring) + "ms  " + .key)
		' 2>/dev/null | head -60
	else
		echo "$json" | python3 -c "
import json, sys
sessions = json.load(sys.stdin)
for s in sessions[:5]:
    print('  session', s.get('session_id'), ' ', s.get('destination','?'), ' [', s.get('outbound_tag','?'), ']', sep='')
    stages = s.get('stages_ms', {})
    for k, v in sorted(stages.items(), key=lambda x: x[1]):
        print('    +{}ms  {}'.format(v, k))
" 2>/dev/null
	fi
}

# ── Get admin token ────────────────────────────────────────────────────────────
ADMIN_TOKEN=$(ssh_cmd "$BRIDGE_HOST" "cat /etc/ultra-relay/environment 2>/dev/null | grep ULTRA_RELAY_ADMIN_TOKEN | cut -d= -f2-" 2>/dev/null || true)
if [[ -z "$ADMIN_TOKEN" ]]; then
	echo "latency-profile: could not read ULTRA_RELAY_ADMIN_TOKEN from bridge — Admin API unavailable" >&2
	ADMIN_TOKEN=""
fi

echo ""
echo "=== LATENCY PROFILE  bridge=${BRIDGE_HOST}  $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
echo ""

# ── 1. bridge → exit TCP RTT ──────────────────────────────────────────────────
echo "[1] bridge → exit TCP RTT"
if [[ -n "$ADMIN_TOKEN" ]]; then
	start_tunnel
	PROBE_JSON=$(api_get "/v1/latency/probe" 2>/dev/null || echo "{}")
	stop_tunnel; TUNNEL_PID=""

	B2E_MS=$(jq_or_python ".bridge_to_exit_tcp_ms" "$PROBE_JSON")
	EXIT_ADDR=$(jq_or_python ".exit_addr" "$PROBE_JSON")
	PROBE_ERR=$(jq_or_python ".error" "$PROBE_JSON")

	if [[ "$PROBE_ERR" != "null" && "$PROBE_ERR" != "n/a" && -n "$PROBE_ERR" ]]; then
		echo "  ERROR: $PROBE_ERR"
	else
		echo "  bridge → exit TCP (${EXIT_ADDR}): ${B2E_MS} ms"
	fi
else
	# Fallback: measure from here via SSH on bridge
	B2E_MS=$(ssh_cmd "$BRIDGE_HOST" "
		EXIT_ADDR=\$(python3 -c \"import json; s=json.load(open('/etc/ultra-relay/spec.json')); print(str(s['exit']['address'])+':'+str(s['exit']['port']))\" 2>/dev/null)
		if [[ -n \"\$EXIT_ADDR\" ]]; then
			t0=\$(date +%s%N 2>/dev/null || echo 0)
			nc -z -w3 \${EXIT_ADDR//:/ } >/dev/null 2>&1 && true
			t1=\$(date +%s%N 2>/dev/null || echo 0)
			echo \$(( (t1 - t0) / 1000000 ))
		fi
	" 2>/dev/null || echo "n/a")
	echo "  bridge → exit TCP: ${B2E_MS} ms (SSH fallback)"
fi
echo ""

# ── 2. exit → WARP → Cloudflare ───────────────────────────────────────────────
echo "[2] exit → WARP → Cloudflare"
if [[ -n "$EXIT_HOST" ]]; then
	WARP_RESULT=$(ssh_cmd "$EXIT_HOST" "
		if warp-cli --accept-tos status 2>/dev/null | grep -q Connected; then
			WARP_PORT=\$(cat /etc/ultra-relay/environment 2>/dev/null | grep WARP_PORT | cut -d= -f2 || echo 40000)
			WARP_PORT=\${WARP_PORT:-40000}
			curl -s --proxy \"socks5://127.0.0.1:\${WARP_PORT}\" \
				-w 'connect=%{time_connect}s ttfb=%{time_starttransfer}s total=%{time_total}s ip=%{remote_ip}' \
				-o /dev/null --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null
		else
			echo 'WARP not connected'
		fi
	" 2>/dev/null || echo "SSH failed")
	echo "  $WARP_RESULT"
else
	echo "  (EXIT host not specified — pass as second argument or set EXIT= in install.config)"
fi
echo ""

# ── 3. per-connection session traces ─────────────────────────────────────────
echo "[3] recent connection traces (last 5 sessions)"
if [[ -n "$ADMIN_TOKEN" ]]; then
	start_tunnel
	SESSIONS_JSON=$(api_get "/v1/latency/sessions?limit=5" 2>/dev/null || echo "")
	stop_tunnel; TUNNEL_PID=""

	if echo "$SESSIONS_JSON" | grep -q "trace_latency not enabled"; then
		echo '  tracing disabled — add "trace_latency": true to /etc/ultra-relay/spec.json on bridge'
	elif [[ -z "$SESSIONS_JSON" ]] || echo "$SESSIONS_JSON" | grep -q "^\[\]"; then
		echo "  no sessions captured yet (relay just started, or no traffic since enable)"
	else
		sessions_table "$SESSIONS_JSON"
	fi
else
	echo "  (admin token unavailable)"
fi
echo ""

# ── 4. full SOCKS5 end-to-end RTT ────────────────────────────────────────────
echo "[4] full SOCKS5 end-to-end (client → relay → exit → WARP → destination)"
if ! command -v xray >/dev/null 2>&1; then
	echo "  xray not found in PATH — skipping full E2E measurement"
else
	if [[ -n "$ADMIN_TOKEN" ]]; then
		TMPDIR=$(mktemp -d)
		start_tunnel

		UUID=$(api_get "/v1/users" 2>/dev/null | \
			python3 -c "import json,sys; u=json.load(sys.stdin); print(u[0]['uuid'] if u else '')" 2>/dev/null || true)

		if [[ -n "$UUID" ]]; then
			B64=$(api_get "/v1/users/${UUID}/client" 2>/dev/null | \
				python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('full_xray_config_base64',''))" 2>/dev/null || true)
			echo "$B64" | base64 -d > "$TMPDIR/client.json" 2>/dev/null || true
		fi

		stop_tunnel; TUNNEL_PID=""

		if [[ -f "$TMPDIR/client.json" ]] && [[ -s "$TMPDIR/client.json" ]]; then
			xray -c "$TMPDIR/client.json" >/dev/null 2>&1 &
			XRAY_PID=$!
			sleep 2
			echo "  (5 requests to api.ipify.org — exit IP should be Cloudflare)"
			for i in 1 2 3 4 5; do
				curl -s --socks5-hostname "127.0.0.1:${SOCKS_PORT}" \
					-w "  req $i: ttfb=%{time_starttransfer}s  total=%{time_total}s\n" \
					-o /dev/null --max-time 15 https://api.ipify.org 2>/dev/null || echo "  req $i: timeout"
			done
			kill "$XRAY_PID" 2>/dev/null || true
		else
			echo "  could not get client config"
		fi
		rm -rf "$TMPDIR"
	else
		echo "  (admin token unavailable — cannot fetch client config)"
	fi
fi

echo ""
echo "=== breakdown guide ==="
echo "  [1] bridge→exit:  the SplitHTTP hop — should be 25-40ms Russia→Netherlands"
echo "  [2] WARP ttfb:    WARP+Cloudflare overhead — typically 100-140ms"
echo "  [3] tunnel_up ms: bridge-side processing time per session (target: <40ms)"
echo "  [4] full ttfb:    total one-way path from your machine through the relay"
echo ""
