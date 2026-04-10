#!/bin/bash
# WARP proxy watchdog — verifies real SOCKS5 connectivity and reconnects if broken.
# Invoked by ultra-warp-watchdog.timer every 5 minutes.
# Requires: WARP_PROXY_PORT env var (set via systemd Environment= in the .service file).
set -euo pipefail

PROXY_PORT="${WARP_PROXY_PORT:-40000}"

# Quick sanity: is warp-svc running at all?
if ! systemctl is-active --quiet warp-svc 2>/dev/null; then
  echo "ultra-warp-watchdog: warp-svc not active — starting..." >&2
  systemctl start warp-svc || true
  sleep 3
fi

# Test real connectivity through the SOCKS5 proxy.
# A "Connected" status can be stale; a successful curl proves the proxy actually works.
if curl --socks5-hostname "127.0.0.1:${PROXY_PORT}" \
        --max-time 10 --silent --fail -o /dev/null \
        "https://cloudflare.com/" 2>/dev/null; then
  exit 0
fi

echo "ultra-warp-watchdog: SOCKS5 proxy on 127.0.0.1:${PROXY_PORT} unresponsive — reconnecting..." >&2
warp-cli --accept-tos disconnect 2>/dev/null || true
sleep 2
warp-cli --accept-tos connect 2>/dev/null || true

# Wait up to 15 s for WARP to reconnect.
for i in $(seq 1 15); do
  if warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
    echo "ultra-warp-watchdog: WARP reconnected on port ${PROXY_PORT}."
    exit 0
  fi
  sleep 1
done

echo "ultra-warp-watchdog: WARNING — WARP did not reconnect within 15 s." >&2
exit 1
