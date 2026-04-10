#!/bin/bash
# Template processed by fmt.Sprintf — see WARPSetupScript in warp.go for arg order.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "ultra: installing Cloudflare WARP…"

# ── Repository ────────────────────────────────────────────────────────────────
if ! command -v warp-cli >/dev/null 2>&1; then
  apt-get install -y -q curl gnupg lsb-release
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
    | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] \
https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/cloudflare-client.list
  apt-get update -q
  apt-get install -y -q cloudflare-warp
fi

# ── Enable and start the warp-svc daemon ──────────────────────────────────────
systemctl enable warp-svc 2>/dev/null || true
systemctl start  warp-svc 2>/dev/null || true
sleep 1

# ── Register (idempotent: if already registered, re-use the session) ──────────
if ! warp-cli --accept-tos status 2>/dev/null | grep -qE "(Connected|Connecting)"; then
  warp-cli --accept-tos registration new 2>/dev/null || true
fi

# ── Set proxy mode and port, then (re)connect ────────────────────────────────
# Always disconnect+reconnect: warp-cli may report "Connected" while the proxy
# silently drops all traffic (known stale-tunnel bug). A fresh connect fixes it.
warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli --accept-tos set-mode proxy 2>/dev/null || true
warp-cli --accept-tos proxy port %d 2>/dev/null || true
warp-cli --accept-tos disconnect 2>/dev/null || true
sleep 1
warp-cli --accept-tos connect

# Wait up to 15 s for WARP to become Connected.
for i in $(seq 1 15); do
  if warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
    break
  fi
  sleep 1
done

if ! warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
  echo "ultra: WARNING — WARP did not connect within 15 s; check 'warp-cli status' on the exit node." >&2
else
  echo "ultra: Cloudflare WARP proxy running on 127.0.0.1:%d"
fi
