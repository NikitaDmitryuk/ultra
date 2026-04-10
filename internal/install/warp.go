package install

import "fmt"

// WARPSetupScript returns a bash script that installs Cloudflare WARP on a Debian/Ubuntu
// exit node and starts it in SOCKS5 proxy mode on the given port (default 40000).
//
// After this script runs, warp-cli listens on 127.0.0.1:<proxyPort> as a SOCKS5 proxy.
// All TCP connections going through that proxy appear to originate from a Cloudflare IP
// instead of the VPS's datacenter IP.
//
// The warp-svc systemd service is enabled so WARP auto-starts on reboot.
// warp-cli connect is idempotent: re-running the script on an already-connected node is safe.
func WARPSetupScript(proxyPort int) string {
	if proxyPort <= 0 {
		proxyPort = 40000
	}
	return fmt.Sprintf(`#!/bin/bash
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

# ── Set proxy mode and port, then connect ─────────────────────────────────────
warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli --accept-tos set-mode proxy 2>/dev/null || true
warp-cli --accept-tos proxy port %d 2>/dev/null || true
warp-cli --accept-tos connect

# Wait up to 10 s for WARP to become Connected.
for i in $(seq 1 10); do
  if warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
    break
  fi
  sleep 1
done

if ! warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
  echo "ultra: WARNING — WARP did not connect within 10 s; check 'warp-cli status' on the exit node." >&2
else
  echo "ultra: Cloudflare WARP proxy running on 127.0.0.1:%d"
fi
`, proxyPort, proxyPort)
}

// SetupWARP installs and starts Cloudflare WARP in proxy mode on the given host via SSH.
func SetupWARP(sshUser, host, identity string, proxyPort int) error {
	return RunSSH(sshUser, host, identity, WARPSetupScript(proxyPort))
}
