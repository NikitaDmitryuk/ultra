package install

import (
	_ "embed"
	"fmt"
)

//go:embed scripts/warp-setup.sh
var warpSetupScriptTmpl string

//go:embed scripts/warp-watchdog.sh
var warpWatchdogScript string

// WARPSetupScript returns a bash script that installs Cloudflare WARP on a Debian/Ubuntu
// exit node and starts it in SOCKS5 proxy mode on the given port (default 40000).
//
// After this script runs, warp-cli listens on 127.0.0.1:<proxyPort> as a SOCKS5 proxy.
// All TCP connections going through that proxy appear to originate from a Cloudflare IP
// instead of the VPS's datacenter IP.
//
// The warp-svc systemd service is enabled so WARP auto-starts on reboot.
// The script always disconnects and reconnects to avoid the known stale-tunnel bug where
// warp-cli reports "Connected" but the proxy silently drops all traffic.
func WARPSetupScript(proxyPort int) string {
	if proxyPort <= 0 {
		proxyPort = 40000
	}
	return fmt.Sprintf(warpSetupScriptTmpl, proxyPort, proxyPort)
}

// SetupWARP installs and starts Cloudflare WARP in proxy mode on the given host via SSH.
func SetupWARP(sshUser, host, identity string, proxyPort int) error {
	return RunSSH(sshUser, host, identity, WARPSetupScript(proxyPort))
}

// WARPWatchdogInstallScript returns a bash script that installs the WARP watchdog:
// writes /usr/local/bin/ultra-warp-watchdog and registers a systemd timer that runs it
// every 5 minutes. The watchdog tests real SOCKS5 connectivity and reconnects WARP if broken.
func WARPWatchdogInstallScript(proxyPort int) string {
	if proxyPort <= 0 {
		proxyPort = 40000
	}
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail

# Write the watchdog script.
cat > /usr/local/bin/ultra-warp-watchdog << 'WDEOF'
%s
WDEOF
chmod 755 /usr/local/bin/ultra-warp-watchdog

# Write the systemd service (port is baked into Environment=).
cat > /etc/systemd/system/ultra-warp-watchdog.service << 'SVCEOF'
[Unit]
Description=ultra WARP proxy watchdog — verify SOCKS5 connectivity and reconnect if broken
After=warp-svc.service

[Service]
Type=oneshot
Environment=WARP_PROXY_PORT=%d
ExecStart=/usr/local/bin/ultra-warp-watchdog
SVCEOF

# Write the systemd timer.
cat > /etc/systemd/system/ultra-warp-watchdog.timer << 'TIMEREOF'
[Unit]
Description=Run ultra WARP proxy watchdog every 5 minutes
After=warp-svc.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=ultra-warp-watchdog.service

[Install]
WantedBy=timers.target
TIMEREOF

systemctl daemon-reload
systemctl enable --now ultra-warp-watchdog.timer
echo "ultra: WARP watchdog timer installed and active."
`, warpWatchdogScript, proxyPort)
}

// SetupWARPWatchdog installs the WARP watchdog timer on the exit node via SSH.
func SetupWARPWatchdog(sshUser, host, identity string, proxyPort int) error {
	return RunSSH(sshUser, host, identity, WARPWatchdogInstallScript(proxyPort))
}
