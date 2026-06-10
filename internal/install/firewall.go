package install

import (
	"fmt"
	"strconv"
	"strings"
)

// OpenTCPPortsScript returns an idempotent remote shell script that opens TCP ports
// in the host firewall when ufw or iptables is present.
func OpenTCPPortsScript(ports []int) string {
	var vals []string
	seen := map[int]bool{}
	for _, p := range ports {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		vals = append(vals, strconv.Itoa(p))
	}
	if len(vals) == 0 {
		return "true"
	}
	return fmt.Sprintf(`set -euo pipefail
ports=(%s)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  for p in "${ports[@]}"; do ufw allow "${p}/tcp" >/dev/null || true; done
elif command -v iptables >/dev/null 2>&1; then
  for p in "${ports[@]}"; do
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
  done
  if [ -f /etc/iptables/rules.v4 ] && command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4 || true
  fi
fi
`, strings.Join(vals, " "))
}

// SetupFirewallPorts opens TCP ports on a remote host as part of installation.
func SetupFirewallPorts(sshUser, host, identity string, ports []int) error {
	return RunSSH(sshUser, host, identity, OpenTCPPortsScript(ports))
}
