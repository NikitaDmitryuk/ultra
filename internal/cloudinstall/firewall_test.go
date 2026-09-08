package cloudinstall

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuestFirewallRestrictsTunnelToBridge(t *testing.T) {
	for _, active := range []bool{true, false} {
		t.Run(map[bool]string{true: "active", false: "inactive"}[active], func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			state := "inactive"
			if active {
				state = "active"
			}
			fake := "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'Status: " + state + "'; else printf '%s\\n' \"$*\" >> \"$CALLS\"; fi\n"
			if err := os.WriteFile(filepath.Join(dir, "ufw"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			script, err := tunnelFirewallScript("192.0.2.10", 51001)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CALLS="+log)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			calls, _ := os.ReadFile(log)
			if active && strings.TrimSpace(string(calls)) != "allow from 192.0.2.10 to any port 51001 proto tcp" {
				t.Fatalf("unexpected firewall mutation: %q", calls)
			}
			if !active && len(calls) != 0 {
				t.Fatal("inactive firewall was modified")
			}
		})
	}
	for _, source := range []string{"", "::1", "192.0.2.10; echo bad", "0.0.0.0/0"} {
		if _, err := tunnelFirewallScript(source, 443); err == nil {
			t.Fatalf("accepted %q", source)
		}
	}
	for _, port := range []int{0, 65536} {
		if _, err := tunnelFirewallScript("192.0.2.10", port); err == nil {
			t.Fatal("accepted invalid port")
		}
	}
}
