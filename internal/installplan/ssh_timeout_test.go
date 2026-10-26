package installplan

import (
	"strconv"
	"strings"
	"testing"
)

func TestSSHTimeoutValidationBeforeDeployment(t *testing.T) {
	for _, seconds := range []int{0, 1, 30, 300, -1, 301} {
		t.Run(strconv.Itoa(seconds), func(t *testing.T) {
			p := LegacyValuesToPlan(
				map[string]string{
					"BRIDGE_IP":                 "192.0.2.10",
					"MAIN_EXIT_IP":              "192.0.2.20",
					"ULTRA_SSH_CONNECT_TIMEOUT": strconv.Itoa(seconds),
				},
			)
			// A deliberately incomplete plan may fail later role checks, but invalid
			// timeouts must be identified before any deployment preparation.
			err := validatePlanRoles(p)
			invalid := seconds < 0 || seconds > 300
			timeoutError := err != nil && strings.Contains(err.Error(), "ssh.connect_timeout_sec")
			if timeoutError != invalid {
				t.Fatalf("timeout %d: %v", seconds, err)
			}
			if seconds == 0 && p.SSH.ConnectTimeoutSec != 10 {
				t.Fatal("default timeout changed")
			}
		})
	}
}
