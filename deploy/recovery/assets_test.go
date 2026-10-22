package recoveryassets

import (
	"encoding/json"
	"testing"
)

func TestSharedSSHPolicyShipsWithRecoveryAssets(t *testing.T) {
	raw, err := Scripts.ReadFile("ssh_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if policy["version"] != float64(1) || policy["probe_connect_timeout_seconds"] != float64(15) ||
		policy["mutate_connect_timeout_seconds"] != float64(30) {
		t.Fatalf("unexpected SSH policy shipped: %v", policy)
	}
	if _, err := Scripts.ReadFile("ssh_policy.py"); err != nil {
		t.Fatal(err)
	}
}
