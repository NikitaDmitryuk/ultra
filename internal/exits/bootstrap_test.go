package exits

import "testing"

func TestBootstrapTunnelUUID(t *testing.T) {
	entries := []BootstrapEntry{
		{Name: "primary", Address: "10.0.0.1", Port: 443, TunnelUUID: "uuid-1"},
		{Name: "backup", Address: "10.0.0.2", Port: 51001, TunnelUUID: "uuid-2"},
	}
	if got := BootstrapTunnelUUID(entries, "10.0.0.2", 51001); got != "uuid-2" {
		t.Fatalf("got %q want uuid-2", got)
	}
	if got := BootstrapTunnelUUID(entries, "missing", 443); got != "" {
		t.Fatalf("got %q want empty", got)
	}
}
