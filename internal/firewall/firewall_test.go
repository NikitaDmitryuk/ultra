package firewall

import (
	"context"
	"os"
	"runtime"
	"testing"
)

func TestNewManagerOpenCloseNoPanic(t *testing.T) {
	// Linux implementation calls ufw/iptables; CI runners are non-root → permission denied.
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		t.Skip("linux firewall integration requires root (CAP_NET_ADMIN for iptables)")
	}
	ctx := context.Background()
	m := New()
	if err := m.OpenPort(ctx, 10810); err != nil {
		t.Fatal(err)
	}
	if err := m.ClosePort(ctx, 10810); err != nil {
		t.Fatal(err)
	}
}

func TestNewReturnsNonNil(t *testing.T) {
	if New() == nil {
		t.Fatal("New() returned nil")
	}
}
