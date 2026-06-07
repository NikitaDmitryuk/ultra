package install

import (
	"testing"
)

func TestSSHConnectTimeoutSec(t *testing.T) {
	t.Setenv("ULTRA_SSH_CONNECT_TIMEOUT", "")
	if got := sshConnectTimeoutSec(); got != defaultSSHConnectTimeoutSec {
		t.Fatalf("default: got %d want %d", got, defaultSSHConnectTimeoutSec)
	}
	t.Setenv("ULTRA_SSH_CONNECT_TIMEOUT", "25")
	if got := sshConnectTimeoutSec(); got != 25 {
		t.Fatalf("override: got %d want 25", got)
	}
	t.Setenv("ULTRA_SSH_CONNECT_TIMEOUT", "bad")
	if got := sshConnectTimeoutSec(); got != defaultSSHConnectTimeoutSec {
		t.Fatalf("invalid: got %d want default %d", got, defaultSSHConnectTimeoutSec)
	}
}

func TestSSHBaseOptsIncludesConnectTimeout(t *testing.T) {
	t.Setenv("ULTRA_SSH_CONNECT_TIMEOUT", "7")
	opts := sshBaseOpts()
	var saw bool
	for i := 0; i < len(opts)-1; i++ {
		if opts[i] == "-o" && opts[i+1] == "ConnectTimeout=7" {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("ConnectTimeout=7 not in %#v", opts)
	}
}
