package cloudinstall

import (
	"context"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/install"
)

// Firewall active/inactive behavior is exercised against the actual Ansible role
// by scripts/test-ansible-exit.py. No legacy shell installer remains here.
func TestMissingExecutorCannotReachCloudPreparation(t *testing.T) {
	p := &Provisioner{
		CheckReady: func(context.Context) error { return nil },
		Replica:    func(context.Context, string, install.Remote) (string, error) { return "", nil },
	}
	if _, err := p.Prepare(context.Background(), &cloud.Operation{}); err == nil || err.Error() != "ansible controller required" {
		t.Fatalf("unexpected preflight result: %v", err)
	}
}
