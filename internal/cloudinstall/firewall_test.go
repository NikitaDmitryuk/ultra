package cloudinstall

import (
	"context"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

// Firewall active/inactive behavior is exercised against the actual Ansible role
// by scripts/test-ansible-exit.py. No legacy shell installer remains here.
func TestMissingExecutorCannotReachCloudPreparation(t *testing.T) {
	p := &Provisioner{}
	if _, err := p.Prepare(context.Background(), &cloud.Operation{}); err == nil || err.Error() != "ansible controller required" {
		t.Fatalf("unexpected preflight result: %v", err)
	}
}
