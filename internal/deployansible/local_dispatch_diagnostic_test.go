package deployansible

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A guard that stops before the controller leaves no receipt behind. The caller
// printed stage/node/code from an empty Receipt and the operator saw a triple that
// was indistinguishable from an Ansible task failure.
func TestLocalDispatchFailureCarriesDiagnostic(t *testing.T) {
	root := t.TempDir()
	receipt, err := RunLocal(
		context.Background(),
		"arbitrary",
		map[string]any{},
		map[string]any{},
		filepath.Join(root, "attempt"),
		"/usr/bin/python3",
		"/usr/bin/ansible-playbook",
	)
	if err == nil {
		t.Fatal("unapproved operation admitted")
	}
	if receipt.Diagnostic.Stage != "dispatch" || receipt.Diagnostic.Node != "local" ||
		receipt.Diagnostic.Code != "operation_not_allowed" {
		t.Fatalf("pre-dispatch failure reported as %q/%q/%q",
			receipt.Diagnostic.Stage, receipt.Diagnostic.Node, receipt.Diagnostic.Code)
	}
	if receipt.State != "" {
		t.Fatalf("undispatched attempt reported state %q", receipt.State)
	}
}

// The namespace guard is the failure that closed a one-shot fleet admission
// without dispatching anything. Each pre-dispatch guard keeps its own identifier
// so a repeated failure is attributable without reading private operation inputs.
func TestLocalDispatchFailureIdentifiesGuard(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	receipt, err := RunLocal(
		context.Background(),
		"inspect-bootstrap",
		map[string]any{},
		map[string]any{},
		filepath.Join(root, "attempt"),
		"/usr/bin/python3",
		"/usr/bin/ansible-playbook",
	)
	if err == nil {
		t.Fatal("public lock directory admitted")
	}
	if receipt.Diagnostic.Stage != "dispatch" || receipt.Diagnostic.Code != "lock_directory_insecure" {
		t.Fatalf("public lock directory reported as %q/%q",
			receipt.Diagnostic.Stage, receipt.Diagnostic.Code)
	}
}
