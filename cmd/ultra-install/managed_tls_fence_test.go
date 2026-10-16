package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestManagedTLSRenewalFenceAndPreservation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	command := exec.Command(python, filepath.Join("..", "..", "scripts", "test-managed-tls-fence.py"))
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("managed TLS fence/preservation checks failed: %v\n%s", runErr, output)
	}
}
