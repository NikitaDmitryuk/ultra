package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestUpgradeSubscriptionRemoteProjection(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	command := exec.Command(python, filepath.Join("..", "..", "scripts", "test-subscription-key-projection.py"))
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("private subscription projection failed: %v\n%s", runErr, output)
	}
}
