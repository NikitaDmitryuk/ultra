package main

import "testing"

func TestRecoveryCommandBundledCLI(t *testing.T) {
	if HandleRecoveryCommand([]string{"unrelated"}) {
		t.Fatal("unrelated command handled")
	}
	for _, command := range []string{"restore", "recovery-key"} {
		if err := runRecoveryCommand([]string{command, "--help"}); err != nil {
			t.Fatalf("%s bundled CLI: %v", command, err)
		}
	}
}
