package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAutomationSignatureProjectionPreservesSourceAndRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	values := map[string]any{}
	if err := automationSignatureInput(directory, values); err != nil || values["ultra_automation_signature_source"] != "" {
		t.Fatalf("unsigned projection: %v", err)
	}
	source := filepath.Join(directory, "release-manifest.json.minisig")
	original := []byte("untrusted comment: synthetic signature fixture\nexact bytes\n")
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := automationSignatureInput(directory, values); err != nil || values["ultra_automation_signature_source"] != source {
		t.Fatalf("signed source projection: %v", err)
	}
	got, err := os.ReadFile(source)
	if err != nil || string(got) != string(original) {
		t.Fatal("source bytes altered")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("foreign", source); err != nil {
		t.Fatal(err)
	}
	if err := automationSignatureInput(directory, values); err == nil {
		t.Fatal("symlink signature accepted")
	}
}
