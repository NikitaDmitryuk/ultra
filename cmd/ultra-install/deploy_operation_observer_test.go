package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployOperationObserverExactProcessAndCleanup(t *testing.T) {
	directory := t.TempDir()
	identity := strings.Repeat("a", 64)
	cleanup, err := publishDeployOperationObserver(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(directory, "observers", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("observer missing: %v", err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var observer deployOperationObserver
	if json.Unmarshal(raw, &observer) != nil || observer.PID != os.Getpid() || observer.RequestSHA256 != identity ||
		observer.Starttime == "" {
		t.Fatal("observer not bound to process")
	}
	exe, _ := os.ReadFile("/proc/self/exe")
	argv, _ := os.ReadFile("/proc/self/cmdline")
	if observer.ExecutableSHA256 != digestSHA256(exe) || observer.ArgvSHA256 != digestSHA256(argv) {
		t.Fatal("process digests differ")
	}
	if _, err = publishDeployOperationObserver(directory, identity); err == nil {
		t.Fatal("existing descriptor overwritten")
	}
	cleanup()
	if _, err = os.Lstat(files[0]); !os.IsNotExist(err) {
		t.Fatal("descriptor left behind")
	}
}

func TestDeployOperationObserverCleanupPreservesReplacement(t *testing.T) {
	directory := t.TempDir()
	cleanup, err := publishDeployOperationObserver(directory, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(directory, "observers", "*.json"))
	if err = os.WriteFile(files[0], []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if raw, err := os.ReadFile(files[0]); err != nil || string(raw) != "changed" {
		t.Fatal("changed descriptor removed")
	}
}

func TestDeployObserverStarttimeHandlesParenthesesAndRejectsMalformed(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[19] = "1234"
	value, err := deployObserverStarttime([]byte("42 (name ) with parentheses) " + strings.Join(fields, " ")))
	if err != nil || value != "1234" {
		t.Fatalf("starttime: %q %v", value, err)
	}
	for _, raw := range []string{"", "42 (name) S", "42 (name) " + strings.Repeat("0 ", 19) + "-1"} {
		if _, err := deployObserverStarttime([]byte(raw)); err == nil {
			t.Fatal("malformed stat accepted")
		}
	}
}
