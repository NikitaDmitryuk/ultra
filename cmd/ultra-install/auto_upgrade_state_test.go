package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelStateRemainsReadableForUpgradeRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	identity := `"version":"v9.0.0","source_commit":"` + strings.Repeat("a", 40) + `","manifest_sha256":"` + strings.Repeat("b", 64) + `"`
	data := `{"schema_version":1,"accepted":{` + identity + `},"pending":{` + identity + `},"failed":{"v9.1.0":"activation_failed"}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := readChannelState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.Failed["v9.1.0"] != "activation_failed" || state.Accepted == nil || state.Pending == nil {
		t.Fatalf("channel recovery metadata was not preserved: %#v", state)
	}
}
