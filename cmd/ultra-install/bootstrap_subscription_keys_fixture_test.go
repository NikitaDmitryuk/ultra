package main

import (
	"os"
	"testing"
)

func writeTestSubscriptionKeyring(t *testing.T, path string, raw string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
}
