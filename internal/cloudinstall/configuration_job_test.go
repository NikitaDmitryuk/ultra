package cloudinstall

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestConfigurationJobChangesWithoutChangingPurchase(t *testing.T) {
	directory := t.TempDir()
	paths := []string{filepath.Join(directory, "binary"), filepath.Join(directory, "identity"), filepath.Join(directory, "pins")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(path), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := deployansible.ExitRequest{Host: "192.0.2.2", User: "root", Identity: paths[1], KnownHosts: paths[2], BridgeIPv4: "192.0.2.1"}
	first, err := configurationJobID("purchase", paths[0], request)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := configurationJobID("purchase", paths[0], request)
	if err != nil || first != repeated {
		t.Fatal("unchanged attempt lost identity", err)
	}
	legacy, err := configurationAttemptJobID("purchase", 0, paths[0], request)
	if err != nil || legacy != first {
		t.Fatal("legacy attempt lost receipt identity", err)
	}
	retried, err := configurationAttemptJobID("purchase", 1, paths[0], request)
	if err != nil || retried == first {
		t.Fatal("explicit retry reused terminal receipt", err)
	}
	resumed, err := configurationAttemptJobID("purchase", 1, paths[0], request)
	if err != nil || resumed != retried {
		t.Fatal("explicit retry lost persisted identity", err)
	}
	request.BridgeIPv4 = "192.0.2.3"
	moved, err := configurationJobID("purchase", paths[0], request)
	if err != nil || first == moved {
		t.Fatal("new bridge reused obsolete receipt", err)
	}
	for _, path := range paths {
		before, err := configurationJobID("purchase", paths[0], request)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		after, err := configurationJobID("purchase", paths[0], request)
		if err != nil || before == after {
			t.Fatal("changed sealed input reused receipt", err)
		}
	}
	if err := os.Remove(paths[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := configurationJobID("purchase", paths[0], request); err == nil {
		t.Fatal("missing input accepted")
	}
}
