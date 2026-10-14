package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAutoDownloadOwnershipIncludesSignedInputs(t *testing.T) {
	parent := t.TempDir()
	incoming := filepath.Join(parent, "incoming")
	if err := os.Mkdir(incoming, 0700); err != nil {
		t.Fatal(err)
	}
	installer := "ultra-install-linux-" + runtime.GOARCH
	contents := map[string]string{installer: "verified installer", "release-manifest.json": "signed manifest", "release-manifest.json.minisig": "signature"}
	for name, value := range contents {
		if err := os.WriteFile(filepath.Join(incoming, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var manifest automationRelease
	digest := sha256.Sum256([]byte(contents[installer]))
	if err := json.Unmarshal([]byte(`{"version":"v1.2.3","assets":[{"name":"`+installer+`","sha256":"`+hex.EncodeToString(digest[:])+`"}]}`), &manifest); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "v1.2.3")
	policy := autoUpgradePolicy{OperationLockDirectory: parent}
	if err := sealAutoDownload(policy, incoming, target, manifest); err != nil {
		t.Fatal(err)
	}
	pathDigest := sha256.Sum256([]byte(target))
	path := filepath.Join(parent, "retention", hex.EncodeToString(pathDigest[:])+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Path     string
		Identity struct {
			Version string
			Assets  map[string]string
		}
		Inventory map[string][]any
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Path != target || receipt.Identity.Version != "v1.2.3" || len(receipt.Inventory) != 3 || len(receipt.Identity.Assets) != 3 || receipt.Inventory[installer][2] != float64(0700) {
		t.Fatalf("unexpected ownership: %s", raw)
	}
	for name, value := range contents {
		digest := sha256.Sum256([]byte(value))
		if receipt.Identity.Assets[name] != hex.EncodeToString(digest[:]) {
			t.Fatal("unsigned ownership identity")
		}
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("hook published target")
	}
	if err := sealAutoDownload(policy, incoming, target, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incoming, "release-manifest.json.minisig"), []byte("changed signature"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sealAutoDownload(policy, incoming, target, manifest); err == nil {
		t.Fatal("replaced signed identity")
	}
}
