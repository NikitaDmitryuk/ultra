package deployansible

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedBootstrapBundleCloneAndSourceIdentity(t *testing.T) {
	source, _ := retryFixture(t)
	if err := Export(filepath.Join(source, "bundle")); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(source, "bundle", "legacy-source-marker")
	if err := os.WriteFile(legacy, []byte("old-version\n"), 0600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(source, "bundle", "empty-source-marker")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(filepath.Join(source, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(source, "next-generation")
	export, err := pinnedBootstrapExporter(source, target, "bootstrap", request)
	if err != nil {
		t.Fatal(err)
	}
	// Publish through the same atomic preparation path and retention receipt hook.
	digest := sha256.Sum256(request)
	hash := hex.EncodeToString(digest[:])
	if err = prepareLocalOperation(target, "bootstrap", request, hash, export); err != nil {
		t.Fatal(err)
	}
	original, err := retentionInventory(filepath.Join(source, "bundle"))
	if err != nil {
		t.Fatal(err)
	}
	copied, err := retentionInventory(filepath.Join(target, "bundle"))
	if err != nil {
		t.Fatal(err)
	}
	originalRaw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	copiedRaw, err := json.Marshal(copied)
	if err != nil || !bytes.Equal(originalRaw, copiedRaw) {
		t.Fatal("source role/controller tree changed")
	}
	if _, err = pinnedBootstrapExporter(source, target, "bootstrap", request); err != nil {
		t.Fatal("same pin did not resume", err)
	}
	if _, err = pinnedBootstrapExporter(source, filepath.Join(source, "changed"), "bootstrap", []byte(`{}`)); err == nil {
		t.Fatal("original request drift accepted")
	}
	if err = os.WriteFile(legacy, []byte("different-version"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = pinnedBootstrapExporter(source, target, "bootstrap", request); err == nil {
		t.Fatal("source bundle drift accepted")
	}
}

func TestPinnedBootstrapBundleRejectsUnsafeTree(t *testing.T) {
	source, _ := retryFixture(t)
	if err := Export(filepath.Join(source, "bundle")); err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(filepath.Join(source, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(source, "request.json"), filepath.Join(source, "bundle", "untrusted")); err != nil {
		t.Fatal(err)
	}
	if _, err = pinnedBootstrapExporter(source, filepath.Join(source, "next"), "bootstrap", request); err == nil {
		t.Fatal("unsafe bundle symlink accepted")
	}
}
