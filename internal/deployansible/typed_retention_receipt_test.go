package deployansible

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func assertTypedRetentionReceipt(t *testing.T, directory string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "bundle.retention.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Schema    int
		Path      string
		Identity  map[string]string
		Inventory map[string]any
	}
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(filepath.Join(directory, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(request)
	inventory, err := retentionInventory(filepath.Join(directory, "bundle"))
	if err != nil {
		t.Fatal(err)
	}
	// Normalize Go inventory integer modes to decoded JSON numbers.
	inventoryRaw, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	var normalized map[string]any
	if err = json.Unmarshal(inventoryRaw, &normalized); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != 1 || receipt.Path != filepath.Join(directory, "bundle") ||
		receipt.Identity["request_sha256"] != hex.EncodeToString(digest[:]) ||
		!reflect.DeepEqual(normalized, receipt.Inventory) {
		t.Fatal("typed bundle ownership does not match frozen inputs")
	}
}

func TestTypedExitPreparesBundleOwnership(t *testing.T) {
	binary, request := fixture(t)
	directory := filepath.Join(t.TempDir(), "exit")
	if err := Prepare(directory, binary, request); err != nil {
		t.Fatal(err)
	}
	assertTypedRetentionReceipt(t, directory)
	if err := os.Remove(filepath.Join(directory, "bundle.retention.json")); err != nil {
		t.Fatal(err)
	}
	// Legacy prepared exit jobs cannot be replaced by preparation, and are not
	// retroactively enrolled merely because an operator repeats the call.
	if err := Prepare(directory, binary, request); err == nil {
		t.Fatal("replaced legacy prepared exit")
	}
	if _, err := os.Lstat(filepath.Join(directory, "bundle.retention.json")); !os.IsNotExist(err) {
		t.Fatal("claimed legacy exit bundle")
	}
}
