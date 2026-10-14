package deployansible

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionReceiptExactCreateOnlyInventory(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "tree")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "binary"), []byte("verified"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "receipt.json")
	final := filepath.Join(parent, "published")
	identity := map[string]string{"request_sha256": "identity"}
	if err := WriteRetentionReceipt(root, final, path, identity); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Schema    int
		Path      string
		Identity  map[string]string
		Inventory map[string][]any
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("verified"))
	if receipt.Schema != 1 || receipt.Path != final || receipt.Identity["request_sha256"] != "identity" || len(receipt.Inventory) != 2 || receipt.Inventory["nested"][0] != "directory" || receipt.Inventory["nested/binary"][1] != hex.EncodeToString(digest[:]) || receipt.Inventory["nested/binary"][2] != float64(0700) {
		t.Fatalf("unexpected receipt: %s", raw)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("receipt is not private")
	}
	if err := WriteRetentionReceipt(root, final, path, identity); err != nil {
		t.Fatal(err)
	}
	if err := WriteRetentionReceipt(root, final, path, map[string]string{"request_sha256": "changed"}); err == nil {
		t.Fatal("replaced receipt identity")
	}
	if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteRetentionReceipt(root, final, path, identity); err == nil {
		t.Fatal("adopted changed inventory")
	}
	retained, _ := os.ReadFile(path)
	if string(retained) != string(raw) {
		t.Fatal("changed existing receipt")
	}
}

func TestRetentionReceiptRejectsUnsafeMembers(t *testing.T) {
	for _, member := range []string{"symlink", "hardlink", "writable", "ancestor"} {
		t.Run(member, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(parent, "tree")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(root, "source")
			if err := os.WriteFile(source, []byte("content"), 0600); err != nil {
				t.Fatal(err)
			}
			switch member {
			case "symlink":
				if err := os.Symlink(source, filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(source, filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(source, 0666); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				if err := os.Symlink(parent, filepath.Join(parent, "alias")); err != nil {
					t.Fatal(err)
				}
				root = filepath.Join(parent, "alias", "tree")
			}
			receipt := filepath.Join(parent, "receipt.json")
			if err := WriteRetentionReceipt(root, root, receipt, "identity"); err == nil {
				t.Fatal("unsafe ownership claimed")
			}
			if _, err := os.Lstat(receipt); !os.IsNotExist(err) {
				t.Fatal("unsafe receipt published")
			}
		})
	}
}

func TestLocalPreparationSealsBundleBeforePublication(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "operation")
	if err := prepareLocalOperation(directory, "upgrade", []byte(`{}`), "request-id", func(bundle string) error {
		if _, err := os.Lstat(directory); !os.IsNotExist(err) {
			t.Fatal("published before export")
		}
		if err := os.Mkdir(bundle, 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(bundle, "controller.py"), []byte("controller"), 0600)
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "bundle.retention.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Path      string
		Identity  map[string]string
		Inventory map[string][]any
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Path != filepath.Join(directory, "bundle") || receipt.Identity["request_sha256"] != "request-id" || len(receipt.Inventory) != 1 {
		t.Fatalf("wrong bundle ownership: %s", raw)
	}
}

func TestLocalPreparationDoesNotPublishUnsealableBundle(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "operation")
	err := prepareLocalOperation(directory, "upgrade", []byte(`{}`), "request-id", func(bundle string) error {
		if err := os.Mkdir(bundle, 0700); err != nil {
			return err
		}
		return os.Symlink("/nonexistent", filepath.Join(bundle, "controller.py"))
	})
	if err == nil {
		t.Fatal("published an unowned bundle")
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatal("failed ownership left published operation")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed preparation retained its staging tree", err)
	}
}

func TestRetentionReceiptRetryAfterLinkPublicationCrash(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "tree")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binary"), []byte("verified"), 0700); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(parent, "receipt.json")
	identity := map[string]string{"request_sha256": "frozen"}
	if err := WriteRetentionReceipt(root, root, receipt, identity); err != nil {
		t.Fatal(err)
	}
	// Exact state after link(temp, receipt), before remove(temp): two names for
	// the same complete synced inode. Its temporary alias has unknown provenance.
	orphan := filepath.Join(parent, ".retention-interrupted")
	if err := os.Link(receipt, orphan); err != nil {
		t.Fatal(err)
	}
	if err := WriteRetentionReceipt(root, root, receipt, identity); err != nil {
		t.Fatalf("crashed publication poisoned retry: %v", err)
	}
	if _, err := os.Lstat(orphan); err != nil {
		t.Fatal("removed an unproven alias", err)
	}
	if err := WriteRetentionReceipt(root, root, receipt, map[string]string{"request_sha256": "different"}); err == nil {
		t.Fatal("crash recovery changed receipt identity")
	}
}
