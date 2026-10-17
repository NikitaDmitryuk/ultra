package deployansible

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func retainedCacheFixture(t *testing.T) (string, string, []byte, string, map[string]any, map[string]any) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "retention")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"inventory": map[string]any{}, "variables": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	id := hex.EncodeToString(digest[:])
	job := map[string]any{"schema_version": 1, "operation": "retain-artifacts", "request_sha256": id, "binary_sha256": id, "attempt": 1}
	saved := map[string]any{
		"schema_version": 1,
		"operation":      "retain-artifacts",
		"request_sha256": id,
		"binary_sha256":  id,
		"attempt":        1,
		"state":          "succeeded",
		"result":         map[string]any{"verified": true},
	}
	if err := writePrivate(filepath.Join(directory, "request.json"), raw); err != nil {
		t.Fatal(err)
	}
	if err := writeCachedJSON(filepath.Join(directory, "job.json"), job); err != nil {
		t.Fatal(err)
	}
	if err := writeCachedJSON(filepath.Join(directory, "receipt.json"), saved); err != nil {
		t.Fatal(err)
	}
	return root, directory, raw, id, job, saved
}

func TestCollectedRetentionRunLocalReturnsDurableSuccess(t *testing.T) {
	root, directory, _, _, _, _ := retainedCacheFixture(t)
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	receipt, err := RunLocal(
		ctx,
		"retain-artifacts",
		map[string]any{},
		map[string]any{},
		directory,
		"/nonexistent/python",
		"/nonexistent/ansible",
	)
	if err != nil || receipt.State != "succeeded" || receipt.Result.Values["verified"] != true {
		t.Fatal("completed retention re-executed", receipt, err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "bundle")); !os.IsNotExist(err) {
		t.Fatal("recreated a collected bundle")
	}
}

func TestCollectedRetentionCacheRejectsChangedMetadata(t *testing.T) {
	for _, kind := range []string{"request", "job-hash", "receipt-hash", "binary", "operation", "schema", "attempt", "failed", "unverified", "missing-request", "missing-job", "missing-receipt", "public-receipt", "symlink-receipt"} {
		t.Run(kind, func(t *testing.T) {
			_, directory, raw, id, job, saved := retainedCacheFixture(t)
			switch kind {
			case "request":
				if err := os.WriteFile(filepath.Join(directory, "request.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "job-hash":
				job["request_sha256"] = "changed"
			case "receipt-hash":
				saved["request_sha256"] = "changed"
			case "binary":
				saved["binary_sha256"] = "changed"
			case "operation":
				saved["operation"] = "upgrade"
			case "schema":
				saved["schema_version"] = 2
			case "attempt":
				saved["attempt"] = 2
			case "failed":
				saved["state"] = "failed"
			case "unverified":
				saved["result"] = map[string]any{"verified": false}
			}
			if err := writeCachedJSON(filepath.Join(directory, "job.json"), job); err != nil {
				t.Fatal(err)
			}
			if err := writeCachedJSON(filepath.Join(directory, "receipt.json"), saved); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing-request":
				if err := os.Remove(filepath.Join(directory, "request.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-job":
				if err := os.Remove(filepath.Join(directory, "job.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-receipt":
				if err := os.Remove(filepath.Join(directory, "receipt.json")); err != nil {
					t.Fatal(err)
				}
			case "public-receipt":
				if err := os.Chmod(filepath.Join(directory, "receipt.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-receipt":
				path := filepath.Join(directory, "receipt.json")
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, handled, err := collectedRetentionResult("retain-artifacts", directory, raw, id); !handled || err == nil {
				t.Fatal("invalid collected result accepted", handled, err)
			}
		})
	}
}

func TestCollectedRetentionCacheLeavesNormalExecution(t *testing.T) {
	_, directory, raw, id, _, _ := retainedCacheFixture(t)
	if _, handled, err := collectedRetentionResult("upgrade", directory, raw, id); handled || err != nil {
		t.Fatal("changed operator behavior", handled, err)
	}
	if err := os.Mkdir(filepath.Join(directory, "bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, handled, err := collectedRetentionResult("retain-artifacts", directory, raw, id); handled || err != nil {
		t.Fatal("changed existing bundle behavior", handled, err)
	}
}

func writeCachedJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}
