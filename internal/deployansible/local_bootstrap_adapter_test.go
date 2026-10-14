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

func TestAdaptedBootstrapPreservesOriginalBundleAndLinksProof(t *testing.T) {
	source, _ := retryFixture(t)
	// This fixture's original hashed request and job are valid legacy bootstrap.
	raw, err := os.ReadFile(filepath.Join(source, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	if err = json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	if err = Export(filepath.Join(source, "bundle")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "bundle", "roles", "host", "tasks", "main.yml"), []byte("# original frozen role\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "bundle", "controller.py"), []byte("# original frozen controller\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bootstrap-postgres.yml", "bootstrap-exit.yml", "bootstrap-bridge.yml"} {
		if err = os.Remove(filepath.Join(source, "bundle", "playbooks", name)); err != nil {
			t.Fatal(err)
		}
	}
	before, err := retentionInventory(filepath.Join(source, "bundle"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(source)
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	original.Variables["ultra_lock_directory"] = root
	// Keep original lease binding in the immutable request as well.
	request, _ := json.Marshal(map[string]any{"inventory": original.Inventory, "variables": original.Variables})
	jobRaw, _ := os.ReadFile(filepath.Join(source, "job.json"))
	var job map[string]any
	_ = json.Unmarshal(jobRaw, &job)
	job["request_sha256"] = localAdapterTestHash(request)
	job["binary_sha256"] = job["request_sha256"]
	jobRaw, _ = json.Marshal(job)
	if err = os.WriteFile(filepath.Join(source, "request.json"), request, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "job.json"), jobRaw, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "component-anchor")
	lease := ctx.Value(operationLeaseKey{}).(*operationLease)
	for n := 0; n < 2; n++ {
		if err = prepareAdaptedBootstrapPostgres(lease, original.Inventory, original.Variables, target, source); err != nil {
			t.Fatal(err)
		}
	}
	after, err := retentionInventory(filepath.Join(source, "bundle"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("original bundle modified")
	}
	role, err := os.ReadFile(filepath.Join(target, "bundle", "roles", "host", "tasks", "main.yml"))
	if err != nil || string(role) != "# original frozen role\n" {
		t.Fatal("original role not preserved", err)
	}
	proof, err := readRetryPrivate(filepath.Join(target, "bundle.adapter.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err = json.Unmarshal(proof, &saved); err != nil || saved["parent_request_sha256"] != job["request_sha256"] {
		t.Fatal("parent link missing", err)
	}
	if err = os.WriteFile(filepath.Join(target, "bundle", "roles", "host", "tasks", "main.yml"), []byte("# changed role\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = prepareAdaptedBootstrapPostgres(lease, original.Inventory, original.Variables, target, source); err == nil {
		t.Fatal("adapted role drift accepted")
	}
}

func localAdapterTestHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
