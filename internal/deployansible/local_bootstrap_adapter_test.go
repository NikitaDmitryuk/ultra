package deployansible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
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
	for _, name := range []string{"roles/db_tunnel/tasks/reuse.yml", "roles/db_tunnel/tasks/install.yml"} {
		if err = os.WriteFile(filepath.Join(source, "bundle", name), []byte("# frozen old tunnel task\n"), 0600); err != nil {
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
	if err = VerifyAdaptedBootstrapPostgres(original.Inventory, original.Variables, target, source); err != nil {
		t.Fatal("re-entry verification failed", err)
	}
	for _, name := range bootstrapPostgresAdapterPaths {
		want, _ := ansibleassets.Bundle.ReadFile(name)
		got, readErr := os.ReadFile(filepath.Join(target, "bundle", name))
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("overlay %s did not use current source: %v", name, readErr)
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
	// A previous generation's proof remains immutable; the current identity
	// creates a new anchor, while attempting to reuse the old one fails closed.
	oldProof := []byte(`{"schema":1,"adapter_sha256":"old-generation"}`)
	if err = os.WriteFile(filepath.Join(target, "bundle.adapter.json"), oldProof, 0600); err != nil {
		t.Fatal(err)
	}
	if err = prepareAdaptedBootstrapPostgres(lease, original.Inventory, original.Variables, target, source); err == nil ||
		err.Error() != "bootstrap_adapter_proof_conflict" {
		t.Fatal("old generation accepted", err)
	}
	id, err := BootstrapPostgresAdapterID()
	if err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(root, "linked-components-"+id)
	if err = prepareAdaptedBootstrapPostgres(lease, original.Inventory, original.Variables, next, source); err != nil {
		t.Fatal("new generation rejected", err)
	}
	if got, _ := os.ReadFile(filepath.Join(target, "bundle.adapter.json")); !bytes.Equal(got, oldProof) {
		t.Fatal("previous generation proof overwritten")
	}
	if err = os.WriteFile(filepath.Join(target, "bundle.adapter.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"roles/db_tunnel/tasks/reuse.yml", "roles/db_tunnel/tasks/install.yml"} {
		path := filepath.Join(target, "bundle", name)
		current, _ := os.ReadFile(path)
		if err = os.WriteFile(path, []byte("# altered tunnel task\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = VerifyAdaptedBootstrapPostgres(original.Inventory, original.Variables, target, source); err == nil {
			t.Fatalf("changed overlay %s accepted", name)
		}
		if err = os.WriteFile(path, current, 0600); err != nil {
			t.Fatal(err)
		}
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

func TestBootstrapPostgresAdapterIdentityCoversEveryOverlay(t *testing.T) {
	original, err := BootstrapPostgresAdapterID()
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range bootstrapPostgresAdapterPaths {
		t.Run(changed, func(t *testing.T) {
			id, err := bootstrapPostgresAdapterID(func(name string) ([]byte, error) {
				data, err := ansibleassets.Bundle.ReadFile(name)
				if name == changed {
					data = append(data, '#')
				}
				return data, err
			})
			if err != nil || id == original {
				t.Fatal("overlay change did not create new generation", err)
			}
		})
	}
	want := errors.New("missing overlay")
	if _, err := bootstrapPostgresAdapterID(func(string) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal("missing source accepted", err)
	}
}
