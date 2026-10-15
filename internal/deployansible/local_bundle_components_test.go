package deployansible

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComponentAnchorRejectsInventoryDriftAndOtherOperations(t *testing.T) {
	source, _ := retryFixture(t)
	request := []byte(`{"inventory":{"all":{"children":{"exits":{"hosts":{"exit_0":{"ansible_host":"192.0.2.1"}}}}}},"variables":{}}`)
	hash := sha256.Sum256(request)
	digest := hex.EncodeToString(hash[:])
	job, _ := json.Marshal(
		map[string]any{"schema_version": 1, "operation": "bootstrap-postgres", "request_sha256": digest, "binary_sha256": digest},
	)
	if err := os.WriteFile(filepath.Join(source, "request.json"), request, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "job.json"), job, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Export(filepath.Join(source, "bundle")); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"bootstrap-exit", "bootstrap-bridge", "configure-bot", "ingress", "bootstrap-automation"} {
		if _, err := pinnedBootstrapExporter(source, filepath.Join(source, operation), operation, request); err != nil {
			t.Fatal(operation, err)
		}
	}
	changed := []byte(`{"inventory":{"all":{}},"variables":{}}`)
	if _, err := pinnedBootstrapExporter(source, filepath.Join(source, "changed"), "bootstrap-exit", changed); err == nil {
		t.Fatal("different fleet accepted")
	}
	if _, err := pinnedBootstrapExporter(source, filepath.Join(source, "other"), "adopt", request); err == nil {
		t.Fatal("unrelated operation accepted")
	}
}
