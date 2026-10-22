package deployansible

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeploymentBackgroundReadyNeverCreatesOrOpensUnfinishedOperation(t *testing.T) {
	root, _ := executionFixture(t)
	if err := DeploymentBackgroundReady(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "deploy-operations")); !os.IsNotExist(err) {
		t.Fatal("read-only check created state")
	}
	request := []byte(`{"schema":2,"args":["operator-upgrade"]}`)
	sha := executionHash(request)
	directory := filepath.Join(root, "deploy-operations", sha)
	_ = os.MkdirAll(directory, 0700)
	_ = os.WriteFile(filepath.Join(directory, "request.json"), request, 0600)
	pointer, _ := json.Marshal(map[string]any{"schema": 1, "request_sha256": sha})
	_ = os.WriteFile(filepath.Join(root, "deploy-operations", "current.json"), pointer, 0600)
	for _, state := range []string{"submitted", "running", "blocked", "retry_prepared", "completed"} {
		raw, _ := json.Marshal(map[string]any{"schema": 1, "request_sha256": sha, "stage": "status", "state": state})
		_ = os.WriteFile(filepath.Join(directory, "state.json"), raw, 0600)
		err := DeploymentBackgroundReady()
		if (err == nil) != (state == "completed") {
			t.Fatalf("state %s: %v", state, err)
		}
		after, _ := os.ReadFile(filepath.Join(directory, "state.json"))
		if string(raw) != string(after) {
			t.Fatal("check mutated state")
		}
	}
	_ = os.WriteFile(filepath.Join(directory, "request.json"), []byte("changed"), 0600)
	if DeploymentBackgroundReady() == nil {
		t.Fatal("changed request opened background gate")
	}
}
