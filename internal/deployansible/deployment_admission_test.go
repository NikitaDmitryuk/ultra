package deployansible

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentAdmissionOwnsDispatchBetweenAnsibleGenerations(t *testing.T) {
	root := lifecycleTestDirectory(t)
	request := []byte(`{"schema":2,"args":["operator-upgrade"],"preparation":{"bound":true}}`)
	identity := executionHash(request)
	directory := filepath.Join(root, "deploy-operations", identity)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, value any) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "request.json"), request, 0600); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "deploy-operations/current.json"), map[string]any{"schema": 1, "request_sha256": identity})
	cgroup := []byte("0::/system.slice/ultra-deploy-" + identity + ".service\n")
	state := map[string]any{"schema": 1, "request_sha256": identity, "stage": "recovery_reconciled", "state": "running"}
	write(filepath.Join(directory, "state.json"), state)
	for _, other := range [][]byte{nil, []byte("0::/system.slice/ultra-ansible-controller.service\n"),
		[]byte("0::/system.slice/ultra-deploy-" + strings.Repeat("0", 64) + ".service\n")} {
		if err := checkDeploymentExecutionAdmission(root, other); err == nil {
			t.Fatal("other dispatcher admitted between child generations")
		}
	}
	if err := checkDeploymentExecutionAdmission(root, cgroup); err != nil {
		t.Fatal("coordinator child rejected:", err)
	}
	state["state"] = "blocked"
	write(filepath.Join(directory, "state.json"), state)
	if err := checkDeploymentExecutionAdmission(root, cgroup); err == nil {
		t.Fatal("blocked coordinator's surviving child admitted new dispatch")
	}
	state["state"], state["stage"] = "completed", "status"
	write(filepath.Join(directory, "state.json"), state)
	if err := checkDeploymentExecutionAdmission(root, nil); err != nil {
		t.Fatal("verified completed coordinator kept admission closed:", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "request.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkDeploymentExecutionAdmission(root, cgroup); err == nil {
		t.Fatal("changed request accepted")
	}
}
