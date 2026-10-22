package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedControllerEnvelopeRequiresExactRunningUpgradeSupervisor(t *testing.T) {
	root := t.TempDir()
	r := deployOperationRequest{
		Schema:      2,
		Args:        []string{"operator-upgrade"},
		Preparation: &recoveryPreparationRequest{Protocol: "fixture"},
	}
	raw, _ := json.Marshal(r)
	sha := digestSHA256(raw)
	dir := filepath.Join(root, sha)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for path, v := range map[string]any{filepath.Join(root, "current.json"): map[string]any{"schema": 1, "request_sha256": sha}, filepath.Join(dir, "request.json"): r} {
		if err := saveDeployOperation(path, v); err != nil {
			t.Fatal(err)
		}
	}
	cgroup := []byte("0::/system.slice/ultra-deploy-" + sha + ".service\n")
	for _, tc := range []struct {
		stage, state    string
		cg              []byte
		valid, ordinary bool
	}{
		{"upgrade", "running", cgroup, true, false}, {"upgrade", "running", []byte("0::/foreign\n"), false, false},
		{"tools_staged", "running", cgroup, false, false}, {"upgrade", "blocked", cgroup, false, false},
		{"status", "completed", []byte("0::/foreign\n"), true, true},
	} {
		t.Run(tc.stage+tc.state+string(tc.cg), func(t *testing.T) {
			if err := saveDeployOperation(filepath.Join(dir, "state.json"), deployOperationState{1, sha, tc.stage, tc.state, ""}); err != nil {
				t.Fatal(err)
			}
			_, got, err := preparedControllerEnvelope(root, tc.cg)
			if (err == nil) != tc.valid || (tc.valid && (got == nil) != tc.ordinary) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestPreparedControllerRetainsHistoricalRollbackAndRawCandidateInspection(t *testing.T) {
	candidate := map[string]any{"directory": "/candidate", "unit_sha256": strings.Repeat("a", 64)}
	rollback := map[string]any{"directory": "/original", "unit_sha256": strings.Repeat("b", 64)}
	spec := map[string]any{
		"operation_id":    "operation",
		"scope_sha256":    "scope",
		"manifest_sha256": "manifest",
		"proof":           map[string]any{"candidate": candidate, "rollback": rollback},
	}
	inspection := upgradeInspection{
		ControllerDirectory: "/candidate",
		ControllerUnitSHA:   strings.Repeat("a", 64),
		PreviousManifestSHA: "baseline",
	}
	policy := map[string]any{
		"policy":                   retainPreparedControllerPolicy,
		"operation_id":             "operation",
		"scope_sha256":             "scope",
		"manifest_sha256":          "manifest",
		"candidate":                candidate,
		"baseline_manifest_sha256": "baseline",
	}
	directory, unit, err := preparedControllerRollbackIdentity(policy, spec, inspection)
	if err != nil || directory != "/original" || unit != rollback["unit_sha256"] || inspection.ControllerDirectory != "/candidate" {
		t.Fatalf("%s %s %v %+v", directory, unit, err, inspection)
	}
	policy["operation_id"] = "foreign"
	if _, _, err = preparedControllerRollbackIdentity(policy, spec, inspection); err == nil {
		t.Fatal("foreign policy accepted")
	}
	directory, _, err = preparedControllerRollbackIdentity(nil, spec, inspection)
	if err != nil || directory != "/candidate" {
		t.Fatal("ordinary subsequent upgrade lost actual predecessor")
	}
}

func TestPreparedControllerEnvelopeAbsentAndUnsafePointer(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{root, filepath.Join(root, "not-created")} {
		if identity, envelope, err := preparedControllerEnvelope(directory, nil); err != nil || identity != "" || envelope != nil {
			t.Fatalf("ordinary upgrade without supervisor record: %q %+v %v", identity, envelope, err)
		}
	}
	path := filepath.Join(root, "current.json")
	target := filepath.Join(root, "other.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparedControllerEnvelope(root, nil); err == nil {
		t.Fatal("symlink pointer accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparedControllerEnvelope(root, nil); err == nil {
		t.Fatal("malformed pointer treated as absent")
	}
}
