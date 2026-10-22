package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestRecoveryPostActivationFirstAbsentIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "post-activation-1.started.json")
	if _, err := readOptionalRecoveryPrivate(path); !os.IsNotExist(err) {
		t.Fatalf("first attempt cannot dispatch: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"request_sha256":"bound"}`), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := readOptionalRecoveryPrivate(path)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	_ = os.Symlink("/nonexistent", path)
	if _, err = readOptionalRecoveryPrivate(path); err == nil || os.IsNotExist(err) {
		t.Fatalf("unsafe intent treated as absent: %v", err)
	}
}

func TestRecoveryActivationWatermarkRequiresExactExecutorCleanup(t *testing.T) {
	directory := t.TempDir()
	job := filepath.Join(directory, "activate")
	_ = os.Mkdir(job, 0700)
	write := func(name string, value any) []byte {
		t.Helper()
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(job, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	jobRaw := write("job.json", map[string]any{"operation": "upgrade"})
	request := write("request.json", map[string]any{"frozen": true})
	receipt := write("receipt.json", map[string]any{"state": "succeeded", "result": map[string]any{"activated_at": 123}})
	complete := map[string]any{
		"outcome":        "succeeded",
		"local_cleanup":  true,
		"receipt_sha256": digestSHA256(receipt),
		"fence": deployansible.ExecutionFence{
			Operation:     "upgrade",
			JobDirectory:  job,
			JobSHA256:     digestSHA256(jobRaw),
			RequestSHA256: digestSHA256(request),
		},
	}
	write("execution-completion.json", complete)
	if got, err := recoveryActivationWatermark(directory); err != nil || got != 123 {
		t.Fatal(got, err)
	}
	complete["local_cleanup"] = false
	write("execution-completion.json", complete)
	if _, err := recoveryActivationWatermark(directory); err == nil {
		t.Fatal("receipt without executor cleanup trusted")
	}
	complete["local_cleanup"] = true
	write("execution-completion.json", complete)
	write("job.json", map[string]any{"operation": "foreign"})
	if _, err := recoveryActivationWatermark(directory); err == nil {
		t.Fatal("changed activation job trusted")
	}
}

func TestRecoveryPostActivationUnknownChildNeverReplays(t *testing.T) {
	r := recoveryPreparationRequest{StateDirectory: t.TempDir()}
	path := filepath.Join(r.StateDirectory, "post-activation-1")
	if complete, err := completedDeployPostActivationAttempt(r.digest(), path, 100); err != nil || complete {
		t.Fatal(complete, err)
	}
	raw, _ := json.Marshal(map[string]any{"request_sha256": r.digest(), "watermark": 100, "started_at": 101})
	_ = os.WriteFile(path+".started.json", raw, 0600)
	if _, err := completedDeployPostActivationAttempt(r.digest(), path, 100); err == nil {
		t.Fatal("missing terminal authorized child replay")
	}
	terminal := map[string]any{
		"protocol":       "ultra-deploy-post-activation-v1",
		"request_sha256": r.digest(),
		"phase":          "post_activation_reconciled",
		"started_at":     101,
		"verified":       true,
	}
	raw, _ = json.Marshal(terminal)
	_ = os.WriteFile(path+".json", raw, 0600)
	if complete, err := completedDeployPostActivationAttempt(r.digest(), path, 102); err != nil || !complete {
		t.Fatal("normal old terminal must permit fresh status pass", complete, err)
	}
	terminal["request_sha256"] = "foreign"
	raw, _ = json.Marshal(terminal)
	_ = os.WriteFile(path+".json", raw, 0600)
	if _, err := completedDeployPostActivationAttempt(r.digest(), path, 102); err == nil {
		t.Fatal("foreign completion authorized replay")
	}
}
