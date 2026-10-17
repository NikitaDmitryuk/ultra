package deployansible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func retryFixture(t *testing.T) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"inventory":{},"variables":{}}`)
	hash := sha256.Sum256(request)
	id := hex.EncodeToString(hash[:])
	job := map[string]any{"schema_version": 1, "operation": "bootstrap", "request_sha256": id, "binary_sha256": id}
	data, _ := json.Marshal(job)
	if err := os.WriteFile(filepath.Join(root, "job.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "request.json"), request, 0600); err != nil {
		t.Fatal(err)
	}
	job["state"] = "failed"
	job["code"] = "playbook_failed"
	receipt, _ := json.Marshal(job)
	if err := os.WriteFile(filepath.Join(root, "receipt.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	return root, receipt
}

func TestRetryArchivesBeforeAdvancingAndResumesCrashes(t *testing.T) {
	for _, failAt := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			root, original := retryFixture(t)
			calls := 0
			err := retryFailedLocalAttemptWith(root, func(path string) error {
				calls++
				if calls == failAt {
					return syscall.ENOSPC
				}
				return syncDirectory(path)
			})
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("expected injected ENOSPC, got %v", err)
			}
			saved, readErr := os.ReadFile(filepath.Join(root, "history", "attempt-1.json"))
			if readErr != nil || !bytes.Equal(saved, original) {
				t.Fatal("failure history lost")
			}
			if err = retryFailedLocalAttempt(root); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(filepath.Join(root, "job.json"))
			var job map[string]any
			_ = json.Unmarshal(data, &job)
			if job["attempt"] != float64(2) {
				t.Fatalf("duplicate or missing attempt advance: %s", data)
			}
			if _, err = os.Lstat(filepath.Join(root, "receipt.json")); !os.IsNotExist(err) {
				t.Fatal("active failure retained")
			}
		})
	}
}

func TestRetryArchivesDiagnosticAndClearsItForEachAttempt(t *testing.T) {
	root, _ := retryFixture(t)
	first := []byte(`{"stage":"first failure"}`)
	diagnosticPath := filepath.Join(root, "diagnostic.json")
	if err := os.WriteFile(diagnosticPath, first, 0600); err != nil {
		t.Fatal(err)
	}
	if err := retryFailedLocalAttempt(root); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(root, "history", "diagnostic-attempt-1.json"))
	if err != nil || !bytes.Equal(saved, first) {
		t.Fatal("first attempt diagnostic was not preserved")
	}
	if _, err = os.Lstat(diagnosticPath); !os.IsNotExist(err) {
		t.Fatal("stale diagnostic survived retry")
	}

	jobPath := filepath.Join(root, "job.json")
	jobRaw, err := os.ReadFile(jobPath)
	if err != nil {
		t.Fatal(err)
	}
	var job map[string]any
	if err = json.Unmarshal(jobRaw, &job); err != nil {
		t.Fatal(err)
	}
	job["attempt"] = float64(2)
	jobRaw, _ = json.Marshal(job)
	if err = os.WriteFile(jobPath, jobRaw, 0600); err != nil {
		t.Fatal(err)
	}
	job["attempt"] = float64(2)
	job["state"] = "failed"
	job["code"] = "playbook_failed"
	receiptRaw, _ := json.Marshal(job)
	if err = os.WriteFile(filepath.Join(root, "receipt.json"), receiptRaw, 0600); err != nil {
		t.Fatal(err)
	}
	second := []byte(`{"stage":"second failure"}`)
	if err = os.WriteFile(diagnosticPath, second, 0600); err != nil {
		t.Fatal(err)
	}
	if err = retryFailedLocalAttempt(root); err != nil {
		t.Fatal(err)
	}
	saved, err = os.ReadFile(filepath.Join(root, "history", "diagnostic-attempt-2.json"))
	if err != nil || !bytes.Equal(saved, second) {
		t.Fatal("second attempt diagnostic was not preserved")
	}
}

func TestRetryRejectsConflictWithoutErasingFailure(t *testing.T) {
	cases := map[string]func(string){
		"changed request": func(root string) { _ = os.WriteFile(filepath.Join(root, "request.json"), []byte("{}"), 0600) },
		"history collision": func(root string) {
			_ = os.Mkdir(filepath.Join(root, "history"), 0700)
			_ = os.WriteFile(filepath.Join(root, "history", "attempt-1.json"), []byte("{}"), 0600)
		},
		"diagnostic history collision": func(root string) {
			_ = os.Mkdir(filepath.Join(root, "history"), 0700)
			_ = os.WriteFile(filepath.Join(root, "history", "diagnostic-attempt-1.json"), []byte("{}"), 0600)
			_ = os.WriteFile(filepath.Join(root, "diagnostic.json"), []byte(`{"stage":"failure"}`), 0600)
		},
		"job advanced without archive": func(root string) {
			data, _ := os.ReadFile(filepath.Join(root, "job.json"))
			var job map[string]any
			_ = json.Unmarshal(data, &job)
			job["attempt"] = 2
			data, _ = json.Marshal(job)
			_ = os.WriteFile(filepath.Join(root, "job.json"), data, 0600)
		},
		"corrupt binary hash": func(root string) {
			for _, name := range []string{"job.json", "receipt.json"} {
				data, _ := os.ReadFile(filepath.Join(root, name))
				var metadata map[string]any
				_ = json.Unmarshal(data, &metadata)
				metadata["binary_sha256"] = "bad"
				data, _ = json.Marshal(metadata)
				_ = os.WriteFile(filepath.Join(root, name), data, 0600)
			}
		},
		"receipt symlink": func(root string) {
			_ = os.Rename(filepath.Join(root, "receipt.json"), filepath.Join(root, "elsewhere"))
			_ = os.Symlink(filepath.Join(root, "elsewhere"), filepath.Join(root, "receipt.json"))
		},
		"private history": func(root string) { _ = os.Mkdir(filepath.Join(root, "history"), 0755) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root, _ := retryFixture(t)
			mutate(root)
			before, _ := os.ReadFile(filepath.Join(root, "receipt.json"))
			if err := retryFailedLocalAttempt(root); err == nil {
				t.Fatal("conflict accepted")
			}
			after, _ := os.ReadFile(filepath.Join(root, "receipt.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("failure erased")
			}
		})
	}
}

func TestExplicitLocalRetryPreservesFrozenBundleAndSuccessCache(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	executable := filepath.Join(root, "ansible")
	source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
count=job/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
if n==1:sys.exit(1)
result=job/'result.json'
result.write_text(json.dumps({'verified':True}))
result.chmod(0o600)
`
	if err = os.WriteFile(executable, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "apply")
	inventory := map[string]any{}
	vars := map[string]any{"ultra_lock_directory": root}
	if _, err = RunLocal(ctx, "bootstrap", inventory, vars, directory, python, executable); err == nil {
		t.Fatal("initial failure missing")
	}
	bundle := filepath.Join(directory, "bundle", "controller.py")
	original, _ := os.ReadFile(bundle)
	if _, err = RunLocal(ctx, "bootstrap", inventory, vars, directory, python, executable); err == nil {
		t.Fatal("ordinary invocation retried failure")
	}
	if _, err = RunLocalRetryFailed(context.Background(), "bootstrap", inventory, vars, directory, python, executable); err == nil {
		t.Fatal("retry without lease accepted")
	}
	other := t.TempDir()
	_ = os.Chmod(other, 0700)
	wrong, unlock, lockErr := WithOperationLock(context.Background(), other)
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	if _, err = RetryFrozenBootstrap(wrong, directory, python, executable); err == nil {
		t.Fatal("wrong infrastructure lease accepted")
	}
	unlock()
	vars["changed"] = true
	if _, err = RunLocalRetryFailed(ctx, "bootstrap", inventory, vars, directory, python, executable); err == nil {
		t.Fatal("changed inputs retried")
	}
	delete(vars, "changed")
	if _, err = os.Stat(filepath.Join(directory, "receipt.json")); err != nil {
		t.Fatal("rejected retry removed receipt")
	}
	for i := 0; i < 2; i++ {
		if _, err = RetryFrozenBootstrap(ctx, directory, python, executable); err != nil {
			t.Fatal(err)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(directory, "calls"))
	if string(calls) != "2" {
		t.Fatalf("unexpected execution count %s", calls)
	}
	if _, err = RetryFrozenBootstrapWithLock(context.Background(), directory, python, executable); err == nil {
		t.Fatal("frozen lease already held but retry acquired it")
	}
	release()
	if _, err = RetryFrozenBootstrapWithLock(context.Background(), directory, python, executable); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(bundle)
	if !bytes.Equal(original, after) {
		t.Fatal("frozen bundle changed")
	}
	if _, err = os.Stat(filepath.Join(directory, "history", "attempt-1.json")); err != nil {
		t.Fatal("failure archive missing")
	}
}

func TestFrozenBootstrapRetryRejectsMissingOrInvalidLock(t *testing.T) {
	for _, value := range []any{nil, "relative", 7, "/path-that-does-not-exist"} {
		root := t.TempDir()
		_ = os.Chmod(root, 0700)
		variables := map[string]any{}
		if value != nil {
			variables["ultra_lock_directory"] = value
		}
		raw, _ := json.Marshal(map[string]any{"inventory": map[string]any{}, "variables": variables})
		if err := os.WriteFile(filepath.Join(root, "request.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		jobRaw, _ := json.Marshal(map[string]any{"operation": "bootstrap", "request_sha256": hex.EncodeToString(hash[:])})
		if err := os.WriteFile(filepath.Join(root, "job.json"), jobRaw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := RetryFrozenBootstrapWithLock(context.Background(), root, "/usr/bin/python3", "/bin/false"); err == nil {
			t.Fatalf("invalid frozen lock accepted: %v", value)
		}
	}
}

func TestUpgradeCompensationRetryExactRequestAndReceipt(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, test := range []struct{ operation, action string }{
		{"upgrade-runtime", "prepare"}, {"upgrade-runtime", "commit"}, {"upgrade-runtime", "rollback"}, {"upgrade-runtime", "tls-release"},
		{"rollback", "rollback"},
		{"upgrade-domain", "apply"}, {"upgrade-domain", "accept"}, {"upgrade-domain", "rollback"}, {"upgrade-domain", "retire"}, {"upgrade-domain", "finalize"},
		{"upgrade-dns-migration", "prepare"}, {"upgrade-dns-migration", "promote"}, {"upgrade-dns-migration", "retire"}, {"upgrade-dns-migration", "rollback"},
	} {
		operation := test.operation
		t.Run(operation+"/"+test.action, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, unlock, err := WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			executable := filepath.Join(root, "ansible")
			source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
count=job/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
if n==1:sys.exit(1)
result=job/'result.json'
result.write_text(json.dumps({'verified':True}))
result.chmod(0o600)
`
			if err := os.WriteFile(executable, []byte(source), 0700); err != nil {
				t.Fatal(err)
			}
			variables := map[string]any{
				"ultra_lock_directory":        root,
				"ultra_runtime_action":        "rollback",
				"ultra_runtime_effect_inputs": map[string]string{"bridge": "exact"},
				"ultra_upgrade_domain_action": "rollback",
				"ultra_dns_migration_action":  "rollback",
			}
			if test.action == "tls-release" {
				variables["ultra_managed_tunnel_requests"] = map[string]string{"exit_fixture": "exact"}
				variables["ultra_managed_tunnel_hook_sha256"] = strings.Repeat("a", 64)
			}
			variables["ultra_runtime_action"] = test.action
			variables["ultra_upgrade_domain_action"] = test.action
			variables["ultra_dns_migration_action"] = test.action
			stage := filepath.Join(root, "rollback")
			if _, err := RunLocal(ctx, operation, map[string]any{}, variables, stage, python, executable); err == nil {
				t.Fatal("missing failed rollback")
			}
			original, err := os.ReadFile(filepath.Join(stage, "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RunLocal(ctx, operation, map[string]any{}, variables, stage, python, executable); err == nil {
				t.Fatal("ordinary replay retried failed rollback")
			}
			variables["changed"] = true
			if _, err := RunLocalRetryFailed(ctx, operation, map[string]any{}, variables, stage, python, executable); err == nil {
				t.Fatal("changed compensation accepted")
			}
			delete(variables, "changed")
			for range 2 {
				if _, err := RunLocalRetryFailed(ctx, operation, map[string]any{}, variables, stage, python, executable); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(filepath.Join(stage, "request.json"))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("frozen request changed", err)
			}
			calls, _ := os.ReadFile(filepath.Join(stage, "calls"))
			if string(calls) != "2" {
				t.Fatalf("executions: %s", calls)
			}
			if _, err := os.Stat(filepath.Join(stage, "history", "attempt-1.json")); err != nil {
				t.Fatal("failed receipt not preserved", err)
			}
		})
	}
	for _, operation := range []string{"upgrade", "restore", "upgrade-runtime", "upgrade-domain", "upgrade-dns-migration", "rollback"} {
		if localRetryOperation(
			operation,
			map[string]any{
				"ultra_runtime_action":        "apply",
				"ultra_upgrade_domain_action": "arbitrary",
				"ultra_dns_migration_action":  "arbitrary",
			},
		) {
			t.Fatalf("unauthorized retry: %s", operation)
		}
	}
}
