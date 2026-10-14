package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedUpgradeRetryPreservesHistoryAndResetsRollbackCache(t *testing.T) {
	directory := t.TempDir()
	for step, state := range map[string]string{"activate": "succeeded", "rollback": "succeeded"} {
		path := filepath.Join(directory, step)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		job := map[string]any{"operation": step, "request_sha256": "fixture", "binary_sha256": "fixture"}
		receipt := map[string]any{"state": state, "request_sha256": "fixture", "binary_sha256": "fixture", "attempt": 1}
		for name, value := range map[string]map[string]any{"job.json": job, "receipt.json": receipt} {
			data, _ := json.Marshal(value)
			if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := resetFailedUpgradeAttempt(directory); err != nil {
		t.Fatal(err)
	}
	// Repeating --retry-failed after receipt removal resumes the prepared attempt.
	if err := resetFailedUpgradeAttempt(directory); err != nil {
		t.Fatal(err)
	}
	// Simulate the earlier crash boundary: job 2 with the old receipt 1 still active.
	oldReceipt, err := os.ReadFile(filepath.Join(directory, "history", "activate-attempt-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "activate", "receipt.json"), oldReceipt, 0600); err != nil {
		t.Fatal(err)
	}
	if err = resetFailedUpgradeAttempt(directory); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"activate", "rollback"} {
		if _, err := os.Stat(filepath.Join(directory, step, "receipt.json")); (step == "activate" && !os.IsNotExist(err)) || (step != "activate" && err != nil) {
			t.Fatal("activation cache not cleared or dependent history removed")
		}
		if _, err := os.Stat(filepath.Join(directory, "history", step+"-attempt-1.json")); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(directory, step, "job.json"))
		if err != nil {
			t.Fatal(err)
		}
		var job map[string]any
		expectedAttempt := any(nil)
		if step == "activate" {
			expectedAttempt = float64(2)
		}
		if json.Unmarshal(raw, &job) != nil || job["attempt"] != expectedAttempt || job["request_sha256"] != "fixture" {
			t.Fatal("attempt counter or frozen hash changed incorrectly")
		}
	}
}
func TestUpgradeRetryRejectsCommittedOrUnfailedOperations(t *testing.T) {
	if resetFailedUpgradeAttempt(t.TempDir()) == nil {
		t.Fatal("no failed operation accepted")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "commit")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "receipt.json"), []byte(`{"state":"succeeded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if resetFailedUpgradeAttempt(directory) == nil {
		t.Fatal("committed operation repeated")
	}
}
func TestAutomationStatusNeverPublishesPrivateInspection(t *testing.T) {
	result := publicAutomationStatus(map[string]any{"ready": true, "version": "v2.4.7", "identity": "private", "nodes": []string{"private"}, "pins": "private", "auto_policy": "private"})
	if len(result) != 2 || result["ready"] != true || result["version"] != "v2.4.7" {
		t.Fatal("public status projection leaked or dropped fields")
	}
}

func TestUpgradeRetryGeneratesFreshTimestampDependentStages(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
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
result=job/'result.json'
result.write_text(json.dumps({'verified':True,'activated_at':n*100}))
result.chmod(0o600)
`
	if err = os.WriteFile(executable, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{}
	variables := map[string]any{"ultra_lock_directory": root, "ultra_upgrade_observed_at": 1}
	activation, err := deployansible.RunLocal(ctx, "upgrade", inventory, variables, filepath.Join(root, "activate"), python, executable)
	if err != nil {
		t.Fatal(err)
	}
	variables["ultra_upgrade_observed_at"] = activation.Result.Values["activated_at"]
	for _, stage := range []string{"publish", "rollback"} {
		operation := stage
		if stage == "publish" {
			operation = "publish-release"
		}
		if _, err = deployansible.RunLocal(ctx, operation, inventory, variables, upgradeDependentStageDirectory(root, stage, 1), python, executable); err != nil {
			t.Fatal(err)
		}
	}
	originalRequest, err := os.ReadFile(filepath.Join(root, "publish", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = resetFailedUpgradeAttempt(root); err != nil {
		t.Fatal(err)
	}
	generation, err := upgradeActivationGeneration(root, false)
	if err != nil || generation != 2 {
		t.Fatalf("generation: %d %v", generation, err)
	}
	variables["ultra_upgrade_observed_at"] = 1
	activation, err = deployansible.RunLocal(ctx, "upgrade", inventory, variables, filepath.Join(root, "activate"), python, executable)
	if err != nil {
		t.Fatal(err)
	}
	variables["ultra_upgrade_observed_at"] = activation.Result.Values["activated_at"]
	// The previous layout reproduces the confirmed immutable-input failure.
	if _, err = deployansible.RunLocal(ctx, "publish-release", inventory, variables, filepath.Join(root, "publish"), python, executable); err == nil || !strings.Contains(err.Error(), "local operation inputs changed") {
		t.Fatal("old timestamp request unexpectedly accepted")
	}
	for _, stage := range []string{"publish", "commit"} {
		operation := "publish-release"
		if stage == "commit" {
			operation = "commit-release"
		}
		path := upgradeDependentStageDirectory(root, stage, generation)
		for i := 0; i < 2; i++ {
			if _, err = deployansible.RunLocal(ctx, operation, inventory, variables, path, python, executable); err != nil {
				t.Fatal(err)
			}
		}
		calls, _ := os.ReadFile(filepath.Join(path, "calls"))
		if string(calls) != "1" {
			t.Fatal("same generation replayed a successful stage")
		}
		variables["ultra_upgrade_observed_at"] = 300
		if _, err = deployansible.RunLocal(ctx, operation, inventory, variables, path, python, executable); err == nil {
			t.Fatal("same-generation identity changed")
		}
		variables["ultra_upgrade_observed_at"] = activation.Result.Values["activated_at"]
	}
	after, err := os.ReadFile(filepath.Join(root, "publish", "request.json"))
	if err != nil || !bytes.Equal(originalRequest, after) {
		t.Fatal("historical publish request changed")
	}
	if _, err = os.Stat(filepath.Join(root, "publish", "receipt.json")); err != nil {
		t.Fatal("historical publish receipt removed")
	}
}

func TestUpgradeInspectionFailureReleasesGateAndRetries(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, retryFailed := range []bool{false, true} {
		for _, operation := range []string{"inspect-upgrade", "inspect-release-hosts", "legacy-inspect-release-hosts", "lifecycle-applying", "lifecycle-foreign", "legacy-success", "legacy-rollback-failure"} {
			t.Run(fmt.Sprintf("%s/retry-failed=%t", operation, retryFailed), func(t *testing.T) {
				root := t.TempDir()
				if err := os.Chmod(root, 0700); err != nil {
					t.Fatal(err)
				}
				release := filepath.Join(root, "release")
				if err := os.Mkdir(release, 0700); err != nil {
					t.Fatal(err)
				}
				names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz", "ultra-install-linux-amd64", "ultra-install-linux-arm64", "ultra-ansible.tar.gz", "ultra-ansible-runtime-linux-amd64.tar.gz", "ultra-ansible-runtime-linux-arm64.tar.gz", "mobile-bootstrap.sh", "checksums.txt"}
				assets := []map[string]any{}
				for _, name := range names {
					data := []byte(name)
					if name == "ultra-recovery.tar.gz" {
						var archive bytes.Buffer
						zipped := gzip.NewWriter(&archive)
						writer := tar.NewWriter(zipped)
						for _, tool := range []string{"recovery.py", "monitor.py", "heartbeat.py", "reconcile.py", "ultra-recovery-backup.service", "ultra-recovery-backup.timer"} {
							if err := writer.WriteHeader(&tar.Header{Name: tool, Mode: 0600, Size: 4}); err != nil {
								t.Fatal(err)
							}
							if _, err := writer.Write([]byte("test")); err != nil {
								t.Fatal(err)
							}
						}
						if err := writer.Close(); err != nil {
							t.Fatal(err)
						}
						if err := zipped.Close(); err != nil {
							t.Fatal(err)
						}
						data = archive.Bytes()
					}
					if err := os.WriteFile(filepath.Join(release, name), data, 0600); err != nil {
						t.Fatal(err)
					}
					assets = append(assets, map[string]any{"name": name, "sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "size": len(data)})
				}
				manifest := map[string]any{"schema_version": 1, "version": "v2.5.0", "source_commit": strings.Repeat("a", 40), "database_schema_min": 24, "database_schema_max": 25, "capabilities": []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"}, "assets": assets}
				raw, _ := json.Marshal(manifest)
				if err := os.WriteFile(filepath.Join(release, "release-manifest.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				pins := filepath.Join(root, "known_hosts")
				if err := os.WriteFile(pins, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
				p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443", "IDENTITY": filepath.Join(root, "identity")})
				local := false
				p.ControllerLocal = &local
				p.ControllerLocalTarget = p.Bridge.SSHHost + "|" + p.Bridge.Address
				directory := filepath.Join(root, "upgrade")
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if operation == "lifecycle-foreign" {
					for _, name := range []string{"gate", "foreign-owner"} {
						if err := os.WriteFile(filepath.Join(directory, name), []byte("foreign-owner"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := os.WriteFile(filepath.Join(directory, "fail-once"), []byte(operation), 0600); err != nil {
					t.Fatal(err)
				}
				executable := filepath.Join(root, "ansible")
				source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
root=job.parent
request=json.loads((job/'request.json').read_text())
variables=request['variables']
operation=json.loads((job/'job.json').read_text())['operation']
key=operation
if operation=='lifecycle':
    key+='-'+variables['ultra_lifecycle_phase']
    if variables['ultra_lifecycle_phase']=='applying' and (root/'foreign-owner').exists():
        with (root/'calls').open('a') as log: log.write(key+'\n')
        sys.exit(1)
    (root/'gate').write_text(variables['ultra_lifecycle_phase'])
with (root/'calls').open('a') as log: log.write(key+'\n')
fail=root/'fail-once'
if fail.exists() and (fail.read_text()==key or fail.read_text()=='legacy-'+key):
    fail.unlink()
    sys.exit(1)
result={'verified':True}
if operation=='lifecycle' and variables.get('ultra_lifecycle_reserve_only'):
    result.update({'reservation_id':variables['ultra_lifecycle_id'],'reservation_phase':variables['ultra_lifecycle_phase']})
if operation=='inspect-upgrade':
    previous=json.loads((root.parent/'release'/'release-manifest.json').read_text())
    if fail.exists() and fail.read_text().startswith('legacy-'):
        previous['version']='v2.4.6'
        previous['capabilities']=['service-access-v1','provider-pool-quota-v1']
    result={'database_schema':24,'architecture':'amd64','observed_at':1,'topology_sha256':'a'*64,'identity':'fixture','nodes':[{'id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','address':'192.0.2.2','pins':'fixture'}],'previous_manifest':previous}
if operation=='resume-automation' and not (root/'activate').exists() and variables.get('ultra_legacy_bridge_maintenance'):
    sys.exit(1)
if operation=='upgrade': result['activated_at']=2
if fail.exists() and fail.read_text()=='legacy-rollback-failure' and operation in ('upgrade','rollback'):
    sys.exit(1)
if operation=='inspect-release-hosts':
    output=pathlib.Path(variables['ultra_release_inspection_directory'])/'exit_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json'
    output.write_text(json.dumps({'architecture':'amd64','observed_at':1}))
    output.chmod(0o600)
output=job/'result.json'
output.write_text(json.dumps(result))
output.chmod(0o600)
`
				if err := os.WriteFile(executable, []byte(source), 0700); err != nil {
					t.Fatal(err)
				}
				firstErr := ansibleUpgrade(context.Background(), p, release, directory, python, executable, false)
				if operation == "legacy-success" {
					if firstErr != nil {
						t.Fatalf("legacy upgrade failed: %v", firstErr)
					}
					calls, err := os.ReadFile(filepath.Join(directory, "calls"))
					if err != nil || strings.Count(string(calls), "resume-automation\n") != 1 {
						t.Fatalf("legacy success restored service states more than once: %q %v", calls, err)
					}
					return
				}
				if operation == "legacy-rollback-failure" {
					if firstErr == nil || !strings.Contains(firstErr.Error(), "upgrade_compatible_rollback_incomplete") {
						t.Fatalf("expected incomplete legacy rollback, got %v", firstErr)
					}
					calls, err := os.ReadFile(filepath.Join(directory, "calls"))
					if err != nil || strings.Contains(string(calls), "resume-automation\n") {
						t.Fatalf("incomplete legacy rollback restored producers: %q %v", calls, err)
					}
					return
				}
				if firstErr == nil || !strings.Contains(firstErr.Error(), "ansible operation failed") {
					t.Fatalf("expected inspection failure, got %v", firstErr)
				}
				gate, err := os.ReadFile(filepath.Join(directory, "gate"))
				expectedGate := "released"
				switch operation {
				case "lifecycle-applying":
					expectedGate = "applying"
				case "lifecycle-foreign":
					expectedGate = "foreign-owner"
				}
				if err != nil || string(gate) != expectedGate {
					t.Fatalf("durable gate retained after inspection failure: %q %v", gate, err)
				}
				if strings.HasPrefix(operation, "lifecycle-") {
					calls, err := os.ReadFile(filepath.Join(directory, "calls"))
					if err != nil || string(calls) != "lifecycle-applying\n" {
						t.Fatalf("unconfirmed acquisition ran cleanup or inspection: %q %v", calls, err)
					}
					if operation == "lifecycle-foreign" {
						return
					}
				}
				if _, err := os.Stat(filepath.Join(directory, "activate")); !os.IsNotExist(err) {
					t.Fatal("inspection failure reached activation")
				}
				failedStage := map[string]string{"inspect-upgrade": "inspect", "inspect-release-hosts": "hosts", "legacy-inspect-release-hosts": "hosts"}[operation]
				var original []byte
				if failedStage != "" {
					original, err = os.ReadFile(filepath.Join(directory, failedStage, "receipt.json"))
					if err != nil {
						t.Fatal(err)
					}
					requestRaw, err := os.ReadFile(filepath.Join(directory, failedStage, "request.json"))
					var request struct {
						Inventory map[string]any `json:"inventory"`
						Variables map[string]any `json:"variables"`
					}
					if err != nil || json.Unmarshal(requestRaw, &request) != nil {
						t.Fatal("failed request unavailable", err)
					}
					request.Variables["changed"] = true
					if _, err := runUpgradeInspection(context.Background(), strings.TrimPrefix(operation, "legacy-"), request.Inventory, request.Variables, filepath.Join(directory, failedStage), python, executable); err == nil || err.Error() != "upgrade_inspection_inputs_changed" {
						t.Fatal("changed inspection inputs accepted", err)
					}
					if _, err := os.Stat(filepath.Join(directory, failedStage+"-attempt-2")); !os.IsNotExist(err) {
						t.Fatal("rejected inspection created another job")
					}
				}
				// The next invocation passes the failed inspection and completes the
				// upgrade, including --retry-failed before an activation job exists.
				retryErr := ansibleUpgrade(context.Background(), p, release, directory, python, executable, retryFailed)
				if retryErr != nil {
					t.Fatalf("inspection retry did not progress: %v", retryErr)
				}
				calls, err := os.ReadFile(filepath.Join(directory, "calls"))
				if err != nil {
					t.Fatal(err)
				}
				if failedStage != "" {
					after, err := os.ReadFile(filepath.Join(directory, failedStage, "receipt.json"))
					if err != nil || !bytes.Equal(original, after) {
						t.Fatal("failed inspection receipt changed")
					}
					var receipt deployansible.Receipt
					raw, err := os.ReadFile(filepath.Join(directory, failedStage+"-attempt-2", "receipt.json"))
					if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" {
						t.Fatalf("new inspection receipt missing: %v", err)
					}
					if strings.Count(string(calls), strings.TrimPrefix(operation, "legacy-")+"\n") != 2 {
						t.Fatalf("failed inspection not retried exactly once: %s", calls)
					}
				}
				if operation == "inspect-release-hosts" && strings.Count(string(calls), "inspect-upgrade\n") != 1 {
					t.Fatal("successful inspection cache was discarded")
				}
				if _, err := runUpgradeInspection(context.Background(), "upgrade", nil, nil, directory, python, executable); err == nil || err.Error() != "upgrade_inspection_operation_required" {
					t.Fatal("mutating operation accepted by inspection retry")
				}
				if _, err := os.Stat(filepath.Join(directory, "activate", "receipt.json")); err != nil {
					t.Fatal("inspection retry never reached activation", err)
				}
				before := string(calls)
				if err := ansibleUpgrade(context.Background(), p, release, directory, python, executable, false); err != nil {
					t.Fatal("completed replay", err)
				}
				calls, err = os.ReadFile(filepath.Join(directory, "calls"))
				if err != nil || string(calls) != before {
					t.Fatal("completed replay executed another operation")
				}
				gate, err = os.ReadFile(filepath.Join(directory, "gate"))
				if err != nil || string(gate) != "released" {
					t.Fatal("retry retained applying gate")
				}
				if !strings.Contains(string(calls), "resume-automation\n") {
					t.Fatal("automation was not restored")
				}
			})
		}
	}
}
