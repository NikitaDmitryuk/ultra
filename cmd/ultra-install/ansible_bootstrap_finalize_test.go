package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestVerifiedBootstrapFinalizationFaultsNeverRollbackAcceptedFleet(t *testing.T) {
	for _, fault := range []string{"attempt-journal", "release-reply"} {
		t.Run(fault, func(t *testing.T) {
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Skip("Python unavailable")
			}
			root := t.TempDir()
			if err = os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "attempt-fault")
			if err = os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{"adoption-maintenance.json": `{"legacy":true}`, "inventory.frozen.json": `{"all":{}}`} {
				if err = os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			faultPath := filepath.Join(root, "fail-release")
			if fault == "attempt-journal" {
				faultPath = filepath.Join(root, "attempt.json")
				if err = os.Mkdir(faultPath, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err = os.WriteFile(faultPath, []byte("1"), 0600); err != nil {
				t.Fatal(err)
			}
			stub := filepath.Join(root, "ansible-playbook")
			source := "#!" + python + `
import json,pathlib,sys
variables=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
job=pathlib.Path(variables['ultra_result_file']).parent
root=job.parent.parent
operation=json.loads((job/'job.json').read_text())['operation']
with (root/'operations').open('a') as stream: stream.write(operation+':'+str(variables.get('ultra_lifecycle_phase',''))+'\n')
if variables.get('ultra_lifecycle_phase')=='released' and (root/'fail-release').exists(): sys.exit(1)
result=pathlib.Path(variables['ultra_result_file']); result.write_text(json.dumps({'verified':True})); result.chmod(0o600)
`
			if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "192.0.2.1"}}
			err = applyReservedBootstrap(ctx, context.Background(), p, map[string]any{"all": map[string]any{}}, nil, directory, root, root, python, stub, "human", release)
			if err == nil {
				t.Fatal("finalization fault reported success")
			}
			operations, err := os.ReadFile(filepath.Join(root, "operations"))
			if err != nil {
				t.Fatal(err)
			}
			if string(operations) != "bootstrap:\nlifecycle:released\n" {
				t.Fatalf("verified fleet was rolled back: %s", operations)
			}
			if err = os.Remove(faultPath); err != nil {
				t.Fatal(err)
			}
			resumed, err := resumeBootstrapFinalization(ctx, p, directory, root, python, stub)
			if !resumed || err != nil {
				t.Fatal("finalization did not resume", err)
			}
			operations, err = os.ReadFile(filepath.Join(root, "operations"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(operations), "bootstrap:") != 1 || strings.Contains(string(operations), "rollback") {
				t.Fatalf("retry reapplied/rolled back fleet: %s", operations)
			}
			completed, err := os.ReadFile(filepath.Join(root, "attempt.json"))
			if err != nil || !strings.Contains(string(completed), `"complete":true`) {
				t.Fatal("attempt completion missing", err)
			}
			if err = os.WriteFile(filepath.Join(directory, "inventory.frozen.json"), []byte(`{"all":{"changed":true}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = resumeBootstrapFinalization(ctx, p, directory, root, python, stub); err == nil {
				t.Fatal("finalization accepted changed frozen topology")
			}
		})
	}
}
