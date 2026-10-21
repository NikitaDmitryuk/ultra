package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestBootstrapAutomationVerificationUsesSelectedGeneration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, oldResult := range []bool{false, true} {
		name := "first-generation-never-configured"
		if oldResult {
			name = "first-generation-stale-activation"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			writeResult := func(stage, result string) {
				t.Helper()
				path := filepath.Join(root, stage)
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "result.json"), []byte(result), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if oldResult {
				writeResult("automation", `{"configured":true,"activated_at":100}`)
			}
			writeResult("automation-generation-2", `{"configured":true,"activated_at":200}`)
			stub := filepath.Join(root, "ansible-playbook")
			source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
variables=json.loads((job/'variables.json').read_text())
if variables['ultra_automation_activated_at'] != 200:
    sys.exit(1)
result=job/'result.json'
result.write_text(json.dumps({'verified':True}))
result.chmod(0o600)
`
			if err := os.WriteFile(stub, []byte(source), 0700); err != nil {
				t.Fatal(err)
			}
			p := &installplan.InstallPlan{
				Automation: &installplan.AutomationConfig{Version: "v2.5.0", ReleaseDir: root, ReadinessTimeoutSec: 30},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := verifyBootstrapAutomation(ctx, p, map[string]any{"all": map[string]any{}}, root, python, stub, 2); err != nil {
				t.Fatalf("second generation readiness: %v", err)
			}
		})
	}
}

func TestBootstrapAutomationVerificationDoesNotFallbackFromInvalidGeneration(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for stage, result := range map[string]string{
		"automation":              `{"configured":true,"activated_at":100}`,
		"automation-generation-2": `{"configured":false,"activated_at":200}`,
	} {
		path := filepath.Join(root, stage)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "result.json"), []byte(result), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{Version: "v2.5.0", ReleaseDir: root, ReadinessTimeoutSec: 1}}
	for _, generation := range []int{0, 2, 101} {
		if err := verifyBootstrapAutomation(context.Background(), p, map[string]any{}, root, "/missing-python", "/missing-ansible", generation); err == nil {
			t.Fatalf("invalid generation %d accepted", generation)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "verify-automation")); !os.IsNotExist(err) {
		t.Fatal("invalid generation launched an observation")
	}
}
