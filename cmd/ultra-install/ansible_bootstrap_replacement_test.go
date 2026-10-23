package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestPreservedBootstrapCompletesWithoutAuxiliaryAutomation(t *testing.T) {
	for _, mode := range []string{"monolithic", "components", "without-optional-services", "regular"} {
		t.Run(mode, func(t *testing.T) {
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Skip("python unavailable")
			}
			root := githubPrivateStage(t)
			files, _, _ := githubFixture(t)
			releaseDir := retentionReleaseFixture(t, root, "v2.5.0", files)
			planRoot := filepath.Join(root, "plan")
			if err = os.Mkdir(planRoot, 0700); err != nil {
				t.Fatal(err)
			}
			directory, err := beginBootstrapAttempt(planRoot)
			if err != nil {
				t.Fatal(err)
			}
			preserve := mode != "regular"
			optional := mode != "without-optional-services"
			p := &installplan.InstallPlan{
				SchemaVersion: installplan.CurrentSchemaVersion,
				Bridge:        installplan.BridgeConfig{SSHHost: "192.0.2.1"},
				Bot:           installplan.BotConfig{Enabled: optional},
				Automation:    &installplan.AutomationConfig{ReleaseDir: releaseDir, Version: "v2.5.0", BridgeIPv4: "192.0.2.1"},
			}
			providerEnabled := mode == "components"
			if providerEnabled {
				p.Automation.CloudKeyFile = filepath.Join(root, "fixture-provider-key")
				if err = os.WriteFile(p.Automation.CloudKeyFile, []byte("fixture-provider-key"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if preserve {
				p.SourceValues = map[string]string{preservePrimarySourceKey: "true"}
			}
			if optional {
				p.Automation.Ingress = &installplan.AutomationIngress{Domain: "vpn.example.com"}
			}
			inventory := map[string]any{"all": map[string]any{
				"vars": map[string]any{"ultra_preserve_primary": preserve},
				"children": map[string]any{
					"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ultra_bot_enabled": optional}}},
					"exits":  map[string]any{"hosts": map[string]any{"exit_0": map[string]any{}}},
				},
			}}
			write := func(name string, value any) {
				t.Helper()
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("inventory.frozen.json", inventory)
			engine := ""
			if mode == "components" {
				engine = "components-v1"
			}
			write("execution-mode.json", frozenExecution{Schema: 1, BootstrapEngine: engine})
			if err = freezeOperatorPlan(directory, p, releaseDir); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(root, "operations")
			stub := filepath.Join(root, "ansible-playbook")
			source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
v=json.loads((job/'variables.json').read_text())
op=json.loads((job/'job.json').read_text())['operation']
with pathlib.Path(` + string(mustPreservedJSON(t, logPath)) + `).open('a') as f:f.write(op+':'+v.get('ultra_lifecycle_phase','')+'\n')
if op=='verify-automation':sys.exit(91)
if op=='bootstrap-automation':
 if v.get('ultra_bootstrap_recovery_enabled') is not False:sys.exit(91)
 if any(k.startswith('ultra_automation_') for k in v):sys.exit(92)
 if not all(v.get(k) for k in ('ultra_install_source','ultra_install_sha256','ultra_controller_runtime_archive','ultra_controller_runtime_sha256')):sys.exit(93)
 if bool(v.get('ultra_fleet_provider_key_source')) != json.loads('` + string(mustPreservedJSON(t, providerEnabled)) + `'):sys.exit(94)
 if v.get('ultra_fleet_provider_bridge_ip') != '192.0.2.1':sys.exit(95)
r={'verified':True}
if op=='bootstrap-exit':r.update(exit_host=v['ultra_bootstrap_exit_host'],cert_pin='a'*64)
f=job/'result.json';f.write_text(json.dumps(r));f.chmod(0o600)
`
			if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			err = applyReservedBootstrap(
				ctx,
				context.Background(),
				p,
				inventory,
				map[string]bootstrapInspection{"bridge": {Architecture: "amd64"}},
				directory,
				planRoot,
				root,
				python,
				stub,
				"human",
				release,
			)
			if !preserve {
				// The fixture recovery tar is deliberately invalid: a regular full
				// bootstrap still has to configure auxiliary automation.
				if err == nil {
					t.Fatal("regular bootstrap skipped automation")
				}
				if _, statErr := os.Stat(filepath.Join(directory, "finalization.json")); !os.IsNotExist(statErr) {
					t.Fatal("regular bootstrap finalized without automation", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			calls, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(calls), "verify-automation") || strings.Contains(string(calls), "checking") {
				t.Fatalf("auxiliary step dispatched: %s", calls)
			}
			if strings.Count(string(calls), "bootstrap-automation:") != 1 {
				t.Fatalf("required fleet controller skipped: %s", calls)
			}
			if !strings.HasSuffix(string(calls), "lifecycle:released\n") {
				t.Fatalf("lifecycle not finalized: %s", calls)
			}
			if optional && (strings.Count(string(calls), "ingress:") != 2 || !strings.Contains(string(calls), "configure-bot:")) {
				t.Fatalf("core services skipped: %s", calls)
			}
			if cached, err := completedOperatorOperation(directory, "bootstrap", ""); !cached || err != nil {
				t.Fatal("completion not sealed", cached, err)
			}
			if resumed, err := resumeBootstrapFinalization(ctx, p, directory, planRoot, python, stub); !resumed || err != nil {
				t.Fatal("sealed finalization cannot replay", err)
			}
			after, err := os.ReadFile(logPath)
			if err != nil || string(after) != string(calls) {
				t.Fatal("finalization replay dispatched mutations", err)
			}
			manifest, err := verifyAutomationRelease(releaseDir, p.Automation.Version)
			if err != nil {
				t.Fatal(err)
			}
			manifestSHA, err := sourceSHA(filepath.Join(releaseDir, "release-manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			stages := []string{"apply"}
			if mode == "components" {
				stages = []string{"bootstrap-postgres", "bootstrap-exit_0", "bootstrap-bridge"}
			}
			if optional {
				stages = append(stages, "ingress-prepare", "ingress-activate", "bot")
			}
			for _, stage := range stages {
				path := filepath.Join(directory, stage, "receipt.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = operatorWinningChain(directory, "bootstrap", manifest, manifestSHA); err == nil {
					t.Fatalf("replacement accepted missing %s receipt", stage)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestBootstrapAutomationKeepsFleetControllerWhenRecoveryDisabled(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "ansible", "playbooks", "bootstrap-automation.yml"))
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(raw)
	for _, required := range []string{"- postgres_client", "- role: fleet_access", "fleet_access_ultra_stage: generate", "fleet_access_ultra_stage: authorize", "- controller", "- role: fleet_provider\n      when: not (ultra_bootstrap_recovery_enabled | default(true) | bool)", "- role: recovery_primary\n      when: ultra_bootstrap_recovery_enabled | default(true) | bool"} {
		if !strings.Contains(playbook, required) {
			t.Fatalf("missing required controller/recovery split: %s", required)
		}
	}
	tasks, err := os.ReadFile(filepath.Join("..", "..", "deploy", "ansible", "roles", "fleet_provider", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"src: \"{{ ultra_fleet_provider_key_source }}\"", "mode: \"0600\"", "no_log: true", "ansible.builtin.stat:", "fleet_provider_existing_key:", "src: provider.conf.j2"} {
		if !strings.Contains(string(tasks), required) {
			t.Fatalf("provider configuration missing %q", required)
		}
	}
	if strings.Contains(string(tasks), "state: absent") {
		t.Fatal("missing local provider credential must not delete the installed credential")
	}
}
