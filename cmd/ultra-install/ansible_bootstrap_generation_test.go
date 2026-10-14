package main

import (
	"bytes"
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

func TestBootstrapRollbackReappliesCompletedStagesWithSameFrozenIdentity(t *testing.T) {
	for _, interruption := range []string{"proof-publication", "running", "missing", "failed"} {
		t.Run(interruption, func(t *testing.T) {
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Skip("python unavailable")
			}
			root := t.TempDir()
			if err = os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			directory, err := beginBootstrapAttempt(root)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]string{"adoption-maintenance.json": `{"legacy":true}`, "inventory.frozen.json": `{"all":{}}`} {
				if err = os.WriteFile(filepath.Join(directory, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			inventory := map[string]any{"all": map[string]any{}}
			stub := filepath.Join(root, "ansible-playbook")
			source := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
variables=json.loads((job/'variables.json').read_text())
operation=json.loads((job/'job.json').read_text())['operation']
if operation=='inspect-bootstrap':
 inventory=json.loads((job/'inventory.json').read_text())
 inspection=pathlib.Path(inventory['all']['vars']['ultra_inspect_dir'])
 (inspection/'bridge.json').write_text(json.dumps({'architecture':'amd64'}))
root=job.parent.parent
with (root/'operations').open('a') as stream:stream.write(operation+'\n')
fail=root/'failed-bot-once'
if operation=='configure-bot' and not fail.exists():
 fail.write_text('1')
 sys.exit(1)
result=job/'result.json';result.write_text(json.dumps({'verified':True}));result.chmod(0o600)
`
			if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			pins := filepath.Join(root, "known-hosts")
			if err = os.WriteFile(pins, []byte("synthetic fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
			p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "192.0.2.1", RemoteDir: "/etc/ultra-relay"}, SSH: installplan.SSHConfig{Identity: filepath.Join(root, "identity")}, Bot: installplan.BotConfig{Enabled: true}}
			if _, _, err = inspectBootstrap(ctx, p, filepath.Join(directory, "post-gate"), python, stub, root); err != nil {
				t.Fatal(err)
			}
			if err = applyReservedBootstrap(ctx, context.Background(), p, inventory, nil, directory, root, root, python, stub, "human", release); err == nil {
				t.Fatal("bot failure missing")
			}
			request, err := os.ReadFile(filepath.Join(directory, "apply", "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := os.ReadFile(filepath.Join(directory, "apply", "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			// Model an older immutable installer bundle, distinct from current Export.
			for _, stage := range []string{"apply", "bot"} {
				path := filepath.Join(directory, stage, "bundle", "controller.py")
				raw, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = os.WriteFile(path, append(raw, []byte("\n# original prior-version bundle\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Recreate a crash after durable successful rollback, before proof publication.
			if err = os.Remove(filepath.Join(directory, "rollback-generation-1.json")); err != nil {
				t.Fatal(err)
			}
			rollbackPath := filepath.Join(directory, "rollback-adoption", "receipt.json")
			switch interruption {
			case "missing":
				if err = os.Remove(rollbackPath); err != nil {
					t.Fatal(err)
				}
			case "running", "failed":
				raw, readErr := os.ReadFile(rollbackPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var value map[string]any
				if err = json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				value["state"] = interruption
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(rollbackPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			resumed, err := beginBootstrapAttempt(root)
			if err != nil || resumed != directory {
				t.Fatal("attempt UUID changed", err)
			}
			frozen, previous, err := prepareReservedBootstrap(ctx, p, inventory, nil, directory, root, python, stub)
			if err != nil || previous["bridge"].Architecture != "amd64" {
				t.Fatal("original checkpoint not re-reserved", err)
			}
			frozenRaw, _ := json.Marshal(frozen)
			if string(frozenRaw) != `{"all":{}}` {
				t.Fatal("new baseline captured")
			}
			if err = applyReservedBootstrap(ctx, context.Background(), p, inventory, nil, directory, root, root, python, stub, "human", release); err != nil {
				t.Fatal(err)
			}
			calls, err := os.ReadFile(filepath.Join(root, "operations"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(calls), "reserve-rolledback-bootstrap\n") != 1 || strings.Contains(string(calls), "prepare-controller") {
				t.Fatalf("original checkpoint re-captured: %s", calls)
			}
			rollbackCalls := 1
			if interruption != "proof-publication" {
				rollbackCalls = 2
			}
			if interruption == "failed" {
				if _, err = os.Stat(filepath.Join(directory, "rollback-adoption", "history", "attempt-1.json")); err != nil {
					t.Fatal("failed rollback history erased", err)
				}
			}
			if strings.Count("\n"+string(calls), "\nbootstrap\n") != 2 || strings.Count(string(calls), "configure-bot\n") != 2 || strings.Count(string(calls), "rollback-adoption\n") != rollbackCalls {
				t.Fatalf("undone success cache reused: %s", calls)
			}
			for name, original := range map[string][]byte{"request.json": request, "receipt.json": receipt} {
				after, readErr := os.ReadFile(filepath.Join(directory, "apply", name))
				if readErr != nil || !bytes.Equal(original, after) {
					t.Fatal("old generation changed", name)
				}
			}
			nextRequest, err := os.ReadFile(filepath.Join(directory, "apply-generation-2", "request.json"))
			if err != nil || !bytes.Equal(request, nextRequest) {
				t.Fatal("retry changed frozen inputs")
			}
			for _, stage := range []string{"apply", "bot"} {
				oldBundle, oldErr := os.ReadFile(filepath.Join(directory, stage, "bundle", "controller.py"))
				newBundle, newErr := os.ReadFile(filepath.Join(directory, stage+"-generation-2", "bundle", "controller.py"))
				if oldErr != nil || newErr != nil || !bytes.Equal(oldBundle, newBundle) {
					t.Fatal("original controller bundle not pinned", stage)
				}
			}
			if _, err = os.Stat(filepath.Join(directory, "rollback-generation-1.json")); err != nil {
				t.Fatal("rollback proof not reconstructed")
			}
			rollbackReceiptPath := filepath.Join(directory, "rollback-adoption", "receipt.json")
			rollbackReceipt, err := os.ReadFile(rollbackReceiptPath)
			if err != nil {
				t.Fatal(err)
			}
			failed := bytes.Replace(rollbackReceipt, []byte(`"state":"succeeded"`), []byte(`"state":"failed"`), 1)
			// Python JSON includes spaces; tolerate its serialized spelling.
			failed = bytes.Replace(failed, []byte(`"state": "succeeded"`), []byte(`"state": "failed"`), 1)
			if bytes.Equal(failed, rollbackReceipt) {
				t.Fatal("fixture state replacement missing")
			}
			if err = os.WriteFile(rollbackReceiptPath, failed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = bootstrapMutationGeneration(directory, inventory); err == nil {
				t.Fatal("failed rollback unlocked generation")
			}
			if err = os.WriteFile(rollbackReceiptPath, rollbackReceipt, 0600); err != nil {
				t.Fatal(err)
			}
			// Corrupt proof cannot unlock another generation or erase its evidence.
			if err = os.WriteFile(filepath.Join(directory, "rollback-generation-1.json"), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = bootstrapMutationGeneration(directory, inventory); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}
