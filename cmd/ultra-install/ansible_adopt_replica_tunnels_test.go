package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestAdoptionReplicaTunnelFrozenInputs(t *testing.T) {
	directory := t.TempDir()
	topology := adoptionTopology{Nodes: []adoptionTopologyNode{{ID: "11111111-1111-4111-8111-111111111111", Name: "actual-enabled", Address: "192.0.2.10", Port: 8443, TunnelUUID: "22222222-2222-4222-8222-222222222222", CertPin: strings.Repeat("a", 64), Priority: 100, Enabled: true, Pins: "192.0.2.10 ssh-ed25519 fixture\n"}}}
	common := map[string]any{"ansible_ssh_private_key_file": filepath.Join(directory, "identity")}
	inventory := map[string]any{"all": map[string]any{"vars": common, "children": map[string]any{"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_host": "192.0.2.1"}}}}}}
	if err := os.Mkdir(filepath.Join(directory, "post-gate"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := applyAdoptionTopology(&installplan.InstallPlan{}, inventory, filepath.Join(directory, "post-gate"), topology); err != nil {
		t.Fatal(err)
	}
	inspection := bootstrapInspection{}
	spec := []byte(`{"role":"bridge","database":{"dsn":"postgres://fixture@127.0.0.1:5544/fixture?sslmode=disable"}}`)
	inspection.Files = append(inspection.Files, struct {
		Content string `json:"content"`
		Source  string `json:"source"`
	}{Content: base64.StdEncoding.EncodeToString(spec), Source: "/etc/ultra-relay/spec.json"})
	var prior config.Spec
	if err := json.Unmarshal(spec, &prior); err != nil {
		t.Fatal(err)
	}
	selected, variables, err := adoptionReplicaTunnelInventory(inventory, topology, inspection, directory, directory, 0)
	if err != nil {
		t.Fatal(err)
	}
	if variables["ultra_replica_slot"] != "ultra_11111111111141118111111111111111" || variables["ultra_replica_primary_port"] != 5544 || variables["ultra_replica_address"] != "192.0.2.10" || variables["ultra_lock_directory"] != directory {
		t.Fatal("actual frozen ID/address or existing port lost")
	}
	children := selected["all"].(map[string]any)["children"].(map[string]any)
	if len(children) != 2 || children["bridge"] == nil || children["exits"] == nil || variables["ultra_bootstrap_replica_host"] != "exit_0" {
		t.Fatal("full frozen inventory or exact target alias lost")
	}
	original, _ := json.Marshal(inventory)
	derived, _ := json.Marshal(selected)
	if string(original) != string(derived) {
		t.Fatal("frozen inventory changed")
	}
	for _, change := range []func(){
		func() { topology.Nodes[0].ID = "foreign" },
		func() { topology.Nodes[0].Address = "192.0.2.99" },
		func() { topology.Nodes[0].Pins = "changed" },
		func() { common["ansible_ssh_private_key_file"] = "relative" },
	} {
		oldNode := topology.Nodes[0]
		oldIdentity := common["ansible_ssh_private_key_file"]
		change()
		if _, _, err = adoptionReplicaTunnelInventory(inventory, topology, inspection, directory, directory, 0); err == nil {
			t.Fatal("changed frozen input accepted")
		}
		topology.Nodes[0] = oldNode
		common["ansible_ssh_private_key_file"] = oldIdentity
	}
	oldSpecification := inspection.Files[0].Content
	for _, dsn := range []string{"", "   "} {
		fixture, _ := json.Marshal(map[string]any{"role": "bridge", "database": map[string]any{"dsn": dsn}})
		inspection.Files[0].Content = base64.StdEncoding.EncodeToString(fixture)
		if _, _, err = adoptionReplicaTunnelInventory(inventory, topology, inspection, directory, directory, 0); err == nil {
			t.Fatal("empty frozen DSN accepted implicit PostgreSQL defaults")
		}
	}
	inspection.Files[0].Content = oldSpecification
	pins := filepath.Join(directory, "post-gate", "topology-exit_0.known_hosts")
	if err = os.Chmod(pins, 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err = adoptionReplicaTunnelInventory(inventory, topology, inspection, directory, directory, 0); err == nil {
		t.Fatal("untrusted pin file accepted")
	}
}

func TestAdoptionReplicaTunnelPinnedRetryAndGeneration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "attempt")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	topology := adoptionTopology{Nodes: []adoptionTopologyNode{{ID: "11111111-1111-4111-8111-111111111111", Name: "actual-enabled", Address: "192.0.2.10", Port: 8443, TunnelUUID: "22222222-2222-4222-8222-222222222222", CertPin: strings.Repeat("a", 64), Priority: 100, Enabled: true, Pins: "192.0.2.10 ssh-ed25519 fixture\n"}}}
	inventory := map[string]any{"all": map[string]any{"vars": map[string]any{"ansible_ssh_private_key_file": filepath.Join(root, "identity")}, "children": map[string]any{"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_host": "192.0.2.1"}}}, "unrelated": map[string]any{"hosts": map[string]any{"reserved": map[string]any{}}}}}}
	if err = os.Mkdir(filepath.Join(directory, "post-gate"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = applyAdoptionTopology(&installplan.InstallPlan{}, inventory, filepath.Join(directory, "post-gate"), topology); err != nil {
		t.Fatal(err)
	}
	inspection := bootstrapInspection{}
	inspection.Files = append(inspection.Files, struct {
		Content string `json:"content"`
		Source  string `json:"source"`
	}{Content: base64.StdEncoding.EncodeToString([]byte(`{"role":"bridge","database":{"dsn":"postgres://fixture@127.0.0.1:5544/fixture?sslmode=disable"}}`)), Source: "/etc/ultra-relay/spec.json"})
	expected, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "expected.json"), expected, 0600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
meta=json.loads((job/'job.json').read_text())
variables=json.loads((job/'variables.json').read_text())
inventory=json.loads((job/'inventory.json').read_text())
assert inventory==json.loads((job.parent/'expected.json').read_text())
operation=meta['operation']
with (job.parent/'calls').open('a') as f:f.write(operation+'\n')
if operation=='adopt-replica-tunnels':
 assert variables['ultra_bootstrap_replica_host']=='exit_0'
 assert variables['ultra_replica_slot']=='ultra_11111111111141118111111111111111'
 assert variables['ultra_replica_primary_port']==5544
 assert pathlib.Path(variables['ultra_lock_directory'])==job.parent.parent
 failure=job.parent/'fail-once'
 if failure.exists():failure.unlink();sys.exit(1)
result=job/'result.json';result.write_text('{"verified":true}');result.chmod(0o600)
`
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	anchor := bootstrapMutationStage(directory, "bootstrap-postgres", 1)
	if _, err = deployansible.RunLocal(ctx, "bootstrap-postgres", inventory, map[string]any{}, anchor, python, stub); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "fail-once"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = runAdoptionReplicaTunnels(ctx, inventory, topology, inspection, directory, root, 1, python, stub); err == nil {
		t.Fatal("failed transport stage reported success")
	}
	for _, generation := range []int{1, 1, 2} {
		if err = runAdoptionReplicaTunnels(ctx, inventory, topology, inspection, directory, root, generation, python, stub); err != nil {
			t.Fatal(err)
		}
	}
	calls, err := os.ReadFile(filepath.Join(directory, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if string(calls) != "bootstrap-postgres\nadopt-replica-tunnels\nadopt-replica-tunnels\nadopt-replica-tunnels\n" {
		t.Fatalf("retry/cache/generation calls = %q", calls)
	}
	original, err := os.ReadFile(filepath.Join(anchor, "bundle", "controller.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, generation := range []int{1, 2} {
		stage := bootstrapMutationStage(directory, "adopt-replica-exit_0", generation)
		actual, readErr := os.ReadFile(filepath.Join(stage, "bundle", "controller.py"))
		if readErr != nil || string(original) != string(actual) {
			t.Fatalf("pinned bundle changed: %v", readErr)
		}
	}
	// Cached success still needs a verified transport receipt.
	receiptPath := filepath.Join(bootstrapMutationStage(directory, "adopt-replica-exit_0", 1), "receipt.json")
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err = json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["result"].(map[string]any)["verified"] = false
	unverified, _ := json.Marshal(receipt)
	if err = os.WriteFile(receiptPath, unverified, 0600); err != nil {
		t.Fatal(err)
	}
	if err = runAdoptionReplicaTunnels(ctx, inventory, topology, inspection, directory, root, 1, python, stub); err == nil {
		t.Fatal("unverified cached receipt accepted")
	}
	if err = os.WriteFile(receiptPath, receiptBytes, 0600); err != nil {
		t.Fatal(err)
	}
	// A cached stage is bound to full inventory including unrelated groups.
	inventory["all"].(map[string]any)["children"].(map[string]any)["unrelated"] = map[string]any{"hosts": map[string]any{"changed": map[string]any{}}}
	if err = runAdoptionReplicaTunnels(ctx, inventory, topology, inspection, directory, root, 1, python, stub); err == nil {
		t.Fatal("changed frozen full inventory accepted")
	}
}
