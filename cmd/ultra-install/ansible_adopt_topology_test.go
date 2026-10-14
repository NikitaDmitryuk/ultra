package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestAdoptionTopologyUsesDBNamesAndAllEnabledExits(t *testing.T) {
	p := &installplan.InstallPlan{Exits: []installplan.ExitNode{{Name: "primary", SSHHost: "192.0.2.10"}, {Name: "disabled-old", SSHHost: "192.0.2.99"}}}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{}}}
	topology := adoptionTopology{Nodes: []adoptionTopologyNode{
		{ID: "11111111-1111-4111-8111-111111111111", Name: "actual-static", Address: "192.0.2.10", Port: 8443, TunnelUUID: "22222222-2222-4222-8222-222222222222", CertPin: strings.Repeat("a", 64), Priority: 250, Enabled: true, Pins: "192.0.2.10 ssh-ed25519 fixture\n"},
		{ID: "33333333-3333-4333-8333-333333333333", Name: "dynamic-us", Address: "192.0.2.20", Port: 9443, TunnelUUID: "44444444-4444-4444-8444-444444444444", CertPin: strings.Repeat("b", 64), Priority: 75, Enabled: true, Pins: "192.0.2.20 ssh-ed25519 fixture\n"},
	}}
	directory := t.TempDir()
	entries, err := applyAdoptionTopology(p, inventory, directory, topology)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Exits) != 2 || p.Exits[0].Name != "actual-static" || p.Exits[1].Name != "dynamic-us" || entries[1].Priority != 75 || entries[1].PinnedPeerCertSHA256 != strings.Repeat("b", 64) {
		t.Fatal("DB topology lost or historical node resurrected")
	}
	nodes := inventory["all"].(map[string]any)["children"].(map[string]any)["exits"].(map[string]any)["hosts"].(map[string]any)
	if nodes["exit_1"].(map[string]any)["ansible_user"] != "root" {
		t.Fatal("managed SSH account not preserved")
	}
	pins, err := os.ReadFile(filepath.Join(directory, "topology-exit_1.known_hosts"))
	if err != nil || string(pins) != topology.Nodes[1].Pins {
		t.Fatal("managed SSH trust lost")
	}
}

func TestAdoptionTopologyProbeSyntheticRegressions(t *testing.T) {
	script := `
import importlib.util,json,copy
spec=importlib.util.spec_from_file_location('probe','../../deploy/ansible/library/ultra_adopt_topology.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
config={'static_nodes':[{'address':'192.0.2.10','known_hosts':'/etc/pins/static'}], 'vultr_state_dir':'/var/lib/ultra-relay/vultr'}
a={'id':'11111111-1111-4111-8111-111111111111','name':'db-static','address':'192.0.2.10','port':8443,'tunnel_uuid':'22222222-2222-4222-8222-222222222222','pinned_peer_cert_sha256':'a'*64,'priority':250,'enabled':True,'operations':[]}
b={'id':'33333333-3333-4333-8333-333333333333','name':'dynamic-us','address':'192.0.2.20','port':9443,'tunnel_uuid':'44444444-4444-4444-8444-444444444444','pinned_peer_cert_sha256':'b'*64,'priority':75,'enabled':True,'operations':[{'id':'33333333-3333-4333-8333-333333333333','exit_id':'33333333-3333-4333-8333-333333333333','state':'ready','phase':'ready','instance_id':'existing-instance'}]}
read=lambda path: path+' ssh-ed25519 fixture\n'
f=m.topology(config,[a,b],read,False)
assert [n['name'] for n in f['nodes']]==['db-static','dynamic-us']
assert f['nodes'][1]['priority']==75
assert '33333333-3333-4333-8333-333333333333/known_hosts' in f['nodes'][1]['pins']
for field,value in [('priority',100),('pinned_peer_cert_sha256','c'*64),('tunnel_uuid','55555555-5555-4555-8555-555555555555')]:
 changed=copy.deepcopy(b);changed[field]=value
 assert m.topology(config,[a,changed],read,False)['sha256']!=f['sha256']
assert m.topology(config,[a,b],lambda path:read(path)+'# changed',False)['sha256']!=f['sha256']
for mutate in [lambda n:n.update(enabled=False),lambda n:n.update(operations=[]),lambda n:n['operations'][0].update(state='deleted'),lambda n:n['operations'][0].update(exit_id=a['id']),lambda n:n.update(name=a['name'])]:
 changed=copy.deepcopy(b);mutate(changed)
 try:m.topology(config,[a,changed],read,False)
 except ValueError:pass
 else:raise AssertionError('unsafe topology accepted')
# Exercise actual reader and descriptor checks against temporary fixture files;
# root-owned ancestry is mocked because the test runner is unprivileged.
import os,tempfile,stat,types
from pathlib import Path
from unittest.mock import patch
with tempfile.TemporaryDirectory() as directory:
 base=Path(directory); owned=base/'relay';owned.mkdir(mode=0o700)
 pin=owned/'known_hosts';pin.write_text('192.0.2.20 ssh-ed25519 fixture\n');pin.chmod(0o600)
 original=Path.lstat
 def metadata(path):
  actual=original(path)
  uid=os.geteuid() if path==owned or owned in path.parents else 0
  return types.SimpleNamespace(st_uid=uid,st_mode=actual.st_mode & ~0o022)
 with patch.object(Path,'lstat',metadata):
  assert m.trusted_read(pin,relay_prefix=owned,relay_uid=os.geteuid())==pin.read_text()
  try:m.trusted_read(pin,relay_prefix=base/'other',relay_uid=os.geteuid()+1)
  except ValueError:pass
  else:raise AssertionError('foreign owner accepted')
  pin.chmod(0o622)
  try:m.trusted_read(pin,relay_prefix=owned,relay_uid=os.geteuid())
  except ValueError:pass
  else:raise AssertionError('writable descriptor accepted')
  pin.chmod(0o600)
  link=owned/'link';link.symlink_to(pin)
  try:m.trusted_read(link,relay_prefix=owned,relay_uid=os.geteuid())
  except ValueError:pass
  else:raise AssertionError('symlink accepted')
assert 'BEGIN READ ONLY' in m.QUERY and "statement_timeout='5s'" in m.QUERY and 'WHERE n.enabled' in m.QUERY
`
	command := exec.Command("python3", "-c", script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic topology regression: %v: %s", err, output)
	}
}

func TestAdoptionTopologyAttestsActualExitIdentity(t *testing.T) {
	node := adoptionTopologyNode{Port: 8443, TunnelUUID: "22222222-2222-4222-8222-222222222222", CertPin: strings.Repeat("a", 64)}
	topology := adoptionTopology{Nodes: []adoptionTopologyNode{node}}
	makeInspection := func(port int, identity, pin string) map[string]bootstrapInspection {
		raw, _ := json.Marshal(config.Spec{Role: config.RoleExit, VLESSPort: port, Exit: config.ExitTunnelSpec{TunnelUUID: identity}})
		item := bootstrapInspection{CertificatePin: pin}
		item.Files = append(item.Files, struct {
			Content string `json:"content"`
			Source  string `json:"source"`
		}{base64.StdEncoding.EncodeToString(raw), "/etc/ultra-relay/spec.json"})
		return map[string]bootstrapInspection{"exit_0": item}
	}
	if err := validateAdoptionTopologyInspection(topology, makeInspection(node.Port, node.TunnelUUID, node.CertPin)); err != nil {
		t.Fatal(err)
	}
	for _, item := range []map[string]bootstrapInspection{makeInspection(9443, node.TunnelUUID, node.CertPin), makeInspection(node.Port, "33333333-3333-4333-8333-333333333333", node.CertPin), makeInspection(node.Port, node.TunnelUUID, strings.Repeat("b", 64)), {}} {
		if validateAdoptionTopologyInspection(topology, item) == nil {
			t.Fatal("conflicting exit identity accepted")
		}
	}
}

func TestAdoptionTopologyFirstProbeAndRepeatAttestFreshState(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "attempt")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	pins := filepath.Join(root, "known-hosts")
	if err = os.WriteFile(pins, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{RemoteDir: "/etc/ultra-relay", SSHHost: "192.0.2.1"}, SSH: installplan.SSHConfig{Identity: filepath.Join(root, "identity")}, Database: installplan.DatabaseConfig{Name: "fixture"}}
	topology := adoptionTopology{SHA256: strings.Repeat("a", 64), Nodes: []adoptionTopologyNode{{Name: "fixture"}}}
	raw, _ := json.Marshal(topology)
	state := filepath.Join(root, "source.json")
	if err = os.WriteFile(state, raw, 0600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible")
	source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
variables=json.loads((job/'variables.json').read_text())
inventory=json.loads((job/'inventory.json').read_text())
root=job.parent.parent.parent
topology=json.loads((root/'source.json').read_text())
with (root/'calls').open('a') as stream:stream.write('probe\n')
if variables['ultra_topology_expected'] and variables['ultra_topology_expected']!=topology['sha256']:sys.exit(1)
inspection=pathlib.Path(inventory['all']['vars']['ultra_inspect_dir'])
(inspection/'topology.json').write_text(json.dumps(topology))
result=pathlib.Path(variables['ultra_result_file']);result.write_text('{"verified":true}');result.chmod(0o600)
`
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		observed, probeErr := inspectAdoptionTopology(context.Background(), p, directory, python, stub, root)
		if probeErr != nil {
			t.Fatalf("probe %d: %v", index, probeErr)
		}
		if observed.SHA256 != topology.SHA256 {
			t.Fatal("frozen topology changed")
		}
	}
	calls, _ := os.ReadFile(filepath.Join(root, "calls"))
	if string(calls) != "probe\nprobe\n" {
		t.Fatalf("cached topology attestation: %q", calls)
	}
	// Altering the private snapshot without updating its stored digest must fail.
	changed := topology
	changed.Nodes = append([]adoptionTopologyNode(nil), topology.Nodes...)
	changed.Nodes[0].Name = "tampered"
	modified, _ := json.Marshal(changed)
	frozenPath := filepath.Join(directory, "topology.frozen.json")
	if err = os.WriteFile(frozenPath, modified, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = inspectAdoptionTopology(context.Background(), p, directory, python, stub, root); err == nil {
		t.Fatal("modified frozen identities accepted")
	}
	if err = os.WriteFile(frozenPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	topology.SHA256 = strings.Repeat("b", 64)
	raw, _ = json.Marshal(topology)
	if err = os.WriteFile(state, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = inspectAdoptionTopology(context.Background(), p, directory, python, stub, root); err == nil {
		t.Fatal("late DB topology drift accepted")
	}
}
