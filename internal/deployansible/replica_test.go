package deployansible

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func replicaFixture(t *testing.T) ReplicaRequest {
	_, exit := fixture(t)
	return ReplicaRequest{ID: "11111111-2222-3333-4444-555555555555", Host: exit.Host, Identity: exit.Identity, KnownHosts: exit.KnownHosts, User: "ultra_replication", Password: strings.Repeat("a", 64), PrimaryPort: 5432, Architecture: "x86_64", RequiredBytes: 5 << 30, Connections: 100, Workers: 8, Prepared: 0, Locks: 64, Senders: 10}
}

func TestReplicaPolicyRejectsUntrustedInputs(t *testing.T) {
	request := replicaFixture(t)
	if err := request.ValidatePolicy(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ReplicaRequest){func(r *ReplicaRequest) { r.ID = "../../unit" }, func(r *ReplicaRequest) { r.Host = "example.com" }, func(r *ReplicaRequest) { r.User = "{{ lookup('pipe','id') }}" }, func(r *ReplicaRequest) { r.Password = "secret\n" }, func(r *ReplicaRequest) { r.PrimaryPort = 0 }, func(r *ReplicaRequest) { r.RequiredBytes = 1 }} {
		invalid := request
		change(&invalid)
		if invalid.ValidatePolicy() == nil {
			t.Fatal("unsafe replica input accepted")
		}
	}
}

func TestReplicaPinnedSourcesAndFixedLocalInventory(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	request := replicaFixture(t)
	inputs, err := openReplicaInputs(request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeInputs(inputs)
	directory := filepath.Join(t.TempDir(), "replica")
	if err := prepareReplica(directory, "configure-replica", request, inputs); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(t.TempDir(), "ansible")
	source := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
inventory=json.loads((job/'inventory.json').read_text())
assert inventory['all']['children']['bridges']['hosts']=={'bridge':{'ansible_connection':'local'}}
assert inventory['all']['children']['replicas']['hosts']['replica']['ansible_host']=='192.0.2.2'
value=json.loads((job/'variables.json').read_text())
assert value['ultra_replica_slot']=='ultra_11111111222233334444555555555555'
assert 'identity' in value['ultra_replica_identity_source']
p=pathlib.Path(value['ultra_result_file']);p.write_text('{"verified":true}');p.chmod(0o600)
`
	if err := os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), directory, python, stub); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" {
		t.Fatal("replica receipt missing")
	}
	if err := os.WriteFile(filepath.Join(directory, "identity"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), directory, python, stub); err == nil {
		t.Fatal("changed identity accepted")
	}
}
