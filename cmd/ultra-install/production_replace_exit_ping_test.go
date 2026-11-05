package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestReplacementPingPlanningCoverageAndCompatibility(t *testing.T) {
	yes := true
	p := &installplan.InstallPlan{
		Features: installplan.FeatureConfig{ExitPing: &yes, HappExitPing: &yes},
		Bridge:   installplan.BridgeConfig{SSHHost: "203.0.113.1"},
		Database: installplan.DatabaseConfig{PrimaryHost: "203.0.113.2"},
		Exits:    []installplan.ExitNode{{SSHHost: "203.0.113.3", Port: 443}},
	}
	static := replacementPingRoute{
		ID:         "a6844f19-48ce-445a-bfda-3e8bfa108c18",
		Address:    "203.0.113.3",
		Port:       443,
		TunnelUUID: "de9cb0f8-6a24-4e4c-9b9c-a3bc75edc3ac",
		Pin:        strings.Repeat("a", 64),
	}
	dynamic := static
	dynamic.ID = "dab2ff42-8188-4705-9a43-2816ddf368ec"
	dynamic.Address = "203.0.113.4"
	dynamic.OperationID = dynamic.ID
	dynamic.State = "ready"
	dynamic.InstanceID = "provider-instance"
	for _, tc := range []struct {
		name  string
		nodes []replacementPingRoute
		valid bool
	}{
		{"static only", []replacementPingRoute{static}, true}, {"static and retained", []replacementPingRoute{static, dynamic}, true}, {"no coverage", nil, false}, {"duplicate host", []replacementPingRoute{static, static}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := planReplacementPing(p, replacementPrimary{PingRoutes: tc.nodes}, strings.Repeat("b", 64), strings.Repeat("c", 64))
			if (err == nil) != tc.valid {
				t.Fatalf("result %v", err)
			}
			if r != nil && len(r.Nodes) > 1 && !r.Nodes[1].Retained {
				t.Fatal("dynamic route omitted")
			}
		})
	}
	for _, field := range []string{"operation", "instance", "state", "certificate", "protected"} {
		t.Run(field, func(t *testing.T) {
			bad := dynamic
			switch field {
			case "operation":
				bad.OperationID = ""
			case "instance":
				bad.InstanceID = ""
			case "state":
				bad.State = "creating"
			case "certificate":
				bad.Pin = ""
			case "protected":
				bad.Address = p.Database.PrimaryHost
			}
			if _, err := planReplacementPing(p, replacementPrimary{PingRoutes: []replacementPingRoute{static, bad}}, "binding", "binary"); err == nil {
				t.Fatal("unverified binding accepted")
			}
		})
	}
	p.Features.HappExitPing = nil
	if r, err := planReplacementPing(p, replacementPrimary{}, "", ""); err != nil || r != nil {
		t.Fatal("disabled feature changed historical replacement")
	}
}

func TestReplacementPingEffectivePolicy(t *testing.T) {
	yes, no := true, false
	provider := "fixture-provider"
	for _, tc := range []struct {
		name                                               string
		publication, dataplane                             *bool
		installedPublication, installedExit, valid, wanted bool
	}{
		{"omitted disabled", nil, nil, false, false, true, false},
		{"omitted published requires explicit", nil, nil, true, true, false, false},
		{"explicit false rollback", &no, nil, true, true, true, false},
		{"dataplane inherits", &yes, nil, false, true, true, true},
		{"explicit true", &yes, &yes, false, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &installplan.InstallPlan{
				Features: installplan.FeatureConfig{HappExitPing: tc.publication, ExitPing: tc.dataplane, HappProviderID: &provider},
			}
			err := resolveReplacementPingPolicy(p, tc.installedExit, tc.installedPublication)
			if (err == nil) != tc.valid {
				t.Fatalf("policy %v", err)
			}
			if tc.valid && replacementPingRequested(p) != tc.wanted {
				t.Fatal("effective publication changed")
			}
			if tc.name == "dataplane inherits" && (p.Features.ExitPing == nil || !*p.Features.ExitPing) {
				t.Fatal("inherited dataplane lost")
			}
		})
	}
}

func TestReplacementPingRestorePinsPreservesIdentity(t *testing.T) {
	programJSON, _ := json.Marshal(replacementPingBridgeProgram)
	fixture := `import json,sys,os,types
from pathlib import Path
source=json.loads(sys.argv[1]).split("need(os.geteuid()==0,'exit_ping_root_required')")[0]
d=Path(sys.argv[2]);root=d/'runtime';root.mkdir(mode=0o700)
source=source.replace('/var/lib/ultra-relay/vultr',str(root/'vultr'))
source=source.replace('for a in [op]+list(op.parents):','for a in [op]:').replace('for a in [p]+list(p.parents):','for a in [p]:') # Temporary fixture trust root.
ns={'__name__':'fixture'};exec(source,ns)
ns['pwd'].getpwnam=lambda _:types.SimpleNamespace(pw_uid=os.geteuid(),pw_gid=os.getegid())
node={'operation_id':'dab2ff42-8188-4705-9a43-2816ddf368ec','known_hosts':'203.0.113.8 ssh-ed25519 AAAA\n'}
ns['restore_pins'](node)
p=root/'vultr'/node['operation_id']/'known_hosts';assert p.read_text()==node['known_hosts'] and p.stat().st_mode&0o777==0o600
ns['restore_pins'](node) # Exact retained trust is idempotent.
p.write_text('foreign')
failed=False
try:ns['restore_pins'](node)
except ValueError:failed=True
assert failed and p.read_text()=='foreign'
`
	command := exec.Command("python3", "-c", fixture, string(programJSON), t.TempDir())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("retained pin fixture %v: %s", err, out)
	}
}

func TestReplacementPingPythonProgramsCompile(t *testing.T) {
	for name, program := range map[string]string{"capture": replacementPingCaptureProgram, "exit": replacementPingExitProgram, "dispatch": replacementPingExitDispatch, "bridge": replacementPingBridgeProgram, "publication": replacementPingPublicationProgram, "release": replacementPingReleaseProgram} {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("python3", "-c", "import sys;compile(sys.stdin.read(),'fixture','exec')")
			command.Stdin = strings.NewReader(program)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile %v: %s", err, out)
			}
		})
	}
}

func TestReplacementPingCaptureStrictPinPolicy(t *testing.T) {
	for _, mode := range []string{"missing", "wildcard", "exact", "hashed", "bad-ssh"} {
		t.Run(mode, func(t *testing.T) {
			programJSON, _ := json.Marshal(replacementPingCaptureProgram)
			fixture := `import json,sys,os,types,subprocess
from pathlib import Path
source=json.loads(sys.argv[1]);d=Path(sys.argv[2]);mode=sys.argv[3];key=d/'key';key.write_bytes(b'fixture');key.chmod(0o600)
source=source.replace('/etc/ultra-fleet/id_ed25519',str(key)).replace('/var/lib/ultra-relay/vultr',str(d/'cloud'))
# A temporary unprivileged fixture has a different trust root. Exercise exact pin selection and strict SSH; production ancestry checks are unchanged.
source=source.replace('for a in [p]+list(p.parents):','for a in [p]:')
os.geteuid=lambda:0
address='203.0.113.8';op='dab2ff42-8188-4705-9a43-2816ddf368ec';calls=[]
fallback='' if mode=='missing' else ('*' if mode=='wildcard' else '|1|fixture|fixture' if mode=='hashed' else address)+' ssh-ed25519 AAAA\n'
def run(args,**kwargs):
 calls.append(args)
 if args[0]=='ssh-keygen':return types.SimpleNamespace(returncode=0 if fallback else 1,stdout=fallback)
 assert args[0]=='ssh' and 'StrictHostKeyChecking=yes' in args and 'UpdateHostKeys=no' in args and 'GlobalKnownHostsFile=/dev/null' in args
 assert not any('accept-new' in a or 'Checking=no' in a for a in args)
 return types.SimpleNamespace(returncode=1 if mode=='bad-ssh' else 0)
subprocess.run=run
request={'binding':'a'*64,'nodes':[{'operation_id':op,'address':address,'retained':True}]}
sys.argv=['capture',json.dumps(request),fallback]
failed=False
try:exec(source,{'__name__':'fixture'})
except ValueError as e:failed=True;assert str(e)=='exit_ping_verified_host_pin_unavailable'
assert failed==(mode in ('missing','wildcard','bad-ssh'))
assert key.read_bytes()==b'fixture'
`
			command := exec.Command("python3", "-c", fixture, string(programJSON), t.TempDir(), mode)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("pin fixture %v: %s", err, out)
			}
		})
	}
}

func TestReplacementPingExitTransactionRollback(t *testing.T) {
	for _, failure := range []string{"none", "check", "restart", "postcheck", "interrupted"} {
		t.Run(failure, func(t *testing.T) {
			programJSON, _ := json.Marshal(replacementPingExitProgram)
			fixture := `import json,sys,types,stat
from pathlib import Path
ns={'__name__':'fixture'}
exec(json.loads(sys.argv[1]),ns)
ns['os'].fchown=lambda *args:None # Ownership changes require root; content/permission transaction runs unprivileged.
d=Path(sys.argv[2]);failure=sys.argv[3]
binary=d/'binary';spec=d/'spec';tx=d/'transaction';tx.mkdir(mode=0o700)
binary.write_bytes(b'old-binary');binary.chmod(0o755)
old={'role':'exit','vless_port':443,'exit':{'tunnel_uuid':'fixture-uuid'},'unknown':{'preserve':[1,2]},'exit_cert':{'preserve':True}}
original=json.dumps(old).encode();spec.write_bytes(original);spec.chmod(0o600)
request={'binding':'a'*64,'binary_sha256':ns['digest'](b'new-binary'),'node':{'tunnel_uuid':'fixture-uuid','address':'203.0.113.8','port':443,'pin':'pin'}}
(tx/'request.json').write_text(json.dumps(request));(tx/'candidate').write_bytes(b'new-binary')
ns['regular']=lambda p:Path(p)
ns['running']=lambda p:None
ns['time'].sleep=lambda _:None
checks=[0];restarts=[0]
def certificate(spec):
 checks[0]+=1
 if failure=='postcheck' and checks[0]>1:raise ValueError('injected_postcheck')
 return 'pin'
ns['certificate']=certificate
def service(*args):
 if args[0]=='restart':
  restarts[0]+=1
  if failure=='restart' and restarts[0]==1:raise ValueError('injected_restart')
ns['service']=service
def run(args,**kwargs):
 if args[0]=='ip':return types.SimpleNamespace(returncode=0,stdout='[{"addr_info":[{"local":"203.0.113.8"}]}]')
 return types.SimpleNamespace(returncode=1 if failure=='check' else 0)
ns['subprocess'].run=run
failed=False
try:ns['apply'](tx,binary,spec)
except ValueError:
 failed=True
 assert json.loads((tx/'receipt.json').read_text())['state']=='applying'
 ns['restore'](tx,binary,spec) # The unit's independent ExecStopPost runs after failed ExecStart.
if failure=='none':
 assert not failed and binary.read_bytes()==b'new-binary'
 expected=dict(old);expected['exit_ping']=True
 assert json.loads(spec.read_text())==expected
 assert json.loads((tx/'receipt.json').read_text())['state']=='succeeded'
elif failure=='interrupted':
 ns['save'](tx,'applying',binding='a'*64)
 ns['restore'](tx,binary,spec)
 assert binary.read_bytes()==b'old-binary' and spec.read_bytes()==original
else:
 assert failed and binary.read_bytes()==b'old-binary' and spec.read_bytes()==original
 assert json.loads((tx/'receipt.json').read_text())['state']=='rolled_back'
assert stat.S_IMODE(binary.stat().st_mode)==0o755 and stat.S_IMODE(spec.stat().st_mode)==0o600
`
			command := exec.Command("python3", "-c", fixture, string(programJSON), t.TempDir(), failure)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("transaction fixture %v: %s", err, out)
			}
		})
	}
}

func TestReplacementPingPublicationRollback(t *testing.T) {
	for _, failure := range []string{"none", "restart", "cache", "interrupted"} {
		t.Run(failure, func(t *testing.T) {
			programJSON, _ := json.Marshal(replacementPingPublicationProgram)
			fixture := `import json,sys
from pathlib import Path
base=Path(sys.argv[2]);spec=base/'spec';binding='a'*64;d=base/binding;d.mkdir(mode=0o700);failure=sys.argv[3]
program=json.loads(sys.argv[1]).replace('/var/lib/ultra-replacement-ping',str(base)).replace('/etc/ultra-relay/spec.json',str(spec))
ns={'__name__':'fixture'};exec(program,ns)
ns['os'].geteuid=lambda:0;ns['os'].fchown=lambda *args:None
ns['fcntl'].flock=lambda *args:None # Production worker/recovery are distinct processes; this fixture invokes both in one process.
prior={'role':'bridge','exit_ping':True,'happ_exit_ping':False,'unknown':{'preserve':True}}
raw=json.dumps(prior).encode();spec.write_bytes(raw);spec.chmod(0o600)
request=d/'publication-publish.json';request.write_text(json.dumps({'binding':binding,'mode':'publish','bot_enabled':True,'spec_sha256':ns['digest'](raw)}))
calls=[];restarts=[0]
def service(name):
 restarts[0]+=1
 if failure=='restart' and restarts[0]==1:raise ValueError('injected_restart')
def cache(expected,started):
 calls.append(expected)
 if failure=='cache' and expected:raise ValueError('injected_cache')
ns['service']=service;ns['cache']=cache;ns['ready']=lambda _:None;ns['sys'].argv=['worker','apply',str(request)]
failed=False
try:ns['main']()
except ValueError:
 failed=True
 assert json.loads((d/'publication-publish-receipt.json').read_text())['state']=='applying'
 ns['sys'].argv=['worker','recover',str(request)];ns['main']() # Independent unit stop/recovery phase.
if failure=='none':assert not failed and json.loads(spec.read_text())['happ_exit_ping'] and calls==[True]
elif failure=='interrupted':
 ns['atomic'](d/'publication-publish-receipt.json',json.dumps({'binding':binding,'state':'applying'}).encode())
 ns['sys'].argv=['worker','recover',str(request)];ns['main']()
 assert spec.read_bytes()==raw and calls==[True,False]
else:
 assert failed and spec.read_bytes()==raw and calls[-1]==False
 assert json.loads((d/'publication-publish-receipt.json').read_text())['state']=='rolled_back'
`
			command := exec.Command("python3", "-c", fixture, string(programJSON), t.TempDir(), failure)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("publication fixture %v: %s", err, out)
			}
		})
	}
}
