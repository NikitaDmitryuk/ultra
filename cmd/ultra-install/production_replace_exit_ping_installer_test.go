package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestReplacementPingUsesImmutableControllerInstaller(t *testing.T) {
	program, _ := json.Marshal(
		map[string]string{
			"acquire":                     replacementPingBridgeProgram,
			"replacement-exit-ping-probe": replacementPingBridgeProgram,
			"ready":                       replacementPingPublicationProgram,
			"release":                     replacementPingReleaseProgram,
		},
	)
	fixture := `import ast,json,sys,subprocess,types,hashlib
from pathlib import Path
programs=json.loads(sys.argv[1]);root=Path(sys.argv[2]);expected=sys.argv[3]
executable=root/expected.lstrip('/');executable.parent.mkdir(parents=True,mode=0o700)
executable.write_text('#!/usr/bin/python3\nimport sys\na=sys.argv[1:]\nassert len(a)==3 and ((a[0]=="replacement-exit-ping-lease" and a[1]=="a"*64 and a[2] in ("acquire","ready","release")) or (a[0]=="replacement-exit-ping-probe" and a[2]=="a"*64))\n');executable.chmod(0o755)
assert not (root/'usr/local/bin/ultra-install').exists()
real_run=subprocess.run
def run(args,**kwargs):
 args=list(args);args[0]=str(root/args[0].lstrip('/'))
 return real_run(args,**kwargs)
ns={'subprocess':types.SimpleNamespace(run=run),'binding':'a'*64,'r':{'installer':expected,'installer_sha256':hashlib.sha256(executable.read_bytes()).hexdigest()},'request':root/'probe.json','installer':expected,'remaining':35,'sys':types.SimpleNamespace(argv=['release','a'*64])}
ns['verified_installer']=lambda path,sha:path
ns['scoped_installer']=lambda binding:expected
for action,source in programs.items():
 tree=ast.parse(source)
 calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run' and any(isinstance(part,ast.Constant) and part.value==action for part in ast.walk(node))]
 assert len(calls)==1,(action,len(calls))
 result=eval(compile(ast.Expression(calls[0]),'<actual-'+action+'-call>','eval'),ns)
 assert result.returncode==0
`
	command := exec.Command("python3", "-c", fixture, string(program), t.TempDir(), managedControllerDirectory("v0.0.123")+"/ultra-install")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("immutable controller layout: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

func TestReplacementPingInstallerPathAndDigestFailClosed(t *testing.T) {
	definitions, _ := json.Marshal(replacementPingInstallerDefinitions)
	fixture := `import json,sys,os,hashlib
from pathlib import Path
root=Path(sys.argv[2]);prefix=root/'opt/ultra-ansible/releases';prefix.mkdir(parents=True,mode=0o700)
source=json.loads(sys.argv[1]).replace('/opt/ultra-ansible/releases/',str(prefix)+'/')
source=source.replace('s.st_uid==0','s.st_uid=='+str(os.geteuid())).replace('for parent in [p,*p.parents]:','for parent in [p]:') # Unprivileged fixture trust root.
ns={'__name__':'fixture'};exec(source,ns)
p=prefix/'managed-v0.0.123'/'ultra-install';p.parent.mkdir(mode=0o700);p.write_bytes(b'candidate-installer');p.chmod(0o755)
sha=hashlib.sha256(p.read_bytes()).hexdigest()
assert ns['verified_installer'](str(p),sha)==str(p)
for path,pin in [(str(p),'0'*64),(str(root/'usr/local/bin/ultra-install'),sha),(str(prefix/'missing'/'ultra-install'),sha)]:
 failed=False
 try:ns['verified_installer'](path,pin)
 except (ValueError,FileNotFoundError):failed=True
 assert failed
target=p.with_name('other');target.write_bytes(p.read_bytes());target.chmod(0o755);p.unlink();p.symlink_to(target)
failed=False
try:ns['verified_installer'](str(p),sha)
except ValueError:failed=True
assert failed
`
	command := exec.Command("python3", "-c", fixture, string(definitions), t.TempDir())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("immutable installer trust: %v: %s", err, out)
	}
}

func TestReplacementPingInstallerMatchesControllerRole(t *testing.T) {
	for _, test := range []struct{ path, fragment string }{
		{"../../deploy/ansible/roles/controller/tasks/runtime-files.yml", `dest: "{{ ultra_controller_directory }}/ultra-install"`},
		{"../../deploy/ansible/roles/controller/templates/ultra-ansible-controller.service.j2", `ExecStart={{ ultra_controller_directory }}/ultra-install ansible-controller`},
	} {
		raw, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), test.fragment) {
			t.Fatal("controller install contract changed; revalidate rollout executable")
		}
	}
}

func TestReplacementPingPreflightAttestsActiveControllerLayout(t *testing.T) {
	definitions, _ := json.Marshal(replacementPingInstallerDefinitions)
	fixture := `import json,sys,os,types
from pathlib import Path
root=Path(sys.argv[2]);prefix=root/'opt/ultra-ansible/releases';proc=root/'proc'/'4242';proc.mkdir(parents=True,mode=0o700)
p=prefix/'managed-v0.0.123'/'ultra-install';p.parent.mkdir(parents=True,mode=0o700);p.write_bytes(b'\x7fELF'+bytes([2,1,1])+bytes(11)+(62).to_bytes(2,'little'));p.chmod(0o755)
(proc/'exe').symlink_to(p);(proc/'cmdline').write_bytes(str(p).encode()+b'\0ansible-controller\0--executable\0fixture\0')
source=json.loads(sys.argv[1]).replace('/opt/ultra-ansible/releases/',str(prefix)+'/').replace("Path('/proc')","Path("+repr(str(root/'proc'))+")")
source=source.replace('s.st_uid==0','s.st_uid=='+str(os.geteuid())).replace('for parent in [p,*p.parents]:','for parent in [p]:') # Fixture trust root.
ns={'__name__':'fixture'};exec(source,ns)
def run(args,**kwargs):
 assert args==['systemctl','show','--property=MainPID','--value','ultra-ansible-controller.service'] and kwargs['timeout']==5
 return types.SimpleNamespace(returncode=0,stdout='4242\n')
ns['subprocess'].run=run
for system,machine,elf_machine,valid in [('Linux','x86_64',62,True),('Linux','amd64',62,True),('Linux','aarch64',183,False),('Linux','arm64',183,False),('Linux','unknown',62,False),('Linux','',62,False),('Linux','x86_64 aarch64',62,False),('Darwin','x86_64',62,False),('Linux','x86_64',183,False),('Linux','x86_64',None,False)]:
 ns['os'].uname=lambda:types.SimpleNamespace(sysname=system,machine=machine)
 p.write_bytes(b'\x7fELF'+bytes([2,1,1])+bytes(11)+elf_machine.to_bytes(2,'little') if elf_machine is not None else b'missing-elf')
 failed=False
 try:result=ns['verify_current_installer']()
 except ValueError as e:failed=True;assert str(e)=='exit_ping_controller_architecture_unsupported'
 assert failed!=valid
 if valid:assert result=='linux-amd64'
(proc/'cmdline').write_bytes(str(p).encode()+b'\0other-command\0')
failed=False
try:ns['verify_current_installer']()
except ValueError as e:failed=True;assert str(e)=='exit_ping_controller_command_invalid'
assert failed
`
	command := exec.Command("python3", "-c", fixture, string(definitions), t.TempDir())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("existing controller layout preflight: %v: %s", err, out)
	}
}

func TestReplacementPingArchitectureAttestationFailsClosedBeforeFencing(t *testing.T) {
	for _, tc := range []struct {
		name, architecture string
		layout, valid      bool
	}{
		{"amd64", "linux-amd64", true, true},
		{"arm64", "linux-arm64", true, false},
		{"missing", "", true, false},
		{"unknown", "unknown", true, false},
		{"ambiguous", "linux-amd64,linux-arm64", true, false},
		{"unverified layout", "linux-amd64", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReplacementPingControllerAttestation(
				replacementPingRollout{ControllerLayoutVerified: tc.layout, ControllerArchitecture: tc.architecture},
			)
			if (err == nil) != tc.valid {
				t.Fatalf("attestation=%v", err)
			}
		})
	}
	// Capture performs the architecture check before pin SSH or any replacement
	// mutation. The replacement caller must retain that pre-fencing order.
	caller, err := os.ReadFile("production_replace.go")
	if err != nil {
		t.Fatal(err)
	}
	capture, reserve := strings.Index(
		string(caller),
		"captureReplacementPing(ctx",
	), strings.Index(
		string(caller),
		"deployansible.ReserveReplacement(ctx",
	)
	if capture < 0 || reserve < 0 || capture >= reserve {
		t.Fatal("architecture capture moved after replacement reservation/mutation")
	}
	program, _ := json.Marshal(replacementPingCaptureProgram)
	fixture := `import json,sys,types
source=json.loads(sys.argv[1]);prefix=source.split("for n in r['nodes']:")[0]
ns={'__name__':'fixture'};exec(prefix.split("need(os.geteuid()==0,'exit_ping_root_required')")[0],ns)
ns['os'].geteuid=lambda:0;ns['sys'].argv=['capture',json.dumps({'binding':'a'*64,'nodes':[]})]
def reject():raise ValueError('exit_ping_controller_architecture_unsupported')
ns['verify_current_installer']=reject
ns['subprocess'].run=lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError('SSH/worker dispatched before architecture rejection'))
failed=False
try:exec("need(os.geteuid()==0,'exit_ping_root_required')"+prefix.split("need(os.geteuid()==0,'exit_ping_root_required')")[1],ns)
except ValueError as e:failed=True;assert str(e)=='exit_ping_controller_architecture_unsupported'
assert failed
`
	command := exec.Command("python3", "-c", fixture, string(program))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("architecture pre-fence fixture: %v: %s", err, out)
	}
}
