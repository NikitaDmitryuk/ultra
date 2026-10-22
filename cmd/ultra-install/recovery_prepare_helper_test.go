package main

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
)

func TestRecoveryPreparationHelperOriginalIdentityAndNoAutomaticReplay(t *testing.T) {
	raw, err := ansibleassets.Bundle.ReadFile("roles/recovery_preparation/files/prepare.py")
	if err != nil {
		t.Fatal(err)
	}
	// Execute the real embedded helper with only fixed paths/owner lookup mapped
	// to an isolated rootless tree. No service, DB, SSH or installed key is used.
	program := strings.ReplaceAll(string(raw), "if __name__ == '__main__':", "if False:")
	root := t.TempDir()
	for _, prefix := range []string{"/opt/ultra-", "/etc/systemd/", "/etc/ultra-", "/var/lib/ultra-", "/usr/local/bin/ultra-"} {
		program = strings.ReplaceAll(program, prefix, filepath.ToSlash(root)+prefix)
	}
	program = strings.ReplaceAll(
		program,
		"ConditionPathExists="+filepath.ToSlash(root)+"/var/lib/ultra-",
		"ConditionPathExists=/var/lib/ultra-",
	)
	program = strings.ReplaceAll(program, "info.st_uid != 0", "info.st_uid != os.geteuid()")
	prefix := `import os,types,json,pathlib,sys,hashlib
root=pathlib.Path(` + strconv.Quote(root) + `)
`
	test := `
pwd.getpwnam=lambda name:types.SimpleNamespace(pw_uid=os.geteuid())
grp.getgrnam=lambda name:types.SimpleNamespace(gr_gid=os.getegid())
for directory in ['etc/ultra-recovery','etc/ultra-relay','var/lib/ultra-recovery-reconcile','usr/local/bin','snapshot/recovery','baseline','etc/systemd/system','opt/ultra-recovery']:
 (root/directory).mkdir(parents=True,exist_ok=True)
def doc(name,value):
 return {'destination':str(root/'etc/ultra-recovery'/name),'content':json.dumps(value),'mode':'0600','owner':'root','group':'root'}
original={'version':'v1.2.3'}
backup={'artifact_paths':['/usr/local/bin/ultra-relay'],'independent':False}
reconcile={'monitor_spec_file':'oldspec','probe_profile_file':'originalprofile','chat_id_file':'originalchat','payload_url':'https://payload.example.net'}
files=[doc('backup.json',backup),doc('reconcile.json',reconcile),doc('deployment.json',original)]
module=types.SimpleNamespace(plan=lambda config:{'verified':True,'files':files},read_env=lambda path:{})
planner=lambda snapshot:module
actual_verify_snapshot=verify_snapshot
candidate=root/'snapshot/recovery/fixture.py';candidate.write_bytes(b'fixture');candidate.chmod(0o600)
actual_verify_snapshot(root/'snapshot',{'recovery/fixture.py':hashlib.sha256(b'fixture').hexdigest()})
try:actual_verify_snapshot(root/'snapshot',{})
except ValueError:pass
else:raise AssertionError('empty snapshot inventory accepted')
candidate.write_bytes(b'changed')
try:actual_verify_snapshot(root/'snapshot',{'recovery/fixture.py':hashlib.sha256(b'fixture').hexdigest()})
except ValueError:pass
else:raise AssertionError('changed tools accepted')
candidate.unlink()
verify_snapshot=lambda *args:None
payload={'snapshot':str(root/'snapshot'),'baseline_snapshot':str(root/'baseline'),'candidate_controller_directory':str(root/'candidate-controller'),'baseline_version':'v1.2.3','request_sha256':'a'*64,'tools_manifest_sha256':'b'*64,'baseline_manifest_sha256':'c'*64,'snapshot_inventory':{},'configuration':{'version':'v1.2.3','spec':'originalspec'}}
active=root/'snapshot/recovery/active.py';active.write_bytes(b'active-runtime');active.chmod(0o600)
payload['active_inventory']={str(active):hashlib.sha256(active.read_bytes()).hexdigest()}
schedule_calls=[]
def schedule_run(args,**kwargs):
 schedule_calls.append(args)
 if args[1]=='show':return types.SimpleNamespace(stdout=b'ActiveState=inactive\nUnitFileState=disabled\n')
 return types.SimpleNamespace(stdout=b'')
subprocess.run=schedule_run
sys.modules['live_tools']=types.SimpleNamespace(verify=lambda **kwargs:None)
result=stage(payload)
assert len([a for a in schedule_calls if a[1:3]==['disable','--now']])==2
suspension=json.loads((root/'etc/ultra-recovery/preparation-suspension.json').read_bytes())
assert suspension['active_inventory']==payload['active_inventory']
assert not any(a[1] in ('start','restart','enable') for a in schedule_calls)
for name in ['ultra-recovery-backup.service','ultra-recovery-reconcile.service']:
 assert (root/'etc/systemd/system'/(name+'.d')/'95-deployment-background.conf').read_text()=='[Service]\nExecCondition='+str(root/'opt/ultra-ansible/current/ultra-install')+' deploy-operation background-ready\n'

assert result['verified']
actual=json.loads((root/'etc/ultra-recovery/deployment.json').read_text())
assert actual['version']=='v1.2.3'
actual=json.loads((root/'etc/ultra-recovery/reconcile.json').read_text())
assert 'monitor_spec_file' not in actual and actual['probe_profile_file']=='originalprofile' and actual['chat_id_file']=='originalchat'
assert actual['bundle_dir']==str(root/'snapshot/recovery')
assert json.loads((root/'etc/ultra-recovery/backup.json').read_text())['independent'] is False
# Immutable baseline restoration never replaces a different existing identity.
p=root/'baseline/manifest.json';publish(p,b'original',immutable=True)
try:publish(p,b'candidate',immutable=True)
except ValueError:pass
else:raise AssertionError('replaced baseline')
# Schema verification precedes invoking a DB-opening initializer.
relay=root/'usr/local/bin/ultra-relay';relay.write_bytes(b'original-relay');relay.chmod(0o755)
payload['baseline_relay_sha256']=hashlib.sha256(relay.read_bytes()).hexdigest();payload['primary']={'database':'fixture'}
calls=[]
def blocked_schema(module,expected):raise ValueError('schema mismatch')
schema_identity=blocked_schema
subprocess.run=lambda *a,**k:calls.append(a)
try:initialize_monitor(payload)
except ValueError:pass
else:raise AssertionError('schema mismatch accepted')
assert not calls
# A different installed relay must fail before schema/query/initializer.
payload['baseline_relay_sha256']='d'*64
try:initialize_monitor(payload)
except ValueError:pass
else:raise AssertionError('candidate relay accepted')
assert not calls
# Successful initialization uses the original executable, retains monitoring,
# and creates only an absent heartbeat identity with its actual derived pubkey.
payload['baseline_relay_sha256']=hashlib.sha256(relay.read_bytes()).hexdigest()
schema_identity=lambda *a:None
key=root/'var/lib/ultra-recovery-reconcile/heartbeat_ed25519'
def run(args,**kwargs):
 calls.append(args)
 if args[0]==str(relay):
  profile=root/'etc/ultra-recovery/probe.json';profile.write_text('{}');profile.chmod(0o600)
  chat=root/'etc/ultra-recovery/admin-chat-id';chat.write_text('123\n');chat.chmod(0o600)
  return types.SimpleNamespace(stdout=b'{"monitor_access":"ready","quota_available":true}')
 if args[:2]==['ssh-keygen','-q']:
  key.write_bytes(b'fixture-private');key.chmod(0o600)
  return types.SimpleNamespace(stdout=b'')
 if args[:2]==['ssh-keygen','-y']:return types.SimpleNamespace(stdout=b'ssh-ed25519 Zml4dHVyZQ==\n')
 raise AssertionError(args)
subprocess.run=run
assert initialize_monitor(payload)['monitor_initialized']
assert key.read_bytes()==b'fixture-private'
calls.clear();assert initialize_monitor(payload)['monitor_initialized']
assert not any(args[:2]==['ssh-keygen','-q'] for args in calls)
calls.clear()
(root/'var/lib/ultra-recovery-reconcile/heartbeat_ed25519.pub').write_bytes(b'ssh-ed25519 Y29uZmxpY3Q=\n')
try:initialize_monitor(payload)
except ValueError:pass
else:raise AssertionError('heartbeat trust conflict accepted')
assert not any(args[0]==str(relay) for args in calls)
assert not any('ensure-static-budgets' in str(args) or 'systemctl' in str(args) or 'postgres' in str(args) for args in calls)
# Post-activation capture runs even when an earlier receipt could be fresh.
# Removing suspension drop-ins is a separate exact transaction, never a broad
# systemd reset; normal background schedules remain guarded throughout.
events=[]
current=root/'opt/ultra-ansible/current';current.parent.mkdir(parents=True,exist_ok=True)
current.symlink_to(root/'original-controller')
try:restore_schedules(payload)
except ValueError:pass
else:raise AssertionError('old controller opened recovery schedules')
current.unlink();current.symlink_to(payload['candidate_controller_directory'])
blocked=b'[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
for name in ['ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
 directory=root/'etc/systemd/system'/(name+'.d');directory.mkdir(exist_ok=True)
 path=directory/'90-retained-primary.conf';path.write_bytes(blocked);path.chmod(0o644)
def resumed_run(args,**kwargs):
 events.append(args)
 if args[1]=='show':return types.SimpleNamespace(stdout=b'ActiveState=active\nUnitFileState=enabled\n')
 return types.SimpleNamespace(stdout=b'')
subprocess.run=resumed_run
fence=root/'etc/systemd/system/ultra-recovery-reconcile.timer.d/90-retained-primary.conf'
fence.write_bytes(b'foreign')
try:restore_schedules(payload)
except ValueError:pass
else:raise AssertionError('foreign schedule fence removed')
assert not any(a[1:3]==['enable','--now'] for a in events)
fence.write_bytes(blocked)
events.clear()
restore_schedules(payload)
assert len([a for a in events if isinstance(a,list) and a[1:3]==['enable','--now']])==2
restored=json.loads((root/'etc/ultra-recovery/preparation-schedules-restored.json').read_bytes())
assert restored['request_sha256']==payload['request_sha256']
assert restored['suspension_sha256']==hashlib.sha256((root/'etc/ultra-recovery/preparation-suspension.json').read_bytes()).hexdigest()
assert not fence.exists()
# The persistent gate follows the existing verified controller selection rather
# than a retired generation or /usr/local/bin's original app installer.
gate=root/'etc/systemd/system/ultra-recovery-backup.service.d/95-deployment-background.conf'
original_gate=gate.read_bytes()
current.unlink();current.symlink_to(root/'next-controller')
assert gate.read_bytes()==original_gate
assert str(current/'ultra-install').encode() in original_gate
current.unlink();current.symlink_to(payload['candidate_controller_directory'])
assert gate.read_bytes()==original_gate
print('verified helper contract')
`
	command := exec.Command("python3", "-c", prefix+program+test)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "verified helper contract") {
		t.Fatal("helper did not finish")
	}
}

func TestRecoveryPreparationRuntimeFilesDoNotSelectBrokerOrRestartDuringStaging(t *testing.T) {
	files, err := ansibleassets.Bundle.ReadFile("roles/controller/tasks/runtime-files.yml")
	if err != nil {
		t.Fatal(err)
	}
	selection, err := ansibleassets.Bundle.ReadFile("roles/controller/tasks/runtime.yml")
	if err != nil {
		t.Fatal(err)
	}
	stage, err := ansibleassets.Bundle.ReadFile("roles/recovery_preparation/tasks/main.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"dest: /opt/ultra-ansible/current", "dest: /etc/systemd/system/ultra-ansible-controller.service", "state: started", "state: restarted"} {
		if strings.Contains(string(files), forbidden) {
			t.Fatalf("staging changes broker selection: %s", forbidden)
		}
	}
	if !strings.Contains(string(files), "[] if ultra_controller_stage_only") ||
		!strings.Contains(string(stage), "ultra_controller_stage_only: true") {
		t.Fatal("staging may notify controller restart")
	}
	if !strings.Contains(string(selection), "import_tasks: runtime-files.yml") ||
		!strings.Contains(string(selection), "dest: /opt/ultra-ansible/current") ||
		!strings.Contains(string(selection), "notify: Restart Ansible controller") {
		t.Fatal("normal selection/restart behavior lost")
	}
	for _, forbidden := range []string{"ensure-static-budgets", "ensure-monitor-access", "Restart primary relay", "roles: [postgres", "ansible.builtin.meta: flush_handlers"} {
		if strings.Contains(string(stage), forbidden) {
			t.Fatalf("unsafe preparation action: %s", forbidden)
		}
	}
}
