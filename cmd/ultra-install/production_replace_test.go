package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestProductionReplacementExplicitScopePrecedesJournalAccess(t *testing.T) {
	for _, args := range [][]string{nil, {"--acknowledge", "force"}, {"--manual-journal", "/private/operation.json"}} {
		if err := runProductionReplacement(args, io.Discard); err == nil || err.Error() != "replacement_explicit_scope_required" {
			t.Fatalf("implicit journal bypass: %v", err)
		}
	}
}

func TestProductionReplacementHelpIsReadOnly(t *testing.T) {
	var out strings.Builder
	if err := runProductionReplacement([]string{"--help"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "primary-backup-sha256") || !strings.Contains(out.String(), "acknowledge") {
		t.Fatal("missing explicit operator inputs")
	}
}

func TestProductionReplacementOrderAndFailClosedJournalRetirement(t *testing.T) {
	ctx := context.Background()
	targets := []replacementTarget{{Role: "bridge"}, {Role: "exit-0"}}
	primary := replacementPrimary{SystemIdentifier: "123", Database: "fixture", DatabaseOID: 42, Migrations: "1,2"}
	for _, failure := range []string{"", "discover-exit-0", "fence-exit-0", "clean-exit-0", "bootstrap", "changed-schema", "quiescence-before-cleanup-exit-0", "quiescence-before-cleanup-primary", "quiescence-after-cleanup-bridge", "quiescence-before-journal-primary"} {
		t.Run(failure, func(t *testing.T) {
			var events []string
			retired := false
			stage := ""
			steps := replacementSteps{
				Checkpoint: func(s string) error { stage = s; events = append(events, s); return nil },
				Observe: func(context.Context) (replacementPrimary, error) {
					v := primary
					if failure == "changed-schema" {
						v.Migrations = "1,2,3"
					}
					return v, nil
				},
				Discover: func(context.Context, replacementTarget) error {
					if failure == stage {
						return errors.New("fixture")
					}
					return nil
				},
				Fence: func(context.Context, replacementTarget) error {
					if failure == stage {
						return errors.New("fixture")
					}
					return nil
				},
				Quiescent: func(context.Context, replacementTarget) error {
					if failure == stage {
						return errors.New("unknown session")
					}
					return nil
				},
				PrimaryQuiescent: func(context.Context) error {
					if failure == stage {
						return errors.New("active transaction")
					}
					return nil
				},
				Clean: func(context.Context, replacementTarget, []exits.BootstrapEntry) error {
					if failure == stage {
						return errors.New("fixture")
					}
					return nil
				},
				RetireJournal: func() error { retired = true; return nil },
				Bootstrap: func(context.Context) error {
					if failure == stage {
						return errors.New("fixture")
					}
					return nil
				},
			}
			err := executeProductionReplacement(ctx, targets, primary, steps)
			if failure == "" {
				want := []string{"discover-bridge", "discover-exit-0", "primary-before-fence", "fence-bridge", "fence-exit-0", "primary-before-cleanup", "quiescence-before-cleanup-bridge", "quiescence-before-cleanup-exit-0", "quiescence-before-cleanup-primary", "clean-bridge", "clean-exit-0", "quiescence-after-cleanup-bridge", "quiescence-after-cleanup-exit-0", "quiescence-after-cleanup-primary", "quiescence-before-journal-bridge", "quiescence-before-journal-exit-0", "quiescence-before-journal-primary", "retire-local-journal", "bootstrap", "primary-after-bootstrap", "completed"}
				if err != nil || !reflect.DeepEqual(events, want) {
					t.Fatalf("order: %v %v", events, err)
				}
			} else if err == nil {
				t.Fatal("failed stage was accepted")
			}
			if failure != "" && failure != "bootstrap" && retired {
				t.Fatal("journal retired before all target fences and cleanup succeeded")
			}
			if strings.HasPrefix(failure, "quiescence-before-cleanup") {
				for _, event := range events {
					if strings.HasPrefix(event, "clean-") {
						t.Fatal("cleanup preceded verified session/transaction census")
					}
				}
			}
		})
	}
}

func TestProductionReplacementSessionCensusAndPrimaryTransactions(t *testing.T) {
	program := `import copy,types
exec(sys.stdin.read(),globals())
def row(ppid,sid,uid,comm,*argv):return {'ppid':ppid,'sid':sid,'uids':[uid]*4,'comm':comm,'argv':list(argv)}
base={1:row(0,1,0,'systemd','/sbin/init'),2:row(1,2,0,'sshd','sshd: listener'),90:row(2,2,0,'sshd','sshd: root@notty'),100:row(90,100,0,'python3','python3','-')}
assert validate_sessions(base,100)
sshd_session=copy.deepcopy(base);sshd_session[90]['sid']=90;sshd_session[100]['sid']=90
assert validate_sessions(sshd_session,100)
# A subprocess in this one fresh SSH session is the current probe, not an old worker.
own=copy.deepcopy(base);own[101]=row(100,100,0,'sh','/bin/sh','-c','probe')
assert validate_sessions(own,100)
daemons=copy.deepcopy(base)
def daemon(pid,comm,group,*argv):
 daemons[pid]=row(1,pid,0,comm,*argv);daemons[pid].update(cgroups=[group],loginuid=0)
daemon(996,'chronyd-starter','/system.slice/chrony.service','/bin/sh','/usr/lib/systemd/scripts/chronyd-starter.sh','-n','-F','1')
daemon(1003,'networkd-dispat','/system.slice/networkd-dispatcher.service','/usr/bin/python3','/usr/bin/networkd-dispatcher','--run-startup-triggers')
daemon(1004,'systemd','/user.slice/user-0.slice/user@0.service/init.scope','/usr/lib/systemd/systemd','--user')
daemon(1005,'(sd-pam)','/user.slice/user-0.slice/user@0.service/init.scope','(sd-pam)')
# A second shared root listener is not an authenticated foreign connection.
daemon(1006,'sshd','/system.slice/ssh.service','sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups')
assert validate_sessions(daemons,100)
def rejected(rows,code,uid=None):
 try:validate_sessions(rows,100,uid)
 except ValueError as error:assert str(error)==code,(error,code)
 else:raise AssertionError('unsafe session was accepted')
for pid in (996,1003,1004,1005):
 for mutate in ('path','extra','cgroup','comm'):
  foreign=copy.deepcopy(daemons);candidate=foreign[pid]
  if mutate=='path':candidate['argv'][0]='/tmp/'+os.path.basename(candidate['argv'][0])
  elif mutate=='extra':candidate['argv'].append('/tmp/foreign-hook')
  elif mutate=='cgroup':candidate['cgroups']=['/system.slice/foreign.service']
  else:candidate['comm']='foreign'
  assert not os_service(candidate),(pid,mutate)
  rejected(foreign,'replacement_other_root_ssh_session')
for pid in (996,1003):
 foreign=copy.deepcopy(daemons);candidate=foreign[pid];candidate['argv'][1]='/tmp/'+os.path.basename(candidate['argv'][1]);candidate['loginuid']=4294967295
 assert not os_service(candidate)
 rejected(foreign,'replacement_unknown_root_helper')
foreign=copy.deepcopy(base);foreign[200]=row(2,200,0,'sshd','sshd: root@notty');foreign[201]=row(200,201,0,'python3','/usr/bin/python3','/tmp/ansible/AnsiballZ_command.py')
rejected(foreign,'replacement_other_root_ssh_session')
accepted=copy.deepcopy(base);accepted[32609]=row(2,32609,0,'sshd-session','sshd-session: [accepted]')
rejected(accepted,'replacement_other_root_ssh_session')
preauth=copy.deepcopy(daemons);preauth[33326]=row(2,33326,0,'sshd-session','sshd-session: unknown [priv]');preauth[33327]=row(33326,33326,983,'sshd-auth','sshd-auth: unknown [net]')
assert validate_sessions(preauth,100)
preauth[33329]=row(33326,33329,0,'sh','/bin/sh')
rejected(preauth,'replacement_other_root_ssh_session')
del preauth[33329];preauth[33326]['argv']=['sshd-session: root [priv]']
rejected(preauth,'replacement_other_root_ssh_session')
for pid in (996,1003):
 worker=copy.deepcopy(daemons);worker[pid]['argv'].append('/tmp/ansible/AnsiballZ_command.py')
 worker[pid]['loginuid']=4294967295
 rejected(worker,'replacement_unknown_root_helper')
foreign_manager=copy.deepcopy(daemons);foreign_manager[1007]=row(1004,1007,0,'python3','python3','unknown.py');foreign_manager[1007].update(cgroups=['/user.slice/user-0.slice/user@0.service/init.scope'],loginuid=0)
rejected(foreign_manager,'replacement_other_root_ssh_session')
module=copy.deepcopy(base);module[300]=row(1,300,0,'python3','/usr/bin/python3','/tmp/ansible/AnsiballZ_command.py')
rejected(module,'replacement_unknown_root_helper')
module[300]['argv']+=['--token','secret-value','https://192.0.2.1/private']
module[300]['cgroups']=['/system.slice/ultra-deploy-fixture.service','/system.slice/192.0.2.1.service']
try:validate_sessions(module,100)
except ValueError as error:
 assert str(error)=='replacement_unknown_root_helper'
 assert error.offender=={'pid':300,'ppid':1,'sid':300,'comm':'python3','argv_basenames':['python3','AnsiballZ_command.py'],'cgroups':['/system.slice/ultra-deploy-fixture.service','[redacted]']}
 assert 'secret-value' not in json.dumps(error.offender) and '192.0.2.1' not in json.dumps(error.offender)
else:raise AssertionError('helper was accepted')
orphan=copy.deepcopy(base);orphan[301]=row(1,301,0,'unknown-binary','/tmp/unknown-binary');orphan[301]['loginuid']=0
rejected(orphan,'replacement_other_root_ssh_session')
orphan[301]['loginuid']=1000;orphan[301]['login_scope']=True
rejected(orphan,'replacement_other_root_ssh_session')
tunnel=copy.deepcopy(base);tunnel[400]=row(2,2,0,'sshd-session','sshd-session: ultra-db-tunnel [priv]');tunnel[401]=row(400,401,991,'sshd-session','sshd-session: ultra-db-tunnel@notty')
assert validate_sessions(tunnel,100,991)
# Displayed usernames and a shared tunnel SID never exempt arbitrary root code.
spoof=copy.deepcopy(base);spoof[500]=row(2,500,0,'sshd','sshd: ultra-db-tunnel@notty')
rejected(spoof,'replacement_other_root_ssh_session',991)
tunnel[402]=row(400,401,0,'python3','python3','unknown-helper.py')
rejected(tunnel,'replacement_unknown_root_helper',991)
unisolated=copy.deepcopy(base);unisolated[100]['sid']=2
rejected(unisolated,'replacement_helper_session_unisolated')
# Run the real SQL-producing gate; emulate pg_stat_activity rows locally.
backends=[]
def sql(args,**kw):
 query=kw['input']
 assert 'BEGIN READ ONLY' in query and 'pid<>pg_backend_pid()' in query and "backend_type='client backend'" in query
 assert "state='active'" in query and "state LIKE 'idle in transaction%'" in query and 'xact_start IS NOT NULL' in query
 assert kw['env']['PGOPTIONS'].startswith('-c default_transaction_read_only=on')
 count=sum(1 for b in backends if b['pid']!=900 and b['backend']=='client backend' and (b['state']=='active' or b['state'].startswith('idle in transaction') or b['xact']))
 return types.SimpleNamespace(returncode=0,stdout=str(count))
subprocess.run=sql
backends=[{'pid':900,'backend':'client backend','state':'active','xact':True},{'pid':901,'backend':'walsender','state':'active','xact':True},{'pid':902,'backend':'client backend','state':'idle','xact':False}]
require_primary_idle('fixture')
for state in ('active','idle in transaction','idle in transaction (aborted)'):
 backends.append({'pid':903,'backend':'client backend','state':state,'xact':False})
 try:require_primary_idle('fixture')
 except ValueError as error:assert str(error)=='replacement_primary_client_transactions_active'
 else:raise AssertionError('active client transaction was accepted')
 backends.pop()
`
	cmd := exec.Command("python3", "-c", "import sys\n"+program)
	cmd.Stdin = strings.NewReader(replacementSessionCensusDefinitions)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("quiescence fixture: %v\n%s", err, out)
	}
}

func TestProductionReplacementTransientSSHSessionConfirmation(t *testing.T) {
	program := `import copy,sys
exec(sys.stdin.read(),globals())
def row(ppid,sid,uid,comm,*argv):
 return {'ppid':ppid,'sid':sid,'uids':[uid]*4,'comm':comm,'argv':list(argv)}
base={1:row(0,1,0,'systemd','/sbin/init'),2:row(1,2,0,'sshd','sshd: listener'),90:row(2,90,0,'sshd-session','sshd-session: root@notty'),100:row(90,90,0,'python3','python3','-')}
tail=copy.deepcopy(base)
tail[200]=row(2,200,0,'sshd-session','sshd-session: root@notty')
tail[200]['cgroups']=['/system.slice/ssh.service']
def check(first,second,code=None,pid=None,wait=True,uid=None):
 global read_sessions
 snapshots=[copy.deepcopy(first),copy.deepcopy(second)]
 sleeps=[]
 def read():
  assert snapshots,'unexpected additional census'
  return snapshots.pop(0)
 read_sessions=read
 time.sleep=lambda seconds:sleeps.append(seconds)
 try:
  assert require_sessions_quiescent(100,uid)
 except ValueError as error:
  assert str(error)==code,(str(error),code)
  if pid is not None:assert error.offender['pid']==pid,error.offender
 else:assert code is None,'unsafe session was accepted'
 assert sleeps==([5] if wait else []),sleeps
 assert len(snapshots)==(0 if wait else 1),snapshots
# No delay for an idle census; one complete recheck for an exact transient tail.
check(base,base,wait=False)
check(tail,base)
check(tail,tail,'replacement_other_root_ssh_session',200)
# Even a leader transitioning to an otherwise accepted preauth shape must vanish.
preauth=copy.deepcopy(tail);preauth[200]['argv']=['sshd-session: unknown [priv]']
preauth[201]=row(200,200,983,'sshd-auth','sshd-auth: unknown [net]')
assert validate_sessions(preauth,100)
check(tail,preauth,'replacement_other_root_ssh_session',200)
# A vanished leader cannot hide surviving/new children, even otherwise unknown
# processes or non-root children which the ordinary root census ignores.
for uid in (0,991):
 child=copy.deepcopy(base)
 child[201]=row(1,200,uid,'unknown-binary','/tmp/unknown-binary')
 check(tail,child,'replacement_other_root_ssh_session',201)
child=copy.deepcopy(base);child[201]=row(1,200,0,'sh','/bin/sh')
check(tail,child,'replacement_unknown_root_helper',201)
# Full validation also catches an unrelated blocker arriving during the wait.
new=copy.deepcopy(base);new[300]=row(1,300,0,'python3','python3','/tmp/helper.py')
check(tail,new,'replacement_unknown_root_helper',300)
broken=copy.deepcopy(base);del broken[90]
check(tail,broken,'replacement_session_census_unavailable')
# Dedicated-tunnel handling remains in effect during the second census.
tunnel=copy.deepcopy(base);tunnel[400]=row(2,400,0,'sshd-session','sshd-session: ultra-db-tunnel [priv]');tunnel[401]=row(400,401,991,'sshd-session','sshd-session: ultra-db-tunnel@notty')
check(tail,tunnel,uid=991)
# Other commands, units, and nonleader sessions still fail immediately.
for mutation in ('comm','cgroup','sid'):
 other=copy.deepcopy(tail)
 if mutation=='comm':other[200]['comm']='sshd'
 elif mutation=='cgroup':other[200]['cgroups']=['/system.slice/other.service']
 else:other[200]['sid']=201
 check(other,base,'replacement_other_root_ssh_session',200,wait=False)
`
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = strings.NewReader(replacementSessionCensusDefinitions)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("transient SSH session fixture: %v\n%s", err, out)
	}
}
func TestProductionReplacementQuiescenceDiagnostics(t *testing.T) {
	raw := []byte(`{"quiescent":false,"code":"replacement_unknown_root_helper","offender":{"pid":300,"ppid":1,"sid":300,"comm":"python3","argv_basenames":["python3","AnsiballZ_command.py"],"cgroups":["/system.slice/ultra-deploy-fixture.service"]}}`)
	err := replacementQuiescenceResult(raw)
	if err == nil || !strings.Contains(err.Error(), `replacement_unknown_root_helper: offender={"pid":300`) || !strings.Contains(err.Error(), "AnsiballZ_command.py") {
		t.Fatalf("missing offender: %v", err)
	}
	if err := replacementQuiescenceResult([]byte(`{"quiescent":false,"code":"unknown","offender":{"pid":300}}`)); err == nil || err.Error() != "replacement_quiescence_not_verified" {
		t.Fatalf("unknown code exposed: %v", err)
	}
}

func TestProductionReplacementRemoteFencingAndCleanupIdempotence(t *testing.T) {
	program := `import tempfile,pathlib,os,sys,subprocess,types,shutil,json
root=pathlib.Path(tempfile.mkdtemp(prefix='replacement-fixture-'))
try:
 for p in ('etc/systemd/system','etc/systemd/system/multi-user.target.wants','etc/ultra-relay','etc/ultra-db-tunnel','proc','sys/fs/cgroup','run/systemd/transient','opt','var/lib','usr/local/bin'):(root/p).mkdir(parents=True,exist_ok=True)
 (root/'etc/ultra-relay/fullchain.pem').write_text('fixture-certificate')
 (root/'etc/ultra-relay/privkey.pem').write_text('fixture-key')
 (root/'etc/ultra-db-tunnel/id_ed25519').write_text('fixture-tunnel-key')
 (root/'usr/local/bin/ultra-client').write_text('obsolete-client')
 (root/'etc/systemd/system/multi-user.target.wants/ultra-relay.service').symlink_to('../ultra-relay.service')
 worker=root/'proc/200';worker.mkdir();(worker/'cmdline').write_bytes(b'/usr/local/bin/ultra-install\0operator-upgrade\0');(worker/'stat').write_text('200 (ultra-install) S '+'0 '*18+'123')
 active=True
 def run(args,**kw):
  global active
  if args[0]=='ip':out='[{"addr_info":[{"local":"192.0.2.10"}]}]'
  elif args[1]=='list-units':out='ultra-deploy-'+('a'*64)+'.service loaded active running fixture\n'
  elif args[1]=='list-unit-files':out='ultra-db-tunnel.service enabled\n'
  elif args[1]=='show':out='LoadState='+('loaded' if active or (root/'etc/systemd/system'/args[2]).is_symlink() else 'not-found')+'\nActiveState='+('active' if active else 'inactive')+'\nMainPID='+('200' if active else '0')+'\nControlPID=0\nControlGroup=\n'
  else:active=False;out=''
  return types.SimpleNamespace(returncode=0,stdout=out,stderr='')
 subprocess.run=run
 os.geteuid=lambda:0
 os.kill=lambda pid,sig:shutil.rmtree(root/'proc'/str(pid))
 source=sys.stdin.read()
 for path in ('/etc','/proc','/sys/fs/cgroup','/run','/opt','/var/lib','/usr/local/bin','/usr/lib','/lib'):source=source.replace("'"+path,"'"+str(root)+path)
 for mode in ('fence','clean','clean'):
  sys.argv=['fixture',mode,'bridge','b'*64,'192.0.2.40','[]']
  exec(compile(source,'<replacement-host>','exec'),{})
  mask=root/'etc/systemd/system'/('ultra-deploy-'+('a'*64)+'.service')
  assert mask.is_symlink() and os.readlink(mask)=='/dev/null'
  assert (root/'etc/ultra-relay/fullchain.pem').read_text()=='fixture-certificate'
  assert (root/'etc/ultra-db-tunnel/id_ed25519').read_text()=='fixture-tunnel-key'
  if mode=='clean':
   assert not (root/'etc/systemd/system/ultra-auto-upgrade.timer').is_symlink()
   assert not (root/'etc/systemd/system/ultra-recovery-backup.service').is_symlink()
   assert not (root/'etc/systemd/system/multi-user.target.wants/ultra-relay.service').is_symlink()
   assert not (root/'usr/local/bin/ultra-client').exists()
   inode=(root/'etc/ultra-relay/exit_nodes.bootstrap.json').stat().st_ino
   if 'old_inode' in globals():assert inode==old_inode
   old_inode=inode
finally:shutil.rmtree(root)
`
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = strings.NewReader(replacementHostProgram)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("remote fixture: %v\n%s", err, out)
	}
}

func TestProductionReplacementKeyedRouteComparison(t *testing.T) {
	one := exits.BootstrapEntry{Name: "a", Address: "192.0.2.1", Port: 443, TunnelUUID: "9c92f7c9-a088-4982-a977-9e4fd270b3b5"}
	two := exits.BootstrapEntry{Name: "b", Address: "192.0.2.2", Port: 443, TunnelUUID: "9c92f7c9-a088-4982-a977-9e4fd270b3b6"}
	if err := comparePreservedRouteIdentities([]exits.BootstrapEntry{one, two}, []exits.BootstrapEntry{two, one}); err != nil {
		t.Fatal(err)
	}
	two.TunnelUUID = one.TunnelUUID
	if err := comparePreservedRouteIdentities([]exits.BootstrapEntry{one, two}, []exits.BootstrapEntry{one, one}); err == nil {
		t.Fatal("duplicate/mismatched routes accepted")
	}
}

func TestProductionReplacementRestoreReceiptBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	backup := retainedBackupMetadata{EncryptedSHA256: strings.Repeat("a", 64), DumpSHA256: strings.Repeat("b", 64), ExpectedSourceSHA: strings.Repeat("c", 64), SnapshotStarted: now.Add(-time.Minute)}
	good := replacementRestoreReceipt{Protocol: "ultra-isolated-primary-restore-v1", BackupSHA: backup.EncryptedSHA256, DumpSHA: backup.DumpSHA256, SourceSHA: backup.ExpectedSourceSHA, Database: "fixture", Isolation: "postgres-network-none", RestoredAt: now.Format(time.RFC3339), PublicTables: 37, Migrations: "1,2"}
	if err := validateReplacementRestoreReceipt(mustReplacementJSON(good), backup, "fixture", 2, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*replacementRestoreReceipt){func(r *replacementRestoreReceipt) { r.BackupSHA = strings.Repeat("d", 64) }, func(r *replacementRestoreReceipt) { r.DumpSHA = "wrong" }, func(r *replacementRestoreReceipt) { r.SourceSHA = "wrong" }, func(r *replacementRestoreReceipt) { r.Isolation = "production" }, func(r *replacementRestoreReceipt) { r.PublicTables = 0 }, func(r *replacementRestoreReceipt) { r.Migrations = "1" }, func(r *replacementRestoreReceipt) { r.RestoredAt = now.Add(-time.Hour).Format(time.RFC3339) }} {
		bad := good
		mutate(&bad)
		if err := validateReplacementRestoreReceipt(mustReplacementJSON(bad), backup, "fixture", 2, now); err == nil {
			t.Fatal("unbound/unverified restore accepted")
		}
	}
}

func TestProductionReplacementPreviousTargetUnionAndDigestGate(t *testing.T) {
	plan := func(bridge, exit string) *installplan.InstallPlan {
		p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE_IP": bridge, "MAIN_EXIT_IP": exit, "BRIDGE_SSH_KEY": "/fixture/key", "MAIN_EXIT_SSH_KEY": "/fixture/key", "DATABASE_IP": "192.0.2.40"})
		return p
	}
	current, old := plan("192.0.2.10", "192.0.2.20"), plan("192.0.2.11", "192.0.2.21")
	targets, err := replacementTargets(current)
	if err != nil {
		t.Fatal(err)
	}
	union, err := unionReplacementPreviousTargets(current, old, targets)
	if err != nil || len(union) != 4 {
		t.Fatalf("old workers omitted: %v %v", union, err)
	}
	old.Database.PrimaryHost = "192.0.2.41"
	if _, err = unionReplacementPreviousTargets(current, old, targets); err == nil {
		t.Fatal("old primary silently changed")
	}
	path := t.TempDir() + "/previous.config"
	if err = os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	journal := []byte(`{"mutator_dispatched":true,"config_sha256":"` + strings.Repeat("a", 64) + `"}`)
	if _, err = replacementPreviousTargets(journal, path, current, targets); err == nil || err.Error() != "replacement_exact_dispatched_config_required" {
		t.Fatalf("unbound former config accepted: %v", err)
	}
}
