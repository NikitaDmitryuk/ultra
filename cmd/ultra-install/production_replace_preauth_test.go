package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestProductionReplacementModernOpenSSHPreauth(t *testing.T) {
	program := `import copy,sys,types
exec(sys.stdin.read(),globals())
def row(ppid,sid,uid,comm,title):
 return dict(ppid=ppid,sid=sid,uids=[uid]*4,comm=comm,argv=[title],loginuid=4294967295,login_scope=False,cgroups=['/system.slice/ssh.service'],ssh_executable=True)
base={1:row(0,1,0,'systemd','/sbin/init'),2:row(1,2,0,'sshd','sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups'),90:row(2,90,0,'sshd-session','sshd-session: root@notty'),100:row(90,90,0,'python3','python3')}
def modern():
 rows=copy.deepcopy(base)
 rows[300]=row(2,300,0,'sshd-session','sshd-session: [accepted]')
 rows[301]=row(300,300,983,'sshd-auth','sshd-auth: [session-auth]')
 return rows
valid=modern()
assert modern_preauth_processes(valid)=={300,301}
assert validate_sessions(valid,100)
# Banner-exchange leaf, early auth, and the transient before UID drop are preauth.
leaf=modern();del leaf[301]
assert validate_sessions(leaf,100)
for title in ('sshd-auth: [session-auth]','sshd-auth: [session-auth early]'):
 transient=modern();transient[301].update(argv=[title],uids=[0]*4)
 assert validate_sessions(transient,100)
# Non-root nested helpers must invalidate the whole parent exemption too.
for uid in (0,983):
 unknown=modern();unknown[302]=row(301,300,uid,'unknown','/tmp/unknown')
 assert not modern_preauth_processes(unknown)
def rejected(rows):
 try:validate_sessions(rows,100)
 except ValueError as e:assert str(e)=='replacement_other_root_ssh_session',str(e)
 else:raise AssertionError('unsafe process accepted')
for target in (2,300,301):
 for field,value in (('ssh_executable',False),('cgroups',['/system.slice/foreign.service'])):
  bad=modern();bad[target][field]=value;rejected(bad)
for target in (300,301):
 for field,value in (('loginuid',0),('login_scope',True),('ssh_executable',None),('ssh_executable','unverified')):
  bad=modern();bad[target][field]=value;rejected(bad)
for title in ('sshd-session: root [priv]','sshd-session: root@notty','sshd-session: user [priv]','sshd-session: [accepted] extra'):
 bad=modern();bad[300]['argv']=[title];rejected(bad)
for pid in (300,301):
 bad=modern();bad[pid]['ppid']=1;rejected(bad)
bad=modern();bad[302]=row(300,300,983,'sh','/bin/sh');rejected(bad)
bad=modern();bad[302]=row(301,300,983,'sh','/bin/sh');rejected(bad)
bad=modern();bad[301]['argv']=['sshd-auth: user [net]'];rejected(bad)
bad=modern();del bad[300]['ssh_executable'];rejected(bad)
bad=modern();del bad[301]['login_scope'];rejected(bad)
bad=modern();bad[2]['ppid']=90;assert not modern_preauth_processes(bad)
bad=modern();bad[300]['sid']=2;rejected(bad)
# Pre-fence SSH-only mode permits live app helpers, but authenticated session
# descendants (loginuid/PAM) and all foreign SSH sessions still block.
apps=modern();apps[500]=row(1,500,0,'ultra-install','/opt/ultra-install');apps[500]['argv']=['ultra-install']
assert not session_blockers(apps,100,ssh_only=True)
assert session_blockers(apps,100)[0][0]=='replacement_unknown_root_helper'
for field,value in (('loginuid',0),('login_scope',True)):
 bad=copy.deepcopy(apps);bad[500][field]=value
 assert session_blockers(bad,100,ssh_only=True)[0][0]=='replacement_other_root_ssh_session'
# Validate with fresh snapshots while another root session drains; new allowed
# preauth connections continually replace one another without extending the clock.
clock=[0.0];count=[0]
blocked=modern();blocked[400]=row(2,400,0,'sshd-session','sshd-session: root@notty')
def read():
 count[0]+=1
 if count[0]==1:return blocked
 rows=modern();offset=count[0]*10
 rows[300+offset]=rows.pop(300);rows[301+offset]=rows.pop(301);rows[301+offset]['ppid']=300+offset;rows[300+offset]['sid']=300+offset;rows[301+offset]['sid']=300+offset
 if count[0]<5:rows[400]=copy.deepcopy(blocked[400])
 return rows
read_sessions=read;time.monotonic=lambda:clock[0];time.sleep=lambda duration:clock.__setitem__(0,clock[0]+duration)
assert require_sessions_quiescent(100)
assert clock[0]==1.0 and count[0]==5,(clock,count)
# Once an authenticated session was observed it cannot erase the sticky tree by
# changing back to a valid preauth title, or reparenting and dropping UID.
snapshots=[blocked,valid]
# Use the same PID for the previously authenticated and now preauth monitor.
first=modern();first[300]['argv']=['sshd-session: root [priv]']
snapshots=[first,valid]
read_sessions=lambda:snapshots.pop(0) if len(snapshots)>1 else snapshots[0]
clock[0]=0
try:require_sessions_quiescent(100)
except ValueError as e:assert str(e)=='replacement_other_root_ssh_session'
else:raise AssertionError('tracked authenticated tree was forgotten')
assert clock[0]==40
# Executable verification is independent of title: this Python process cannot
# become an OpenSSH executable by supplying a trusted role name.
assert not trusted_ssh_executable(os.getpid(),'sshd-session')
# Exercise exact inode/root ownership/path checks without production files.
real_path,real_readlink,real_stat=Path,os.readlink,os.stat
metadata=dict(st_mode=0o100755,st_uid=0,st_dev=1,st_ino=7)
class FakePath:
 def __init__(self,value):self.value=value
 @property
 def parents(self):return ()
 def lstat(self):return types.SimpleNamespace(**metadata)
 def stat(self):return types.SimpleNamespace(**metadata)
Path=FakePath;os.readlink=lambda _: '/usr/lib/openssh/sshd-session';os.stat=lambda _:types.SimpleNamespace(**metadata)
assert trusted_ssh_executable(300,'sshd-session')
for key,value in (('st_uid',1000),('st_mode',0o100775),('st_mode',0o120777)):
 old=metadata[key];metadata[key]=value
 assert not trusted_ssh_executable(300,'sshd-session')
 metadata[key]=old
os.stat=lambda _:types.SimpleNamespace(**dict(metadata,st_ino=8))
assert not trusted_ssh_executable(300,'sshd-session')
os.stat=real_stat;os.readlink=lambda _: '/tmp/sshd-session'
assert not trusted_ssh_executable(300,'sshd-session')
Path,os.readlink=real_path,real_readlink
`
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = strings.NewReader(replacementSessionCensusDefinitions)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("modern OpenSSH fixture: %v\n%s", err, out)
	}
}

func TestProductionReplacementPrimarySessionPreflightSkipsTransactions(t *testing.T) {
	program := `import sys,types
exec(sys.stdin.read(),globals())
called=[]
os.geteuid=lambda:0
pwd.getpwnam=lambda _:types.SimpleNamespace(pw_uid=991)
require_sessions_quiescent=lambda pid,uid,ssh_only:called.append(('sessions',uid,ssh_only))
require_primary_idle=lambda db:called.append(('transactions',db))
sys.argv=['fixture','primary-sessions','fixture_db']
exec(sys.argv_program,globals())
assert called==[('sessions',991,True)],called
called.clear();sys.argv=['fixture','bridge-sessions','fixture_db']
exec(sys.argv_program,globals())
assert called==[('sessions',None,True)],called
called.clear();sys.argv=['fixture','primary','fixture_db']
exec(sys.argv_program,globals())
assert called==[('sessions',991,False),('transactions','fixture_db')],called
`
	// Execute the actual entry-point body with synthetic root/process/SQL hooks.
	body := strings.TrimPrefix(replacementQuiescenceProgram, replacementSessionCensusDefinitions)
	cmd := exec.Command("python3", "-c", "import sys\nsys.argv_program="+strconv.Quote(body)+"\n"+program)
	cmd.Stdin = strings.NewReader(replacementSessionCensusDefinitions)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("primary sessions fixture: %v\n%s", err, out)
	}
}
