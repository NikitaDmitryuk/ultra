package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func prepareReplacementSSH(ctx context.Context, plan *installplan.InstallPlan, target replacementTarget) ([]byte, error) {
	raw, err := retainedMutation(
		ctx,
		plan,
		target.Address,
		target.Identity,
		false,
		replacementSSHLivenessProgram,
		[]string{target.Role, plan.Database.PrimaryHost},
	)
	if err != nil {
		return nil, err
	}
	var receipt struct {
		Verified bool `json:"verified"`
		RootOnly bool `json:"root_only"`
		Interval int  `json:"interval"`
		Count    int  `json:"count"`
	}
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &receipt) != nil || !receipt.Verified || !receipt.RootOnly ||
		receipt.Interval != 10 ||
		receipt.Count != 2 {
		return nil, errors.New("replacement_ssh_liveness_receipt_invalid")
	}
	return raw, nil
}

// Match belongs at the end of the main configuration: an early conf.d Include
// would otherwise put subsequent global-only directives inside a Match block.
// No authentication directive or existing configuration byte is rewritten.
const replacementSSHLivenessDefinitions = `import os,sys,json,stat,tempfile,subprocess,ipaddress,re,signal,shlex
from pathlib import Path
EXPECTED_OWNER=0
POLICY=b'Match User root\n    ClientAliveInterval 10\n    ClientAliveCountMax 2\n'
BLOCK=b'\n# BEGIN ultra managed root SSH liveness\nMatch all\nInclude /etc/ssh/ultra-root-liveness.conf\n# END ultra managed root SSH liveness\n'
MARKER=b'ultra managed root SSH liveness'
def require(value,code):
 if not value:raise ValueError(code)
def private_config(path,optional=False):
 for parent in path.parents:require(not parent.is_symlink(),'replacement_ssh_config_symlink')
 try:info=path.lstat()
 except FileNotFoundError:
  if optional:return None
  raise ValueError('replacement_ssh_config_missing')
 require(stat.S_ISREG(info.st_mode) and info.st_uid==EXPECTED_OWNER and info.st_nlink==1 and info.st_mode&0o022==0,'replacement_ssh_config_ownership')
 return path.read_bytes(),stat.S_IMODE(info.st_mode)
def atomic_config(path,data,mode):
 fd,name=tempfile.mkstemp(prefix='.ultra-ssh-',dir=path.parent)
 try:
  os.fchmod(fd,mode)
  with os.fdopen(fd,'wb')as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  os.replace(name,path)
  parent=os.open(path.parent,os.O_DIRECTORY)
  try:os.fsync(parent)
  finally:os.close(parent)
 finally:
  if os.path.exists(name):os.unlink(name)
def bind_ssh_listener(run,proc=Path('/proc'),binary=Path('/usr/sbin/sshd')):
 result=run(['systemctl','show','ssh.service','--property=ActiveState,MainPID,ExecStart'])
 require(result.returncode==0,'replacement_ssh_listener_unavailable')
 fields=dict(line.split('=',1)for line in result.stdout.splitlines()if '='in line)
 require(fields.get('ActiveState')=='active' and fields.get('MainPID','').isdigit(),'replacement_ssh_listener_unavailable')
 pid=int(fields['MainPID']);require(pid>0,'replacement_ssh_listener_unavailable')
 # systemd retains an unexpanded SSHD_OPTS token in the stock unit. The
 # actual listener argv below must independently contain only default flags.
 start=fields.get('ExecStart','')
 match=re.fullmatch(r'\{ path=/usr/sbin/sshd ; argv\[\]=([^;]+) ;[^{}]*\}',start)
 require(match is not None,'replacement_ssh_listener_start_unsupported')
 unit=shlex.split(match.group(1).strip())
 require(unit and unit[0]=='/usr/sbin/sshd' and unit[1:]in (['-D'],['-D','-e'],['-D','$SSHD_OPTS'],['-D','-e','$SSHD_OPTS']),'replacement_ssh_listener_start_unsupported')
 process=proc/str(pid)
 fd=os.pidfd_open(pid)
 try:
  require(not os.readlink(process/'exe').endswith(' (deleted)') and os.path.samefile(process/'exe',binary),'replacement_ssh_listener_binary_unsupported')
  uids=next(line for line in (process/'status').read_text().splitlines()if line.startswith('Uid:')).split()[1:]
  require(len(uids)==4 and all(uid=='0'for uid in uids),'replacement_ssh_listener_identity_invalid')
  args=[value.decode()for value in (process/'cmdline').read_bytes().split(b'\0')if value]
  if len(args)==1 and args[0].startswith('sshd: '):
   # OpenSSH rewrites its argv into a listener title. Require the complete
   # supported prefix and suffix; truncated/custom startup arguments fail shut.
   title=re.fullmatch(r'sshd: (/usr/sbin/sshd -D(?: -e)?) \[listener\] [0-9]+ of [0-9]+-[0-9]+ startups',args[0].strip())
   require(title is not None,'replacement_ssh_listener_args_unsupported')
   args=shlex.split(title.group(1))
  require(args in (['/usr/sbin/sshd','-D'],['/usr/sbin/sshd','-D','-e']),'replacement_ssh_listener_args_unsupported')
  # pidfd pins this process across config validation and avoids unit-specific
  # ExecReload adapters, including a successful no-op reload command.
  def activate():
   signal.pidfd_send_signal(fd,signal.SIGHUP)
  return fd,activate
 except Exception:
  os.close(fd);raise
def configure_ssh_liveness(main,policy,run,reload,connection):
 original=private_config(main)
 previous=private_config(policy,True)
 require(previous is None or previous[0]==POLICY,'replacement_ssh_policy_foreign')
 require(MARKER not in original[0] or (original[0].endswith(BLOCK) and original[0].count(MARKER)==2),'replacement_ssh_config_marker_conflict')
 require(len(connection)==4,'replacement_ssh_connection_unavailable')
 remote,remoteport,local,localport=connection
 ipaddress.ip_address(remote);ipaddress.ip_address(local)
 require(remoteport.isdigit() and localport.isdigit(),'replacement_ssh_connection_invalid')
 def command(arguments):
  result=run(arguments)
  require(result.returncode==0,'replacement_ssh_config_validation_failed')
  return result.stdout
 def effective(user):
  context='user='+user+',host='+remote+',addr='+remote+',laddr='+local+',lport='+localport
  output=command(['/usr/sbin/sshd','-T','-C',context])
  result={}
  for line in output.splitlines():
   key,space,value=line.partition(' ')
   require(space,'replacement_ssh_effective_config_invalid')
   result.setdefault(key,[]).append(value)
  return result
 command(['/usr/sbin/sshd','-t'])
 before={user:effective(user)for user in ('root','nobody')}
 alive=('clientaliveinterval','clientalivecountmax')
 require(tuple(before['root'].get(k,[None])[0]for k in alive) in (('0','3'),('10','2')),'replacement_ssh_liveness_conflict')
 candidate=original[0] if original[0].endswith(BLOCK)else original[0]+BLOCK
 installed=False
 def restore():
  current_main=private_config(main)
  current_policy=private_config(policy,True)
  require(current_main[0] in (original[0],candidate) and (current_policy is None or current_policy[0]==POLICY or current_policy==previous),'replacement_ssh_rollback_foreign_change')
  if previous is None:policy.unlink(missing_ok=True)
  else:atomic_config(policy,previous[0],previous[1])
  atomic_config(main,original[0],original[1])
  command(['/usr/sbin/sshd','-t'])
  require(all(effective(user)==before[user]for user in before),'replacement_ssh_rollback_config_changed')
  reload()
 try:
  require(private_config(main)==original and private_config(policy,True)==previous,'replacement_ssh_config_changed')
  # Install the include target first. A crash cannot publish an include of
  # uncontrolled bytes; the exact owned partial pair is safe to complete later.
  if previous is None:atomic_config(policy,POLICY,0o644);installed=True
  require(private_config(main)==original,'replacement_ssh_config_changed')
  if candidate!=original[0]:atomic_config(main,candidate,original[1]);installed=True
  command(['/usr/sbin/sshd','-t'])
  after={user:effective(user)for user in before}
  require(tuple(after['root'].get(k,[None])[0]for k in alive)==('10','2'),'replacement_ssh_liveness_not_effective')
  require({k:v for k,v in before['root'].items()if k not in alive}=={k:v for k,v in after['root'].items()if k not in alive} and before['nobody']==after['nobody'],'replacement_ssh_other_settings_changed')
  # Disk identity cannot prove that the listener survived activation. A prior
  # crash may have installed both files immediately before its SIGHUP.
  reload()
  require(private_config(main)[0]==candidate and private_config(policy)[0]==POLICY,'replacement_ssh_config_changed')
  require(all(effective(user)==after[user]for user in after),'replacement_ssh_reloaded_settings_changed')
 except Exception as error:
  if installed:
   try:restore()
   except Exception:raise ValueError('replacement_ssh_rollback_failed')from None
  raise error
 return {'verified':True,'root_only':True,'interval':10,'count':2}
`

const replacementSSHLivenessProgram = replacementSSHLivenessDefinitions + `
try:
 role,primary=sys.argv[1:]
 require(os.geteuid()==0 and (role=='bridge' or re.fullmatch('(exit|former)-[0-9]+',role)),'replacement_ssh_role_forbidden')
 addresses=json.loads(subprocess.run(['ip','-j','address','show'],check=True,capture_output=True,text=True,timeout=5).stdout)
 require(all(ipaddress.ip_address(a['local'])!=ipaddress.ip_address(primary)for row in addresses for a in row.get('addr_info',[])),'replacement_ssh_primary_forbidden')
 def run(arguments):return subprocess.run(arguments,capture_output=True,text=True,timeout=5)
 listener_fd,reload=bind_ssh_listener(run)
 try:print(json.dumps(configure_ssh_liveness(Path('/etc/ssh/sshd_config'),Path('/etc/ssh/ultra-root-liveness.conf'),run,reload,os.environ.get('SSH_CONNECTION','').split())))
 finally:os.close(listener_fd)
except Exception as error:
 code=str(error)
 if not code.startswith('replacement_ssh_'):code='replacement_ssh_liveness_unavailable'
 print(json.dumps({'verified':False,'code':code}))
 sys.exit(1)
`
