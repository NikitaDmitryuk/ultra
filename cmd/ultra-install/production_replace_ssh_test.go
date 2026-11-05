package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestReplacementSSHLivenessTransaction(t *testing.T) {
	program := `import os,tempfile,types,sys
exec(sys.stdin.read(),globals())
EXPECTED_OWNER=os.geteuid()
for failure in ('','foreign','suffix','conflicting','validate','changed-auth','changed-nonroot','grace-conflict','grace-ineffective','grace-marker','reload'):
 with tempfile.TemporaryDirectory()as directory:
  main=Path(directory)/'sshd_config';policy=Path(directory)/'policy'
  original=b'Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nSubsystem sftp /usr/lib/openssh/sftp-server\n'
  if failure=='grace-marker':original+=GRACE_PREFIX
  if failure=='suffix':original+=BLOCK+b'PasswordAuthentication yes\n'
  main.write_bytes(original);main.chmod(0o644)
  if failure=='foreign':policy.write_bytes(b'foreign\n');policy.chmod(0o644)
  prior=policy.read_bytes()if policy.exists()else None
  reloads=[]
  def run(args):
   installed=main.read_bytes().endswith(BLOCK)
   if '-t'in args:return types.SimpleNamespace(returncode=1 if failure=='validate'and installed else 0,stdout='')
   root='user=root,'in args[-1]
   active=installed and policy.exists()and policy.read_bytes()==POLICY
   interval,count=('10','2')if active and root else ('0','3')
   if failure=='conflicting'and not active and root:interval='99'
   grace='30'if main.read_bytes().startswith(GRACE_PREFIX)else'120'
   if failure=='grace-conflict'and not active:grace='99'
   if failure=='grace-ineffective':grace='120'
   auth='no'if active and ((failure=='changed-auth'and root)or(failure=='changed-nonroot'and not root))else'yes'
   return types.SimpleNamespace(returncode=0,stdout='logingracetime '+grace+'\nclientaliveinterval '+interval+'\nclientalivecountmax '+count+'\npubkeyauthentication '+auth+'\nhostkey /one\nhostkey /two\n')
  def reload():
   reloads.append(True)
   if failure=='reload'and len(reloads)==1:raise ValueError('replacement_ssh_listener_reload_failed')
  try:receipt=configure_ssh_liveness(main,policy,run,reload,['192.0.2.1','1234','192.0.2.2','22'])
  except ValueError as error:
   assert failure,(failure,error)
   assert main.read_bytes()==original,(failure,'main not rolled back')
   assert (policy.read_bytes()if policy.exists()else None)==prior,(failure,'policy not rolled back')
  else:
   assert not failure,failure
   assert receipt['verified']and receipt['version']==2 and receipt['global_pre_auth']and receipt['login_grace']==30
   assert main.read_bytes()==GRACE_PREFIX+original+BLOCK
   assert policy.read_bytes()==POLICY
   unchanged=main.stat().st_mtime_ns,policy.stat().st_mtime_ns
   configure_ssh_liveness(main,policy,run,reload,['192.0.2.1','1234','192.0.2.2','22'])
   assert unchanged==(main.stat().st_mtime_ns,policy.stat().st_mtime_ns)
   assert len(reloads)==2,reloads
   # An existing root-only managed pair is upgraded without rewriting its bytes.
   main.write_bytes(original+BLOCK)
   configure_ssh_liveness(main,policy,run,reload,['192.0.2.1','1234','192.0.2.2','22'])
   assert main.read_bytes()==GRACE_PREFIX+original+BLOCK
   # Simulate disk publication followed by a crash before the listener HUP.
   listener=[False]
   def activate():listener[0]=True
   configure_ssh_liveness(main,policy,run,activate,['192.0.2.1','1234','192.0.2.2','22'])
   assert listener[0],'identical files skipped interrupted activation'
`
	command := exec.Command("python3", "-c", program)
	command.Stdin = strings.NewReader(replacementSSHLivenessDefinitions)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SSH transaction: %v\n%s", err, output)
	}
}

func TestReplacementSSHListenerBinding(t *testing.T) {
	program := `import os,tempfile,types,sys
exec(sys.stdin.read(),globals())
for failure in ('','unit-custom','argv-custom','argv-override','deleted','uid','inactive','title-custom'):
 with tempfile.TemporaryDirectory()as directory:
  proc=Path(directory);process=proc/str(os.getpid());process.mkdir()
  binary=Path(sys.executable).resolve()
  (process/'exe').symlink_to(str(binary)+(' (deleted)'if failure=='deleted'else''))
  (process/'status').write_text('Uid: '+('1 1 1 1'if failure=='uid'else'0 0 0 0')+'\n')
  args=['sshd: /usr/sbin/sshd -D -e [listener] 0 of 10-100 startups']
  if failure=='argv-custom':args=['/usr/sbin/sshd','-D','-f','/tmp/custom.conf']
  if failure=='argv-override':args=['/usr/sbin/sshd','-D','-o','ClientAliveInterval=0']
  if failure=='title-custom':args=['sshd: /usr/sbin/sshd -D -f /tmp/custom.conf [listener] 0 of 10-100 startups']
  (process/'cmdline').write_bytes(b'\0'.join(a.encode()for a in args)+b'\0')
  def run(args):
   unit='/usr/sbin/sshd -D '+('-f /tmp/custom.conf'if failure=='unit-custom'else'$SSHD_OPTS')
   return types.SimpleNamespace(returncode=0,stdout='ActiveState='+('inactive'if failure=='inactive'else'active')+'\nMainPID='+str(os.getpid())+'\nExecStart={ path=/usr/sbin/sshd ; argv[]='+unit+' ; ignore_errors=no ; }\n')
  try:fd,activate=bind_ssh_listener(run,proc,binary)
  except ValueError as error:assert failure,(failure,error)
  else:
   try:
    assert not failure,failure
    calls=[];original_signal=signal.pidfd_send_signal
    signal.pidfd_send_signal=lambda target,sig:calls.append((target,sig))
    try:activate()
    finally:signal.pidfd_send_signal=original_signal
    assert calls==[(fd,signal.SIGHUP)],calls
   finally:os.close(fd)
`
	command := exec.Command("python3", "-c", program)
	command.Stdin = strings.NewReader(replacementSSHLivenessDefinitions)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SSH listener binding: %v\n%s", err, output)
	}
}

func TestReplacementSSHRoleBinding(t *testing.T) {
	program := `import sys
exec(sys.stdin.read(),globals())
for role in ('primary','bridge','exit-0','former-2','unknown'):
 for local in ('192.0.2.20','192.0.2.21'):
  allowed=role!='unknown'and((role=='primary')==(local=='192.0.2.20'))
  try:validate_ssh_target(role,'192.0.2.20',[{'addr_info':[{'local':local}]}])
  except ValueError:assert not allowed,(role,local)
  else:assert allowed,(role,local)
`
	command := exec.Command("python3", "-c", program)
	command.Stdin = strings.NewReader(replacementSSHLivenessDefinitions)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SSH role binding: %v\n%s", err, output)
	}
}

func TestReplacementSSHReceiptBinding(t *testing.T) {
	good := map[string]any{
		"verified":        true,
		"version":         2,
		"role":            "primary",
		"global_pre_auth": true,
		"login_grace":     30,
		"interval":        10,
		"count":           2,
	}
	for _, field := range []string{"", "verified", "version", "role", "global_pre_auth", "login_grace", "interval", "count"} {
		candidate := make(map[string]any)
		for k, v := range good {
			candidate[k] = v
		}
		if field != "" {
			delete(candidate, field)
		}
		raw, _ := json.Marshal(candidate)
		err := validateReplacementSSHReceipt(raw, "primary")
		if (err == nil) != (field == "") {
			t.Fatalf("field %q: %v", field, err)
		}
	}
	raw, _ := json.Marshal(good)
	if validateReplacementSSHReceipt(raw, "bridge") == nil {
		t.Fatal("primary receipt accepted for bridge")
	}
	if validateReplacementSSHReceipt(append(raw, raw...), "primary") == nil {
		t.Fatal("multiple receipts accepted")
	}
}

func TestReplacementSSHActualConfigParser(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("local sshd unavailable")
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("local ssh-keygen unavailable")
	}
	program := `import os,tempfile,subprocess,sys
exec(sys.stdin.read(),globals())
EXPECTED_OWNER=os.geteuid()
with tempfile.TemporaryDirectory()as directory:
 main=Path(directory)/'sshd_config';policy=Path(directory)/'policy';key=Path(directory)/'hostkey'
 subprocess.run([sys.argv[2],'-q','-t','ed25519','-N','','-f',str(key)],check=True)
 BLOCK=BLOCK.replace(b'/etc/ssh/ultra-root-liveness.conf',str(policy).encode())
 original=('HostKey '+str(key)+'\nLoginGraceTime 120\nPasswordAuthentication no\n').encode()
 main.write_bytes(original);main.chmod(0o600)
 def run(args):return subprocess.run([sys.argv[1],'-f',str(main),*args[1:]],capture_output=True,text=True)
 receipt=configure_ssh_liveness(main,policy,run,lambda:None,['192.0.2.1','1234','192.0.2.2','22'])
 assert receipt['login_grace']==30
 assert main.read_bytes()==GRACE_PREFIX+original+BLOCK
 for user in ('root','nobody'):
  output=run(['sshd','-T','-C','user='+user+',host=192.0.2.1,addr=192.0.2.1,laddr=192.0.2.2,lport=22'])
  assert output.returncode==0,output.stderr
  values={line.split(' ',1)[0].lower():line.split(' ',1)[1]for line in output.stdout.splitlines()}
  assert values['logingracetime']=='30'and values['passwordauthentication']=='no'
  assert values['clientaliveinterval']==('10'if user=='root'else'0')
  assert values['clientalivecountmax']==('2'if user=='root'else'3')
`
	command := exec.Command("python3", "-c", program, sshd, keygen)
	command.Stdin = strings.NewReader(replacementSSHLivenessDefinitions)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual sshd config: %v\n%s", err, output)
	}
}
