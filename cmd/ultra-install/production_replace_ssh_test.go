package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReplacementSSHLivenessTransaction(t *testing.T) {
	program := `import os,tempfile,types,sys
exec(sys.stdin.read(),globals())
EXPECTED_OWNER=os.geteuid()
for failure in ('','foreign','suffix','conflicting','validate','changed-auth','reload'):
 with tempfile.TemporaryDirectory()as directory:
  main=Path(directory)/'sshd_config';policy=Path(directory)/'policy'
  original=b'Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nSubsystem sftp /usr/lib/openssh/sftp-server\n'
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
   auth='no'if failure=='changed-auth'and active and root else'yes'
   return types.SimpleNamespace(returncode=0,stdout='clientaliveinterval '+interval+'\nclientalivecountmax '+count+'\npubkeyauthentication '+auth+'\nhostkey /one\nhostkey /two\n')
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
   assert receipt['verified']and receipt['root_only']
   assert main.read_bytes()==original+BLOCK
   assert policy.read_bytes()==POLICY
   unchanged=main.stat().st_mtime_ns,policy.stat().st_mtime_ns
   configure_ssh_liveness(main,policy,run,reload,['192.0.2.1','1234','192.0.2.2','22'])
   assert unchanged==(main.stat().st_mtime_ns,policy.stat().st_mtime_ns)
   assert len(reloads)==2,reloads
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
