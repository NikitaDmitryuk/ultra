package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const recoveryPreparationAdmissionPath = "/var/lib/ultra-ansible/recovery-preparation-admission.json"

type recoveryPreparationAdmission struct {
	Protocol               string `json:"protocol"`
	FenceSHA256            string `json:"fence_sha256"`
	BaselineManifestSHA256 string `json:"baseline_manifest_sha256"`
	ConfigSHA256           string `json:"config_sha256"`
	Phase                  string `json:"phase"`
}

func (a recoveryPreparationAdmission) valid() bool {
	return a.Protocol == "ultra-recovery-preparation-admission-v1" && a.Phase == "sealed" && runtimeHostValidDigest(a.FenceSHA256) &&
		runtimeHostValidDigest(a.BaselineManifestSHA256) &&
		runtimeHostValidDigest(a.ConfigSHA256)
}

type recoveryPreparationAdmissionLease struct {
	command    *exec.Cmd
	input      io.WriteCloser
	output     *bufio.Scanner
	outputFile *os.File
	done       chan struct{}
	waitErr    error
}

func (l *recoveryPreparationAdmissionLease) close() {
	_ = l.input.Close()
	<-l.done
	_ = l.outputFile.Close()
}

func (l *recoveryPreparationAdmissionLease) recheck() error {
	select {
	case <-l.done:
		return errors.New("recovery_preparation_lease_lost")
	default:
	}
	if _, err := io.WriteString(l.input, "recheck\n"); err != nil {
		return errors.New("recovery_preparation_lease_lost")
	}
	if !l.output.Scan() || l.output.Text() != "verified" {
		return errors.New("recovery_preparation_recheck_unverified")
	}
	select {
	case <-l.done:
		return errors.New("recovery_preparation_lease_lost")
	default:
		return nil
	}
}

// seal=false is strictly observational. The session retains all legacy locks
// until close, allowing callers to publish separately audited evidence safely.
func openRecoveryPreparationAdmission(
	ctx context.Context,
	p *installplan.InstallPlan,
	role, address, key string,
	a recoveryPreparationAdmission,
	baselineInstallers map[string]string,
	seal bool,
) (*recoveryPreparationAdmissionLease, error) {
	if !a.valid() || (role != "bridge" && role != "exit") {
		return nil, errors.New("recovery_preparation_admission_invalid")
	}
	payload, _ := json.Marshal(map[string]any{"admission": a, "baseline_installers": baselineInstallers})
	mode := "validate"
	if seal {
		mode = "seal"
	}
	args := retainedSSH(p, address, key, false, true)
	args = append(
		args,
		strings.Join(
			quoteRetainedArgs(
				[]string{"python3", "-u", "-c", recoveryPreparationAdmissionRemote, mode, role, base64.StdEncoding.EncodeToString(payload)},
			),
			" ",
		),
	)
	return startRecoveryPreparationAdmission(exec.CommandContext(ctx, args[0], args[1:]...), mode)
}

func openLocalRecoveryPreparationAdmission(
	ctx context.Context,
	a recoveryPreparationAdmission,
	baselineInstallers map[string]string,
	seal bool,
) (*recoveryPreparationAdmissionLease, error) {
	if !a.valid() {
		return nil, errors.New("recovery_preparation_admission_invalid")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executableSHA, err := sourceSHA(executable)
	if err != nil {
		return nil, err
	}
	commandLine, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(
		map[string]any{
			"admission":           a,
			"baseline_installers": baselineInstallers,
			"local_invoker": map[string]any{
				"pid":               os.Getpid(),
				"executable_sha256": executableSHA,
				"cmdline_sha256":    digestSHA256(commandLine),
			},
		},
	)
	mode := "validate"
	if seal {
		mode = "seal"
	}
	return startRecoveryPreparationAdmission(
		exec.CommandContext(
			ctx,
			"python3",
			"-u",
			"-c",
			recoveryPreparationAdmissionRemote,
			mode,
			"bridge",
			base64.StdEncoding.EncodeToString(payload),
		),
		mode,
	)
}

func startRecoveryPreparationAdmission(command *exec.Cmd, mode string) (*recoveryPreparationAdmissionLease, error) {
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, writer, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	command.Stdout = writer
	lease := &recoveryPreparationAdmissionLease{
		command:    command,
		input:      input,
		output:     bufio.NewScanner(output),
		outputFile: output,
		done:       make(chan struct{}),
	}
	if err = command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		_ = writer.Close()
		return nil, errors.New("recovery_preparation_admission_start_failed")
	}
	_ = writer.Close()
	go func() { lease.waitErr = command.Wait(); close(lease.done) }()
	if !lease.output.Scan() || lease.output.Text() != "verified" {
		lease.close()
		return nil, fmt.Errorf("recovery_preparation_%s_unverified", mode)
	}
	return lease, nil
}

// This gate closes the legacy broker's actual dispatch origins. Free advisory
// locks or a disappeared PID alone never authorize mutation. An ambiguous legacy
// job is not cancelled, retried, deleted or declared quiescent by this protocol.
const recoveryPreparationAdmissionRemote = `import os,sys,stat,json,fcntl,subprocess,hashlib,base64,re,platform,tempfile
from pathlib import Path
mode,role,encoded=sys.argv[1:]
assert mode in ('seal','validate') and role in ('bridge','exit')
payload=json.loads(base64.b64decode(encoded,validate=True))
expected=payload['admission']
assert set(expected)=={'protocol','fence_sha256','baseline_manifest_sha256','config_sha256','phase'}
assert expected['protocol']=='ultra-recovery-preparation-admission-v1' and expected['phase']=='sealed'
assert all(re.fullmatch('[a-f0-9]{64}',expected[k]) for k in ['fence_sha256','baseline_manifest_sha256','config_sha256'])
state=Path('/var/lib/ultra-ansible')
system=Path('/etc/systemd/system')
proc=Path('/proc')
record=state/'recovery-preparation-admission.json'
blocked='[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
units=['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']
def trusted(path,directory=False,private=False):
 p=Path(path)
 for ancestor in [p]+list(p.parents):
  s=ancestor.lstat();assert s.st_uid==0 and not s.st_mode&0o022 and not stat.S_ISLNK(s.st_mode)
 s=p.lstat()
 assert stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1
 if private:assert stat.S_IMODE(s.st_mode)==0o600
 return p
def read(path):return json.loads(trusted(path,private=True).read_text())
def show(unit):
 r=subprocess.run(['systemctl','show',unit,'--property=LoadState','--property=ActiveState','--property=RefuseManualStart','--property=UnitFileState','--property=MainPID','--property=Id','--property=SubState','--property=FragmentPath','--property=ControlGroup','--property=User','--property=Group','--property=DropInPaths'],capture_output=True,text=True,timeout=10)
 assert r.returncode in (0,1)
 return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def publish(path,raw,mode=0o600):
 # Caller validates any replaceable old content first. Never truncate a link.
 fd,name=tempfile.mkstemp(prefix='.recovery-prepare-',dir=path.parent)
 try:
  os.fchmod(fd,mode)
  with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  os.replace(name,path);syncdir(path.parent)
 finally:
  if os.path.lexists(name):os.unlink(name)
def binding(value):return {k:v for k,v in value.items() if k!='phase'}
trusted(state,True)
assert not os.path.lexists(state/'retained-primary-admission-open')
assert read(state/'retained-primary-admission.json')=={'protocol':'retained-primary-admission-v1','binding_sha256':expected['fence_sha256']}
assert not os.path.lexists(state/'recovery-fence.json') and not os.path.lexists(state/'recovery-anchor.json')
assert not os.path.lexists(state/'execution-fence.json')
locks=[]
lock_paths=[state/'infrastructure.lock',state/'operator-inputs/manual-deploy.lock']
if role=='bridge' or os.path.lexists(state/'operator/infrastructure.lock'):lock_paths.append(state/'operator/infrastructure.lock')
for path in lock_paths:
 trusted(path,private=True)
 fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
if os.path.lexists(record):
 previous=read(record)
 assert binding(previous)==binding(expected) and previous.get('phase') in ('sealing','sealed')
else:assert mode=='seal'
lifecycle=read(state/'lifecycle.json') if os.path.lexists(state/'lifecycle.json') else {}
assert lifecycle.get('phase')=='released' or (role=='exit' and not lifecycle)
def queue():
 assert not os.path.lexists(state/'execution-fence.json')
 assert not os.path.lexists(state/'retained-primary-admission-open')
 assert read(state/'retained-primary-admission.json')=={'protocol':'retained-primary-admission-v1','binding_sha256':expected['fence_sha256']}
 for job in state.iterdir():
  if not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',job.name):continue
  trusted(job,True)
  if not os.path.lexists(job/'prepared'):continue
  # Even a cached failed receipt is ambiguous for an old unfenced executor.
  saved=read(job/'receipt.json');assert saved.get('state')=='succeeded'
  raw=trusted(job/'request.json').read_bytes();metadata=read(job/'job.json')
  assert metadata.get('request_sha256')==hashlib.sha256(raw).hexdigest()
  assert saved.get('request_sha256')==metadata['request_sha256'] and saved.get('binary_sha256')==metadata.get('binary_sha256')
def authenticated_observer(item,args):
 # Only the exact validated start waiter may coexist with its own supervisor.
 # A marker is not a quiescence claim and never authorizes another mutator.
 try:
  operations=state/'deploy-operations'
  pointer=read(operations/'current.json');request_sha=pointer['request_sha256']
  assert pointer.get('schema')==1 and re.fullmatch('[a-f0-9]{64}',request_sha)
  operation=operations/request_sha
  raw=trusted(operation/'request.json',private=True).read_bytes();assert hashlib.sha256(raw).hexdigest()==request_sha
  request=json.loads(raw);status=read(operation/'state.json')
  assert request.get('schema')==2 and status.get('schema')==1 and status.get('request_sha256')==request_sha
  assert status.get('state') in ('submitted','prepared','running','blocked','retry_prepared')
  preparation=request['preparation']
  assert preparation['retained_fence_sha256']==expected['fence_sha256'] and preparation['baseline_manifest_sha256']==expected['baseline_manifest_sha256'] and preparation['config_sha256']==expected['config_sha256']
  start=(item/'stat').read_text().rsplit(')',1)[1].split()[19];assert start.isdigit()
  observer=read(operation/'observers'/(item.name+'-'+start+'.json'))
  assert set(observer)=={'schema','request_sha256','pid','starttime','executable_sha256','argv_sha256'}
  command=(item/'cmdline').read_bytes();executable=(item/'exe').read_bytes()
  assert observer=={'schema':1,'request_sha256':request_sha,'pid':int(item.name),'starttime':start,'executable_sha256':hashlib.sha256(executable).hexdigest(),'argv_sha256':hashlib.sha256(command).hexdigest()}
  argv=[value.decode() for value in args if value]
  assert argv[1:3]==['deploy-operation','start'] and '--' in argv
  separator=argv.index('--');options=argv[3:separator]
  assert len(options)==4 and len(set(options[::2]))==2
  flags=dict(zip(options[::2],options[1::2]));assert set(flags)=={'--preparation-file','--preparation-sha256'}
  imported=Path(preparation['retained_directory']).parent/'preparation.json'
  assert flags['--preparation-file']==str(imported) and hashlib.sha256(trusted(imported,private=True).read_bytes()).hexdigest()==flags['--preparation-sha256']
  frozen=argv[separator+1:];controls=[value for value in frozen if value in ('--retry-failed','--retry-failed=true','--retry-failed=false')]
  assert len(controls)<=1
  frozen=[value for value in frozen if value not in controls]
  assert frozen==request['args'] and frozen[0]=='operator-upgrade'
  release=Path(preparation['tools_release_directory'])
  assert release.parent.parent==state/'operator-inputs' and release.name=='release' and re.fullmatch('manual-[a-f0-9]{40}-[a-f0-9]{64}',release.parent.name)
  manifest_raw=trusted(release/'release-manifest.json').read_bytes()
  assert hashlib.sha256(manifest_raw).hexdigest()==preparation['tools_manifest_sha256']
  manifest=json.loads(manifest_raw);commit=manifest['source_commit']
  assert re.fullmatch('[a-f0-9]{40}',commit) and manifest['version']=='v0.0.'+str(int(commit,16)) and release.parent.name.startswith('manual-'+commit+'-')
  assert frozen[frozen.index('--source-commit')+1]==commit and frozen[frozen.index('--version')+1]==manifest['version']
  arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
  asset=next(row for row in manifest['assets'] if row['name']=='ultra-install-linux-'+arch)
  assert len(executable)==asset['size'] and hashlib.sha256(executable).hexdigest()==asset['sha256']
  assert hashlib.sha256(trusted(release/asset['name']).read_bytes()).hexdigest()==asset['sha256']
  return True
 except (OSError,ValueError,AssertionError,KeyError,IndexError,StopIteration,TypeError):return False
` + recoveryPreparationManagedControllerRemote + `
def census(allowed=None):
 allowed=set(allowed or [])
 invoker=payload.get('local_invoker')
 if invoker is not None:
  assert set(invoker)=={'pid','executable_sha256','cmdline_sha256'} and type(invoker['pid']) is int and invoker['pid']>0
  parent=proc/str(invoker['pid'])
  assert hashlib.sha256((parent/'exe').read_bytes()).hexdigest()==invoker['executable_sha256']
  assert hashlib.sha256((parent/'cmdline').read_bytes()).hexdigest()==invoker['cmdline_sha256']
  allowed.add(invoker['pid'])
 for item in proc.iterdir():
  if not item.name.isdigit() or int(item.name)==os.getpid() or int(item.name) in allowed:continue
  try:args=(item/'cmdline').read_bytes().split(b'\0')
  except (FileNotFoundError,ProcessLookupError):continue
  if authenticated_observer(item,args):continue
  names=[os.path.basename(value.decode(errors='replace')) for value in args]
  assert not any(value in ['ultra-install','ansible-playbook','controller.py','reconcile.py','ansible-controller','ansible-run','ansible-exit','rebuild-retained-primary','operator-upgrade','deploy-operation','ansible-retry-bootstrap','ansible-bootstrap-components','retained-primary-reconcile','apply-remote'] for value in names)
def dropins(allow_opened):
 for unit in units:
  path=trusted(system/(unit+'.d/90-retained-primary.conf'))
  content=path.read_text()
  if content==blocked:continue
  assert allow_opened and role=='bridge' and unit==units[0]
  match=re.fullmatch(r'\[Unit\]\nRefuseManualStart=no\nConditionPathExists=(/var/lib/ultra-ansible/retained-primary-controller-([a-f0-9]{64})\.json)\n',content)
  assert match
  raw=trusted(match[1]).read_bytes();assert hashlib.sha256(raw).hexdigest()==match[2]
  auth=json.loads(raw)
  assert auth['protocol']=='ultra-retained-primary-reconcile-v1' and auth['fence_sha256']==expected['fence_sha256']
  assert auth['artifacts']['manifest']==expected['baseline_manifest_sha256'] and auth['artifacts']['config']==expected['config_sha256']
def sealed():
 assert read(record)==expected
 dropins(False)
 for unit in units:
  properties=show(unit)
  assert properties.get('ActiveState') in ('inactive','failed')
  if properties.get('LoadState')=='loaded':
   assert properties.get('RefuseManualStart')=='yes'
   assert properties.get('UnitFileState') in ('disabled','static','indirect','masked')
   assert properties.get('MainPID','0')=='0'
 queue();census()
if mode=='seal':
 dropins(True);queue()
 properties=show(units[0]);allowed=set();managed=None
 if properties.get('ActiveState')=='active':
  assert role=='bridge'
  pid=int(properties['MainPID']);assert pid>0
  args=[value.decode() for value in (proc/str(pid)/'cmdline').read_bytes().split(b'\0') if value]
  assert len(args)==4 and args[1:3]==['ansible-controller','--executable']
  assert re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}/ultra-install',args[0])
  assert args[3]==str(Path(args[0]).parent/'venv/bin/ansible-playbook')
  arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
  executable=(proc/str(pid)/'exe').read_bytes()
  if hashlib.sha256(executable).hexdigest()!=payload['baseline_installers'][arch]:
   managed_controller(pid,args,executable,arch)
   managed=(pid,args,executable,arch,(proc/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19])
  allowed.add(pid)
 census(allowed)
 publish(record,json.dumps(dict(expected,phase='sealing'),sort_keys=True).encode())
 for unit in units:publish(system/(unit+'.d/90-retained-primary.conf'),blocked.encode(),0o644)
 subprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)
 if managed is not None:
  pid,args,executable,arch,starttime=managed
  assert (proc/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]==starttime
  assert [value.decode() for value in (proc/str(pid)/'cmdline').read_bytes().split(b'\0') if value]==args
  assert (proc/str(pid)/'exe').read_bytes()==executable
  managed_controller(pid,args,executable,arch)
  queue();census(allowed)
 # A free infrastructure lock is only serialization. We stop solely the exact
 # idle broker just authenticated above, never a job or an unknown process.
 for unit in units:
  subprocess.run(['systemctl','stop',unit],check=True,timeout=30)
  subprocess.run(['systemctl','disable',unit],check=True,timeout=20)
 queue();census();dropins(False)
 for unit in units:
  properties=show(unit)
  assert properties.get('ActiveState') in ('inactive','failed') and properties.get('MainPID','0')=='0'
 publish(record,json.dumps(expected,sort_keys=True).encode())
sealed()
print('verified',flush=True)
for command in sys.stdin:
 assert command=='recheck\n'
 sealed()
 print('verified',flush=True)
`
