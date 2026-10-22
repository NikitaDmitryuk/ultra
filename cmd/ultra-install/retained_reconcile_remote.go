package main

import "strconv"

// The same SSH session holds both locks through fresh observations and optional
// authorization. EOF or a killed operator never means "activate". No shell,
// arbitrary operator command, key contents, environment, or SQL write is used.
var retainedReconcileRemote = `import os,sys,stat,json,fcntl,subprocess,hashlib,base64,re,socket,ssl,http.client,time,tempfile
from pathlib import Path
role,binding,encoded,port,bot_domain,exit_domain,cloud_bridge_ipv4=sys.argv[1:]
receipt=base64.b64decode(encoded,validate=True)
evidence=json.loads(receipt)
cloud_expected_relay_sha256=evidence.get('relay_binary_sha256')
cloud_expected_unit_sha256=evidence.get('relay_unit_sha256')
assert role in ['bridge','exit'] and evidence['protocol']=='ultra-retained-primary-reconcile-v1' and evidence['fence_sha256']==binding
state=Path('/var/lib/ultra-ansible')
system=Path('/etc/systemd/system')
original='[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
digest=hashlib.sha256(receipt).hexdigest()
auth=state/('retained-primary-controller-'+digest+'.json')
opened='[Unit]\nRefuseManualStart=no\nConditionPathExists='+str(auth)+'\n'
units=['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']
def trusted(path,directory=False,private=False):
 p=Path(path)
 for ancestor in [p]+list(p.parents):
  s=ancestor.lstat()
  assert s.st_uid==0 and not s.st_mode&0o022 and not stat.S_ISLNK(s.st_mode)
 s=p.lstat()
 assert stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1
 if private:assert stat.S_IMODE(s.st_mode)==0o600
 return p
def show(unit):
 r=subprocess.run(['systemctl','show',unit,'--property=LoadState','--property=ActiveState','--property=RefuseManualStart','--property=UnitFileState','--property=FragmentPath'],capture_output=True,text=True,timeout=10)
 assert r.returncode in [0,1]
 return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
trusted(state,True)
locks=[]
for path in [state/'infrastructure.lock',state/'operator-inputs/manual-deploy.lock']:
 trusted(path,private=True)
 fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
def census():
 for proc in Path('/proc').iterdir():
  if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
  try:args=(proc/'cmdline').read_bytes().split(b'\0')
  except (FileNotFoundError,ProcessLookupError):continue
  names=[os.path.basename(x.decode(errors='replace')) for x in args]
  assert not any(x in ['ultra-install','ansible-playbook','controller.py','reconcile.py','ansible-controller','ansible-run','ansible-exit','rebuild-retained-primary','operator-upgrade','deploy-operation','bridge-preflight-proof','recovery-prepare','ansible-retry-bootstrap','ansible-bootstrap-components','retained-primary-reconcile','apply-remote'] for x in names)
def fences():
 marker=trusted(state/'retained-primary-admission.json',private=True)
 assert json.loads(marker.read_text())=={'protocol':'retained-primary-admission-v1','binding_sha256':binding}
 assert not os.path.lexists(state/'retained-primary-admission-open')
 # These are a separate protocol with deliberately unsupported completion.
 assert not os.path.lexists(state/'recovery-fence.json')
 assert not os.path.lexists(state/'recovery-anchor.json')
 lifecycle=state/'lifecycle.json'
 if os.path.lexists(lifecycle):
  trusted(lifecycle,private=True);j=json.loads(lifecycle.read_text());assert j.get('phase')=='released'
 elif role=='bridge':raise ValueError('lifecycle_required')
 for unit in units:
  p=trusted(system/(unit+'.d/90-retained-primary.conf'));content=p.read_text()
  allowed=unit==units[0] and role=='bridge' and content==opened
  assert content==original or allowed
  if allowed:assert trusted(auth,private=True).read_bytes()==receipt
  properties=show(unit)
  assert properties.get('ActiveState') in ['inactive','failed']
  if properties.get('LoadState')=='loaded':
   assert properties.get('RefuseManualStart')==('no' if allowed else 'yes')
   assert properties.get('UnitFileState') in ['disabled','static','indirect','masked']
  if unit==units[0] and role=='bridge':
   assert properties.get('LoadState')=='loaded'
   trusted(properties['FragmentPath'])
 for job in state.iterdir():
  if not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',job.name):continue
  trusted(job,True)
  if not os.path.lexists(job/'prepared'):continue
  saved=json.loads(trusted(job/'receipt.json',private=True).read_text())
  assert saved.get('state') in ['failed','succeeded']
  request=trusted(job/'request.json',private=True).read_bytes()
  metadata=json.loads(trusted(job/'job.json',private=True).read_text())
  assert metadata.get('request_sha256')==hashlib.sha256(request).hexdigest()
  assert saved.get('request_sha256')==metadata['request_sha256'] and saved.get('binary_sha256')==metadata.get('binary_sha256')
 census()
def health():
 services=['ultra-relay.service']+(['ultra-bot.service'] if role=='bridge' else [])
 for unit in services:subprocess.run(['systemctl','is-active','--quiet',unit],check=True,timeout=10)
 hostname=bot_domain if role=='bridge' else exit_domain
 assert hostname
 with socket.create_connection(('127.0.0.1',443 if role=='bridge' else int(port)),timeout=5) as connection:
  with ssl.create_default_context().wrap_socket(connection,server_hostname=hostname) as secured:
   if role=='bridge':
    secured.sendall(('GET /healthz HTTP/1.1\r\nHost: '+hostname+'\r\nConnection: close\r\n\r\n').encode())
    response=http.client.HTTPResponse(secured);response.begin();response.read(4096);assert response.status==200
fences();health()
if role=='bridge' and evidence.get('configure_cloud_runtime'):
 cloud_preflight_only=True
 exec(` + strconv.Quote(retainedReconcileCloudProgram) + `,globals())
print('verified',flush=True)
command=sys.stdin.readline()
if not command:sys.exit(0)
assert command=='activate-controller\n' and role=='bridge'
fences();health()
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def publish(path,content,mode,replace=False):
 if os.path.lexists(path):
  old=trusted(path,private=mode==0o600).read_bytes()
  if old==content:return
  assert replace and old in [original.encode(),opened.encode()]
 fd,name=tempfile.mkstemp(prefix='.retained-reconcile-',dir=path.parent)
 try:
  os.fchmod(fd,mode)
  with os.fdopen(fd,'wb') as f:f.write(content);f.flush();os.fsync(f.fileno())
  if replace:os.replace(name,path)
  else:os.link(name,path);os.unlink(name)
  syncdir(path.parent)
 finally:
  if os.path.lexists(name):os.unlink(name)
publish(auth,receipt,0o600)
dropin=system/(units[0]+'.d/90-retained-primary.conf')
publish(dropin,opened.encode(),0o644,True)
subprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)
# The old marker and both reconcile fences survive every activation step.
assert json.loads(trusted(state/'retained-primary-admission.json',private=True).read_text())['binding_sha256']==binding
for unit in units[1:]:assert trusted(system/(unit+'.d/90-retained-primary.conf')).read_text()==original
try:
 subprocess.run(['systemctl','start',units[0]],check=True,timeout=30)
 for attempt in range(30):
  try:
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
    s.settimeout(2);s.connect('/run/ultra-ansible/controller.sock');s.sendall(b'{"action":"ready"}\n');answer=json.loads(s.recv(65536))
    assert answer.get('state')=='ready' and not answer.get('code')
   break
  except (OSError,ValueError,AssertionError):
   if attempt==29:raise
   time.sleep(0.2)
 if evidence.get('configure_cloud_runtime'):
  cloud_preflight_only=False
  exec(` + strconv.Quote(retainedReconcileCloudProgram) + `,globals())
  assert cloud_configured is True
 subprocess.run(['systemctl','enable',units[0]],check=True,timeout=20)
except BaseException:
 # A failed readiness probe does not authorize leaving a new running broker.
 subprocess.run(['systemctl','stop',units[0]],check=False,timeout=30)
 publish(dropin,original.encode(),0o644,True)
 subprocess.run(['systemctl','daemon-reload'],check=False,timeout=20)
 raise
print('activated',flush=True)
sys.stdin.buffer.read()
`
