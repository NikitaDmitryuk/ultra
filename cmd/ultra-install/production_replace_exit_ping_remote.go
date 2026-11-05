package main

const replacementPingPolicyProgram = `import json
from pathlib import Path
p=Path('/etc/ultra-relay/spec.json')
if not p.exists():print(json.dumps({'exit_ping':False,'happ_exit_ping':False}))
else:
 if p.is_symlink() or not p.is_file():raise ValueError('exit_ping_policy_untrusted')
 s=json.loads(p.read_text())
 if s.get('role')!='bridge':raise ValueError('exit_ping_policy_role_invalid')
 print(json.dumps({'exit_ping':bool(s.get('exit_ping',False)),'happ_exit_ping':bool(s.get('happ_exit_ping',False))}))
`

// Public host keys only are returned. Neither the fleet private key nor remote
// specs/environment leave their hosts. Strict SSH is tested before any fence.
const replacementPingCaptureProgram = `import os,sys,json,stat,pwd,subprocess,tempfile,ipaddress,re
from pathlib import Path
def need(v,c):
 if not v:raise ValueError(c)
def safe(p,private=False):
 p=Path(p)
 for a in [p]+list(p.parents):
  s=a.lstat();need(not stat.S_ISLNK(s.st_mode) and not s.st_mode&0o022,'exit_ping_unsafe_transport_path')
 s=p.stat();need(stat.S_ISREG(s.st_mode) and 0<s.st_size<1048576,'exit_ping_transport_unavailable')
 if private:need(not s.st_mode&0o077,'exit_ping_private_transport_permissions')
 return p
need(os.geteuid()==0,'exit_ping_root_required')
r=json.loads(sys.argv[1]);fallback=sys.argv[2] if len(sys.argv)>2 else ''
for n in r['nodes']:
 if not n.get('retained'):continue
 key=safe('/etc/ultra-fleet/id_ed25519',True)
 need(re.fullmatch('[a-fA-F0-9-]{36}',n['operation_id']),'exit_ping_operation_invalid')
 ipaddress.ip_address(n['address'])
 p=Path('/var/lib/ultra-relay/vultr')/n['operation_id']/'known_hosts'
 candidates=[]
 if p.exists():candidates.append(safe(p).read_text())
 if fallback:candidates.append(fallback)
 selected=''
 for candidate in candidates:
  with tempfile.NamedTemporaryFile(mode='w+',prefix='ultra-exit-ping-pins-') as f:
   f.write(candidate);f.flush()
   q=subprocess.run(['ssh-keygen','-F',n['address'],'-f',f.name],capture_output=True,text=True,timeout=5)
   lines=[line for line in q.stdout.splitlines() if line and not line.startswith('#')]
   if q.returncode or not lines:continue
   # Never promote a wildcard/CA/global match into host-bound trust.
   if any(len(line.split())<3 or (not line.split()[0].startswith('|1|') and line.split()[0] not in (n['address'],'['+n['address']+']:22')) for line in lines):continue
   exact='\n'.join(lines)+'\n';f.seek(0);f.truncate();f.write(exact);f.flush()
   q=subprocess.run(['ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','GlobalKnownHostsFile=/dev/null','-o','ControlMaster=no','-o','ConnectTimeout=5','-o','UserKnownHostsFile='+f.name,'-i',str(key),'root@'+n['address'],'true'],capture_output=True,timeout=10)
   if q.returncode==0:selected=exact;break
 need(bool(selected),'exit_ping_verified_host_pin_unavailable')
 n['known_hosts']=selected
print(json.dumps(r))
`

// Executed in a host-bound systemd unit on the retained exit. ExecStopPost runs
// recover even if ExecStart is killed; a remaining uncertain receipt blocks all
// subsequent updates rather than assuming that a timed-out worker was stopped.
const replacementPingExitProgram = `import os,sys,json,stat,hashlib,subprocess,base64,fcntl,signal,time,ipaddress,tempfile
from pathlib import Path
def need(v,c):
 if not v:raise ValueError(c)
def digest(data):return hashlib.sha256(data).hexdigest()
def atomic(p,data,uid=0,gid=0,mode=0o600):
 p=Path(p);fd,name=tempfile.mkstemp(prefix='.ultra-exit-ping-',dir=str(p.parent));tmp=Path(name);os.fchmod(fd,mode)
 try:
  os.fchown(fd,uid,gid)
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(tmp,p)
  fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 finally:
  if tmp.exists():tmp.unlink()
def regular(p):
 p=Path(p)
 for a in [p]+list(p.parents):
  s=a.lstat();need(not stat.S_ISLNK(s.st_mode) and not s.st_mode&0o022,'exit_ping_unsafe_path')
 need(p.is_file(),'exit_ping_file_unavailable');return p
def service(*args):
 q=subprocess.run(['systemctl',*args,'ultra-relay.service'],capture_output=True,timeout=95 if args[0]=='restart' else 3)
 need(q.returncode==0,'exit_ping_service_failed')
def running(binary):
 service('is-active','--quiet')
 q=subprocess.run(['systemctl','show','--property=MainPID','--value','ultra-relay.service'],capture_output=True,text=True,timeout=3)
 need(q.returncode==0 and q.stdout.strip().isdigit() and int(q.stdout.strip())>1,'exit_ping_process_unavailable')
 proc=Path('/proc')/q.stdout.strip();need((proc/'exe').samefile(binary),'exit_ping_process_artifact_changed')
 argv=[v.decode() for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
 need(argv in [[str(binary),'-spec','/etc/ultra-relay/spec.json'],[str(binary),'-require-provider-pool-quota','-spec','/etc/ultra-relay/spec.json']],'exit_ping_process_spec_changed')
def certificate(spec):
 need(spec.get('exit_cert',{}).get('cert_file')=='/etc/ultra-relay/fullchain.pem' and spec.get('exit_cert',{}).get('key_file')=='/etc/ultra-relay/privkey.pem','exit_ping_certificate_paths_changed')
 cert=regular('/etc/ultra-relay/fullchain.pem')
 q=subprocess.run(['openssl','x509','-in',str(cert),'-outform','DER'],capture_output=True,timeout=5)
 need(q.returncode==0,'exit_ping_certificate_unavailable');return digest(q.stdout)
def save(d,state,**extra):atomic(d/'receipt.json',json.dumps(dict(state=state,**extra)).encode())
def restore(d,binary,spec):
 m=json.loads((d/'prior.json').read_text())
 for path,backup,key in [(binary,d/'prior-binary','binary'),(spec,d/'prior-spec','spec')]:
  data=regular(backup).read_bytes();need(digest(data)==m[key]['sha256'],'exit_ping_backup_changed')
  atomic(path,data,m[key]['uid'],m[key]['gid'],m[key]['mode'])
 service('restart');service('is-active','--quiet')
 need(digest(binary.read_bytes())==m['binary']['sha256'] and digest(spec.read_bytes())==m['spec']['sha256'],'exit_ping_rollback_not_verified')
 save(d,'rolled_back',binding=m['binding'])
def apply(d,binary,spec):
 request=json.loads(regular(d/'request.json').read_text());node=request['node']
 need(not (d/'cancelled').exists(),'exit_ping_transaction_cancelled')
 need(not (d/'receipt.json').exists(),'exit_ping_transaction_already_started')
 for other in d.parent.glob('*/receipt.json'):
  if other.parent!=d:need(json.loads(regular(other).read_text()).get('state') in ('succeeded','rolled_back'),'exit_ping_previous_transaction_uncertain')
 raw=regular(spec).read_bytes();old=json.loads(raw)
 addresses=json.loads(subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,check=True,timeout=3).stdout)
 need(ipaddress.ip_address(node['address']) in {ipaddress.ip_address(a['local']) for row in addresses for a in row.get('addr_info',[])},'exit_ping_host_binding_changed')
 need(old.get('role')=='exit' and old.get('exit',{}).get('tunnel_uuid')==node['tunnel_uuid'] and old.get('vless_port')==node['port'],'exit_ping_exit_identity_changed')
 need(certificate(old)==node['pin'],'exit_ping_exit_certificate_changed')
 running(binary)
 new=dict(old);new['exit_ping']=True
 data=regular(d/'candidate').read_bytes();need(digest(data)==request['binary_sha256'],'exit_ping_candidate_changed')
 prior={'binding':request['binding']}
 for p,key,data0 in [(regular(binary),'binary',binary.read_bytes()),(regular(spec),'spec',raw)]:
  s=p.stat();prior[key]={'sha256':digest(data0),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
  atomic(d/('prior-'+key),data0)
 atomic(d/'prior.json',json.dumps(prior).encode());save(d,'applying',binding=request['binding'])
 try:
  need(not (d/'cancelled').exists(),'exit_ping_transaction_cancelled')
  m=prior['binary'];atomic(binary,data,m['uid'],m['gid'],m['mode'])
  m=prior['spec'];atomic(spec,json.dumps(new).encode(),m['uid'],m['gid'],m['mode'])
  q=subprocess.run([str(binary),'-spec',str(spec),'-check'],capture_output=True,timeout=10)
  need(q.returncode==0,'exit_ping_candidate_invalid')
  service('restart');time.sleep(.5);running(binary)
  actual=json.loads(spec.read_text());need(actual==new and certificate(actual)==node['pin'] and digest(binary.read_bytes())==request['binary_sha256'],'exit_ping_activation_changed')
  save(d,'succeeded',binding=request['binding'],binary_sha256=request['binary_sha256'])
 except BaseException:raise # Independent ExecStopPost owns recovery and its full stop budget.
def main():
 need(os.geteuid()==0 and len(sys.argv)==3,'exit_ping_root_worker_required')
 mode,directory=sys.argv[1:];d=Path(directory)
 need(d.parent==Path('/var/lib/ultra-exit-ping') and len(d.name)==64 and all(c in '0123456789abcdef' for c in d.name),'exit_ping_directory_invalid')
 regular(d/'request.json')
 lock=os.open(d/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX)
 binary=Path('/usr/local/bin/ultra-relay');spec=Path('/etc/ultra-relay/spec.json')
 if mode=='apply':apply(d,binary,spec)
 elif mode in ('recover','rollback'):
  if (d/'receipt.json').exists() and (mode=='rollback' or json.loads((d/'receipt.json').read_text()).get('state') not in ('succeeded','rolled_back')):
   if mode=='rollback':save(d,'applying',binding=json.loads((d/'request.json').read_text())['binding'])
   try:restore(d,binary,spec)
   except BaseException:save(d,'rollback_failed');raise
 else:raise ValueError('exit_ping_mode_invalid')
if __name__=='__main__':
 try:main()
 except BaseException:
  print('exit_ping_worker_failed',file=sys.stderr);sys.exit(1)
`

const replacementPingExitDispatch = `import os,sys,json,base64,stat,subprocess,hashlib
from pathlib import Path
def need(v,c):
 if not v:raise ValueError(c)
need(os.geteuid()==0,'exit_ping_root_required')
r=json.load(sys.stdin);binding=r['binding']
need(len(binding)==64 and all(c in '0123456789abcdef' for c in binding),'exit_ping_binding_invalid')
base=Path('/var/lib/ultra-exit-ping')
for p in [base,*base.parents]:
 if p.exists():need(not p.is_symlink() and not p.stat().st_mode&0o022 and p.stat().st_uid==0,'exit_ping_directory_unsafe')
base.mkdir(mode=0o700,exist_ok=True);d=base/binding;d.mkdir(mode=0o700)
for name,data,mode in [('worker.py',r.pop('program').encode(),0o600),('candidate',base64.b64decode(r.pop('binary'),validate=True),0o700),('request.json',json.dumps(r).encode(),0o600)]:
 fd=os.open(d/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
unit='ultra-exit-ping-'+binding
q=subprocess.run(['systemd-run','--quiet','--collect','--unit='+unit,'--property=Type=exec','--property=RuntimeMaxSec=150','--property=TimeoutStopSec=120','--property=KillMode=control-group','--property=ExecStopPost=/usr/bin/python3 '+str(d/'worker.py')+' recover '+str(d),'/usr/bin/python3',str(d/'worker.py'),'apply',str(d)],capture_output=True,timeout=10)
need(q.returncode==0,'exit_ping_transaction_start_failed')
print(json.dumps({'state':'running','binding':binding}))
`

const replacementPingBridgeProgram = `import os,sys,json,subprocess,hashlib,base64,stat,pwd
from pathlib import Path
def need(v,c):
 if not v:raise ValueError(c)
def digest(b):return hashlib.sha256(b).hexdigest()
def safe(p):
 p=Path(p)
 for a in [p]+list(p.parents):
  s=a.lstat();need(not stat.S_ISLNK(s.st_mode) and not s.st_mode&0o022,'exit_ping_unsafe_path')
 need(p.is_file(),'exit_ping_file_unavailable');return p
def write(p,data,uid=0,gid=0):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:os.fchown(f.fileno(),uid,gid);f.write(data);f.flush();os.fsync(f.fileno())
def restore_pins(node):
 owner=pwd.getpwnam('ultra-relay');base=Path('/var/lib/ultra-relay/vultr');op=base/node['operation_id']
 for a in [op]+list(op.parents):
  if a.exists():need(not a.is_symlink() and not a.stat().st_mode&0o022,'exit_ping_cloud_state_unsafe')
 for a in (base,op):
  try:a.mkdir(mode=0o700);os.chown(a,owner.pw_uid,owner.pw_gid)
  except FileExistsError:need(a.is_dir() and a.stat().st_uid==owner.pw_uid and not a.stat().st_mode&0o077,'exit_ping_cloud_state_foreign')
 p=op/'known_hosts';data=node['known_hosts'].encode()
 if p.exists():need(safe(p).read_bytes()==data and p.stat().st_uid==owner.pw_uid and not p.stat().st_mode&0o077,'exit_ping_cloud_pins_foreign')
 else:write(p,data,owner.pw_uid,owner.pw_gid)
 fd=os.open(op,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def remote(node,pins,command,body=b'',timeout=20):
 need(safe(pins).read_text()==node['known_hosts'],'exit_ping_retained_pins_changed');key=safe('/etc/ultra-fleet/id_ed25519')
 args=['ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','GlobalKnownHostsFile=/dev/null','-o','ControlMaster=no','-o','ConnectTimeout=5','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-o','UserKnownHostsFile='+str(pins),'-i',str(key),'root@'+node['address'],command]
 q=subprocess.run(args,input=body,capture_output=True,timeout=timeout);need(q.returncode==0,'exit_ping_retained_command_failed');return json.loads(q.stdout)
need(os.geteuid()==0,'exit_ping_root_required')
r=json.loads(sys.argv[1]);mode=sys.argv[2];index=int(sys.argv[3]);binding=r['binding']
need(len(binding)==64 and all(c in '0123456789abcdef' for c in binding),'exit_ping_binding_invalid')
status_ns={'__name__':'status'};exec(status_program,status_ns)
if mode.startswith('status-') or mode in ('stop-publish','stop-update'):
 target=mode[7:] if mode.startswith('status-') else mode
 if target in ('update','rollback','stop-update'):
  node=r['nodes'][index];pins=Path('/var/lib/ultra-replacement-ping')/binding/('pins-'+str(index))
  code=status_program
  if mode=='stop-update':
   code=code.split("if __name__=='__main__':")[0]+"\nstop_worker('exit','update',sys.argv[3])\nprint(json.dumps(observe('exit','stop-update',sys.argv[3],1)))"
  command='python3 -c '+__import__('shlex').quote(code)+' exit '+__import__('shlex').quote(target)+' '+binding+' 1'
  answer=remote(node,pins,command)
 else:
  if mode=='stop-publish':status_ns['stop_worker']('publication','publish',binding)
  answer=status_ns['observe']('publication',target,binding,len(r['nodes']))
 print(json.dumps(answer));sys.exit(0)
base=Path('/var/lib/ultra-replacement-ping')
for a in [base]+list(base.parents):
 if a.exists():need(not a.is_symlink() and a.stat().st_uid==0 and not a.stat().st_mode&0o022,'exit_ping_directory_unsafe')
base.mkdir(mode=0o700,exist_ok=True);d=base/binding;d.mkdir(mode=0o700,exist_ok=True)
spec=safe('/etc/ultra-relay/spec.json');before=spec.read_bytes();j=json.loads(before)
need(j.get('role')=='bridge' and j.get('exit_ping') and (mode=='disable' or not j.get('happ_exit_ping',False)),'exit_ping_bridge_not_staged')
binary=safe('/usr/local/bin/ultra-relay');need(digest(binary.read_bytes())==r['binary_sha256'],'exit_ping_bridge_candidate_changed')
node=r['nodes'][index]
if mode=='disable':
 request=d/'publication-publish.json';workerpath=d/'publication-publish.py'
 if (d/'bridge-prior-metadata.json').exists():
  q=subprocess.run(['systemd-run','--quiet','--collect','--unit=ultra-ping-disable-'+binding,'--property=RuntimeMaxSec=240','--property=TimeoutStopSec=240','--property=KillMode=control-group','--property=ExecStopPost=/usr/bin/python3 '+str(workerpath)+' recover '+str(request),'/usr/bin/python3',str(workerpath),'rollback',str(request)],capture_output=True,timeout=10)
  need(q.returncode==0,'exit_ping_disable_start_failed')
  print(json.dumps({'state':'running','binding':binding}));sys.exit(0)
 else:need(not j.get('happ_exit_ping',False),'exit_ping_disable_without_backup')
 print(json.dumps({'verified':True,'binding':binding}));sys.exit(0)
if mode in ('update','rollback'):
 need(node.get('retained') and node.get('known_hosts'),'exit_ping_retained_pins_required')
 pins=d/('pins-'+str(index))
 if not pins.exists():write(pins,node['known_hosts'].encode())
 if mode=='update':restore_pins(node)
 request={'binding':binding,'binary_sha256':r['binary_sha256'],'node':node,'program':worker,'binary':base64.b64encode(binary.read_bytes()).decode()}
 command='python3 -c '+__import__('shlex').quote(dispatch)
 if mode=='rollback':
  target='/var/lib/ultra-exit-ping/'+binding
  code="import subprocess,json,sys\nd=sys.argv[1];b=sys.argv[2]\nq=subprocess.run(['systemd-run','--quiet','--collect','--unit=ultra-exit-ping-rollback-'+b,'--property=RuntimeMaxSec=150','--property=TimeoutStopSec=120','--property=KillMode=control-group','--property=ExecStopPost=/usr/bin/python3 '+d+'/worker.py recover '+d,'/usr/bin/python3',d+'/worker.py','rollback',d],capture_output=True,timeout=10)\nif q.returncode:raise ValueError('exit_ping_rollback_start_failed')\nprint(json.dumps({'state':'running','binding':b}))"
  command='python3 -c '+__import__('shlex').quote(code)+' '+target+' '+binding
 answer=remote(node,pins,command,json.dumps(request).encode() if mode=='update' else b'',40)
 need(answer.get('state')=='running' and answer.get('binding')==binding,'exit_ping_retained_receipt_invalid')
 print(json.dumps(answer))
elif mode=='probe':
 request=d/('probe-'+str(index)+'.json');write(request,json.dumps({'binding':binding,'nodes':[node]}).encode())
 q=subprocess.run(['/usr/local/bin/ultra-install','replacement-exit-ping-probe',str(request),binding],capture_output=True,timeout=25)
 need(q.returncode==0,'exit_ping_isolated_probe_failed');answer=json.loads(q.stdout)
 need(answer=={'verified':True,'count':1,'mode':'isolated'},'exit_ping_isolated_receipt_invalid')
 write(d/('coverage-'+str(index)+'.json'),json.dumps({'binding':binding,'spec_sha256':digest(before),'node':node}).encode())
 print(json.dumps({'verified':True,'binding':binding}))
elif mode in ('stage','publish'):
 if mode=='stage':
  q=subprocess.run(['/usr/local/bin/ultra-install','replacement-exit-ping-lease',binding,'acquire'],capture_output=True,timeout=28)
  need(q.returncode==0,'exit_ping_topology_lease_failed')
 if mode=='publish':
  for i,n in enumerate(r['nodes']):
   proof=json.loads(safe(d/('coverage-'+str(i)+'.json')).read_text())
   need(proof=={'binding':binding,'spec_sha256':digest(before),'node':n},'exit_ping_coverage_changed')
 workerpath=d/('publication-'+mode+'.py');write(workerpath,publication.encode())
 request=d/('publication-'+mode+'.json');write(request,json.dumps({'binding':binding,'bot_enabled':r['bot_enabled'],'mode':mode,'spec_sha256':digest(before)}).encode())
 q=subprocess.run(['systemd-run','--quiet','--collect','--unit=ultra-ping-publication-'+mode+'-'+binding,'--property=Type=exec','--property=RuntimeMaxSec=240','--property=TimeoutStopSec=240','--property=KillMode=control-group','--property=ExecStopPost=/usr/bin/python3 '+str(workerpath)+' recover '+str(request),'/usr/bin/python3',str(workerpath),'apply',str(request)],capture_output=True,timeout=10)
 need(q.returncode==0,'exit_ping_publication_start_failed')
 print(json.dumps({'state':'running','binding':binding}))
else:raise ValueError('exit_ping_mode_invalid')
`

const replacementPingPublicationProgram = `import os,sys,json,stat,hashlib,subprocess,time,tempfile,fcntl
from pathlib import Path
# Relay has the manager's default stop deadline (normally 90s); bot explicitly
# sets TimeoutStopSec=20s. Each gets 5s command margin and a 3s active check.
RELAY_RESTART_SECONDS=95
BOT_RESTART_SECONDS=25
READY_SECONDS=35
CACHE_SECONDS=50 # 30s worker tick + full 15s refresh request + 5s margin.
def need(v,c):
 if not v:raise ValueError(c)
def digest(b):return hashlib.sha256(b).hexdigest()
def atomic(p,data,uid=0,gid=0,mode=0o600):
 fd,name=tempfile.mkstemp(prefix='.ultra-exit-ping-',dir=str(p.parent));tmp=Path(name);os.fchmod(fd,mode)
 with os.fdopen(fd,'wb') as f:os.fchown(f.fileno(),uid,gid);f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(tmp,p)
 fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def service(name):
 q=subprocess.run(['systemctl','restart',name],capture_output=True,timeout=RELAY_RESTART_SECONDS if name=='ultra-relay.service' else BOT_RESTART_SECONDS);need(q.returncode==0,'exit_ping_restart_failed')
 q=subprocess.run(['systemctl','is-active','--quiet',name],capture_output=True,timeout=3);need(q.returncode==0,'exit_ping_service_inactive')
def ready(binding):
 deadline=time.monotonic()+READY_SECONDS
 while time.monotonic()<deadline:
  remaining=deadline-time.monotonic()
  if remaining<=0:break
  try:
   q=subprocess.run(['/usr/local/bin/ultra-install','replacement-exit-ping-lease',binding,'ready'],capture_output=True,timeout=min(28,remaining))
   if q.returncode==0:return
  except subprocess.TimeoutExpired:pass
  time.sleep(min(.25,max(0,deadline-time.monotonic())))
 raise ValueError('exit_ping_admin_api_not_ready')
def cache(expected,started):
 service('ultra-bot.service');deadline=time.monotonic()+CACHE_SECONDS
 while time.monotonic()<deadline:
  p=Path('/var/lib/ultra-bot/subscriptions.json')
  if p.exists() and not p.is_symlink() and p.stat().st_mtime>=started:
   value=json.loads(p.read_text())
   if value.get('version')==1 and value.get('happ_exit_ping',False)==expected:return
  time.sleep(.25)
 raise ValueError('exit_ping_cache_not_refreshed')
def main():
 need(os.geteuid()==0 and len(sys.argv)==3,'exit_ping_root_required')
 action=sys.argv[1];path=Path(sys.argv[2]);r=json.loads(path.read_text());d=path.parent;binding=r['binding'];mode=r['mode']
 need(d.parent==Path('/var/lib/ultra-replacement-ping') and d.name==binding and mode in ('stage','publish'),'exit_ping_publication_request_invalid')
 lock=os.open(d/'publication.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX)
 receipt=d/('publication-'+mode+'-receipt.json');backup=d/'bridge-prior-spec';metadata=d/'bridge-prior-metadata.json';spec=Path('/etc/ultra-relay/spec.json')
 def save(state):atomic(receipt,json.dumps({'binding':binding,'state':state}).encode())
 def restore():
  m=json.loads(metadata.read_text());data=backup.read_bytes();need(digest(data)==m['sha256'],'exit_ping_publication_backup_changed')
  atomic(spec,data,m['uid'],m['gid'],m['mode']);service('ultra-relay.service');ready(binding)
  if r['bot_enabled']:cache(False,time.time())
  save('rolled_back')
 if action in ('recover','rollback'):
  if action=='rollback':save('applying');restore()
  elif receipt.exists() and json.loads(receipt.read_text()).get('state')=='applying':restore()
  return
 need(action=='apply','exit_ping_publication_action_invalid')
 need(mode!='publish' or not (d/'cancelled-publish').exists(),'exit_ping_publication_cancelled')
 before=spec.read_bytes();need(digest(before)==r['spec_sha256'],'exit_ping_publication_spec_changed');j=json.loads(before)
 need(j.get('role')=='bridge' and j.get('exit_ping') and not j.get('happ_exit_ping',False),'exit_ping_bridge_not_staged')
 if mode=='stage':
  ready(binding)
  if r['bot_enabled']:cache(False,time.time())
  save('succeeded');return
 s=spec.stat();atomic(backup,before);atomic(metadata,json.dumps({'sha256':digest(before),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}).encode());save('applying')
 try:
  need(not (d/'cancelled-publish').exists(),'exit_ping_publication_cancelled')
  j['happ_exit_ping']=True;atomic(spec,json.dumps(j).encode(),s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode));started=time.time()
  service('ultra-relay.service');ready(binding)
  if r['bot_enabled']:cache(True,started)
  need(json.loads(spec.read_text())==j,'exit_ping_publication_changed');save('succeeded')
 except BaseException:raise # ExecStopPost performs recovery with an independent 240s budget.
if __name__=='__main__':
 try:main()
 except BaseException:print('exit_ping_publication_failed',file=sys.stderr);sys.exit(1)
`

const replacementPingReleaseProgram = `import os,sys,subprocess,json
if os.geteuid()!=0 or len(sys.argv)!=2 or len(sys.argv[1])!=64:raise ValueError('exit_ping_release_invalid')
q=subprocess.run(['/usr/local/bin/ultra-install','replacement-exit-ping-lease',sys.argv[1],'release'],capture_output=True,timeout=25)
if q.returncode:raise ValueError('exit_ping_release_failed')
print(json.dumps({'verified':True}))
`
