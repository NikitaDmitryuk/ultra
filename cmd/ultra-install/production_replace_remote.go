package main

// The connection is new and non-multiplexed. Only its own ancestry/session and
// the independently resolved dedicated tunnel UID and known OS daemons are exempt.
// Unknown sessions are never signalled by this read-only gate.
const replacementSessionCensusDefinitions = `import os,sys,json,pwd,subprocess,re,time
from pathlib import Path
def gate_error(code,pid=None,row=None):
 error=ValueError(code)
 if row is not None:
  def name(arg):
   value=os.path.basename(arg)
   return value if re.fullmatch(r'[A-Za-z0-9_.()+-]{1,64}',value) else '[redacted]'
  command=row['argv'][0].split()[0].rstrip(':') if row['argv'] else ''
  scripts=[name(arg) for arg in row['argv'][1:] if arg.startswith('/') and arg.endswith(('.py','.sh'))]
  groups=[group if re.fullmatch(r'/(?:system\.slice/[A-Za-z][A-Za-z0-9_-]*\.(?:service|scope)|user\.slice/user-[0-9]+\.slice/(?:user@[0-9]+\.service/init\.scope|session-[0-9]+\.scope))',group) else '[redacted]' for group in row.get('cgroups',[])[:8]]
  error.offender={'pid':pid,'ppid':row['ppid'],'sid':row['sid'],'comm':name(row['comm']),'argv_basenames':[name(command)]+scripts[:7],'cgroups':groups}
 raise error
def is_ssh(row):
 return row['comm'].startswith('sshd') or any(os.path.basename(x).startswith('sshd') for x in row['argv'])
def shared_ssh_listener(row):
 return row['comm']=='sshd' and row['ppid']==1 and any('[listener]' in x or ': listener' in x for x in row['argv'])
def preauth_ssh(pid,row,rows):
 if row['comm']!='sshd-session' or row['argv']!=['sshd-session: unknown [priv]'] or row.get('loginuid')==0 or row.get('login_scope',False):return False
 children=[child for child in rows.values() if child['ppid']==pid]
 return bool(children) and all(child['comm']=='sshd-auth' and child['uids'] and 0 not in child['uids'] and child['argv']==['sshd-auth: unknown [net]'] for child in children)
def os_service(row):
 # Match the complete observed command, never a basename or cgroup alone.
 groups=row.get('cgroups',[])
 if '/system.slice/chrony.service' in groups and row['comm']=='chronyd-starter' and row['argv']==['/bin/sh','/usr/lib/systemd/scripts/chronyd-starter.sh','-n','-F','1']:return True
 if '/system.slice/networkd-dispatcher.service' in groups and row['comm']=='networkd-dispat' and row['argv']==['/usr/bin/python3','/usr/bin/networkd-dispatcher','--run-startup-triggers']:return True
 if '/user.slice/user-0.slice/user@0.service/init.scope' in groups:
  return (row['comm']=='systemd' and row['argv']==['/usr/lib/systemd/systemd','--user']) or (row['comm']=='(sd-pam)' and row['argv']==['(sd-pam)'])
 return False
def root_helper(row):
 for arg in row['argv']:
  name=os.path.basename(arg)
  if name in ('sh','bash','dash','zsh','ksh','fish','perl','ruby','node','nodejs','busybox','ansible-playbook','ansible.cli.playbook','ultra-install','manual-deploy.py') or name.startswith(('python','ultra-install-linux-','AnsiballZ_')):return True
 return False
def session_blockers(rows,self_pid,tunnel_uid=None):
 if self_pid not in rows:gate_error('replacement_session_census_unavailable')
 ancestors=set();pid=self_pid
 while pid:
  if pid in ancestors or pid not in rows:gate_error('replacement_session_census_unavailable')
  ancestors.add(pid);pid=rows[pid]['ppid']
 sid=rows[self_pid]['sid']
 if sid<=1 or sid not in ancestors or sid not in rows:gate_error('replacement_helper_session_unisolated')
 # An sshd session child may lead this command's SID. A shared listener is
 # not a per-connection boundary and cannot exempt all sibling connections.
 leader=' '.join(rows[sid]['argv'])
 if is_ssh(rows[sid]) and ('[listener]' in leader or ': listener' in leader):gate_error('replacement_helper_session_unisolated')
 allowed=set(ancestors)
 if tunnel_uid is not None:
  if tunnel_uid<=0:gate_error('replacement_tunnel_uid_unavailable')
  for pid,row in rows.items():
   # Use actual kernel UIDs, never the displayed SSH username or argv text.
   if row['uids'] and all(uid==tunnel_uid for uid in row['uids']):
    allowed.add(pid);parent=row['ppid'];chain=set()
    while parent and parent not in ancestors:
     if parent in chain or parent not in rows:break
     chain.add(parent)
     if not is_ssh(rows[parent]):break
     allowed.add(parent);parent=rows[parent]['ppid']
 blockers=[]
 for pid,row in rows.items():
  if pid in allowed or row['sid']==sid or 0 not in row['uids']:continue
  if shared_ssh_listener(row) or preauth_ssh(pid,row,rows) or os_service(row):continue
  if is_ssh(row) or row.get('loginuid')==0 or row.get('login_scope',False):blockers.append(('replacement_other_root_ssh_session',pid,row))
  elif root_helper(row):blockers.append(('replacement_unknown_root_helper',pid,row))
 return blockers
def validate_sessions(rows,self_pid,tunnel_uid=None):
 for code,pid,row in session_blockers(rows,self_pid,tunnel_uid):gate_error(code,pid,row)
 return True
def read_sessions():
 rows={}
 try:
  for d in Path('/proc').iterdir():
   if not d.name.isdigit():continue
   try:
    raw=(d/'stat').read_text();_,rest=raw.rsplit(') ',1);fields=rest.split()
    uid=next(x for x in (d/'status').read_text().splitlines() if x.startswith('Uid:'))
    argv=[x.decode(errors='replace') for x in (d/'cmdline').read_bytes().split(b'\0') if x]
    loginuid=int((d/'loginuid').read_text().strip())
    cgroups=[line.split(':',2)[2] for line in (d/'cgroup').read_text().splitlines()]
    login_scope=any(re.search(r'/session-[^/\n]+\.scope(?:/|$)',group) for group in cgroups)
    rows[int(d.name)]={'ppid':int(fields[1]),'start':fields[19],'sid':int(fields[3]),'uids':[int(x) for x in uid.split()[1:]],'comm':raw.split('(',1)[1].rsplit(') ',1)[0],'argv':argv,'loginuid':loginuid,'login_scope':login_scope,'cgroups':cgroups}
   except (FileNotFoundError,ProcessLookupError):continue
 except Exception:gate_error('replacement_session_census_unavailable')
 return rows
def require_sessions_quiescent(self_pid,tunnel_uid=None):
 # Waiting never authorizes a session, changes configuration or signals it.
 # One deadline covers PAM scopes, old/new OpenSSH layouts and PID churn.
 deadline=time.monotonic()+40
 tracked={};sids=set();scopes=set();latest=None
 def identity(pid,row):return row.get('start',str(pid))
 def remember(rows,seed=None):
  if seed is not None:
   # Climb only per-connection SSH ancestors, never the shared listener.
   pid=seed
   while pid in rows:
    parent=rows[pid]['ppid']
    if parent in own_ancestry or parent not in rows or not is_ssh(rows[parent]) or shared_ssh_listener(rows[parent]):break
    pid=parent
   tracked[pid]=identity(pid,rows[pid])
  for _ in range(len(rows)+1):
   added=False
   alive={pid for pid,value in tracked.items()if pid in rows and identity(pid,rows[pid])==value}
   for pid,row in rows.items():
    session_scopes={cg for cg in row.get('cgroups',[])if re.search(r'/session-[^/]+\.scope(?:/|$)',cg)}
    if pid in alive or row['ppid'] in alive or row['sid'] in sids or session_scopes&scopes:
     if pid not in tracked or tracked[pid]!=identity(pid,row):tracked[pid]=identity(pid,row);added=True
     if row['sid']==pid:sids.add(pid)
     scopes.update(session_scopes)
   if not added:break
 while True:
  rows=read_sessions()
  own_ancestry=set();ancestor=self_pid
  while ancestor in rows and ancestor not in own_ancestry:
   own_ancestry.add(ancestor);ancestor=rows[ancestor]['ppid']
  # Classify once, using exactly the snapshot validator's exemptions. Seed
  # every SSH tree before any parent can disappear between polls.
  blockers=session_blockers(rows,self_pid,tunnel_uid)
  for code,pid,row in blockers:
   if code=='replacement_other_root_ssh_session':remember(rows,pid)
  remember(rows)
  try:
   for code,pid,row in blockers:gate_error(code,pid,row)
   for pid,value in tracked.items():
    if pid in rows and identity(pid,rows[pid])==value:gate_error('replacement_other_root_ssh_session',pid,rows[pid])
   return True
  except ValueError as error:
   if str(error)!='replacement_other_root_ssh_session':raise
   pid=getattr(error,'offender',{}).get('pid')
   if pid not in rows:raise
   remember(rows,pid);latest=error
  remaining=deadline-time.monotonic()
  if remaining<=0:raise latest
  time.sleep(min(.25,remaining))
  if time.monotonic()>=deadline:raise latest

def require_primary_idle(database):
 query="""BEGIN READ ONLY;
 SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'
 AND pid<>pg_backend_pid() AND
 (state='active' OR state LIKE 'idle in transaction%' OR xact_start IS NOT NULL);
 ROLLBACK;"""
 try:
  r=subprocess.run(['runuser','-u','postgres','--','psql','--no-psqlrc','-qAt','-v','ON_ERROR_STOP=1','-d',database],input=query,capture_output=True,text=True,timeout=20,env=dict(os.environ,PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=5000'))
  if r.returncode or not r.stdout.strip().isdigit():gate_error('replacement_primary_activity_unavailable')
  if int(r.stdout.strip())!=0:gate_error('replacement_primary_client_transactions_active')
 except ValueError:raise
 except Exception:gate_error('replacement_primary_activity_unavailable')
`

const replacementQuiescenceProgram = replacementSessionCensusDefinitions + `
try:
 if os.geteuid()!=0:gate_error('replacement_session_census_unavailable')
 primary=sys.argv[1]=='primary'
 tunnel_uid=None
 if primary:
  try:tunnel_uid=pwd.getpwnam('ultra-db-tunnel').pw_uid
  except KeyError:gate_error('replacement_tunnel_uid_unavailable')
 require_sessions_quiescent(os.getpid(),tunnel_uid)
 if primary:require_primary_idle(sys.argv[2])
 print(json.dumps({'quiescent':True,'code':''}))
except Exception as error:
 code=str(error)
 if not code.startswith('replacement_'):code='replacement_session_census_unavailable'
 result={'quiescent':False,'code':code}
 if hasattr(error,'offender'):result['offender']=error.offender
 print(json.dumps(result))
`

const replacementPrimaryProgram = `import subprocess,json,sys,os
q="""BEGIN READ ONLY;
SELECT json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
 'database',current_database(),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'primary',NOT pg_is_in_recovery(),
 'migrations',(SELECT COALESCE(string_agg(version::text,',' ORDER BY version),'') FROM public.schema_migrations),
 'routes',(SELECT COALESCE(json_agg(r ORDER BY r.name,r.address,r.port),'[]'::json) FROM
 (SELECT name,address,port,tunnel_uuid,COALESCE(pinned_peer_cert_sha256,'') AS pinned_peer_cert_sha256,priority,enabled FROM public.exit_nodes) r));
ROLLBACK;"""
r=subprocess.run(['runuser','-u','postgres','--','psql','--no-psqlrc','-qAt','-v','ON_ERROR_STOP=1','-d',sys.argv[1]],input=q,capture_output=True,text=True,timeout=20,env=dict(os.environ,PGOPTIONS='-c default_transaction_read_only=on'))
if r.returncode:raise ValueError('replacement_primary_read_failed')
j=json.loads(r.stdout)
if not j.pop('primary'):raise ValueError('replacement_database_not_primary')
print(json.dumps(j))
`

// Runs over the same pinned root SSH transport as the read-only discovery.
// No PostgreSQL paths, services, binaries or processes enter this allowlist.
const replacementHostProgram = `import os,sys,json,re,stat,subprocess,signal,time,shutil,hashlib,ipaddress
from pathlib import Path
mode,role,binding,primary,routes=sys.argv[1:]
def need(value,code):
 if not value:raise ValueError(code)
need(mode in ('discover','fence','clean') and re.fullmatch('[a-f0-9]{64}',binding),'replacement_request_invalid')
need(role=='bridge' or re.fullmatch('(exit|former)-[0-9]+',role),'replacement_role_invalid')
need(os.geteuid()==0,'replacement_remote_root_required')
addresses=json.loads(subprocess.run(['ip','-j','address','show'],check=True,capture_output=True,text=True,timeout=10).stdout)
need(all(ipaddress.ip_address(a['local'])!=ipaddress.ip_address(primary) for row in addresses for a in row.get('addr_info',[])),'replacement_primary_host_forbidden')
if role.startswith('exit-'):
 local={ipaddress.ip_address(a['local']) for row in addresses for a in row.get('addr_info',[])}
 matches=[r for r in json.loads(routes) if ipaddress.ip_address(r['address']) in local]
 need(len(matches)==1,'replacement_exit_authoritative_identity_unresolved')
 for path in ('/etc/ultra-relay/fullchain.pem','/etc/ultra-relay/privkey.pem'):
  p=Path(path);need(p.is_file() and not p.is_symlink(),'replacement_exit_tls_escrow_required')
 if matches[0].get('pinned_peer_cert_sha256'):
  cert=subprocess.run(['openssl','x509','-in','/etc/ultra-relay/fullchain.pem','-outform','DER'],check=True,capture_output=True,timeout=10).stdout
  need(hashlib.sha256(cert).hexdigest()==matches[0]['pinned_peer_cert_sha256'],'replacement_exit_tls_pin_mismatch')
fixed={'ultra-relay.service','ultra-bot.service','ultra-ansible-controller.service','ultra-ansible-controller.socket',
 'ultra-recovery-backup.service','ultra-recovery-backup.timer','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer','ultra-auto-upgrade.service','ultra-auto-upgrade.timer'}
# These two units carry the retained primary data path across non-DB replacement.
unit_re=re.compile(r'ultra-[A-Za-z0-9_.@-]+\.(?:service|socket|timer|path)\Z')
def owned_unit(name):return bool(unit_re.fullmatch(name)) and name!='ultra-postgres-replica.service' and not name.startswith('ultra-db-tunnel.')
def run(args,ok=True):
 r=subprocess.run(args,capture_output=True,text=True,timeout=15)
 need(not ok or r.returncode==0,'replacement_systemctl_failed')
 return r
def units():
 result=set(fixed)
 for args in (['systemctl','list-units','--all','--plain','--no-legend','--no-pager','ultra-*'],['systemctl','list-unit-files','--no-legend','--no-pager','ultra-*']):
  r=subprocess.run(args,capture_output=True,text=True,timeout=15)
  # systemctl returns 1 (without diagnostics) when a unit-file pattern has no matches.
  # The fixed inventory above still covers Ultra units which are absent from disk.
  if r.returncode and not (args[1]=='list-unit-files' and r.returncode==1 and not r.stdout and not r.stderr):
   raise ValueError('replacement_systemctl_failed')
  for line in r.stdout.splitlines():
   fields=line.split()
   if fields and fields[0]=='●':fields=fields[1:]
   if fields and owned_unit(fields[0]):result.add(fields[0])
 return sorted(result)
def workers():
 found=[]
 for d in Path('/proc').iterdir():
  if not d.name.isdigit() or int(d.name)==os.getpid():continue
  try:
   argv=[x.decode(errors='replace') for x in (d/'cmdline').read_bytes().split(b'\0') if x]
   names=[os.path.basename(x) for x in argv]
   direct=any(x in ('ultra-install','manual-deploy.py') or x.startswith('ultra-install-linux-') for x in names)
   ansible=any(x in ('ansible-playbook','ansible.cli.playbook','controller.py','reconcile.py','recovery.py') for x in names)
   known=any('/ultra-' in x or '/ultra/' in x for x in argv)
   if direct or (ansible and known):
    found.append((int(d.name),(d/'stat').read_text().split(') ',1)[1].split()[19]))
   elif ansible:raise ValueError('replacement_foreign_worker_requires_shutdown')
  except (FileNotFoundError,ProcessLookupError):continue
 return found
def state(name):
 r=run(['systemctl','show',name,'--property=LoadState,ActiveState,MainPID,ControlPID,ControlGroup'],False)
 need(r.returncode in (0,1),'replacement_unit_state_unavailable')
 return dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
def verify_stopped(names):
 for name in names:
  s=state(name)
  need(s.get('LoadState')=='not-found' or (s.get('ActiveState') in ('inactive','failed') and s.get('MainPID','0')=='0' and s.get('ControlPID','0')=='0'),'replacement_unit_not_stopped')
  cg=s.get('ControlGroup','')
  if cg:
   need(cg.startswith('/') and '..' not in Path(cg).parts,'replacement_cgroup_invalid')
   root=Path('/sys/fs/cgroup')/cg.lstrip('/')
   if root.exists():
    for p in root.rglob('cgroup.procs'):need(not p.read_text().strip(),'replacement_cgroup_not_empty')
 need(not workers(),'replacement_worker_survived')
names=units()
old_workers=workers()
for name in names:
 # Removing an /etc mask must not expose an unknown vendor unit later.
 if not re.fullmatch(r'ultra-deploy-[a-f0-9]{64}\.service',name):
  need(not any((Path(base)/name).exists() for base in ('/usr/lib/systemd/system','/lib/systemd/system','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late')),'replacement_vendor_unit_fallback_forbidden')
if mode=='fence':
 # /etc masks take precedence over transient /run units and survive a reboot.
 for name in names:
  path=Path('/etc/systemd/system')/name
  if path.exists() or path.is_symlink():
   need(not path.is_dir() or path.is_symlink(),'replacement_unit_path_invalid')
   path.unlink()
  path.symlink_to('/dev/null')
 run(['systemctl','daemon-reload'])
 for name in names:
  run(['systemctl','kill','--kill-whom=all','--signal=KILL',name],False)
  run(['systemctl','stop','--no-block',name],False)
 for pid,start in old_workers:
  try:
   p=Path('/proc')/str(pid)
   if (p/'stat').read_text().split(') ',1)[1].split()[19]==start:os.kill(pid,signal.SIGKILL)
  except (FileNotFoundError,ProcessLookupError):pass
 for attempt in range(50):
  if not workers() and all(state(n).get('ActiveState') in ('inactive','failed') or state(n).get('LoadState')=='not-found' for n in names):break
  time.sleep(.1)
 verify_stopped(names)
elif mode=='clean':
 verify_stopped(names)
 def remove(path):
  p=Path(path)
  # Never traverse a symlink supplied by the old disposable runtime.
  for parent in p.parents:
   need(not parent.is_symlink(),'replacement_cleanup_parent_symlink')
  if p.is_symlink() or p.is_file():p.unlink()
  elif p.exists():shutil.rmtree(p)
 for path in ('/var/lib/ultra-ansible','/opt/ultra-ansible','/opt/ultra-recovery','/var/lib/ultra-relay/vultr',
  '/etc/ultra-relay/spec.json','/etc/ultra-relay/environment','/etc/ultra-relay/bot.env',
  '/usr/local/bin/ultra-relay','/usr/local/bin/ultra-bot','/usr/local/bin/ultra-install','/usr/local/bin/ultra-client'):
  remove(path)
 for name in names:
  if not re.fullmatch(r'ultra-deploy-[a-f0-9]{64}\.service',name):
   # Remove exact enabled links before removing the stopped old unit mask.
   # All old executables are gone; vendor fallbacks were excluded above.
   for base in ('/etc/systemd/system','/run/systemd/system'):
    for parent in Path(base).glob('*.wants'):
     need(not parent.is_symlink(),'replacement_wants_directory_symlink')
     link=parent/name
     if link.is_symlink():link.unlink()
    for parent in Path(base).glob('*.requires'):
     need(not parent.is_symlink(),'replacement_requires_directory_symlink')
     link=parent/name
     if link.is_symlink():link.unlink()
   remove('/etc/systemd/system/'+name)
   remove('/run/systemd/system/'+name)
  remove('/etc/systemd/system/'+name+'.d')
  remove('/run/systemd/transient/'+name)
  run(['systemctl','reset-failed',name],False)
 # Retain the preexisting exit certificate/key and application DB tunnel key.
 if role=='bridge':
  target=Path('/etc/ultra-relay/exit_nodes.bootstrap.json')
  need(target.parent.is_dir() and not target.parent.is_symlink(),'replacement_bridge_config_directory_invalid')
  same=target.is_file() and not target.is_symlink() and target.read_bytes()==routes.encode()
  if not same:
   if target.exists() or target.is_symlink():target.unlink()
   fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as f:f.write(routes);f.flush();os.fsync(f.fileno())
 run(['systemctl','daemon-reload'])
 for name in names:
  if not re.fullmatch(r'ultra-deploy-[a-f0-9]{64}\.service',name):need(state(name).get('LoadState')=='not-found','replacement_removed_unit_still_loadable')
 need(not workers(),'replacement_worker_restarted_during_cleanup')
print(json.dumps({'state':mode,'binding':binding,'units':names,'workers':len(old_workers)}))
`
