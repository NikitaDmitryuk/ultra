package main

// This authenticates an existing root-managed automation release only for the
// legacy origin seal. It proves retained bytes, not clean source provenance or
// a signed release, and never replaces the application's baseline identity.
const recoveryPreparationManagedControllerRemote = `
def managed_controller(pid,args,executable,arch):
 import configparser,shlex
 directory=Path(args[0]).parent
 match=re.fullmatch(r'/opt/ultra-ansible/releases/managed-(v0[.]0[.]([0-9]{1,49}))',str(directory));assert match
 version=match[1];commit=format(int(match[2]),'040x')
 assert len(commit)==40 and version=='v0.0.'+str(int(commit,16))
 def private_dir(path):
  path=trusted(path,True);assert stat.S_IMODE(path.lstat().st_mode)==0o700
  return path
 private_dir(directory)
 inputs=private_dir(state/'operator-inputs')
 entries=list(inputs.iterdir());assert len(entries)<=4096
 candidates=[entry for entry in entries if re.fullmatch('manual-'+commit+'-[a-f0-9]{64}',entry.name)]
 assert len(candidates)==1
 release=private_dir(private_dir(candidates[0])/'release')
 manifest_path=trusted(release/'release-manifest.json',private=True)
 assert manifest_path.stat().st_size<=1048576
 manifest=json.loads(manifest_path.read_text())
 assert type(manifest.get('schema_version')) is int and manifest['schema_version']==1
 assert manifest.get('version')==version and manifest.get('source_commit')==commit
 def asset(name):
  rows=[row for row in manifest['assets'] if row.get('name')==name];assert len(rows)==1
  row=rows[0];assert re.fullmatch('[a-f0-9]{64}',row['sha256']) and type(row['size']) is int and 0<row['size']<=2147483648
  path=trusted(release/name,private=True)
  assert path.stat().st_size==row['size'] and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256']
  return row
 installer=asset('ultra-install-linux-'+arch)
 runtime=asset('ultra-ansible-runtime-linux-'+arch+'.tar.gz')
 assert len(executable)==installer['size'] and hashlib.sha256(executable).hexdigest()==installer['sha256']
 assert os.readlink(proc/str(pid)/'exe')==args[0]
 binary=trusted(directory/'ultra-install');assert binary.stat().st_mode&0o111
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==installer['sha256']
 marker=trusted(directory/'runtime.sha256',private=True)
 marker_raw=(runtime['sha256']+'\n').encode();assert marker.read_bytes()==marker_raw
 current=Path('/opt/ultra-ansible/current');assert current.is_symlink() and current.lstat().st_uid==0
 trusted(current.parent,True);assert os.readlink(current)==str(directory)
 receipt_dir=private_dir(state/'retention')
 receipt_path=trusted(receipt_dir/(hashlib.sha256(str(directory).encode()).hexdigest()+'.json'),private=True)
 assert receipt_path.stat().st_size<=4*1024*1024
 receipt=json.loads(receipt_path.read_text())
 assert set(receipt)=={'schema','path','identity','inventory'} and type(receipt['schema']) is int and receipt['schema']==1
 assert receipt['path']==str(directory) and receipt['identity']=={'ultra-install':installer['sha256'],'runtime.sha256':hashlib.sha256(marker_raw).hexdigest()}
 # Keep the retention inventory format, including its reproducible pyc rule.
 contents={}
 def walk_error(error):raise error
 for base,dirs,files in os.walk(directory,followlinks=False,onerror=walk_error):
  assert len(contents)+len(dirs)+len(files)<=30000
  for name in sorted(dirs+files):
   path=Path(base)/name;s=path.lstat()
   assert s.st_uid==0 and (stat.S_ISLNK(s.st_mode) or not s.st_mode&0o022)
   if name=='__pycache__' and stat.S_ISDIR(s.st_mode):continue
   if path.parent.name=='__pycache__' and stat.S_ISREG(s.st_mode):
    cached=re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc',name)
    source=path.parent.parent/(cached[1]+'.py') if cached else None
    if source and source.is_file() and not source.is_symlink():continue
   key=str(path.relative_to(directory))
   if stat.S_ISLNK(s.st_mode):contents[key]=['link',os.readlink(path)]
   elif stat.S_ISREG(s.st_mode):
    assert s.st_nlink==1
    contents[key]=['file',hashlib.sha256(path.read_bytes()).hexdigest(),stat.S_IMODE(s.st_mode)]
   else:
    assert stat.S_ISDIR(s.st_mode)
    contents[key]=['directory',stat.S_IMODE(s.st_mode)]
 assert receipt['inventory']==contents
 unit=trusted(system/units[0]);parser=configparser.ConfigParser(interpolation=None,strict=True)
 parser.read_string(unit.read_text());service=parser['Service']
 assert shlex.split(service['ExecStart'])==args and service['User']=='root' and service['Group']=='root' and service['KillMode']=='control-group'
 assert not service.get('ExecStartPre') and not service.get('ExecStartPost')
 assert not service.get('ExecStop') and not service.get('ExecStopPost')
 properties=show(units[0])
 assert properties.get('Id')==units[0] and properties.get('MainPID')==str(pid)
 assert properties.get('ActiveState')=='active' and properties.get('SubState')=='running'
 assert properties.get('FragmentPath')==str(unit) and properties.get('ControlGroup')=='/system.slice/'+units[0]
 assert properties.get('User')=='root' and properties.get('Group')=='root'
 assert properties.get('DropInPaths','').split()==[str(system/(units[0]+'.d/90-retained-primary.conf'))]
 process=proc/str(pid)
 status=dict(line.split(':',1) for line in (process/'status').read_text().splitlines() if ':' in line)
 assert status['Uid'].split()==['0']*4 and status['Gid'].split()==['0']*4
 assert (process/'stat').read_text().rsplit(')',1)[1].split()[1]=='1'
 assert (process/'cgroup').read_text()=='0::/system.slice/'+units[0]+'\n'
`
