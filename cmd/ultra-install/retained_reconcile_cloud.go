package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The recovery's original manifest and sealed request select the only relay
// image safe to restart against the independently observed retained schema.
func retainedReconcileRelayIdentity(in retainedPrimaryRebuildInput, manifestPath string) (string, string, error) {
	fail := errors.New("retained_reconcile_relay_identity_invalid")
	raw, err := readRebuildInput(manifestPath, false)
	if err != nil || digestSHA256(raw) != in.ManifestSHA256 {
		return "", "", fail
	}
	var manifest automationRelease
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != 1 ||
		manifest.DatabaseSchemaMax != len(strings.Split(in.CandidateMigrationVersions, ",")) {
		return "", "", fail
	}
	all, _ := in.Inventory["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	group, _ := children["bridge"].(map[string]any)
	hosts, _ := group["hosts"].(map[string]any)
	bridge, _ := hosts["bridge"].(map[string]any)
	source, _ := bridge["ultra_relay_source"].(string)
	sha, _ := bridge["ultra_relay_sha256"].(string)
	name := filepath.Base(source)
	if (name != "ultra-relay-linux-amd64" && name != "ultra-relay-linux-arm64") || !rebuildSHA.MatchString(sha) ||
		source != filepath.Join(filepath.Dir(manifestPath), name) ||
		rebuildNoSymlinkAncestors(source) != nil {
		return "", "", fail
	}
	seen := map[string]bool{}
	matched := false
	for _, asset := range manifest.Assets {
		if seen[asset.Name] {
			return "", "", fail
		}
		seen[asset.Name] = true
		if asset.Name == name {
			info, e := os.Lstat(source)
			if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() != asset.Size || asset.SHA != sha {
				return "", "", fail
			}
			sum, e := sourceSHA(source)
			if e != nil || sum != sha {
				return "", "", fail
			}
			matched = true
		}
	}
	if !matched {
		return "", "", fail
	}
	unit, err := readRebuildInput(filepath.Join(in.Directory, "execute/bundle/roles/relay/templates/ultra-relay.service.j2"), true)
	if err != nil || strings.Count(string(unit), "ExecStart=") != 1 ||
		!strings.Contains(
			string(unit),
			"ExecStart=/usr/local/bin/ultra-relay -require-provider-pool-quota -spec /etc/ultra-relay/spec.json\n",
		) {
		return "", "", fail
	}
	return sha, digestSHA256(unit), nil
}

// Executed only inside the operator's held bridge reconciliation session.
// A preflight invocation checks every existing input without changing files.
// The caller supplies cloud_bridge_ipv4 and cloud_preflight_only; no secret
// content is returned to the operator, placed in arguments, or logged.
const retainedReconcileCloudProgram = `import os,stat,pwd,grp,subprocess,ipaddress,tempfile,hashlib,re
from pathlib import Path
cloud_root_uid = 0
cloud_root_gid = 0
cloud_account = pwd.getpwnam('ultra-relay')
cloud_group = grp.getgrnam('ultra-relay').gr_gid
def cloud_need(ok):
 if not ok: raise RuntimeError('retained_cloud_runtime_invalid')
def cloud_directory(path,owners,missing=False):
 p=Path(path)
 if not p.exists() and not p.is_symlink():
  cloud_need(missing);return
 s=p.lstat();cloud_need(stat.S_ISDIR(s.st_mode) and s.st_uid in owners and not s.st_mode&0o022)
def cloud_file(path,owners,private=False):
 p=Path(path);s=p.lstat()
 cloud_need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid in owners and not s.st_mode&0o022)
 if private:cloud_need(stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<16384)
 return p
def cloud_verify_relay():
 for path in ['/usr','/usr/local','/usr/local/bin','/etc','/etc/systemd','/etc/systemd/system']:
  cloud_directory(path,[cloud_root_uid])
 binary=cloud_file('/usr/local/bin/ultra-relay',[cloud_root_uid])
 cloud_need(binary.stat().st_mode&0o111 and hashlib.sha256(binary.read_bytes()).hexdigest()==cloud_expected_relay_sha256)
 unit=cloud_file('/etc/systemd/system/ultra-relay.service',[cloud_root_uid])
 cloud_need(hashlib.sha256(unit.read_bytes()).hexdigest()==cloud_expected_unit_sha256)
 dropins=Path('/etc/systemd/system/ultra-relay.service.d')
 if dropins.exists() or dropins.is_symlink():
  cloud_directory(dropins,[cloud_root_uid])
  for p in dropins.glob('*.conf'):
   content=cloud_file(p,[cloud_root_uid]).read_text()
   cloud_need(not re.search(r'^\s*Exec(?:Start|Condition)',content,re.M))
 result=subprocess.run(['systemctl','show','ultra-relay.service','--property=FragmentPath','--property=ExecStart'],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=15)
 cloud_need(result.returncode==0)
 properties=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
 cloud_need(properties.get('FragmentPath')==str(unit))
 command=properties.get('ExecStart','')
 paths=re.findall(r'(?:^|[ {;])path=([^;]+);',command)
 argv=re.findall(r'argv\[\]=([^;]+);',command)
 cloud_need(len(paths)==1 and paths[0].strip()==str(binary))
 cloud_need(len(argv)==1 and argv[0].strip()==str(binary)+' -require-provider-pool-quota -spec /etc/ultra-relay/spec.json')
cloud_verify_relay()
cloud_need(isinstance(ipaddress.ip_address(cloud_bridge_ipv4),ipaddress.IPv4Address))
for cloud_path in ['/etc','/etc/systemd','/etc/systemd/system','/var','/var/lib']:
 cloud_directory(cloud_path,[cloud_root_uid])
cloud_directory('/var/lib/ultra-relay',[cloud_root_uid,cloud_account.pw_uid])
cloud_directory('/var/lib/ultra-relay/automation',[cloud_root_uid,cloud_account.pw_uid])
cloud_key=cloud_file('/var/lib/ultra-relay/automation/vultr-api-key',[cloud_account.pw_uid],True)
cloud_check=subprocess.run(['runuser','-u','ultra-relay','--','test','-r',str(cloud_key)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,timeout=45)
cloud_need(cloud_check.returncode==0)
cloud_directory('/etc/ultra-fleet',[cloud_root_uid],True)
cloud_directory('/etc/systemd/system/ultra-relay.service.d',[cloud_root_uid],True)
cloud_private=Path('/etc/ultra-fleet/id_ed25519')
cloud_public=Path('/etc/ultra-fleet/id_ed25519.pub')
cloud_has_private=cloud_private.exists() or cloud_private.is_symlink()
if cloud_has_private:cloud_file(cloud_private,[cloud_root_uid,cloud_account.pw_uid],True)
cloud_has_public=cloud_public.exists() or cloud_public.is_symlink()
if cloud_has_public:
 cloud_file(cloud_public,[cloud_root_uid,cloud_account.pw_uid])
 cloud_need(cloud_has_private)
cloud_provider=Path('/etc/systemd/system/ultra-relay.service.d/provider.conf')
cloud_content='[Service]\nEnvironment=ULTRA_VULTR_KEY_FILE=/var/lib/ultra-relay/automation/vultr-api-key\nEnvironment=ULTRA_VULTR_SSH_KEY_FILE=/etc/ultra-fleet/id_ed25519\nEnvironment=ULTRA_VULTR_BRIDGE_IP='+cloud_bridge_ipv4+'\n'
if cloud_provider.exists() or cloud_provider.is_symlink():
 cloud_file(cloud_provider,[cloud_root_uid]);cloud_need(cloud_provider.read_text()==cloud_content)
cloud_derived=None
if cloud_has_private:
 cloud_result=subprocess.run(['ssh-keygen','-y','-f',str(cloud_private)],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=15)
 cloud_need(cloud_result.returncode==0)
 cloud_derived=' '.join(cloud_result.stdout.split()[:2])
 cloud_need(cloud_derived.startswith('ssh-ed25519 ') and len(cloud_derived.split())==2)
 if cloud_has_public:cloud_need(cloud_public.read_text().split()[:2]==cloud_derived.split())
def cloud_sync(directory):
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def cloud_publish(path,data,mode,uid,gid):
 fd,tmp=tempfile.mkstemp(prefix='.cloud-runtime-',dir=path.parent)
 try:
  os.fchmod(fd,mode);os.fchown(fd,uid,gid)
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  try:os.link(tmp,path,follow_symlinks=False)
  except FileExistsError:cloud_need(path.read_bytes()==data)
 finally:os.unlink(tmp)
 cloud_sync(path.parent)
if not cloud_preflight_only:
 cloud_fleet=Path('/etc/ultra-fleet')
 cloud_fleet.mkdir(mode=0o750,exist_ok=True)
 os.chown(cloud_fleet,cloud_root_uid,cloud_group);os.chmod(cloud_fleet,0o750)
 if not cloud_has_private:
  cloud_result=subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','ultra-fleet-access','-f',str(cloud_private)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,timeout=45)
  cloud_need(cloud_result.returncode==0)
  cloud_file(cloud_private,[cloud_root_uid],True)
  cloud_result=subprocess.run(['ssh-keygen','-y','-f',str(cloud_private)],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=15)
  cloud_need(cloud_result.returncode==0)
  cloud_derived=' '.join(cloud_result.stdout.split()[:2])
  cloud_need(cloud_derived.startswith('ssh-ed25519 ') and len(cloud_derived.split())==2)
 os.chown(cloud_private,cloud_account.pw_uid,cloud_group);os.chmod(cloud_private,0o600)
 cloud_fd=os.open(cloud_private,os.O_RDONLY|os.O_NOFOLLOW)
 try:os.fsync(cloud_fd)
 finally:os.close(cloud_fd)
 cloud_sync(cloud_fleet)
 if cloud_public.exists():
  cloud_file(cloud_public,[cloud_root_uid,cloud_account.pw_uid])
  cloud_need(cloud_public.read_text().split()[:2]==cloud_derived.split())
  os.chown(cloud_public,cloud_root_uid,cloud_group);os.chmod(cloud_public,0o644)
 else:cloud_publish(cloud_public,(cloud_derived+'\n').encode(),0o644,cloud_root_uid,cloud_group)
 cloud_sync('/etc')
 cloud_dropin=cloud_provider.parent
 cloud_dropin.mkdir(mode=0o755,exist_ok=True)
 if not cloud_provider.exists():cloud_publish(cloud_provider,cloud_content.encode(),0o644,cloud_root_uid,cloud_root_gid)
 cloud_check=subprocess.run(['runuser','-u','ultra-relay','--','test','-r',str(cloud_private)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,timeout=45)
 cloud_need(cloud_check.returncode==0)
 for cloud_args in [['systemctl','daemon-reload'],['systemctl','restart','ultra-relay.service'],['systemctl','is-active','--quiet','ultra-relay.service']]:
  if cloud_args[1]=='restart':cloud_verify_relay()
  cloud_check=subprocess.run(cloud_args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,timeout=45)
  cloud_need(cloud_check.returncode==0)
 cloud_configured=True
`
