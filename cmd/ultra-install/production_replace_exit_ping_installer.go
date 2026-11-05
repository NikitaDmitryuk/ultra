package main

import (
	"errors"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func prepareReplacementPingInstaller(p *installplan.InstallPlan, rollout *replacementPingRollout) error {
	if p.Automation == nil {
		return errors.New("replacement_exit_ping_installer_unavailable")
	}
	manifest, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	if err != nil {
		return errors.New("replacement_exit_ping_installer_candidate_invalid")
	}
	asset, err := upgradeAsset(manifest, "ultra-install-linux-amd64")
	if err != nil {
		return errors.New("replacement_exit_ping_installer_asset_unavailable")
	}
	rollout.Installer = filepath.Join(managedControllerDirectory(manifest.Version), "ultra-install")
	rollout.InstallerSHA256 = asset.SHA
	return nil
}

// The controller role installs only into an immutable release directory. Never
// infer an executable from PATH or recreate the removed legacy /usr/local link.
const replacementPingInstallerDefinitions = `import os,re,stat,hashlib,json,subprocess
from pathlib import Path
def _installer_need(value,code):
 if not value:raise ValueError(code)
def _installer_file(path,private=False):
 p=Path(path)
 for parent in [p,*p.parents]:
  s=parent.lstat();_installer_need(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'exit_ping_installer_path_untrusted')
 s=p.stat();_installer_need(stat.S_ISREG(s.st_mode) and 0<s.st_size<=256*1024*1024,'exit_ping_installer_file_invalid')
 if private:_installer_need(not s.st_mode&0o077,'exit_ping_installer_record_untrusted')
 return p
def verified_installer(path,expected=None):
 _installer_need(isinstance(path,str) and re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}/ultra-install',path),'exit_ping_installer_layout_invalid')
 p=_installer_file(path);_installer_need(p.stat().st_mode&0o111,'exit_ping_installer_not_executable')
 if expected is not None:
  _installer_need(isinstance(expected,str) and re.fullmatch('[a-f0-9]{64}',expected),'exit_ping_installer_digest_invalid')
  h=hashlib.sha256()
  with p.open('rb') as f:
   for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
  _installer_need(h.hexdigest()==expected,'exit_ping_installer_digest_changed')
 return str(p)
def verify_current_installer():
 q=subprocess.run(['systemctl','show','--property=MainPID','--value','ultra-ansible-controller.service'],capture_output=True,text=True,timeout=5)
 _installer_need(q.returncode==0 and q.stdout.strip().isdigit() and int(q.stdout.strip())>1,'exit_ping_controller_process_unavailable')
 proc=Path('/proc')/q.stdout.strip();path=verified_installer(os.readlink(proc/'exe'))
 _installer_need((proc/'exe').samefile(path),'exit_ping_controller_executable_changed')
 argv=[part.decode() for part in (proc/'cmdline').read_bytes().split(b'\0') if part]
 _installer_need(len(argv)>=2 and argv[:2]==[path,'ansible-controller'],'exit_ping_controller_command_invalid')
 # This rollout uses the same Linux/amd64 artifacts as the managed provider.
 # Admit the machine and the actual root-owned running executable together,
 # before fencing; a supported installer layout alone does not prove its ABI.
 machine=os.uname()
 _installer_need(machine.sysname=='Linux' and machine.machine in ('x86_64','amd64'),'exit_ping_controller_architecture_unsupported')
 with Path(path).open('rb') as f:header=f.read(20)
 _installer_need(len(header)==20 and header[:6]==b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little')==62,'exit_ping_controller_architecture_unsupported')
 return 'linux-amd64'
def scoped_installer(binding):
 _installer_need(re.fullmatch('[a-f0-9]{64}',binding),'exit_ping_installer_binding_invalid')
 p=_installer_file(Path('/var/lib/ultra-replacement-ping')/binding/'publication-stage.json',True)
 _installer_need(p.stat().st_size<=65536,'exit_ping_installer_record_invalid');r=json.loads(p.read_text())
 _installer_need(r.get('binding')==binding,'exit_ping_installer_binding_changed')
 return verified_installer(r.get('installer'),r.get('installer_sha256'))
`
