package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runAutomationCommand(action string, args []string) {
	fs := flag.NewFlagSet("ultra-install "+action, flag.ExitOnError)
	plan := fs.String("plan", "", "validated install plan; private file references only")
	configPath := fs.String("config", "", "canonical install.config path (exclusive with --plan)")
	releaseDir := fs.String("release-dir", "", "verified immutable release directory (legacy adopted installations)")
	_ = fs.Parse(args)
	p := readDeploymentOrExit(*plan, *configPath)
	if p.Automation == nil && action == "upgrade" {
		exitOnErr("automation "+action, upgradePersistedAutomation(p, *releaseDir))
		return
	}
	if p.Automation == nil && action == "status" {
		exitOnErr("automation "+action, statusPersistedAutomation(p))
		return
	}
	exitOnErr("automation "+action, applyAutomation(p, action))
}

type automationRelease struct {
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
	Assets       []struct {
		Name string `json:"name"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

type automationPoll struct {
	Unit    string
	Version string
	Ready   bool
	Pending bool
	Error   string
}

func applyAutomation(p *installplan.InstallPlan, action string) error {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	if p.Automation == nil {
		return errors.New("automation configuration required")
	}
	a := p.Automation
	if action != "status" {
		if err := preflightAutomation(p); err != nil {
			return err
		}
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_STRICT_HOST_KEY", "yes"); err != nil {
		return err
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", a.KnownHostsFile); err != nil {
		return err
	}
	local, err := os.MkdirTemp("", "ultra-automation-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(local) //nolint:errcheck
	id := filepath.Base(local)
	remote := path.Join("/var/lib/ultra-automation/staging", id)
	ssh := func(command string) error {
		return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command)
	}
	if err := ssh("install -d -m 700 " + shellQuote(remote)); err != nil {
		return errors.New("automation staging unavailable")
	}
	defer func() { _ = ssh("rm -rf -- " + shellQuote(remote)) }()
	upload := func(source, name string) error {
		return install.SCP(p.SSH.Identity, source, p.SSH.User, p.Bridge.SSHHost, path.Join(remote, name))
	}
	script := filepath.Join(local, "automation.py")
	if err := os.WriteFile(script, []byte(install.AutomationScript), 0600); err != nil {
		return err
	}
	if err := upload(script, "automation.py"); err != nil {
		return errors.New("automation script upload failed")
	}
	command := "python3 " + shellQuote(path.Join(remote, "automation.py")) + " --action " + shellQuote(action)
	if action == "status" {
		return ssh(command)
	}
	// Target architecture is authoritative; local operator architecture need not match.
	output, err := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "dpkg --print-architecture")
	if err != nil {
		return errors.New("automation target architecture unavailable")
	}
	arch := string(output)
	for len(arch) > 0 && (arch[len(arch)-1] == '\n' || arch[len(arch)-1] == '\r') {
		arch = arch[:len(arch)-1]
	}
	if arch != "amd64" && arch != "arm64" {
		return errors.New("unsupported automation target architecture")
	}
	for _, name := range []string{"release-manifest.json", "ultra-recovery.tar.gz", "ultra-client-linux-" + arch, "ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-" + arch} {
		if err := upload(filepath.Join(a.ReleaseDir, name), name); err != nil {
			return errors.New("automation release upload failed")
		}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	config["database"] = p.Database.Name
	if p.Database.Name == "" {
		config["database"] = "ultra_db"
	}
	config["spec"] = path.Join(p.Bridge.RemoteDir, "spec.json")
	if err := upload(a.KnownHostsFile, "known_hosts"); err != nil {
		return errors.New("automation known hosts upload failed")
	}
	config["known_hosts_file"] = path.Join(remote, "known_hosts")
	computeKey, dnsKey, err := prepareProviderSecrets(p, local)
	if err != nil {
		return err
	}
	if computeKey != "" {
		if err := upload(computeKey, "cloud-key"); err != nil {
			return errors.New("automation cloud key upload failed")
		}
		config["cloud_key_file"] = path.Join(remote, "cloud-key")
	}
	if dnsKey != "" {
		if err := upload(dnsKey, "dns-key"); err != nil {
			return errors.New("automation DNS key upload failed")
		}
		config["dns"].(map[string]any)["api_key_file"] = path.Join(remote, "dns-key")
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return err
	}
	configPath := filepath.Join(local, "bootstrap.json")
	if err := os.WriteFile(configPath, payload, 0600); err != nil {
		return err
	}
	if err := upload(configPath, "bootstrap.json"); err != nil {
		return errors.New("automation configuration upload failed")
	}
	bundle, err := persistAutomationBundle(p, remote, a.Version)
	if err != nil {
		return err
	}
	if err := runDurableAutomation(p, action, bundle, a.Version, automationTimeout(a.ReadinessTimeoutSec)); err != nil {
		return fmt.Errorf("full automation %s did not reach readiness: %w", action, err)
	}
	return nil
}

// preflightAutomation verifies every supplied release asset before the installer mutates a host.
func preflightAutomation(p *installplan.InstallPlan) error {
	if !p.FullAutomation() {
		return nil
	}
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	_, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	return err
}

// verifyAutomationRelease verifies every manifest asset and returns its immutable version.
func verifyAutomationRelease(releaseDir, expectedVersion string) (*automationRelease, error) {
	raw, err := os.ReadFile(filepath.Join(releaseDir, "release-manifest.json"))
	if err != nil {
		return nil, errors.New("complete release manifest unavailable")
	}
	var manifest automationRelease
	if json.Unmarshal(raw, &manifest) != nil || !validAutomationVersion(manifest.Version) || (expectedVersion != "" && manifest.Version != expectedVersion) {
		return nil, errors.New("release version mismatch")
	}
	capable := false
	for _, capability := range manifest.Capabilities {
		capable = capable || capability == "service-access-v1"
	}
	if !capable {
		return nil, errors.New("release lacks service-access-v1 capability")
	}
	seen := map[string]bool{}
	for _, asset := range manifest.Assets {
		if filepath.Base(asset.Name) != asset.Name || asset.Name == "." || seen[asset.Name] {
			return nil, errors.New("invalid or repeated release asset")
		}
		seen[asset.Name] = true
		file, err := os.Open(filepath.Join(releaseDir, asset.Name))
		if err != nil {
			return nil, errors.New("release asset missing")
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		_ = file.Close()
		if copyErr != nil || size != asset.Size || hex.EncodeToString(hash.Sum(nil)) != asset.SHA {
			return nil, errors.New("release checksum mismatch")
		}
	}
	for _, name := range []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz"} {
		if !seen[name] {
			return nil, errors.New("incomplete automation release")
		}
	}
	return &manifest, nil
}

func validAutomationVersion(version string) bool {
	return version != "latest" && regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`).MatchString(version)
}

func automationTimeout(readinessSeconds int) time.Duration {
	if readinessSeconds <= 0 {
		readinessSeconds = 900
	}
	return time.Duration(readinessSeconds+600) * time.Second
}

func automationBundlePath(version string) (string, error) {
	if !validAutomationVersion(version) {
		return "", errors.New("invalid immutable automation version")
	}
	return path.Join("/var/lib/ultra-automation/releases", version), nil
}

func automationUnitName(action, version string) (string, error) {
	if action != "bootstrap" && action != "upgrade" {
		return "", errors.New("invalid durable automation action")
	}
	if _, err := automationBundlePath(version); err != nil {
		return "", err
	}
	replacer := strings.NewReplacer(".", "-", "+", "-", "_", "-")
	unit := "ultra-automation-" + action + "-" + replacer.Replace(version)
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(unit) {
		return "", errors.New("invalid durable automation unit")
	}
	return unit, nil
}

func persistAutomationBundle(p *installplan.InstallPlan, source, version string) (string, error) {
	target, err := automationBundlePath(version)
	if err != nil {
		return "", err
	}
	program := `import json,os,pathlib,shutil,sys
src=pathlib.Path(sys.argv[1]); dst=pathlib.Path(sys.argv[2]); version=sys.argv[3]
if not (src/'release-manifest.json').is_file() or not (src/'bootstrap.json').is_file(): raise SystemExit(2)
dst.parent.mkdir(parents=True,exist_ok=True)
if dst.exists():
  if (dst/'release-manifest.json').read_bytes() != (src/'release-manifest.json').read_bytes(): raise SystemExit(3)
else:
  tmp=pathlib.Path(str(dst)+'.incoming')
  shutil.rmtree(tmp,ignore_errors=True); shutil.copytree(src,tmp)
  cfg=json.loads((tmp/'bootstrap.json').read_text())
  def replace(v):
    if isinstance(v,str): return v.replace(str(src),str(dst))
    if isinstance(v,list): return [replace(x) for x in v]
    if isinstance(v,dict): return {k:replace(x) for k,x in v.items()}
    return v
  cfg=replace(cfg); cfg['version']=version
  out=tmp/'bootstrap.json'; out.write_text(json.dumps(cfg,separators=(',',':'))); os.chmod(out,0o600)
  os.chmod(tmp,0o700); os.rename(tmp,dst)
print('ULTRA_BUNDLE=ready')`
	command := "python3 -c " + shellQuote(program) + " " + shellQuote(source) + " " + shellQuote(target) + " " + shellQuote(version)
	if err := install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command); err != nil {
		return "", errors.New("immutable automation bundle unavailable")
	}
	return target, nil
}

func runDurableAutomation(p *installplan.InstallPlan, action, bundle, version string, timeout time.Duration) error {
	unit, err := automationUnitName(action, version)
	if err != nil {
		return err
	}
	launch := durableAutomationLaunchCommand(action, bundle, unit, timeout)
	if err := install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, launch); err != nil {
		return errors.New("durable automation job was not started; repeat the same command")
	}
	program := `import json,pathlib
state=pathlib.Path('/var/lib/ultra-automation'); release={}
try: release=json.loads((state/'release.json').read_text())
except Exception: pass
print('ULTRA_VERSION='+str(release.get('version','missing')))
print('ULTRA_READY='+('true' if bool(release.get('ready_at')) else 'false'))
print('ULTRA_PENDING='+('true' if (state/'upgrade.json').exists() else 'false'))
print('ULTRA_ERROR='+('present' if (state/'last-error.json').exists() else 'absent'))`
	deadline := time.Now().Add(timeout)
	for {
		poll := "printf 'ULTRA_UNIT='; systemctl show -p ActiveState --value " + shellQuote(unit+".service") + " 2>/dev/null || printf unknown; " +
			"python3 -c " + shellQuote(program)
		output, pollErr := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, poll)
		if pollErr == nil {
			state := parseAutomationPoll(string(output))
			if state.Version == version && state.Ready && !state.Pending {
				return nil
			}
			if state.Unit == "failed" || state.Unit == "inactive" || state.Unit == "unknown" || state.Unit == "" {
				return errors.New("durable automation job stopped before publishing readiness; repeat the same command after checking private diagnostics")
			}
		}
		if time.Now().After(deadline) {
			return errors.New("durable automation readiness deadline exceeded; the remote job may still be running")
		}
		time.Sleep(2 * time.Second)
	}
}

func durableAutomationLaunchCommand(action, bundle, unit string, timeout time.Duration) string {
	command := "/usr/bin/python3 " + shellQuote(path.Join(bundle, "automation.py")) + " --action " + shellQuote(action) +
		" --config " + shellQuote(path.Join(bundle, "bootstrap.json")) + " --release " + shellQuote(bundle)
	return "state=$(systemctl show -p ActiveState --value " + shellQuote(unit+".service") + " 2>/dev/null || true); " +
		"case \"$state\" in active|activating) ;; *) " +
		"systemctl reset-failed " + shellQuote(unit+".service") + " >/dev/null 2>&1 || true; " +
		"systemd-run --no-block --collect --unit " + shellQuote(unit) +
		" --property Type=oneshot --property TimeoutStartSec=" + fmt.Sprint(int(timeout.Seconds())) + " " + command + ";; esac"
}

func parseAutomationPoll(output string) automationPoll {
	var result automationPoll
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ULTRA_UNIT="):
			result.Unit = strings.TrimPrefix(line, "ULTRA_UNIT=")
		case strings.HasPrefix(line, "ULTRA_VERSION="):
			result.Version = strings.TrimPrefix(line, "ULTRA_VERSION=")
		case line == "ULTRA_READY=true":
			result.Ready = true
		case line == "ULTRA_PENDING=true":
			result.Pending = true
		case strings.HasPrefix(line, "ULTRA_ERROR="):
			result.Error = strings.TrimPrefix(line, "ULTRA_ERROR=")
		}
	}
	return result
}

func statusPersistedAutomation(p *installplan.InstallPlan) error {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_STRICT_HOST_KEY", "yes"); err != nil {
		return err
	}
	command := persistedAutomationStatusCommand("/var/lib/ultra-automation")
	if err := install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command); err != nil {
		return errors.New("installed automation status unavailable")
	}
	return nil
}

func persistedAutomationStatusCommand(stateRoot string) string {
	program := `import json,os,pathlib,re,sys
state=pathlib.Path(sys.argv[1])
version=json.loads((state/'release.json').read_text()).get('version','')
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?',version): raise SystemExit(2)
script=state/'releases'/version/'automation.py'
if not script.is_file(): raise SystemExit(3)
os.execv('/usr/bin/python3',['python3',str(script),'--action','status'])`
	return "python3 -c " + shellQuote(program) + " " + shellQuote(stateRoot)
}

func upgradePersistedAutomation(p *installplan.InstallPlan, releaseDir string) error {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	if strings.TrimSpace(releaseDir) == "" {
		return errors.New("legacy adopted installation upgrade requires --release-dir")
	}
	manifest, err := verifyAutomationRelease(releaseDir, "")
	if err != nil {
		return err
	}
	if err = os.Setenv("ULTRA_INSTALL_SSH_STRICT_HOST_KEY", "yes"); err != nil {
		return err
	}
	local, err := os.MkdirTemp("", "ultra-persisted-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(local) //nolint:errcheck
	remote := path.Join("/var/lib/ultra-automation/staging", filepath.Base(local))
	ssh := func(command string) error {
		return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command)
	}
	if err = ssh("install -d -m 700 " + shellQuote(remote)); err != nil {
		return errors.New("automation staging unavailable")
	}
	defer func() { _ = ssh("rm -rf -- " + shellQuote(remote)) }()
	copyProgram := `import json,os,pathlib,shutil,sys
state=pathlib.Path('/var/lib/ultra-automation'); dst=pathlib.Path(sys.argv[1])
current=json.loads((state/'release.json').read_text()).get('version','')
src=state/'releases'/current
if not current or not (src/'bootstrap.json').is_file(): raise SystemExit(2)
shutil.copytree(src,dst,dirs_exist_ok=True)
cfg=json.loads((dst/'bootstrap.json').read_text())
def replace(v):
  if isinstance(v,str): return v.replace(str(src),str(dst))
  if isinstance(v,list): return [replace(x) for x in v]
  if isinstance(v,dict): return {k:replace(x) for k,x in v.items()}
  return v
out=dst/'bootstrap.json'; out.write_text(json.dumps(replace(cfg),separators=(',',':'))); os.chmod(out,0o600)`
	if err = ssh("python3 -c " + shellQuote(copyProgram) + " " + shellQuote(remote)); err != nil {
		return errors.New("persisted automation configuration unavailable")
	}
	upload := func(source, name string) error {
		return install.SCP(p.SSH.Identity, source, p.SSH.User, p.Bridge.SSHHost, path.Join(remote, name))
	}
	script := filepath.Join(local, "automation.py")
	if err = os.WriteFile(script, []byte(install.AutomationScript), 0600); err != nil {
		return err
	}
	if err = upload(script, "automation.py"); err != nil {
		return errors.New("automation script upload failed")
	}
	if err = upload(filepath.Join(releaseDir, "release-manifest.json"), "release-manifest.json"); err != nil {
		return errors.New("automation manifest upload failed")
	}
	output, err := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "dpkg --print-architecture")
	if err != nil {
		return errors.New("automation target architecture unavailable")
	}
	arch := strings.TrimSpace(string(output))
	if arch != "amd64" && arch != "arm64" {
		return errors.New("unsupported automation target architecture")
	}
	for _, name := range []string{"ultra-recovery.tar.gz", "ultra-client-linux-" + arch, "ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-" + arch} {
		if err = upload(filepath.Join(releaseDir, name), name); err != nil {
			return errors.New("automation release upload failed")
		}
	}
	bundle, err := persistAutomationBundle(p, remote, manifest.Version)
	if err != nil {
		return err
	}
	return runDurableAutomation(p, "upgrade", bundle, manifest.Version, automationTimeout(0))
}
