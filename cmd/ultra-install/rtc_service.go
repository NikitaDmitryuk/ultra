package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
)

func prepareRTCService(p *installplan.InstallPlan) error {
	d := p.RTCService
	// Explicitly stop obsolete pilot units as well when the entire module is off.
	stop := `systemctl list-unit-files --type=service --no-legend | awk '$1 ~ /^ultra-rtc-.*\.service$/ {print $1}' | xargs -r systemctl disable --now`
	if d == nil || !d.Enabled {
		return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, stop)
	}
	if e := d.Validate(); e != nil {
		return e
	}
	if _, e := rtc.LoadContent(d.ContentFile); e != nil {
		return e
	}
	if e := fileMustExist(d.SupervisorBinary); e != nil {
		return e
	}
	if p.RTCDeployment == nil {
		return fmt.Errorf("rtc: pinned transport deployment required")
	}
	if e := p.RTCDeployment.Verify(); e != nil {
		return e
	}
	setup := `set -eu
id ultra-rtc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-rtc
install -d -o root -g ultra-relay -m 750 /etc/ultra-rtc
`
	if e := install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, setup); e != nil {
		return e
	}
	raw, e := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "id -u ultra-relay")
	if e != nil {
		return e
	}
	uid, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if e != nil {
		return e
	}
	dir, e := os.MkdirTemp("", "ultra-rtc-unit-")
	if e != nil {
		return e
	}
	defer func() { _ = os.RemoveAll(dir) }()
	unit := filepath.Join(dir, "supervisor.service")
	if e = os.WriteFile(unit, []byte(install.RTCServiceUnit(d.GatewayPort, uid)), 0600); e != nil {
		return e
	}
	for _, pair := range [][2]string{{d.ContentFile, "/etc/ultra-rtc/content.upload"}, {d.SupervisorBinary, "/etc/ultra-rtc/supervisor.upload"}, {p.RTCDeployment.Binary, "/etc/ultra-rtc/transport.upload"}, {unit, "/etc/ultra-rtc/unit.upload"}} {
		if e = install.SCP(p.SSH.Identity, pair[0], p.SSH.User, p.Bridge.SSHHost, pair[1]); e != nil {
			return e
		}
	}
	apply := fmt.Sprintf(`set -eu
printf '%%s  %%s\n' '%s' /etc/ultra-rtc/transport.upload | sha256sum -c - >/dev/null
%s
install -o root -g ultra-relay -m 640 /etc/ultra-rtc/content.upload /etc/ultra-rtc/content.json
install -m 755 /etc/ultra-rtc/supervisor.upload /usr/local/bin/ultra-rtc-supervisor
install -m 755 /etc/ultra-rtc/transport.upload /usr/local/bin/olcrtc
install -m 644 /etc/ultra-rtc/unit.upload /etc/systemd/system/ultra-rtc-supervisor.service
rm /etc/ultra-rtc/content.upload /etc/ultra-rtc/supervisor.upload /etc/ultra-rtc/transport.upload /etc/ultra-rtc/unit.upload
python3 - <<'PYKEY'
import os,pathlib,base64,json,grp,pwd
p=pathlib.Path('/etc/ultra-rtc/keys.json')
if not p.exists():
 data=json.dumps({'active':'v1','keys':{'v1':base64.b64encode(os.urandom(32)).decode()}}).encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data)
if p.is_symlink():raise SystemExit('invalid RTC key file')
os.chown(p,pwd.getpwnam('ultra-relay').pw_uid,grp.getgrnam('ultra-relay').gr_gid);os.chmod(p,0o600)
PYKEY
systemctl daemon-reload
systemctl enable --now ultra-rtc-supervisor.service
`, p.RTCDeployment.SHA256, stop)
	return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, apply)
}
