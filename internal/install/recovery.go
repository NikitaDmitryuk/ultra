package install

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// EnableRecoveryNode authorizes the bridge worker to maintain an isolated replica.
// This remains callable by the local installer; no cloud API is required.
func EnableRecoveryNode(user, primary, target, identity string) error {
	if primary == target {
		return errors.New("replica must differ from primary")
	}
	output, err := RunSSHOutput(user, primary, identity, `set -eu
install -d -m 700 /var/lib/ultra-relay/automation
if [ ! -f /var/lib/ultra-relay/automation/id_ed25519 ]; then ssh-keygen -q -t ed25519 -N '' -f /var/lib/ultra-relay/automation/id_ed25519 >/dev/null; fi
cat /var/lib/ultra-relay/automation/id_ed25519.pub
`)
	if err != nil {
		return errors.New("automation public key unavailable")
	}
	parts := strings.Fields(string(output))
	if len(parts) < 2 || parts[0] != "ssh-ed25519" {
		return errors.New("invalid automation public key")
	}
	if _, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return errors.New("invalid automation public key")
	}
	public := parts[0] + " " + parts[1]
	if err = RunSSH(user, target, identity, fmt.Sprintf(`set -eu
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qF -- '%s' /root/.ssh/authorized_keys || printf '%%s\n' '%s ultra-recovery-worker' >> /root/.ssh/authorized_keys
`, public, public)); err != nil {
		return errors.New("replica SSH authorization failed")
	}
	return RunSSH(user, primary, identity, recoveryPrimaryScript)
}

// This script operates on a co-located primary and preserves existing application credentials.
const recoveryPrimaryScript = `set -eu
install -d -m 700 /var/lib/ultra-relay/automation
python3 - <<'PY'
import json,os,secrets,subprocess
path='/var/lib/ultra-relay/automation/replication.json'
def sql(query):
 r=subprocess.run(['runuser','-u','postgres','--','psql','-XAt','-v','ON_ERROR_STOP=1','-d','postgres'],input=query,text=True,capture_output=True)
 if r.returncode: raise SystemExit('Primary recovery setup failed')
 return r.stdout.strip()
if sql('SELECT pg_is_in_recovery();')!='f': raise SystemExit('Recovery setup requires a primary')
if os.path.exists(path):
 with open(path) as f: cfg=json.load(f)
else:
 cfg={'user':'ultra_recovery','password':secrets.token_hex(32),'port':int(sql('SHOW port;'))}
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f: json.dump(cfg,f)
import re
if cfg['user']!='ultra_recovery' or not re.fullmatch('[a-f0-9]{64}',cfg['password']): raise SystemExit('Invalid recovery credentials')
pw=cfg['password']
if sql("SELECT COUNT(*) FROM pg_roles WHERE rolname='ultra_recovery';")=='0': sql('CREATE ROLE ultra_recovery LOGIN REPLICATION;')
sql("ALTER ROLE ultra_recovery WITH LOGIN REPLICATION PASSWORD '"+pw+"'; GRANT pg_monitor TO ultra_recovery;")
sql("ALTER SYSTEM SET max_slot_wal_keep_size='1GB';")
if int(sql('SHOW max_replication_slots;'))<10: sql("ALTER SYSTEM SET max_replication_slots='10';")
if int(sql('SHOW max_wal_senders;'))<10: sql("ALTER SYSTEM SET max_wal_senders='10';")
if sql('SHOW wal_level;') not in ('replica','logical'): sql("ALTER SYSTEM SET wal_level='replica';")
hba=sql('SHOW hba_file;')
with open(hba) as f: content=f.read()
if '# ultra_recovery_loopback' not in content:
 with open(hba,'a') as f: f.write('\nhost replication ultra_recovery 127.0.0.1/32 scram-sha-256 # ultra_recovery_loopback\nhost postgres ultra_recovery 127.0.0.1/32 scram-sha-256 # ultra_recovery_loopback\n')
sql('SELECT pg_reload_conf();')
if sql("SELECT COUNT(*) FROM pg_settings WHERE pending_restart;")!='0': raise SystemExit('Primary parameters require a planned PostgreSQL restart; replica remains disabled')
PY
getent passwd ultra-relay >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay
chown -R ultra-relay:ultra-relay /var/lib/ultra-relay/automation
install -d /etc/systemd/system/ultra-relay.service.d
cat > /etc/systemd/system/ultra-relay.service.d/recovery.conf <<'UNIT'
[Service]
Environment=ULTRA_REPLICATION_KEY_FILE=/var/lib/ultra-relay/automation/replication.json
Environment=ULTRA_VULTR_SSH_KEY_FILE=/var/lib/ultra-relay/automation/id_ed25519
UNIT
systemctl daemon-reload
`
