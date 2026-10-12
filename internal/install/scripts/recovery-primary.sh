#!/usr/bin/env bash
set -eu
install -d -m 700 /var/lib/ultra-relay/automation
python3 - <<'PY'
import json,os,secrets,subprocess
path=os.environ.get('ULTRA_RECOVERY_CONFIG_FILE','/var/lib/ultra-relay/automation/replication.json')
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
role=cfg.get('user','')
if not re.fullmatch(r'ultra_recovery(?:_[a-z0-9]{1,24})?',role) or not re.fullmatch('[a-f0-9]{64}',cfg['password']): raise SystemExit('Invalid recovery credentials')
pw=cfg['password']
if sql("SELECT COUNT(*) FROM pg_roles WHERE rolname='"+role+"';")=='0': sql('CREATE ROLE '+role+' LOGIN REPLICATION;')
sql("ALTER ROLE "+role+" WITH LOGIN REPLICATION PASSWORD '"+pw+"'; GRANT pg_monitor TO "+role+";")
sql("ALTER SYSTEM SET max_slot_wal_keep_size='1GB';")
if int(sql('SHOW max_replication_slots;'))<10: sql("ALTER SYSTEM SET max_replication_slots='10';")
if int(sql('SHOW max_wal_senders;'))<10: sql("ALTER SYSTEM SET max_wal_senders='10';")
if sql('SHOW wal_level;') not in ('replica','logical'): sql("ALTER SYSTEM SET wal_level='replica';")
hba=sql('SHOW hba_file;')
with open(hba) as f: content=f.read()
marker='# '+role+'_loopback'
if marker not in content:
 with open(hba,'a') as f: f.write('\nhost replication '+role+' 127.0.0.1/32 scram-sha-256 '+marker+'\nhost postgres '+role+' 127.0.0.1/32 scram-sha-256 '+marker+'\n')
sql('SELECT pg_reload_conf();')
if sql("SELECT COUNT(*) FROM pg_settings WHERE pending_restart;")!='0':
 if os.environ.get('ULTRA_RECOVERY_ALLOW_RESTART')=='1':
  subprocess.run(['systemctl','restart','postgresql'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  if sql("SELECT COUNT(*) FROM pg_settings WHERE pending_restart;")!='0': raise SystemExit('PostgreSQL restart did not apply recovery parameters')
 else: raise SystemExit('Primary parameters require a planned PostgreSQL restart; replica remains disabled')
PY
[ "${ULTRA_RECOVERY_DB_ONLY:-0}" != 1 ] || exit 0
getent passwd ultra-relay >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay
chown -R ultra-relay:ultra-relay /var/lib/ultra-relay/automation
install -d /etc/systemd/system/ultra-relay.service.d
cat > /etc/systemd/system/ultra-relay.service.d/recovery.conf <<'UNIT'
[Service]
Environment=ULTRA_REPLICATION_KEY_FILE=/var/lib/ultra-relay/automation/replication.json
Environment=ULTRA_VULTR_SSH_KEY_FILE=/var/lib/ultra-relay/automation/id_ed25519
UNIT
systemctl daemon-reload
