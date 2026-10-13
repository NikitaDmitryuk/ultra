#!/usr/bin/env python3
"""Root recovery reconciliation for already-owned, ready exits. No provisioning or migrations."""
import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import stat
import grp
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from recovery import atomic_json, create, digest, private, read_config, ssh

QUERY = """BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT COALESCE(json_agg(json_build_object('id',c.id::text,'state',c.state,
 'phase',c.body->>'phase','instance_id',c.body->>'instance_id','firewall_id',c.body->>'firewall_id',
 'exit_id',c.body->>'exit_id','address',n.address,'enabled',COALESCE(n.enabled,false),
 'country',n.country_code)), '[]'::json)
FROM cloud_operations c LEFT JOIN exit_nodes n ON n.id::text=c.body->>'exit_id'
WHERE c.state IN ('ready','deleted','cancelled');
COMMIT;"""


def discover(config):
    database = config['database']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
        raise ValueError('invalid database')
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', QUERY],
                            capture_output=True, timeout=8)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError('discovery unavailable')
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError('discovery exceeds bounds')
    return rows


def desired_nodes(config, rows):
    nodes = []
    seen = set()
    for node in config.get('static_nodes', []):
        node = dict(node)
        ipaddress.ip_address(node['address'])
        node['managed'] = False
        nodes.append(node)
        seen.add(node['id'])
    retired = set()
    for row in rows:
        operation = str(uuid.UUID(row['id']))
        if row['state'] in ('deleted', 'cancelled'):
            retired.add(operation)
            continue
        if row['state'] != 'ready' or row['phase'] != 'ready' or not row['enabled']:
            continue
        if row['exit_id'] != operation or not row['instance_id']:
            raise ValueError('managed identity mismatch')
        address = str(ipaddress.ip_address(row['address']))
        if operation in seen:
            raise ValueError('duplicate node')
        seen.add(operation)
        nodes.append({'id': operation, 'address': address, 'host': 'root@' + address, 'name': row.get('country') or operation,
                      'provider': 'vultr', 'managed': True, 'instance_id': row['instance_id'], 'firewall_id': row['firewall_id'],
                      'known_hosts': str(Path(config['vultr_state_dir']) / operation / 'known_hosts')})
    if not nodes or len(nodes) > 16:
        raise ValueError('desired nodes exceed bounds')
    for node in nodes:
        node.setdefault('host', 'root@' + node['address'])
        if node['host'] != 'root@' + node['address']:
            raise ValueError('unexpected SSH account')
        if not node.get('provider') or not Path(node['known_hosts']).is_absolute():
            raise ValueError('provider and pinned known hosts required')
        pinned = Path(node['known_hosts'])
        if pinned.is_symlink() or not pinned.is_file() or pinned.stat().st_mode & 0o022 or not pinned.read_bytes():
            raise ValueError('pinned host key unavailable')
    return sorted(nodes, key=lambda node: node['id']), retired


def target(config, node, required=False):
    return {'id': node['id'], 'name': node['name'], 'host': node['host'], 'required': required,
            'identity_file': config['ssh_identity_file'], 'known_hosts': node['known_hosts']}


def execute(config, node, command, **kwargs):
    return ssh({}, target(config, node), command, **kwargs)


READ_MONITOR = r'''
import pathlib,sys
try:
    with pathlib.Path('/etc/ultra-recovery/monitor.json').open('rb') as stream:
        data = stream.read(65537)
except FileNotFoundError:
    data = b'null'
if len(data) > 65536:
    raise SystemExit('monitor config too large')
sys.stdout.buffer.write(data)
'''


def previous_monitor(config, node):
    result = execute(config, node, ['python3', '-'], input=READ_MONITOR.encode(), stdout=subprocess.PIPE, timeout=10)
    value = json.loads(result.stdout)
    if value is not None and not isinstance(value, dict):
        raise ValueError('invalid previous monitor config')
    return value


# Payload is sent over pinned SSH stdin, never through arguments/logs.
INSTALL = r'''
import base64,hashlib,json,os,pathlib,re,subprocess,tempfile
os.umask(0o077)
raw=__import__('sys').stdin.buffer.read(134217729)
if len(raw)>134217728:raise ValueError('installation exceeds bounds')
payload=json.loads(raw)
allowed={'/opt/ultra-recovery/recovery.py','/opt/ultra-recovery/monitor.py','/opt/ultra-recovery/heartbeat.py',
 '/usr/local/bin/ultra-client','/etc/ultra-recovery/monitor.json','/etc/ultra-recovery/probe.json',
 '/etc/ultra-recovery/primary-bot-token','/etc/ultra-recovery/peer_ed25519','/etc/ultra-recovery/peer_known_hosts',
 '/etc/systemd/system/ultra-recovery-prune.service','/etc/systemd/system/ultra-recovery-prune.timer',
 '/etc/systemd/system/ultra-monitor.service','/etc/systemd/system/ultra-monitor.timer','/etc/systemd/system/ultra-monitor-probe.service'}
for folder in ['/opt/ultra-recovery','/etc/ultra-recovery','/var/lib/ultra-recovery','/var/lib/ultra-monitor']:
 p=pathlib.Path(folder)
 if p.is_symlink():raise ValueError('managed directory symlink')
 p.mkdir(mode=0o700,exist_ok=True)
marker=pathlib.Path('/var/lib/ultra-recovery/.ultra-recovery-repository')
if marker.exists():
 if marker.is_symlink() or marker.stat().st_uid!=0 or marker.stat().st_mode&0o077 or json.loads(marker.read_text())!={'source':'bridge','version':1}:raise ValueError('foreign repository')
else:
 if any(marker.parent.iterdir()):raise ValueError('unmarked nonempty repository')
 marker.write_text(json.dumps({'source':'bridge','version':1}));marker.chmod(0o600)
changed=[]
for name,item in payload['files'].items():
 if name not in allowed and not re.fullmatch(r'/etc/ultra-recovery/peer_ed25519-[a-f0-9]{64}(?:\.pub)?',name):raise ValueError('unmanaged path')
 data=base64.b64decode(item['data'],validate=True)
 if hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError('digest differs')
 p=pathlib.Path(name)
 if p.is_symlink():raise ValueError('managed file symlink')
 mode=item['mode']
 if p.exists() and p.read_bytes()==data and p.stat().st_mode&0o777==mode and p.stat().st_uid==0:continue
 fd,tmp=tempfile.mkstemp(dir=p.parent,prefix='.pending-')
 try:
  with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
  os.replace(tmp,p)
  directory=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(directory);os.close(directory)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
 changed.append(name)
if not pathlib.Path('/usr/bin/age').exists():
 subprocess.run(['apt-get','update','-qq'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
 subprocess.run(['apt-get','install','-y','-qq','age'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
if any(name.startswith('/etc/systemd/')for name in changed):subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','ultra-recovery-prune.timer'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if payload.get('monitor'):
 if payload['monitor']=='primary':
  subprocess.run(['systemctl','enable','--now','ultra-monitor-probe.service'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  if '/etc/ultra-recovery/probe.json'in changed or '/usr/local/bin/ultra-client'in changed:subprocess.run(['systemctl','restart','ultra-monitor-probe.service'],check=True)
 subprocess.run(['systemctl','enable','--now','ultra-monitor.timer'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(json.dumps({'changed':len(changed)}))
'''


def file_payload(path, data, mode):
    return path, {'data': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': mode}


def install(config, node, monitor=None, extra=None):
    base = Path(config['bundle_dir'])
    files = {}
    for name in ['recovery.py', 'monitor.py', 'heartbeat.py']:
        files.update([file_payload('/opt/ultra-recovery/' + name, (base / name).read_bytes(), 0o755)])
    for name in ['ultra-recovery-prune.service', 'ultra-recovery-prune.timer', 'ultra-monitor.service', 'ultra-monitor.timer', 'ultra-monitor-probe.service']:
        files.update([file_payload('/etc/systemd/system/' + name, (base / name).read_bytes(), 0o644)])
    if monitor:
        files.update([file_payload('/usr/local/bin/ultra-client', Path(config['client_binary']).read_bytes(), 0o755)])
        files.update([file_payload('/etc/ultra-recovery/monitor.json', json.dumps(monitor, sort_keys=True).encode(), 0o600)])
        files.update([file_payload('/etc/ultra-recovery/primary-bot-token', private(config['bot_token_file']).read_bytes(), 0o600)])
        if monitor['mode'] == 'primary':
            files.update([file_payload('/etc/ultra-recovery/probe.json', private(config['probe_profile_file']).read_bytes(), 0o600)])
    for path, data, mode in extra or []:
        files.update([file_payload(path, data, mode)])
    inventory = {name: {'sha256': item['sha256'], 'mode': item['mode']} for name, item in files.items()}
    check = """import hashlib,json,pathlib,sys
inventory=json.loads(sys.stdin.read());changed=[]
for name,item in inventory.items():
 p=pathlib.Path(name)
 if p.is_symlink():raise ValueError('managed symlink')
 if not p.is_file()or p.stat().st_mode&0o777!=item['mode'] or p.stat().st_uid!=0:changed.append(name);continue
 h=hashlib.sha256()
 with p.open('rb')as stream:
  for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
 if h.hexdigest()!=item['sha256']:changed.append(name)
print(json.dumps(changed))
"""
    inspected = execute(config, node, ['python3', '-c', check], input=json.dumps(inventory).encode(), stdout=subprocess.PIPE, timeout=15)
    changed = json.loads(inspected.stdout)
    if not isinstance(changed, list) or any(name not in files for name in changed):
        raise ValueError('remote installation inventory invalid')
    files = {name: item for name, item in files.items() if name in changed}
    payload = json.dumps({'files': files, 'monitor': monitor['mode'] if monitor else None}).encode()
    if len(payload) > 128 << 20:
        raise ValueError('installation exceeds bounds')
    execute(config, node, ['python3', '-c', INSTALL], input=payload, stdout=subprocess.PIPE, timeout=170)


def validate_delivery(config, node, receipt):
    if node['host'] not in receipt['destinations'] or receipt['snapshot_at'] > time.time() or time.time() - receipt['snapshot_at'] > 300:
        raise ValueError('fresh delivery unavailable')
    names = [receipt['backup_name'], receipt['artifact_name']]
    hashes = [receipt['backup_sha256'], receipt['artifact_sha256']]
    if not re.fullmatch(r'backup-[0-9]{10}-[a-f0-9]{32}\.age', names[0]) or not re.fullmatch(r'artifact-[a-f0-9]{64}\.age', names[1]) or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in hashes):
        raise ValueError('delivery metadata invalid')
    if receipt.get('source') != 'bridge' or int(names[0].split('-')[1]) != int(receipt['snapshot_at']):
        raise ValueError('delivery source or timestamp differs')
    result = execute(config, node, ['sha256sum', *['/var/lib/ultra-recovery/' + name for name in names]], stdout=subprocess.PIPE, timeout=15)
    found = [line.split()[0].decode() for line in result.stdout.splitlines()]
    if found != hashes:
        raise ValueError('delivery integrity differs')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise urllib.error.HTTPError(request.full_url, code, 'redirect rejected', headers, response)


def validate_cloud_owner(info, trusted_owner):
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
        raise ValueError('private cloud credential required')
    allowed = {os.geteuid()}
    if os.geteuid() == 0:
        if trusted_owner not in ('root', 'ultra-relay'):
            raise ValueError('unsupported cloud credential owner')
        if trusted_owner == 'ultra-relay':
            allowed.add(pwd.getpwnam(trusted_owner).pw_uid)
    if info.st_uid not in allowed:
        raise ValueError('untrusted cloud credential owner')


def cloud_private_file(path, trusted_owner):
    path = Path(path)
    validate_cloud_owner(path.lstat(), trusted_owner)
    return path


def read_api_key(config):
    fd = os.open(config['vultr_api_key_file'], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        validate_cloud_owner(os.fstat(stream.fileno()), config.get('api_key_owner', 'ultra-relay'))
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('cloud credential exceeds bounds')
    token = raw.decode().strip()
    if not token or re.search(r'\s', token):
        raise ValueError('cloud credential invalid')
    return token


def write_status(config, value):
    group = grp.getgrnam(config['status_group']).gr_gid if config.get('status_group') else None
    atomic_json(config['status_file'], value, group=group)


def api(config, method, path, data=None):
    token = read_api_key(config)
    if not re.fullmatch(r'/v2/(?:instances|firewalls)/[A-Za-z0-9-]+(?:/rules)?', path):
        raise ValueError('invalid provider path')
    body = None if data is None else json.dumps(data).encode()
    for attempt in range(3 if method == 'GET' else 1):
        request = urllib.request.Request('https://api.vultr.com' + path, data=body, method=method,
                                         headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=8) as response:
                raw = response.read(1 << 20)
                parsed = json.loads(raw) if raw else {}
                if not isinstance(parsed, dict): raise ValueError('provider unavailable')
                return parsed
        except urllib.error.HTTPError as error:
            error.close()
            if method != 'GET' or error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise ValueError('provider unavailable') from None
            retry = error.headers.get('Retry-After', '1')
            delay = min(4, max(1, int(retry))) if retry.isdigit() else 1
            time.sleep(delay)
        except (OSError, ValueError):
            if method != 'GET' or attempt == 2:
                raise ValueError('provider unavailable') from None
            time.sleep(1)
    raise ValueError('provider unavailable')


def ensure_provider_peer_rule(config, primary, peer):
    if not primary.get('managed'):
        return  # Static receiver firewall remains operator-managed.
    identifier = primary['instance_id']
    firewall = primary['firewall_id']
    if not re.fullmatch(r'[A-Za-z0-9-]+', identifier or '') or not re.fullmatch(r'[A-Za-z0-9-]+', firewall or ''):
        raise ValueError('managed firewall unavailable')
    instance = api(config, 'GET', '/v2/instances/' + identifier).get('instance', {})
    if instance.get('id') != identifier or instance.get('main_ip') != primary['address'] or instance.get('firewall_group_id') != firewall:
        raise ValueError('foreign provider resource')
    group = api(config, 'GET', '/v2/firewalls/' + firewall).get('firewall_group', {})
    if group.get('id') != firewall or group.get('description') != 'ultra-operation-' + primary['id']:
        raise ValueError('foreign managed firewall')
    rules = api(config, 'GET', '/v2/firewalls/' + firewall + '/rules').get('firewall_rules', [])
    address = str(ipaddress.IPv4Address(peer['address']))
    required = {'ip_type': 'v4', 'protocol': 'tcp', 'subnet': address, 'subnet_size': 32, 'port': '22'}
    if not any(all(rule.get(key) == value for key, value in required.items()) for rule in rules):
        api(config, 'POST', '/v2/firewalls/' + firewall + '/rules', required)
    return address


def allow_peer(config, primary, peer):
    address = ensure_provider_peer_rule(config, primary, peer)
    if address is None:
        return
    command = "if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then ufw allow from " + address + " to any port 22 proto tcp >/dev/null; fi"
    execute(config, primary, ['sh', '-c', command], stdout=subprocess.DEVNULL)


def ensure_heartbeat_key(config, primary):
    directory = Path(config['state_dir'])
    key = directory / 'heartbeat_ed25519'
    if not key.exists():
        subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-q', '-f', str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    material = private(key).read_bytes()
    derived = subprocess.run(['ssh-keygen', '-y', '-f', str(key)], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    public = derived.stdout.decode().strip().split()
    if len(public) < 2 or public[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/=]+', public[1]):
        raise ValueError('heartbeat key unavailable')
    entry = 'restrict,command="/usr/bin/python3 /opt/ultra-recovery/heartbeat.py" ' + ' '.join(public[:2]) + ' ultra-recovery-heartbeat'
    code = """import json,os,pathlib,sys,tempfile
entry=json.loads(sys.stdin.read())
p=pathlib.Path('/root/.ssh');p.mkdir(mode=0o700,exist_ok=True)
a=p/'authorized_keys'
if a.is_symlink():raise ValueError('symlink')
text=a.read_text()if a.exists()else''
if entry not in text.splitlines():
 fd,name=tempfile.mkstemp(dir=p,prefix='.heartbeat-')
 with os.fdopen(fd,'w')as f:f.write(text+(''if not text or text.endswith('\\n')else'\\n')+entry+'\\n');f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o600)
 os.replace(name,a)
"""
    execute(config, primary, ['python3', '-c', code], input=json.dumps(entry).encode(), stdout=subprocess.DEVNULL)
    return material, (' '.join(public[:2]) + '\n').encode()


def peer_key_pair(material, public):
    # A versioned path keeps a previous active private/public pair intact during staging.
    path = '/etc/ultra-recovery/peer_ed25519-' + hashlib.sha256(public).hexdigest()
    return path, [(path, material, 0o600), (path + '.pub', public, 0o644)]


def monitor_ready(config, node, mode, independent=False):
    expected = {'us_monitor', 'us_notifications', 'probe_execution'} if mode == 'peer' else {
        'bridge_https', 'vpn_payload', 'probe_execution', 'independent_backup' if independent else 'backup_generation'}
    for _ in range(2):
        execute(config, node, ['systemctl', 'start', 'ultra-monitor.service'], stdout=subprocess.DEVNULL, timeout=55)
        result = execute(config, node, ['cat', '/var/lib/ultra-monitor/heartbeat.json'], stdout=subprocess.PIPE, timeout=10)
        if len(result.stdout) > 4096:
            raise ValueError('monitor state exceeds bounds')
        heartbeat = json.loads(result.stdout)
        checks = heartbeat.get('checks', {})
        # A fresh monitor needs both successful samples to establish debounce.
        # Require current health each time, then confirmed health after sample two.
        current = heartbeat.get('current_checks', {})
        if not (0 <= time.time() - heartbeat['updated_at'] <= 120 and expected <= current.keys() and all(current[key] is True for key in expected) and not heartbeat.get('send_error')):
            raise ValueError('monitor not ready')
    if not (expected <= checks.keys() and all(checks[key] is True for key in expected)):
        raise ValueError('monitor not ready')


def candidate_backup(config, backup, nodes, retired):
    old_required = [item for item in backup['destinations'] if item.get('required')]
    candidates = [target(config, node, any(item.get('id') == node['id'] or item['host'] == node['host'] for item in old_required)) for node in nodes]
    hosts = {item['host'] for item in candidates}
    for item in backup['destinations']:
        if item['host'] not in hosts and item.get('id') not in retired:
            candidates.append(dict(item))  # Disabled/unobserved is not conclusive deletion.
    if not any(item.get('required') for item in candidates):
        candidates[0]['required'] = True
    independent = bool(backup.get('independent')) and any(
        node['provider'].lower() != config['bridge_provider'].lower() and any(item['host'] == node['host'] and item.get('required') for item in candidates) for node in nodes)
    return {**backup, 'destinations': candidates, 'independent': independent}


def topology_fingerprint(config, nodes):
    value = {'nodes': nodes, 'bridge_provider': config['bridge_provider']}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()



def reconcile(config):
    directory = Path(config['state_dir'])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError('private state directory required')
    with open(directory / 'reconcile.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            stage = 'discover'
            cloud_private_file(config['ssh_identity_file'], config.get('ssh_identity_owner', 'ultra-relay'))
            rows = discover(config)  # No DB failure may be interpreted as an empty topology.
            nodes, retired = desired_nodes(config, rows)
            previous = read_config(directory / 'state.json') if (directory / 'state.json').exists() else {}
            backup = read_config(config['backup_config'])
            if backup.get('source') != 'bridge': raise ValueError('unexpected backup source')
            stage = 'receiver'
            reachable = []
            setup_pending = []
            for node in nodes:
                try:
                    install(config, node)
                    reachable.append(node)
                except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
                    setup_pending.append(node['id'])
            if not reachable:
                raise ValueError('no reachable receiver')
            stage = 'backup'
            candidate = candidate_backup(config, backup, nodes, retired)
            reachable_hosts = {node['host'] for node in reachable}
            for item in candidate['destinations']:
                if item['host'] not in reachable_hosts:
                    item['required'] = False
            if not any(item.get('required') for item in candidate['destinations']):
                next(item for item in candidate['destinations'] if item['host'] == reachable[0]['host'])['required'] = True
            candidate['independent'] = bool(candidate['independent']) and any(
                node['provider'].lower() != config['bridge_provider'].lower() and any(item['host'] == node['host'] and item.get('required') for item in candidate['destinations']) for node in reachable)
            fingerprint = topology_fingerprint(config, nodes)
            receipt_path = Path(backup['repository']) / 'last-success.json'
            receipt = read_config(receipt_path) if receipt_path.exists() else {}
            if previous.get('topology') != fingerprint or previous.get('nodes') != [node['id'] for node in nodes] or not receipt.get('backup_sha256') or not 0 <= time.time() - receipt.get('snapshot_at', 0) <= 300:
                create(candidate)
                receipt = read_config(receipt_path)
            candidates = candidate['destinations']
            confirmed = []
            for node in reachable:
                try:
                    validate_delivery(config, node, receipt)
                    confirmed.append(node)
                except (ValueError, subprocess.SubprocessError):
                    if any(item.get('id') == node['id'] and item.get('required') for item in candidates):
                        raise
                    setup_pending.append(node['id'])
            independent = [node for node in confirmed if node['provider'].lower() != config['bridge_provider'].lower()]
            choices = independent or confirmed
            if not choices:
                raise ValueError('no confirmed destination')
            primary = next((node for node in choices if node['id'] == previous.get('primary')), choices[0])
            monitor = {'mode': 'primary', 'node': primary['name'], 'bridge_url': config['bridge_url'], 'payload_url': config['payload_url'],
                       'probe_socks': '127.0.0.1:10818', 'backup_status': '/var/lib/ultra-recovery/last-success.json',
                       'backup_independent': bool(independent), 'token_file': '/etc/ultra-recovery/primary-bot-token',
                       'chat_id': private(config['chat_id_file']).read_text().strip()}
            stage = 'primary_monitor'
            install(config, primary, monitor)
            monitor_ready(config, primary, 'primary', bool(independent))
            key, public = ensure_heartbeat_key(config, primary)
            peer_key_path, key_files = peer_key_pair(key, public)
            peer_pending = list(setup_pending)
            stage = 'peer_monitor'
            for peer in confirmed:
                if peer['id'] == primary['id']:
                    continue
                try:
                    allow_peer(config, primary, peer)
                    peer_config = {'mode': 'peer', 'node': peer['name'], 'peer_host': primary['host'],
                                   'peer_identity_file': peer_key_path, 'peer_known_hosts': '/etc/ultra-recovery/peer_known_hosts',
                                   'token_file': monitor['token_file'], 'chat_id': monitor['chat_id']}
                    peer_files = key_files + [('/etc/ultra-recovery/peer_known_hosts', Path(primary['known_hosts']).read_bytes(), 0o600)]
                    install(config, peer, extra=peer_files)
                    # Validate scoped access before changing the old primary's mode.
                    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                               '-o', 'ConnectTimeout=5', '-o', 'IdentitiesOnly=yes', '-i', peer_key_path,
                               '-o', 'UserKnownHostsFile=/etc/ultra-recovery/peer_known_hosts', primary['host'], 'heartbeat']
                    result = execute(config, peer, command, stdout=subprocess.PIPE, timeout=10)
                    heartbeat = json.loads(result.stdout)
                    if not 0 <= time.time() - heartbeat['updated_at'] <= 120:
                        raise ValueError('peer access not ready')
                    old_monitor = previous_monitor(config, peer)
                    try:
                        install(config, peer, peer_config)
                        monitor_ready(config, peer, 'peer')
                    except (ValueError, subprocess.SubprocessError):
                        if old_monitor:
                            install(config, peer, old_monitor)
                        raise
                except (ValueError, subprocess.SubprocessError):
                    peer_pending.append(peer['id'])
            final_targets = [target(config, node, node['id'] == primary['id']) for node in confirmed]
            final_hosts = {item['host'] for item in final_targets}
            for item in backup['destinations']:
                if item['host'] not in final_hosts and item.get('id') not in retired:
                    retained = dict(item)
                    retained['required'] = False
                    final_targets.append(retained)
            final = {**backup, 'destinations': final_targets, 'independent': bool(independent)}
            if final != backup:
                create(final)
                atomic_json(config['backup_config'], final)
            # Publish independence only after confirmed required delivery.
            state = {'primary': primary['id'], 'nodes': [node['id'] for node in confirmed], 'peer_pending': peer_pending, 'updated_at': int(time.time()), 'topology': fingerprint, 'node_metadata': confirmed}
            atomic_json(directory / 'state.json', state)
            write_status(config, {'state': 'pending' if peer_pending else 'ready', 'updated_at': int(time.time()),
                                              'independent': bool(independent), 'primary': primary['id'], 'peer_pending': peer_pending})
            for old in previous.get('node_metadata', []):
                if old['id'] in retired and old['id'] != primary['id']:
                    try:
                        execute(config, old, ['systemctl', 'disable', '--now', 'ultra-monitor.timer', 'ultra-monitor-probe.service'], stdout=subprocess.DEVNULL, timeout=10)
                    except (ValueError, subprocess.SubprocessError):
                        pass  # Deleted/unreachable VM; archives and prune timer remain.
            return state
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
            write_status(config, {'state': 'error', 'code': 'reconcile_unavailable', 'stage': stage, 'updated_at': int(time.time())})
            raise ValueError('reconciliation unavailable') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        reconcile(read_config(args.config))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('recovery reconciliation unavailable') from None


if __name__ == '__main__':
    main()
