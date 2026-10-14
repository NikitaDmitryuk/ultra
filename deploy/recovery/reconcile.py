#!/usr/bin/env python3
"""Root recovery reconciliation for already-owned, ready exits. No provisioning or migrations."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import stat
import shlex
import shutil
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


# Reconciliation chooses topology; Ansible exclusively applies host configuration.
def compact_completed_attempts(directory, now=None):
    """Bound reconciliation caches; never remove a queued/running attempt."""
    now = time.time() if now is None else now
    complete = []
    for path in directory.glob('attempt-*'):
        if path.is_symlink() or not path.is_dir():
            continue
        try:
            receipt = json.loads(private(path / 'receipt.json').read_text())
            if receipt.get('state') not in ('succeeded', 'failed'):
                continue
            complete.append((receipt.get('finished_at', path.stat().st_mtime), path))
        except (OSError, ValueError, TypeError):
            continue
    complete.sort(reverse=True)
    for finished, path in complete[8:]:
        if not isinstance(finished, (int, float)) or now - finished < 86400:
            continue
        if now - finished > 30 * 86400:
            shutil.rmtree(path)
            continue
        # Preserve only safe receipt/manifest hashes. These attempt IDs are local
        # reconcile retries, never fixed cloud/purchase journal identities.
        for child in path.iterdir():
            if child.name in ('receipt.json', 'job.json', 'diagnostic.json'):
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()


def compact_projected_sources(config, now=None):
    now = time.time() if now is None else now
    root = Path(config['state_dir'])
    sources = root / 'ansible-files'
    if not sources.is_dir() or sources.is_symlink():
        return
    referenced = set()

    def inspect(value):
        if isinstance(value, str) and str(sources) + '/' in value:
            referenced.add(value)
        elif isinstance(value, dict):
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)
    requests = list((root / 'ansible').glob('*/attempt-*/request.json'))
    requests += list((root / 'ansible').glob('*/variables.json'))
    for path in requests:
        try:
            inspect(json.loads(private(path).read_text()))
        except (OSError, ValueError, TypeError):
            return  # An unreadable request may still own its sources; fail safe.
    for source in sources.iterdir():
        if (re.fullmatch(r'[a-f0-9]{64}', source.name) and source.is_file() and not source.is_symlink()
                and str(source) not in referenced and now - source.stat().st_mtime > 86400):
            private(source).unlink()


def ansible_apply(config, node, variables):
    variables = dict(variables, ultra_lock_directory=config.get('controller_state_dir', '/var/lib/ultra-ansible'))
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', node['id']):
        raise ValueError('invalid ansible node identity')
    directory = Path(config['state_dir']) / 'ansible' / node['id']
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    inventory = {'all': {'children': {'recovery_nodes': {'hosts': {'receiver': {
        'ansible_host': node['address'], 'ansible_user': 'root',
        'ansible_ssh_private_key_file': config['ssh_identity_file'],
        'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
        'ansible_ssh_common_args': '-o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile=' + shlex.quote(node['known_hosts']),
    }}}}}}
    atomic_json(directory / 'inventory.json', inventory)
    atomic_json(directory / 'variables.json', variables)
    executable = config.get('installer_binary', '/usr/local/bin/ultra-install')
    result = subprocess.run([executable, 'ansible-run', '--operation', 'reconcile',
                             '--inventory', str(directory / 'inventory.json'),
                             '--variables', str(directory / 'variables.json'),
                             '--state-dir', str(directory / ('attempt-' + str(uuid.uuid4())))],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
    compact_completed_attempts(directory)
    compact_projected_sources(config)
    if result.returncode:
        raise ValueError('ansible_reconcile_failed')


def install(config, node, monitor=None, extra=None):
    base = Path(config['bundle_dir'])
    directory = Path(config['state_dir']) / 'ansible-files'
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    files = []

    def project(destination, source=None, data=None, mode=0o600):
        if data is None:
            source = Path(source)
        else:
            source = directory / hashlib.sha256(data).hexdigest()
            if source.exists() and hashlib.sha256(private(source).read_bytes()).hexdigest() != source.name:
                raise ValueError('projected_source_changed')
            if not source.exists():
                with source.open('xb') as stream:
                    os.chmod(source, 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
        files.append({'destination': destination, 'source': str(source.resolve()), 'mode': format(mode, '04o')})

    for name in ['recovery.py', 'monitor.py', 'heartbeat.py']:
        project('/opt/ultra-recovery/' + name, source=base / name, mode=0o755)
    for name in ['ultra-recovery-prune.service', 'ultra-recovery-prune.timer', 'ultra-monitor.service', 'ultra-monitor.timer', 'ultra-monitor-probe.service']:
        project('/etc/systemd/system/' + name, source=base / name, mode=0o644)
    if monitor:
        project('/usr/local/bin/ultra-client', source=config['client_binary'], mode=0o755)
        project('/etc/ultra-recovery/monitor.json', data=json.dumps(monitor, sort_keys=True).encode())
        project('/etc/ultra-recovery/primary-bot-token', source=private(config['bot_token_file']))
        if monitor['mode'] == 'primary':
            project('/etc/ultra-recovery/probe.json', source=private(config['probe_profile_file']))
    for path, data, mode in extra or []:
        project(path, data=data, mode=mode)
    ansible_apply(config, node, {'ultra_recovery_files': files,
                               'ultra_monitor_mode': monitor['mode'] if monitor else 'none'})


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


def ensure_provider_peer_rule(config, primary, peer, port=22):
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('invalid peer port')
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
    required = {'ip_type': 'v4', 'protocol': 'tcp', 'subnet': address, 'subnet_size': 32, 'port': str(port)}
    if not any(all(rule.get(key) == value for key, value in required.items()) for rule in rules):
        api(config, 'POST', '/v2/firewalls/' + firewall + '/rules', required)
    return address


def allow_peer(config, primary, peer, port=22):
    address = ensure_provider_peer_rule(config, primary, peer, port=port)
    if address is None:
        return
    ansible_apply(config, primary, {'ultra_recovery_peer_rules': [{'address': address, 'port': port}]})


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
    ansible_apply(config, primary, {'ultra_recovery_heartbeat_entry': entry})
    return material, (' '.join(public[:2]) + '\n').encode()


def peer_key_pair(material, public):
    # A versioned path keeps a previous active private/public pair intact during staging.
    path = '/etc/ultra-recovery/peer_ed25519-' + hashlib.sha256(public).hexdigest()
    return path, [(path, material, 0o600), (path + '.pub', public, 0o644)]


def monitor_ready(config, node, mode, independent=False):
    expected = {'us_monitor', 'us_notifications', 'probe_execution'} if mode == 'peer' else {
        'bridge_https', 'vpn_payload', 'probe_execution', 'independent_backup' if independent else 'backup_generation'}
    for _ in range(2):
        ansible_apply(config, node, {'ultra_monitor_run_once': True})
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



def refresh_monitor_profile(config):
    # Only provisioned installations opt in; legacy manually managed profiles
    # remain compatible until adopted by the full installer.
    spec = config.get('monitor_spec_file')
    if not spec:
        return
    cloud_private_file(spec, 'ultra-relay')
    targets = config.get('monitor_targets', [config['payload_url']])
    if not isinstance(targets, list) or not targets or any(not isinstance(t, str) or ',' in t for t in targets):
        raise ValueError('invalid monitor targets')
    result = subprocess.run(['/usr/local/bin/ultra-relay', '-ensure-monitor-access', '-spec', spec,
                    '-monitor-profile-output', config['probe_profile_file'],
                    '-monitor-targets', ','.join(targets)], check=True, timeout=65,
                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if len(result.stdout) > 1024:
        raise ValueError('monitor status exceeds bounds')
    status = json.loads(result.stdout)
    if status.get('monitor_access') != 'ready' or type(status.get('quota_available')) is not bool:
        raise ValueError('invalid monitor access status')
    return status['quota_available']


def reconcile(config):
    directory = Path(config['state_dir'])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError('private state directory required')
    with open(directory / 'reconcile.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            stage = 'monitor_profile'
            monitor_quota = refresh_monitor_profile(config)
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
            if monitor_quota is not None:
                monitor['service_quota_available'] = monitor_quota
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
                        ansible_apply(config, old, {'ultra_monitor_retire': True})
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
