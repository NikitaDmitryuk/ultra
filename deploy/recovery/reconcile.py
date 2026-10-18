#!/usr/bin/env python3
"""Root recovery reconciliation for already-owned, ready exits. No provisioning or migrations."""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import stat
import shlex
import shutil
import signal
import grp
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from recovery import atomic_json, create, digest, private, read_config, ssh
import recovery
import db_connection

# Leave time to cancel the controller and publish status before systemd's 540s
# deadline. Lifecycle lock acquisition allows 600s, including its retry margin.
RECONCILE_BUDGET_SECONDS = 480
ANSIBLE_TIMEOUT_SECONDS = 450
CHILD_STOP_SECONDS = 10
_deferring_budget = False
_budget_expired = False
_budget_deadline = None


class ReconcileBlocked(Exception):
    def __init__(self, code, attempt=None):
        self.code, self.attempt = code, attempt
        super().__init__(code)


@contextlib.contextmanager
def reconcile_budget():
    global _budget_expired, _budget_deadline
    _budget_expired = False
    _budget_deadline = time.monotonic() + RECONCILE_BUDGET_SECONDS
    def expired(_signum, _frame):
        global _budget_expired
        if _deferring_budget:
            # Never raise inside Popen launch or subprocess.run cleanup. Native
            # run timeouts use the remaining budget and reap their child first.
            _budget_expired = True
            return
        raise ReconcileBlocked('reconcile_budget_exhausted')
    previous = signal.signal(signal.SIGALRM, expired)
    previous_recovery_run = recovery.run
    # create() and ssh() resolve this module function for pg_dump, age and SSH.
    # The oneshot service is single threaded; restore it for library callers.
    recovery.run = recovery_command
    signal.setitimer(signal.ITIMER_REAL, RECONCILE_BUDGET_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        recovery.run = previous_recovery_run
        _budget_expired = False
        _budget_deadline = None


def run_command(arguments, **kwargs):
    """Let subprocess.run finish bounded native cleanup before budget errors."""
    global _deferring_budget
    deadline = _budget_deadline
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or _budget_expired:
            raise ReconcileBlocked('reconcile_budget_exhausted')
        kwargs['timeout'] = min(kwargs.get('timeout', remaining), remaining)
    previous = _deferring_budget
    _deferring_budget = True
    try:
        return subprocess.run(arguments, **kwargs)
    finally:
        _deferring_budget = previous
        if deadline is not None and (_budget_expired or time.monotonic() >= deadline):
            raise ReconcileBlocked('reconcile_budget_exhausted')


def recovery_command(arguments, **kwargs):
    result = run_command(arguments, stderr=subprocess.DEVNULL,
                         timeout=kwargs.pop('timeout', 60), **kwargs)
    if result.returncode:
        raise ValueError('recovery command failed')
    return result

QUERY = """BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT COALESCE(json_agg(json_build_object('id',c.id::text,'state',c.state,
 'phase',c.body->>'phase','instance_id',c.body->>'instance_id','firewall_id',c.body->>'firewall_id',
 'exit_id',c.body->>'exit_id','address',n.address,'enabled',COALESCE(n.enabled,false),
 'country',n.country_code,'tunnel_port',n.port)), '[]'::json)
FROM cloud_operations c LEFT JOIN exit_nodes n ON n.id::text=c.body->>'exit_id'
WHERE c.state IN ('ready','deleted','cancelled');
COMMIT;"""


EXIT_PORT_QUERY = """BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT COALESCE(json_agg(json_build_object('id',id::text,'address',address,'port',port)),'[]'::json) FROM exit_nodes WHERE enabled=true;
COMMIT;"""


def discover(config, query=QUERY):
    database = config['database']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
        raise ValueError('invalid database')
    try:
        dsn = db_connection.dsn_from_runtime(database)
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError('discovery unavailable') from None
    with tempfile.TemporaryDirectory(prefix='ultra-db-discovery-') as directory:
        with db_connection.pgpass(directory, dsn) as environment:
            result = run_command(db_connection.connection_args(dsn, database, 'psql') +
                                    ['-XAtq', '-v', 'ON_ERROR_STOP=1', '-c', query],
                                    capture_output=True, timeout=8, env=environment)
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
    # An interrupted full pass still needs the exact earlier request evidence.
    if (directory.parent.parent / 'reconcile-progress.json').exists():
        return

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


def write_reconcile_progress(journal):
    atomic_json(journal['path'], {'calls': journal['calls'], 'baseline': journal['baseline'],
                                 'health_start': journal.get('health_start')})


def ansible_apply(config, node, variables):
    global _deferring_budget
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
    # Do not abandon an interrupted controller, even if the desired inputs have
    # changed. RunLocal resumes only an identical immutable request. A conflicting
    # unfinished job needs explicit resolution before new work may be dispatched.
    request = {'inventory': inventory, 'variables': variables}
    journal = config.get('_reconcile_journal')
    entry = None
    if journal is not None and journal['cursor'] < len(journal['calls']):
        entry = journal['calls'][journal['cursor']]
        if entry.get('node') != node['id'] or entry.get('request') != request:
            raise ReconcileBlocked('ansible_pending_conflict', entry.get('attempt'))
        journal['cursor'] += 1
        attempt = directory / entry['attempt']
        if attempt.is_symlink():
            raise ReconcileBlocked('ansible_attempt_unavailable', attempt.name)
        receipt = {}
        if attempt.exists():
            try:
                saved = read_config(private(attempt / 'request.json'))
                job = read_config(private(attempt / 'job.json'))
                receipt = read_config(private(attempt / 'receipt.json')) if (attempt / 'receipt.json').exists() else {}
                if saved != request or job.get('operation') != 'reconcile':
                    raise ReconcileBlocked('ansible_pending_conflict', attempt.name)
            except (OSError, ValueError, TypeError):
                raise ReconcileBlocked('ansible_receipt_unavailable', attempt.name) from None
        if receipt.get('state') == 'succeeded':
            return False  # Replayed evidence cannot establish fresh health.
        if receipt.get('state') == 'failed':
            # A failed final call is terminal and safe to retry with a new
            # attempt; earlier failed optional calls must replay their branch.
            if journal['cursor'] != len(journal['calls']):
                raise ValueError('ansible_reconcile_failed')
            journal['calls'].pop()
            journal['cursor'] -= 1
            write_reconcile_progress(journal)
            entry = None

    unfinished = []
    for path in directory.glob('attempt-*'):
        if path.is_symlink() or not path.is_dir():
            raise ReconcileBlocked('ansible_attempt_unavailable', path.name)
        try:
            receipt = read_config(private(path / 'receipt.json')) if (path / 'receipt.json').exists() else {}
            if receipt.get('state') in ('succeeded', 'failed'):
                continue
            saved = read_config(private(path / 'request.json'))
            job = read_config(private(path / 'job.json'))
            if saved != request or job.get('operation') != 'reconcile':
                raise ReconcileBlocked('ansible_pending_conflict', path.name)
            unfinished.append(path)
        except (OSError, ValueError, TypeError):
            raise ReconcileBlocked('ansible_receipt_unavailable', path.name) from None
    if len(unfinished) > 1:
        raise ReconcileBlocked('ansible_multiple_pending')
    attempt = unfinished[0] if unfinished else directory / (entry['attempt'] if entry else 'attempt-' + str(uuid.uuid4()))
    if entry is not None and attempt.name != entry['attempt']:
        raise ReconcileBlocked('ansible_pending_conflict', entry['attempt'])
    if journal is not None and entry is None:
        journal['calls'].append({'node': node['id'], 'request': request, 'attempt': attempt.name})
        write_reconcile_progress(journal)
        journal['cursor'] += 1

    atomic_json(directory / 'inventory.json', inventory)
    atomic_json(directory / 'variables.json', variables)
    executable = config.get('installer_binary', '/usr/local/bin/ultra-install')
    process = None
    _deferring_budget = True
    try:
        process = subprocess.Popen([executable, 'ansible-run', '--operation', 'reconcile',
                             '--inventory', str(directory / 'inventory.json'),
                             '--variables', str(directory / 'variables.json'),
                             '--state-dir', str(attempt)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _deferring_budget = False
        if _budget_expired:
            raise ReconcileBlocked('reconcile_budget_exhausted', attempt.name)
        returncode = process.wait(timeout=ANSIBLE_TIMEOUT_SECONDS)
    except BaseException as error:
        _deferring_budget = False
        if process is None:
            raise
        # Once aborting the run, finish the bounded cleanup uninterrupted. The
        # service retains at least 60s after the run budget for these two waits.
        if isinstance(error, (ReconcileBlocked, subprocess.TimeoutExpired)):
            signal.setitimer(signal.ITIMER_REAL, 0)
        # SIGTERM lets ultra-install cancel its isolated controller, which kills
        # the Ansible session and persists an interrupted receipt before exiting.
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=CHILD_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=CHILD_STOP_SECONDS)
            except subprocess.TimeoutExpired:
                raise ReconcileBlocked('ansible_cancel_timeout', attempt.name) from None
        if isinstance(error, subprocess.TimeoutExpired):
            raise ReconcileBlocked('ansible_child_timeout', attempt.name) from None
        if isinstance(error, ReconcileBlocked):
            error.attempt = attempt.name
        raise
    compact_completed_attempts(directory)
    compact_projected_sources(config)
    try:
        receipt = read_config(private(attempt / 'receipt.json'))
    except (OSError, ValueError, TypeError):
        raise ReconcileBlocked('ansible_receipt_unavailable', attempt.name) from None
    if receipt.get('state') not in ('succeeded', 'failed'):
        raise ReconcileBlocked('ansible_attempt_pending', attempt.name)
    if returncode or receipt['state'] != 'succeeded':
        # Safe correlation survives optional-receiver fallback; raw Ansible
        # output and private inputs never enter the published controller status.
        code = receipt.get('code')
        atomic_json(directory / 'last-failure.json', {
            'attempt': attempt.name, 'reason_code': 'ansible_receipt_failed',
            'receipt_code': code if code in ('ansible_failed', 'execution_failed', 'interrupted') else 'unavailable',
            'updated_at': int(time.time())})
        raise ValueError('ansible_reconcile_failed')
    return True


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

    for name in ['recovery.py', 'db_connection.py', 'monitor.py', 'heartbeat.py']:
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


def admit_restored_bridge(config, address):
    """Restore bridge admission to pinned exits; never reseed PostgreSQL."""
    address = str(ipaddress.IPv4Address(address))
    rows = discover(config)
    ready = any(row.get('state') == 'ready' and row.get('phase') == 'ready' and row.get('enabled') for row in rows)
    if not ready and not config.get('static_nodes'):
        return {'verified': True, 'managed_exits': 0, 'static_exits': 0}
    nodes, _ = desired_nodes(config, rows)
    exit_rows = discover(config, EXIT_PORT_QUERY)
    enabled = {}
    exit_ids = set()
    for row in exit_rows:
        host = str(ipaddress.IPv4Address(row['address']))
        port = row.get('port')
        if host in enabled or row['id'] in exit_ids or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('restored_exit_tunnel_port_unavailable')
        enabled[host] = (row['id'], port)
        exit_ids.add(row['id'])
    ports = {}
    # Validate all ports, identities and pins before the first mutation.
    for node in nodes:
        persisted = enabled.get(node['address'])
        if persisted is None or persisted[0] != node['id'] or node['address'] == address:
            raise ValueError('restored_exit_tunnel_port_unavailable')
        port = persisted[1]
        if node.get('managed'):
            cloud = next(row for row in rows if row['id'] == node['id'])
            if cloud.get('tunnel_port') != port:
                raise ValueError('restored_exit_tunnel_port_unavailable')
        ports[node['id']] = sorted({22, port})
    cloud_private_file(config['ssh_identity_file'], config.get('ssh_identity_owner', 'ultra-relay'))
    for node in nodes:
        # Provider changes require proven resource ownership; static provider
        # admission remains an explicit operator prerequisite.
        if node.get('managed'):
            for port in ports[node['id']]:
                ensure_provider_peer_rule(config, node, {'address': address}, port)
        try:
            ansible_apply(config, node, {'ultra_recovery_peer_rules': [
                {'address': address, 'port': port} for port in ports[node['id']]]})
        except (OSError, ValueError, subprocess.SubprocessError):
            if not node.get('managed'):
                raise ValueError('static_exit_firewall_operator_admission_required') from None
            raise
    managed = sum(bool(node.get('managed')) for node in nodes)
    return {'verified': True, 'managed_exits': managed, 'static_exits': len(nodes) - managed}


def allow_peer(config, primary, peer, port=22):
    address = ensure_provider_peer_rule(config, primary, peer, port=port)
    if address is None:
        return
    ansible_apply(config, primary, {'ultra_recovery_peer_rules': [{'address': address, 'port': port}]})


def ensure_heartbeat_key(config, primary):
    directory = Path(config['state_dir'])
    key = directory / 'heartbeat_ed25519'
    if not key.exists():
        run_command(['ssh-keygen', '-t', 'ed25519', '-N', '', '-q', '-f', str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    material = private(key).read_bytes()
    derived = run_command(['ssh-keygen', '-y', '-f', str(key)], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
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
    journal = config.get('_reconcile_journal')
    if (journal is not None and journal.get('deferred_monitors')
            and (journal['cursor'] == len(journal['calls']) or
                 journal.get('health_start') is not None and journal['cursor'] >= journal['health_start'])
            and not journal.get('refreshing_health')):
        journal['deferred_monitors'].append((node, mode, independent))
        return
    expected = {'us_monitor', 'us_notifications', 'probe_execution'} if mode == 'peer' else {
        'bridge_https', 'vpn_payload', 'probe_execution', 'independent_backup' if independent else 'backup_generation'}
    replayed = False
    for _ in range(2):
        replayed = ansible_apply(config, node, {'ultra_monitor_run_once': True}) is False or replayed
        if replayed:
            # Traverse the saved call sequence to its late pending attempt.
            # Refresh both samples after traversal; old receipts prove execution
            # but cannot prove that the current heartbeat is healthy or fresh.
            continue
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
    if replayed:
        config['_reconcile_journal'].setdefault('deferred_monitors', []).append((node, mode, independent))
        return
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


def verify_peer_access(config, peer, command):
    result = execute(config, peer, command, stdout=subprocess.PIPE, timeout=10)
    heartbeat = json.loads(result.stdout)
    if not 0 <= time.time() - heartbeat['updated_at'] <= 120:
        raise ValueError('peer access not ready')


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
    result = run_command(['/usr/local/bin/ultra-relay', '-ensure-monitor-access', '-spec', spec,
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
    with open(directory / 'reconcile.lock', 'a') as lock, reconcile_budget():
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            stage = 'resume'
            # Keep progress outside immutable Ansible attempts. Replaying the
            # identical earlier calls reaches a late interrupted request without
            # dispatching receiver work over that pending controller.
            config = dict(config)
            progress = directory / 'reconcile-progress.json'
            saved_progress = read_config(private(progress)) if progress.exists() else {'calls': []}
            if not isinstance(saved_progress, dict):
                raise ReconcileBlocked('ansible_progress_unavailable')
            calls = saved_progress.get('calls')
            if not isinstance(calls, list) or any(
                    not isinstance(call, dict) or not isinstance(call.get('request'), dict)
                    or not isinstance(call.get('node'), str)
                    or not isinstance(call.get('attempt'), str)
                    or not re.fullmatch(r'attempt-[A-Za-z0-9-]{1,64}', call['attempt'])
                    for call in calls):
                raise ReconcileBlocked('ansible_progress_unavailable')
            # Inspect every node before any controller dispatch, even when a
            # legacy interrupted attempt has no progress journal to replay.
            pending_nodes = set()
            for attempt in (directory / 'ansible').glob('*/attempt-*'):
                if attempt.is_symlink() or not attempt.is_dir():
                    raise ReconcileBlocked('ansible_attempt_unavailable', attempt.name)
                receipt = read_config(private(attempt / 'receipt.json')) if (attempt / 'receipt.json').exists() else {}
                if receipt.get('state') in ('succeeded', 'failed'):
                    continue
                matching = [call for call in calls if call['node'] == attempt.parent.name and call['attempt'] == attempt.name]
                if len(matching) != 1 or read_config(private(attempt / 'request.json')) != matching[0]['request'] or read_config(private(attempt / 'job.json')).get('operation') != 'reconcile':
                    raise ReconcileBlocked('ansible_pending_conflict', attempt.name)
                if attempt.parent.name in pending_nodes:
                    raise ReconcileBlocked('ansible_multiple_pending')
                pending_nodes.add(attempt.parent.name)
            journal = {'path': progress, 'calls': calls, 'cursor': 0,
                       'baseline': saved_progress.get('baseline'), 'health_start': saved_progress.get('health_start')}
            if journal['health_start'] is not None and (type(journal['health_start']) is not int or not 0 <= journal['health_start'] <= len(calls)):
                raise ReconcileBlocked('ansible_progress_unavailable')
            config['_reconcile_journal'] = journal

            stage = 'monitor_profile'
            monitor_quota = refresh_monitor_profile(config)
            stage = 'discover'
            cloud_private_file(config['ssh_identity_file'], config.get('ssh_identity_owner', 'ultra-relay'))
            rows = discover(config)  # No DB failure may be interpreted as an empty topology.
            nodes, retired = desired_nodes(config, rows)
            previous = read_config(directory / 'state.json') if (directory / 'state.json').exists() else {}
            backup = read_config(config['backup_config'])
            if journal['baseline'] is None:
                journal['baseline'] = {'previous': previous, 'backup': backup}
            else:
                baseline = journal['baseline']
                if not isinstance(baseline, dict) or not isinstance(baseline.get('previous'), dict) or not isinstance(baseline.get('backup'), dict):
                    raise ReconcileBlocked('ansible_progress_unavailable')
                if backup != baseline['backup'] and backup != baseline.get('published_backup'):
                    raise ReconcileBlocked('ansible_pending_conflict')
                previous, backup = baseline['previous'], baseline['backup']
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
                    if journal.get('deferred_monitors') and journal['cursor'] < len(journal['calls']):
                        journal.setdefault('deferred_peer_access', []).append((peer, command))
                    else:
                        verify_peer_access(config, peer, command)
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
            for old in previous.get('node_metadata', []):
                if old['id'] in retired and old['id'] != primary['id']:
                    try:
                        ansible_apply(config, old, {'ultra_monitor_retire': True})
                    except (ValueError, subprocess.SubprocessError):
                        pass  # Deleted/unreachable VM; archives and prune timer remain.
            journal = config['_reconcile_journal']
            deferred = journal.setdefault('deferred_monitors', [])
            if deferred and journal.get('health_start') is None:
                journal['health_start'] = journal['cursor']
                write_reconcile_progress(journal)
            journal['refreshing_health'] = True
            try:
                while deferred:
                    node, mode, required_independence = deferred.pop(0)
                    monitor_ready(config, node, mode, required_independence)
            finally:
                journal['refreshing_health'] = False
            for peer, command in journal.get('deferred_peer_access', []):
                verify_peer_access(config, peer, command)
            if journal['cursor'] != len(journal['calls']):
                raise ReconcileBlocked('ansible_pending_conflict')
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
                journal['baseline']['published_backup'] = final
                write_reconcile_progress(journal)
                atomic_json(config['backup_config'], final)
            # Publish independence only after confirmed required delivery.
            state = {'primary': primary['id'], 'nodes': [node['id'] for node in confirmed], 'peer_pending': peer_pending, 'updated_at': int(time.time()), 'topology': fingerprint, 'node_metadata': confirmed}
            atomic_json(directory / 'state.json', state)
            write_status(config, {'state': 'pending' if peer_pending else 'ready', 'updated_at': int(time.time()),
                                              'independent': bool(independent), 'primary': primary['id'], 'peer_pending': peer_pending})
            progress.unlink(missing_ok=True)
            for attempts in (directory / 'ansible').glob('*'):
                compact_completed_attempts(attempts)
            compact_projected_sources(config)

            return state
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, ReconcileBlocked) as error:
            status = {'state': 'error', 'code': 'reconcile_unavailable', 'stage': stage, 'updated_at': int(time.time())}
            if isinstance(error, ReconcileBlocked):
                status['reason_code'] = error.code
                if error.attempt and re.fullmatch(r'attempt-[A-Za-z0-9-]{1,64}', error.attempt):
                    status['attempt'] = error.attempt
            write_status(config, status)
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
