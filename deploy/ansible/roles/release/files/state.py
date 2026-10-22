#!/usr/bin/python3
"""Read-only application preflight; infrastructure changes belong to playbooks."""
import argparse
import base64
import importlib.util
import platform
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


def read(path):
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 1024 * 1024:
        raise ValueError('state_unavailable')
    return json.loads(source.read_text())


def recovery_installation_reason(root=Path('/')):
    """Classify installation without reading private recovery configuration."""
    names = ('opt/ultra-recovery/release-manifest.json',
             'opt/ultra-recovery/recovery.py', 'opt/ultra-recovery/reconcile.py',
             'etc/ultra-recovery/backup.json', 'etc/ultra-recovery/reconcile.json')
    paths = [root / name for name in names]
    if not any(path.exists() or path.is_symlink() for path in paths):
        return 'recovery_not_installed'
    if not all(path.is_file() and not path.is_symlink() for path in paths):
        return 'recovery_installation_incomplete'
    return None


def database_query(database, query):
    sys.path.insert(0, '/opt/ultra-recovery')
    import db_connection
    parsed = db_connection.dsn_from_runtime(database)
    with db_connection.pgpass('/var/lib/ultra-recovery', parsed) as environment:
        return subprocess.run(db_connection.connection_args(parsed, database, 'psql') + ['-XAtq', '-v', 'ON_ERROR_STOP=1', '-c', query],
                              env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=8)


def runtime_node_proofs(database, nodes):
    """Bind only public tunnel digests to the already inspected DB topology."""
    query = "SELECT COALESCE(json_agg(json_build_object('id',id::text,'address',address,'tunnel_uuid',tunnel_uuid,'pin',pinned_peer_cert_sha256,'enabled',enabled)), '[]'::json) FROM exit_nodes"
    result = database_query(database, query)
    if len(result.stdout) > 65536:
        raise ValueError('runtime_identity_unavailable')
    rows = json.loads(result.stdout)
    if not isinstance(rows, list):
        raise ValueError('runtime_topology_changed')
    indexed = {row['id']: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError('runtime_topology_changed')
    node_ids = {node['id'] for node in nodes}
    if any(row.get('enabled') is True and row['id'] not in node_ids for row in rows):
        raise ValueError('runtime_topology_changed')
    for node in nodes:
        row = indexed.get(node['id'], {})
        if not row or (node.get('managed') and row.get('enabled') is not True):
            raise ValueError('runtime_topology_changed')
        tunnel = row.get('tunnel_uuid', '')
        pin = row.get('pin', '')
        if (row.get('address') != node['address'] or not re.fullmatch(r'[0-9a-fA-F-]{36}', tunnel)
                or (pin and not re.fullmatch(r'[a-f0-9]{64}', pin))):
            raise ValueError('runtime_identity_unavailable')
        node['tunnel_identity_digest'] = hashlib.sha256(tunnel.encode()).hexdigest()
        node['certificate_pin'] = pin


def active_relay_sha256():
    """Bind maintenance to the exact bridge process observed during preflight."""
    result = subprocess.run(['systemctl', 'show', 'ultra-relay.service',
                             '--property=ActiveState', '--property=MainPID', '--property=ControlPID'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=8).stdout.decode().splitlines()
    fields = dict(line.split('=', 1) for line in result if '=' in line)
    pid = fields.get('MainPID', '')
    binary = Path('/usr/local/bin/ultra-relay')
    executable = Path('/proc') / pid / 'exe'
    metadata = binary.lstat() if binary.exists() else None
    if (fields.get('ActiveState') != 'active' or not pid.isdigit() or pid == '0'
            or fields.get('ControlPID') != '0' or metadata is None
            or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0 or metadata.st_mode & 0o022
            or executable.resolve() != binary):
        raise ValueError('active_relay_identity_unavailable')
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    process_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    if binary_hash != process_hash:
        raise ValueError('active_relay_identity_changed')
    return process_hash


def readiness(now=None):
    """Read only public recovery evidence; no discovery, DB, or credentials."""
    now = time.time() if now is None else now
    controller = read('/var/lib/ultra-relay/recovery-reconcile-status.json')
    backup = read('/var/lib/ultra-recovery/last-success.json')
    if not (controller.get('state') == 'ready' and controller.get('independent') is True
            and 0 <= now - controller['updated_at'] <= 180 and 0 <= now - backup['snapshot_at'] <= 300):
        raise ValueError('fresh_independent_backup_required')
    return controller, backup


def applying_reservation(operation, pending=False, journal=Path('/var/lib/ultra-ansible/lifecycle.json')):
    """Observe only the broker's protected journal; never reserve or attach a lease."""
    if not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', operation):
        raise ValueError('invalid_readiness_lifecycle_id')
    try:
        # O_NOFOLLOW and fstat bind permissions and contents to the same file.
        descriptor = os.open(journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if pending:
            raise ValueError('upgrade_readiness_reservation_ambiguous')
        return False
    with os.fdopen(descriptor) as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o077 or metadata.st_size > 4096):
            raise ValueError('upgrade_readiness_reservation_unverified')
        value = json.loads(source.read(4097))
    if (not isinstance(value, dict) or set(value) != {'id', 'phase'}
            or not isinstance(value['id'], str)
            or not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', value['id'])
            or value['phase'] not in ('applying', 'checking', 'released')):
        raise ValueError('upgrade_readiness_reservation_unverified')
    if value == {'id': operation, 'phase': 'applying'}:
        return True
    if pending or value['phase'] != 'released':
        raise ValueError('upgrade_readiness_reservation_ambiguous')
    return False


def wait_readiness(timeout=600, interval=10, monotonic=time.monotonic, sleep=time.sleep,
                   operation=None, pending=False):
    deadline = monotonic() + timeout
    while True:
        if operation and applying_reservation(operation, pending):
            return {'verified': True, 'reservation_id': operation, 'reservation_phase': 'applying'}
        try:
            readiness()
            return {'verified': True, 'ready': True}
        except ValueError as failure:
            if str(failure) != 'fresh_independent_backup_required':
                raise
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ValueError('fresh_independent_backup_required')
        sleep(min(interval, remaining))


def prepared_suspension(encoded, include_tools=False):
    """An authenticated prepared pause changes only schedule availability.

    Fresh independent receipts and every runtime/schema/topology check still run.
    The shared enforcement validator reopens no origin and checks the actual
    candidate broker and exact same-unit protected operation independently.
    """
    if not encoded:
        return (False, {}) if include_tools else False
    try:
        p = json.loads(base64.b64decode(encoded, validate=True))
        policy = p['prepared_policy']
        sha = policy['manifest_sha256']
        if not re.fullmatch('[a-f0-9]{64}', sha):
            raise ValueError('prepared_suspension_unverified')
        identity = read('/etc/ultra-recovery/recovery-tools.json')
        snapshot = Path('/opt/ultra-ansible/recovery-tools') / sha
        if identity.get('tools_manifest_sha256') != sha or identity.get('snapshot_directory') != str(snapshot):
            raise ValueError('prepared_suspension_unverified')
        path = snapshot / 'controller-enforcement.py'
        raw = path.read_bytes()
        if (path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022
                or hashlib.sha256(raw).hexdigest() != identity['inventory']['controller-enforcement.py']):
            raise ValueError('prepared_suspension_unverified')
        spec = importlib.util.spec_from_file_location('prepared_enforcement', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        arch = {'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
        p['candidate'] = p['candidates'][arch]['identity']
        if not module.prepared_policy(p):
            raise ValueError('prepared_suspension_unverified')
        tools = module.prepared_tools_inventory(json.loads(module.regular(Path('/var/lib/ultra-ansible/deploy-operations') / policy['envelope_sha256'] / 'request.json', True))['preparation'], policy['preparation_sha256'])
        if module.prepared_schedules_restored(request=json.loads(module.regular(Path('/var/lib/ultra-ansible/deploy-operations') / policy['envelope_sha256'] / 'request.json', True))['preparation'], preparation_sha=policy['preparation_sha256']):
            return (False, tools) if include_tools else False
        suspension = json.loads(module.regular('/etc/ultra-recovery/preparation-suspension.json', True))
        if (suspension.get('protocol') != 'ultra-recovery-preparation-suspension-v1'
                or suspension.get('request_sha256') != policy['preparation_sha256']
                or suspension.get('tools_manifest_sha256') != sha or not suspension.get('active_inventory')):
            raise ValueError('prepared_suspension_unverified')
        for path, checksum in suspension['active_inventory'].items():
            if not path.startswith(('/opt/ultra-recovery/','/etc/systemd/system/')) or hashlib.sha256(module.regular(path)).hexdigest() != checksum:
                raise ValueError('prepared_suspension_unverified')
        for unit in ('ultra-recovery-backup.timer','ultra-recovery-reconcile.timer'):
            observed = subprocess.run(['systemctl','show','--property=ActiveState','--property=UnitFileState',unit], check=True, stdout=subprocess.PIPE, timeout=10).stdout.decode().splitlines()
            values = dict(line.split('=',1) for line in observed if '=' in line)
            if values.get('ActiveState') != 'inactive' or values.get('UnitFileState') != 'disabled':
                raise ValueError('prepared_suspension_unverified')
        return (True, tools) if include_tools else True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise ValueError('prepared_suspension_unverified') from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--prepared-policy')
    parser.add_argument('--wait-readiness', action='store_true')
    parser.add_argument('--lifecycle-id')
    parser.add_argument('--reservation-pending', action='store_true')
    parser.add_argument('--expected')
    parser.add_argument('--not-before', type=int)
    args = parser.parse_args()
    suspended, prepared_hashes = prepared_suspension(args.prepared_policy, include_tools=True)
    if args.wait_readiness:
        if args.status or args.expected or args.not_before is not None:
            raise ValueError('invalid_readiness_probe_arguments')
        if not args.lifecycle_id:
            raise ValueError('invalid_readiness_lifecycle_id')
        print(json.dumps(wait_readiness(operation=args.lifecycle_id, pending=args.reservation_pending)))
        return
    if args.lifecycle_id or args.reservation_pending:
        raise ValueError('invalid_readiness_probe_arguments')
    if args.status:
        reason = recovery_installation_reason()
        if reason:
            raise ValueError(reason)
    sys.path.insert(0, '/opt/ultra-recovery')
    import reconcile
    config = read('/etc/ultra-recovery/reconcile.json')
    nodes, _ = reconcile.desired_nodes(config, reconcile.discover(config))
    topology = [{'id': n['id'], 'address': n['address'], 'known_hosts': n['known_hosts']} for n in nodes]
    digest = hashlib.sha256(json.dumps(topology, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if args.expected:
        if digest != args.expected:
            raise ValueError('topology_changed')
        if args.not_before is None:
            print('{}')
            return
    now = time.time()
    controller, backup = readiness(now)
    if args.not_before is not None and (controller['updated_at'] <= args.not_before or backup['snapshot_at'] <= args.not_before):
        raise ValueError('post_activation_evidence_required')
    database = config['database']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
        raise ValueError('database_invalid')
    schema_evidence = database_query(database, "SELECT COALESCE(max(version),0)::text || ':' || count(*)::text FROM schema_migrations").stdout.decode().strip()
    schema_max, schema_count = map(int, schema_evidence.split(':'))
    if schema_max <= 0 or schema_max != schema_count:
        raise ValueError('partial_database_schema')
    for unit in (() if suspended else ('ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer')):
        subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if args.status:
        manifest = read('/opt/ultra-recovery/release-manifest.json')
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', manifest['version']):
            raise ValueError('previous_version_invalid')
        print(json.dumps({'ready': True, 'independent': True, 'version': manifest['version'],
                          'backup_age_seconds': int(now - backup['snapshot_at']),
                          'controller_age_seconds': int(now - controller['updated_at']),
                          'replicas_ready': True, 'reasons': []}))
        return
    runtime_node_proofs(database, nodes)
    for node in nodes:
        pin = Path(node['known_hosts'])
        if pin.is_symlink() or pin.stat().st_mode & 0o022 or not 0 < pin.stat().st_size <= 65536:
            raise ValueError('pins_invalid')
        node['pins'] = pin.read_text()
    identity = Path(config['ssh_identity_file'])
    if identity.is_symlink() or identity.stat().st_mode & 0o077 or not 0 < identity.stat().st_size <= 65536:
        raise ValueError('identity_invalid')
    architecture = subprocess.run(['dpkg', '--print-architecture'], check=True, stdout=subprocess.PIPE, timeout=5).stdout.decode().strip()
    previous = read('/opt/ultra-recovery/release-manifest.json')
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', previous['version']):
        raise ValueError('previous_version_invalid')
    prior_directory = Path('/opt/ultra-recovery/releases') / previous['version']
    tool_hashes = {}
    if prior_directory.is_dir():
        for source in prior_directory.iterdir():
            if source.is_file() and not source.is_symlink() and source.stat().st_size <= 4 * 1024 * 1024:
                tool_hashes[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
    tool_identity = {}
    if Path('/opt/ultra-recovery/tools-inventory.json').exists():
        import live_tools
        live = live_tools.verify()
        tool_hashes = live['members']
        tool_identity = live_tools.identity_hashes()
    if prepared_hashes:
        if any(tool_hashes.get(name) != checksum for name, checksum in prepared_hashes.items()):
            raise ValueError('prepared_tools_predecessor_changed')
        tool_hashes = prepared_hashes
    controller_directory = str(Path('/opt/ultra-ansible/current').resolve())
    if not re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}', controller_directory):
        raise ValueError('adopted_controller_required')
    controller_unit = Path('/etc/systemd/system/ultra-ansible-controller.service')
    if controller_unit.is_symlink() or not controller_unit.is_file():
        raise ValueError('controller_unit_invalid')
    controller_unit_hash = hashlib.sha256(controller_unit.read_bytes()).hexdigest()
    auto_policy = read('/etc/ultra-ansible/auto-upgrade.json') if Path('/etc/ultra-ansible/auto-upgrade.json').exists() else {'enabled': False}
    print(json.dumps({'nodes': nodes, 'runtime_nodes': {n['id']: {k: n.get(k) for k in ('name', 'managed', 'tunnel_identity_digest', 'certificate_pin')} for n in nodes}, 'topology_sha256': digest, 'architecture': architecture, 'observed_at': int(now), 'database_schema': schema_max, 'active_relay_sha256': active_relay_sha256(),
                      'identity': identity.read_text(), 'previous_manifest': previous, 'previous_manifest_sha256': hashlib.sha256(Path('/opt/ultra-recovery/release-manifest.json').read_bytes()).hexdigest(), 'tool_hashes': tool_hashes, 'tool_identity_hashes': tool_identity, 'auto_policy': auto_policy, 'controller_directory': controller_directory, 'controller_unit_sha256': controller_unit_hash}))


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        if '--status' in sys.argv:
            allowed = {'state_unavailable', 'fresh_independent_backup_required', 'replica_not_ready',
                       'recovery_not_installed', 'recovery_installation_incomplete',
                       'partial_database_schema', 'database_invalid', 'previous_version_invalid'}
            reason = str(failure) if isinstance(failure, ValueError) and str(failure) in allowed else 'readiness_evidence_unavailable'
            print(json.dumps({'ready': False, 'independent': False, 'reasons': [reason]}))
        else:
            print('release_preflight_failed', file=sys.stderr)
            raise SystemExit(1)
