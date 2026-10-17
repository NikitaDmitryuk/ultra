#!/usr/bin/python3
"""Read-only application preflight; infrastructure changes belong to playbooks."""
import argparse
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


def database_query(database, query):
    sys.path.insert(0, '/opt/ultra-recovery')
    import db_connection
    parsed = db_connection.dsn_from_runtime(database)
    with db_connection.pgpass('/var/lib/ultra-recovery', parsed) as environment:
        return subprocess.run(db_connection.connection_args(parsed, database, 'psql') + ['-XAtq', '-v', 'ON_ERROR_STOP=1', '-c', query],
                              env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=8)


def runtime_node_proofs(database, nodes):
    """Bind only public tunnel digests to the already inspected DB topology."""
    query = "SELECT COALESCE(json_agg(json_build_object('id',id::text,'address',address,'tunnel_uuid',tunnel_uuid,'pin',pinned_peer_cert_sha256)), '[]'::json) FROM exit_nodes WHERE enabled"
    result = database_query(database, query)
    if len(result.stdout) > 65536:
        raise ValueError('runtime_identity_unavailable')
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) != len(nodes):
        raise ValueError('runtime_topology_changed')
    indexed = {row['id']: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError('runtime_topology_changed')
    for node in nodes:
        row = indexed.get(node['id'], {})
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--wait-readiness', action='store_true')
    parser.add_argument('--lifecycle-id')
    parser.add_argument('--reservation-pending', action='store_true')
    parser.add_argument('--expected')
    parser.add_argument('--not-before', type=int)
    args = parser.parse_args()
    if args.wait_readiness:
        if args.status or args.expected or args.not_before is not None:
            raise ValueError('invalid_readiness_probe_arguments')
        if not args.lifecycle_id:
            raise ValueError('invalid_readiness_lifecycle_id')
        print(json.dumps(wait_readiness(operation=args.lifecycle_id, pending=args.reservation_pending)))
        return
    if args.lifecycle_id or args.reservation_pending:
        raise ValueError('invalid_readiness_probe_arguments')
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
    for unit in ('ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer'):
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
    controller_directory = str(Path('/opt/ultra-ansible/current').resolve())
    if not re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}', controller_directory):
        raise ValueError('adopted_controller_required')
    controller_unit = Path('/etc/systemd/system/ultra-ansible-controller.service')
    if controller_unit.is_symlink() or not controller_unit.is_file():
        raise ValueError('controller_unit_invalid')
    controller_unit_hash = hashlib.sha256(controller_unit.read_bytes()).hexdigest()
    auto_policy = read('/etc/ultra-ansible/auto-upgrade.json') if Path('/etc/ultra-ansible/auto-upgrade.json').exists() else {'enabled': False}
    print(json.dumps({'nodes': nodes, 'runtime_nodes': {n['id']: {k: n.get(k) for k in ('name', 'managed', 'tunnel_identity_digest', 'certificate_pin')} for n in nodes}, 'topology_sha256': digest, 'architecture': architecture, 'observed_at': int(now), 'database_schema': schema_max, 'active_relay_sha256': active_relay_sha256(),
                      'identity': identity.read_text(), 'previous_manifest': previous, 'previous_manifest_sha256': hashlib.sha256(Path('/opt/ultra-recovery/release-manifest.json').read_bytes()).hexdigest(), 'tool_hashes': tool_hashes, 'auto_policy': auto_policy, 'controller_directory': controller_directory, 'controller_unit_sha256': controller_unit_hash}))


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        if '--status' in sys.argv:
            allowed = {'state_unavailable', 'fresh_independent_backup_required', 'replica_not_ready',
                       'partial_database_schema', 'database_invalid', 'previous_version_invalid'}
            reason = str(failure) if isinstance(failure, ValueError) and str(failure) in allowed else 'readiness_evidence_unavailable'
            print(json.dumps({'ready': False, 'independent': False, 'reasons': [reason]}))
        else:
            print('release_preflight_failed', file=sys.stderr)
            raise SystemExit(1)
