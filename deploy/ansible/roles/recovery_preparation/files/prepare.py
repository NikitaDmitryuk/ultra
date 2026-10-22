#!/usr/bin/env python3
"""Recovery-only preparation. Never provisions primary or activates applications."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True


def private(path, missing=False):
    path = Path(path)
    if missing and not os.path.lexists(path):
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('recovery_preparation_private_input_unsafe')
    return path


def publish(path, data, mode=0o600, owner='root', group='root', immutable=False):
    path = Path(path)
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != pwd.getpwnam(owner).pw_uid or info.st_mode & 0o022:
            raise ValueError('recovery_preparation_destination_unsafe')
        if path.read_bytes() == data:
            return
        if immutable:
            raise ValueError('recovery_preparation_original_baseline_conflict')
    fd, name = tempfile.mkstemp(prefix='.prepare-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def document(path, value, immutable=False):
    publish(path, json.dumps(value, sort_keys=True, separators=(',', ':')).encode(), immutable=immutable)


def verify_snapshot(snapshot, expected):
    if not isinstance(expected, dict) or not expected:
        raise ValueError('recovery_preparation_tools_inventory_missing')
    actual = {}
    for path in snapshot.rglob('*'):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('recovery_preparation_tools_unsafe')
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            actual[str(path.relative_to(snapshot))] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError('recovery_preparation_tools_unsafe')
    if actual != expected:
        raise ValueError('recovery_preparation_tools_inventory_changed')


def planner(snapshot):
    sys.path.insert(0, str(snapshot / 'recovery'))
    spec = importlib.util.spec_from_file_location('recovery_preparation_renderer', snapshot / 'recovery' / 'bootstrap_plan.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def schema_identity(module, expected):
    query = "BEGIN READ ONLY; SELECT json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'database',current_database(),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'primary',NOT pg_is_in_recovery(),'migration_versions',COALESCE(string_agg(version::text,',' ORDER BY version),'')) FROM public.schema_migrations; ROLLBACK;"
    value = json.loads(module.query_database(expected['database'], query))
    if value.get('primary') is not True or any(value.get(k) != expected[k] for k in ['system_identifier', 'database', 'database_oid', 'migration_versions']):
        raise ValueError('recovery_preparation_primary_identity_changed')


def stage(payload):
    snapshot = Path(payload['snapshot'])
    verify_snapshot(snapshot, payload['snapshot_inventory'])
    module = planner(snapshot)
    config = payload['configuration']
    if config['version'] != payload['baseline_version']:
        raise ValueError('recovery_preparation_original_version_changed')
    result = module.plan(config)
    if result.get('verified') is not True:
        raise ValueError('recovery_preparation_renderer_unverified')
    files = {entry['destination']: entry for entry in result['files']}
    backup = json.loads(files['/etc/ultra-recovery/backup.json']['content'])
    reconcile = json.loads(files['/etc/ultra-recovery/reconcile.json']['content'])
    deployment = json.loads(files['/etc/ultra-recovery/deployment.json']['content'])
    if deployment['version'] != payload['baseline_version']:
        raise ValueError('recovery_preparation_application_version_changed')
    # The later approved monitor phase initializes/validates the profile using
    # the original relay. Normal reconciliation continues every real VPN probe.
    reconcile.pop('monitor_spec_file', None)
    reconcile['bundle_dir'] = str(snapshot / 'recovery')
    reconcile['installer_binary'] = str(snapshot / 'recovery-tools-installer')
    reconcile.pop('ansible_executable',None)
    backup['artifact_paths'] = sorted(set(backup['artifact_paths'] + [str(snapshot), payload['baseline_snapshot'], payload['candidate_controller_directory'], '/opt/ultra-recovery/tools-manifest.json', '/opt/ultra-recovery/tools.tar.gz', '/opt/ultra-recovery/tools-inventory.json'] + list(payload['active_inventory'])))
    for name, value in [('backup.json', backup), ('reconcile.json', reconcile), ('deployment.json', deployment)]:
        files['/etc/ultra-recovery/' + name]['content'] = json.dumps(value, sort_keys=True)
    # The renderer may derive operation pins, but existing pins must be exact.
    for destination, entry in files.items():
        path = Path(destination)
        if not destination.startswith(('/etc/ultra-recovery/', '/var/lib/ultra-relay/vultr/')):
            raise ValueError('recovery_preparation_renderer_destination_invalid')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        publish(path, entry['content'].encode(), int(entry['mode'], 8), entry['owner'], entry['group'])
    members = {Path(path).name: checksum for path, checksum in payload['active_inventory'].items() if path.startswith('/opt/ultra-recovery/')}
    document('/opt/ultra-recovery/tools-inventory.json', {'protocol':'ultra-recovery-tools-v1',
             'manifest_sha256':payload['tools_manifest_sha256'],'members':members})
    sys.path.insert(0, str(snapshot / 'recovery'))
    import live_tools
    live_tools.verify(dispatcher=False)
    # Publish executable recovery tools separately from the original app release.
    # The role has verified each replacement against original/candidate hashes.
    active = payload['active_inventory']
    if not active or any(hashlib.sha256(private(path).read_bytes()).hexdigest() != sha
                         for path, sha in active.items() if path.endswith('.py')):
        raise ValueError('recovery_preparation_active_runtime_changed')
    for path, sha in active.items():
        info = Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha:
            raise ValueError('recovery_preparation_active_runtime_changed')
    gate = b'[Service]\nExecCondition=/opt/ultra-ansible/current/ultra-install deploy-operation background-ready\n'
    for unit in ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'):
        directory = Path('/etc/systemd/system') / (unit + '.d')
        directory.mkdir(mode=0o755, exist_ok=True)
        publish(directory / '95-deployment-background.conf', gate, 0o644, immutable=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=20)
    for unit in ('ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer'):
        subprocess.run(['systemctl', 'disable', '--now', unit], check=True, timeout=20)
        observed = subprocess.run(['systemctl', 'show', '--property=ActiveState', '--property=UnitFileState', unit], check=True, stdout=subprocess.PIPE, timeout=10).stdout.decode().splitlines()
        values = dict(line.split('=', 1) for line in observed if '=' in line)
        if values.get('ActiveState') != 'inactive' or values.get('UnitFileState') != 'disabled':
            raise ValueError('recovery_preparation_schedule_not_suspended')
    document('/etc/ultra-recovery/preparation-suspension.json', {
        'protocol':'ultra-recovery-preparation-suspension-v1', 'request_sha256':payload['request_sha256'],
        'tools_manifest_sha256':payload['tools_manifest_sha256'], 'active_inventory':active,
        'background_gate_sha256':hashlib.sha256(gate).hexdigest()}, immutable=True)
    document('/etc/ultra-recovery/recovery-tools.json', {
        'protocol': 'ultra-recovery-preparation-tools-v1', 'request_sha256': payload['request_sha256'],
        'tools_manifest_sha256': payload['tools_manifest_sha256'], 'baseline_manifest_sha256': payload['baseline_manifest_sha256'],
        'application_version': payload['baseline_version'], 'snapshot_directory': str(snapshot),
        'candidate_controller_directory': payload['candidate_controller_directory'],
        'inventory': {str(path.relative_to(snapshot)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in sorted(snapshot.rglob('*')) if path.is_file()}})
    return {'configured': True, 'verified': True}


def initialize_monitor(payload):
    snapshot = Path(payload['snapshot'])
    verify_snapshot(snapshot, payload['snapshot_inventory'])
    module = planner(snapshot)
    relay = Path('/usr/local/bin/ultra-relay')
    info = relay.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or hashlib.sha256(relay.read_bytes()).hexdigest() != payload['baseline_relay_sha256']:
        raise ValueError('recovery_preparation_original_relay_changed')
    # db.Open runs migrations: exact original release/schema identity must be
    # established before entering the original executable's initializer.
    schema_identity(module, payload['primary'])
    key = Path('/var/lib/ultra-recovery-reconcile/heartbeat_ed25519')
    public = Path(str(key) + '.pub')
    if not os.path.lexists(key):
        if os.path.lexists(public):
            raise ValueError('recovery_preparation_heartbeat_trust_conflict')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    private(key)
    actual = subprocess.run(['ssh-keygen', '-y', '-f', str(key)], check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.split()
    if len(actual) != 2 or actual[0] != b'ssh-ed25519':
        raise ValueError('recovery_preparation_heartbeat_identity_invalid')
    if os.path.lexists(public) and public.read_bytes().split()[:2] != actual:
        raise ValueError('recovery_preparation_heartbeat_trust_conflict')
    publish(public, b' '.join(actual) + b'\n')
    environment = dict(os.environ, **module.read_env('/etc/ultra-relay/environment'))
    args = [str(relay), '-ensure-monitor-access', '-spec', payload['configuration']['spec'],
            '-monitor-profile-output', '/etc/ultra-recovery/probe.json',
            '-monitor-chat-output', '/etc/ultra-recovery/admin-chat-id']
    admin = payload['configuration'].get('admin_telegram_id', 0)
    if admin:
        args += ['-monitor-admin-telegram-id', str(admin)]
    result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, timeout=90)
    status = json.loads(result.stdout)
    if status.get('monitor_access') != 'ready' or type(status.get('quota_available')) is not bool:
        raise ValueError('recovery_preparation_monitor_initialization_unverified')
    profile = json.loads(private('/etc/ultra-recovery/probe.json').read_bytes())
    if not isinstance(profile, dict) or not re.fullmatch(r'-?[1-9][0-9]*\n?', private('/etc/ultra-recovery/admin-chat-id').read_text()):
        raise ValueError('recovery_preparation_monitor_profile_invalid')
    schema_identity(module, payload['primary'])
    return {'verified': True, 'monitor_initialized': True, 'heartbeat_public_sha256': hashlib.sha256(b' '.join(actual)).hexdigest()}


def run_reconcile(payload):
    snapshot = Path(payload['snapshot'])
    sys.path.insert(0, str(snapshot / 'recovery'))
    identity = json.loads(private('/etc/ultra-recovery/recovery-tools.json').read_bytes())
    if identity.get('request_sha256') != payload['request_sha256']:
        raise ValueError('recovery_preparation_tools_identity_changed')
    verify_snapshot(snapshot, identity['inventory'])
    import reconcile
    reconcile.reconcile(reconcile.read_config('/etc/ultra-recovery/reconcile.json'))
    return {'verified': True, 'recovery_reconciled': True}


def activate_tools(payload):
    identity = json.loads(private('/etc/ultra-recovery/recovery-tools.json').read_bytes())
    if identity.get('request_sha256') != payload['request_sha256']:
        raise ValueError('recovery_preparation_tools_identity_changed')
    sys.path.insert(0, '/opt/ultra-recovery')
    import live_tools
    live_tools.verify()
    config_path = Path('/etc/ultra-recovery/reconcile.json')
    config = json.loads(private(config_path).read_bytes())
    config.update(bundle_dir='/opt/ultra-recovery', installer_binary='/opt/ultra-ansible/current/ultra-install',
                  ansible_executable='/opt/ultra-ansible/current/venv/bin/ansible-playbook')
    document(config_path, config)
    return {'verified':True,'canonical_tools_activated':True}


def restore_schedules(payload):
    identity = json.loads(private('/etc/ultra-recovery/recovery-tools.json').read_bytes())
    current = Path('/opt/ultra-ansible/current')
    if (identity.get('request_sha256') != payload['request_sha256'] or not current.is_symlink()
            or os.readlink(current) != identity['candidate_controller_directory']):
        raise ValueError('recovery_preparation_schedule_candidate_required')
    suspension_path = Path('/etc/ultra-recovery/preparation-suspension.json')
    suspension_raw = private(suspension_path).read_bytes()
    suspension = json.loads(suspension_raw)
    if suspension.get('request_sha256') != payload['request_sha256']:
        raise ValueError('recovery_preparation_suspension_changed')
    for path, checksum in suspension['active_inventory'].items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != checksum:
            raise ValueError('recovery_preparation_active_runtime_changed')
    blocked = b'[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
    for name in ('ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer'):
        path = Path('/etc/systemd/system') / (name + '.d/90-retained-primary.conf')
        if os.path.lexists(path):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or path.read_bytes() != blocked):
                raise ValueError('recovery_preparation_schedule_fence_changed')
            path.unlink()
            fd = os.open(path.parent, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
    subprocess.run(['systemctl','daemon-reload'], check=True, timeout=20)
    for name in ('ultra-recovery-backup.timer','ultra-recovery-reconcile.timer'):
        subprocess.run(['systemctl','enable','--now',name], check=True, timeout=20)
        values = dict(line.split('=',1) for line in subprocess.run(['systemctl','show','--property=ActiveState','--property=UnitFileState',name],check=True,stdout=subprocess.PIPE,timeout=10).stdout.decode().splitlines() if '=' in line)
        if values.get('ActiveState') != 'active' or values.get('UnitFileState') != 'enabled':
            raise ValueError('recovery_preparation_schedule_restore_uncertain')
    document('/etc/ultra-recovery/preparation-schedules-restored.json', {
        'protocol':'ultra-recovery-preparation-schedules-restored-v1',
        'request_sha256':payload['request_sha256'], 'suspension_sha256':hashlib.sha256(suspension_raw).hexdigest()}, immutable=True)


def main():
    action = sys.argv[1]
    payload = json.load(sys.stdin)
    if action not in ('stage', 'monitor', 'reconcile','activate-tools') or not re.fullmatch('[a-f0-9]{64}', payload['request_sha256']):
        raise ValueError('recovery_preparation_action_invalid')
    result = {'stage': stage, 'monitor': initialize_monitor, 'reconcile': run_reconcile,'activate-tools':activate_tools}[action](payload)
    result.update(protocol='ultra-recovery-preparation-terminal-v1', request_sha256=payload['request_sha256'], phase={'stage':'tools_staged','monitor':'monitor_initialized','reconcile':'recovery_reconciled','activate-tools':'canonical_tools_activated'}[action], started_at=payload['started_at'])
    if action != 'activate-tools':
        document(payload['remote_phase_receipt'], result, immutable=True)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('recovery preparation unavailable') from None
