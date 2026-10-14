#!/usr/bin/python
"""Validate durable application identity before a legacy control maintenance stop."""
from ansible.module_utils.basic import AnsibleModule
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import tempfile
import shutil
import time
import pwd
import shlex
import subprocess
import stat
import ipaddress
import uuid

FILES = ['/usr/local/bin/ultra-relay', '/etc/ultra-relay/spec.json', '/etc/ultra-relay/environment', '/etc/systemd/system/ultra-relay.service']


def digest(path):
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_mode & 0o022:
        raise ValueError('unowned_adoption_file')
    value = hashlib.sha256()
    with source.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            value.update(chunk)
    return value.hexdigest()


def read(path):
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 1048576:
        raise ValueError('adoption_state_unavailable')
    return json.loads(source.read_text())


def owned_file(path, private=False, owner='root'):
    source = Path(path)
    allowed = {0}
    if owner == 'ultra-relay':
        allowed.add(pwd.getpwnam(owner).pw_uid)
    elif owner != 'root':
        raise ValueError('adoption_file_owner_invalid')
    if (not source.is_absolute() or source.is_symlink() or not source.is_file()
            or source.stat().st_uid not in allowed or source.stat().st_mode & (0o077 if private else 0o022)):
        raise ValueError('unowned_adoption_file')


def checked_pins(config, primary):
    pins = Path(primary['known_hosts'])
    managed = primary.get('managed') is True
    prefix = Path('/var/lib/ultra-relay')
    if managed and (config.get('vultr_state_dir') != '/var/lib/ultra-relay/vultr'
                    or str(uuid.UUID(primary['id'])) != primary['id']
                    or primary['known_hosts'] != '/var/lib/ultra-relay/vultr/' + primary['id'] + '/known_hosts'):
        raise ValueError('adoption_ssh_pins_invalid')
    relay_uid = pwd.getpwnam('ultra-relay').pw_uid if managed else None
    if not pins.is_absolute() or '..' in pins.parts:
        raise ValueError('adoption_ssh_pins_invalid')
    for path in [pins, *pins.parents]:
        metadata = path.lstat()
        relay_owned = managed and (path == prefix or prefix in path.parents) and metadata.st_uid == relay_uid
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_mode & 0o022 or (metadata.st_uid != 0 and not relay_owned):
            raise ValueError('adoption_ssh_pins_invalid')
    if not pins.is_file() or not 0 < pins.stat().st_size <= 65536:
        raise ValueError('adoption_ssh_pins_invalid')
    address = str(ipaddress.ip_address(primary['address']))
    if primary['host'] != 'root@' + address:
        raise ValueError('adoption_ssh_destination_invalid')
    result = subprocess.run(['ssh-keygen', '-F', address, '-f', str(pins)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    if result.returncode:
        raise ValueError('adoption_ssh_pins_missing')


def verify_delivery(config, topology, backup_config, backup):
    # Match reconcile.validate_delivery: the bridge retains the artifact, while
    # the encrypted database generation lives on its confirmed receiver.
    primary = next(node for node in topology['node_metadata'] if node['id'] == topology['primary'])
    destinations = [item for item in backup_config['destinations']
                    if item.get('id') == primary['id'] and item.get('host') == primary['host'] and item.get('required') is True]
    if len(destinations) != 1 or primary['host'] not in backup['destinations']:
        raise ValueError('adoption_primary_delivery_required')
    destination = destinations[0]
    names = [backup['backup_name'], backup['artifact_name']]
    hashes = [backup['backup_sha256'], backup['artifact_sha256']]
    if (not re.fullmatch(r'backup-[0-9]{10}-[a-f0-9]{32}\.age', names[0])
            or not re.fullmatch(r'artifact-[a-f0-9]{64}\.age', names[1])
            or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in hashes)
            or int(names[0].split('-')[1]) != int(backup['snapshot_at'])
            or not 0 <= time.time() - backup['snapshot_at'] <= 300):
        raise ValueError('adoption_generation_invalid')
    host = primary['host']
    if not re.fullmatch(r'[A-Za-z0-9_.@:-]+', host) or host.startswith('-'):
        raise ValueError('adoption_ssh_destination_invalid')
    identity, pins = config['ssh_identity_file'], primary['known_hosts']
    if destination.get('identity_file') != identity or destination.get('known_hosts') != pins:
        raise ValueError('adoption_ssh_identity_invalid')
    owned_file(identity, private=True, owner=config.get('ssh_identity_owner', 'ultra-relay'))
    checked_pins(config, primary)
    artifact = '/var/lib/ultra-recovery/' + names[1]
    owned_file(artifact, private=True)
    if digest(artifact) != hashes[1]:
        raise ValueError('adoption_generation_invalid')
    command = ['sha256sum', *['/var/lib/ultra-recovery/' + name for name in names]]
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                             '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                             '-o', 'IdentitiesOnly=yes', '-i', identity, '-o', 'UserKnownHostsFile=' + pins,
                             host, shlex.join(command)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    expected = [[value.encode('ascii'), ('/var/lib/ultra-recovery/' + name).encode('ascii')]
                for value, name in zip(hashes, names)]
    if result.returncode or [line.split() for line in result.stdout.splitlines()] != expected:
        raise ValueError('adoption_generation_invalid')


def checked_asset(manifest, architecture, binary, component="ultra-relay"):
    if not {'service-access-v1', 'provider-pool-quota-v1'} <= set(manifest.get('capabilities', [])):
        raise ValueError('adoption_accounting_contract_missing')
    assets = [item for item in manifest['assets'] if item['name'] == component + '-linux-' + architecture]
    if len(assets) != 1 or assets[0]['sha256'] != digest(binary) or assets[0]['size'] != Path(binary).stat().st_size:
        raise ValueError('adoption_binary_identity_invalid')


def check_private_checkpoint(path):
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise ValueError('adoption_checkpoint_unowned')


def main():
    module = AnsibleModule(argument_spec={
        'id': {'type': 'str', 'required': True},
        'contract_sha256': {'type': 'str'},
        'action': {'type': 'str', 'choices': ['inspect', 'checkpoint', 'resume-check', 'prepare-gate', 'rollback-check', 'retry-check'], 'default': 'inspect'},
    }, supports_check_mode=True)
    try:
        identity = module.params['id']
        if not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', identity) or os.geteuid() != 0:
            raise ValueError('invalid_adoption_identity')
        gate = Path('/var/lib/ultra-ansible/lifecycle.json')
        if gate.exists() or gate.is_symlink():
            if gate.is_symlink() or not gate.is_file() or gate.stat().st_uid != 0 or gate.stat().st_mode & 0o077:
                raise ValueError('adoption_lifecycle_invalid')
            previous = read(gate)
            if previous.get('phase') not in ('applying', 'checking', 'released') or not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', previous.get('id', '')):
                raise ValueError('adoption_lifecycle_invalid')
            if previous.get('phase') in ('applying', 'checking') and previous.get('id') != identity:
                raise ValueError('adoption_lifecycle_busy')
        if module.params['action'] == 'prepare-gate':
            if not module.check_mode:
                with tempfile.NamedTemporaryFile(dir=gate.parent, delete=False) as stream:
                    temporary = stream.name
                    stream.write(json.dumps({'id': identity, 'phase': 'applying'}).encode())
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, gate)
                directory = os.open(gate.parent, os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            module.exit_json(changed=False, verified=True)
        if not Path(FILES[0]).exists() and not Path(FILES[1]).exists():
            module.exit_json(changed=False, legacy=False, fresh=True, stopped=True)
        code, output, _ = module.run_command([FILES[0], '--capabilities'])
        if code or not isinstance(json.loads(output), list):
            raise ValueError('adoption_capabilities_unavailable')
        legacy = 'lifecycle-gate-v1' not in json.loads(output)
        active, _, _ = module.run_command(['systemctl', 'is-active', 'ultra-relay.service'])
        if active not in (0, 3, 4):
            raise ValueError('adoption_service_state_unavailable')
        stopped = active in (3, 4)
        if active == 3:
            code, main_pid, _ = module.run_command(['systemctl', 'show', '-p', 'MainPID', '--value', 'ultra-relay.service'])
            if code or main_pid.strip() != '0':
                raise ValueError('adoption_service_not_stopped')

        checkpoint = Path('/var/lib/ultra-ansible/adoption') / identity / 'checkpoint.json'
        if module.params['action'] in ('rollback-check', 'retry-check'):
            saved = read(checkpoint)
            emergency = saved['emergency_manifest']
            checked_asset(emergency, saved['architecture'], str(checkpoint.parent / 'rollback-relay'))
            database = saved['database']
            if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
                raise ValueError('adoption_database_invalid')
            code, schema, _ = module.run_command(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database,
                                                '-c', "SELECT COALESCE(max(version),0)::text || ':' || count(*)::text FROM schema_migrations"])
            maximum, count = map(int, schema.strip().split(':'))
            if code or count != maximum or maximum <= 0 or not emergency['database_schema_min'] <= maximum <= emergency['database_schema_max']:
                raise ValueError('adoption_emergency_schema_invalid')
            for entry in saved['restore_files']:
                if digest(entry['source']) != saved['files'][entry['destination']]:
                    raise ValueError('adoption_saved_file_corrupt')
            if module.params['action'] == 'retry-check':
                check_private_checkpoint(checkpoint)
                checked_asset(emergency, saved['architecture'], FILES[0])
                for entry in saved['restore_files']:
                    if digest(entry['destination']) != saved['files'][entry['destination']]:
                        raise ValueError('adoption_restored_file_changed')
                    metadata = Path(entry['destination']).stat()
                    if (metadata.st_uid != int(entry['owner']) or metadata.st_gid != int(entry['group'])
                            or stat.S_IMODE(metadata.st_mode) != int(entry['mode'], 8)):
                        raise ValueError('adoption_restored_file_metadata_changed')
            module.exit_json(changed=False, verified=True, restore_files=saved['restore_files'],
                             binary=str(checkpoint.parent / 'rollback-relay'), bot_active=saved.get('bot_active', False),
                             verified_binary_sha256=(digest(FILES[0]) if module.params['action'] == 'retry-check' else ''))
        if module.params['action'] == 'resume-check':
            saved = read(checkpoint)
            if any(digest(path) != value for path, value in saved['files'].items()):
                raise ValueError('adoption_checkpoint_changed')
            module.exit_json(changed=False, legacy=saved['legacy'], verified=True)
        # A running worker may have loaded its spec before an earlier operation
        # changed the file owner. The next restart would then fail even though
        # the bytes still match. Check the service identity before fencing it.
        if legacy:
            code, _, _ = module.run_command(['runuser', '-u', 'ultra-relay', '--', 'test', '-r', FILES[1]])
            if code:
                raise ValueError('adoption_spec_unreadable')
        if not legacy or module.params['action'] == 'inspect':
            module.exit_json(changed=False, legacy=legacy, fresh=False, stopped=stopped)
        backup = read('/var/lib/ultra-recovery/last-success.json')
        reconcile = read('/var/lib/ultra-relay/recovery-reconcile-status.json')
        for path in ['/etc/ultra-recovery/backup.json', '/etc/ultra-recovery/reconcile.json',
                     '/var/lib/ultra-recovery-reconcile/state.json']:
            owned_file(path, private=True)
        backup_config = read('/etc/ultra-recovery/backup.json')
        reconcile_config = read('/etc/ultra-recovery/reconcile.json')
        if reconcile_config.get('state_dir') != '/var/lib/ultra-recovery-reconcile':
            raise ValueError('adoption_reconcile_state_invalid')
        topology = read('/var/lib/ultra-recovery-reconcile/state.json')
        if not 0 <= time.time() - topology['updated_at'] <= 180:
            raise ValueError('adoption_topology_stale')
        contract_path = '/var/lib/ultra-ansible/adoption/' + identity + '/recovery_status.py'
        expected_contract = module.params.get('contract_sha256', '')
        if not re.fullmatch(r'[a-f0-9]{64}', expected_contract) or digest(contract_path) != expected_contract:
            raise ValueError('adoption_generation_contract_invalid')
        contract_spec = importlib.util.spec_from_file_location('ultra_adoption_generation_contract', Path(contract_path))
        contract = importlib.util.module_from_spec(contract_spec)
        contract_spec.loader.exec_module(contract)
        if not contract.independent_generation(reconcile_config, topology, reconcile, backup):
            raise ValueError('adoption_current_independent_delivery_required')
        required = [target['host'] for target in backup_config['destinations'] if target.get('required')]
        if backup_config.get('independent') is not True or not required or not set(required) <= set(backup.get('destinations', [])):
            raise ValueError('adoption_independent_delivery_required')
        if backup_config['repository'] != '/var/lib/ultra-recovery':
            raise ValueError('adoption_repository_invalid')
        if reconcile.get('independent') is not True or reconcile.get('state') != 'ready' or not 0 <= time.time() - reconcile['updated_at'] <= 180 or not 0 <= time.time() - backup['snapshot_at'] <= 300 or not backup.get('destinations'):
            raise ValueError('adoption_independent_backup_required')
        verify_delivery(reconcile_config, topology, backup_config, backup)
        code, architecture, _ = module.run_command(['dpkg', '--print-architecture'])
        if code or architecture.strip() not in ('amd64', 'arm64'):
            raise ValueError('adoption_architecture_invalid')
        previous = read('/opt/ultra-recovery/release-manifest.json')
        owned_file('/usr/local/libexec/ultra-emergency-manifest.json')
        owned_file('/usr/local/libexec/ultra-relay-emergency')
        emergency = read('/usr/local/libexec/ultra-emergency-manifest.json')
        checked_asset(emergency, architecture.strip(), '/usr/local/libexec/ultra-relay-emergency')
        try:
            checked_asset(previous, architecture.strip(), FILES[0])
        except ValueError:
            # A completed compatible rollback leaves the fixed emergency
            # running. A fresh legacy bridge checkpoint must re-verify it;
            # the old operation's saved hash is not an identity for this one.
            current_spec = read(FILES[1])
            if not isinstance(current_spec, dict) or current_spec.get('role') != 'bridge':
                raise ValueError('adoption_binary_identity_invalid')
            owned_file(FILES[0])
            checked_asset(emergency, architecture.strip(), FILES[0])
        config = read('/etc/ultra-recovery/reconcile.json')
        database = config['database']
        if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
            raise ValueError('adoption_database_invalid')
        code, schema, _ = module.run_command(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database,
                                            '-c', "SELECT COALESCE(max(version),0)::text || ':' || count(*)::text FROM schema_migrations"])
        maximum, count = map(int, schema.strip().split(':'))
        if code or count != maximum or maximum <= 0 or not emergency['database_schema_min'] <= maximum <= emergency['database_schema_max']:
            raise ValueError('adoption_emergency_schema_invalid')
        files = list(FILES)
        bot_files = ['/usr/local/bin/ultra-bot', '/etc/ultra-relay/bot.env', '/etc/systemd/system/ultra-bot.service']
        bot_exists = [Path(path).exists() for path in bot_files]
        if any(bot_exists) and not all(bot_exists):
            raise ValueError('adoption_partial_bot_identity')
        bot_active = False
        if all(bot_exists):
            checked_asset(previous, architecture.strip(), bot_files[0], 'ultra-bot')
            files.extend(bot_files)
            active, _, _ = module.run_command(['systemctl', 'is-active', 'ultra-bot.service'])
            if active not in (0, 3, 4):
                raise ValueError('adoption_bot_state_unavailable')
            bot_active = active == 0
        state = {'bot_present': all(bot_exists), 'bot_active': bot_active, 'legacy': True, 'files': {path: digest(path) for path in files}, 'created_at': int(time.time()),
                 'architecture': architecture.strip(), 'database': database, 'emergency_manifest': emergency, 'restore_files': []}
        checkpoint.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        for path in files[1:]:
            original = Path(path)
            saved_file = checkpoint.parent / original.name
            if saved_file.exists():
                if digest(str(saved_file)) != state['files'][path]:
                    raise ValueError('adoption_saved_file_conflict')
            elif not module.check_mode:
                with saved_file.open('xb') as target, original.open('rb') as source:
                    os.chmod(saved_file, 0o600)
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fsync(target.fileno())
            metadata = original.stat()
            state['restore_files'].append({'source': str(saved_file), 'destination': path,
                                           'owner': str(metadata.st_uid), 'group': str(metadata.st_gid),
                                           'mode': format(metadata.st_mode & 0o777, '04o')})
        saved_binary = checkpoint.parent / 'rollback-relay'
        if saved_binary.exists():
            checked_asset(emergency, architecture.strip(), str(saved_binary))
        elif not module.check_mode:
            with saved_binary.open('xb') as target, Path('/usr/local/libexec/ultra-relay-emergency').open('rb') as source:
                os.chmod(saved_binary, 0o600)
                shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
        if checkpoint.exists():
            if read(checkpoint)['files'] != state['files']:
                raise ValueError('adoption_checkpoint_changed')
        elif not module.check_mode:
            checkpoint.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(checkpoint.parent.parent, 0o700)
            with tempfile.NamedTemporaryFile(dir=checkpoint.parent, delete=False) as stream:
                temporary = stream.name
                stream.write(json.dumps(state).encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, checkpoint)
            directory = os.open(checkpoint.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        module.exit_json(changed=False, legacy=True, fresh=False, stopped=stopped, verified=True)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError):
        module.fail_json(msg='adoption_guard_failed')


if __name__ == '__main__':
    main()
