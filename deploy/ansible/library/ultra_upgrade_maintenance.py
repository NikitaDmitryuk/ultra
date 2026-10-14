#!/usr/bin/python
"""Private same-operation legacy maintenance barrier."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from ansible.module_utils.basic import AnsibleModule

SERVICES = ('ultra-bot.service', 'ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer')
FILES = ('/etc/ultra-relay/spec.json', '/etc/ultra-relay/environment', '/etc/systemd/system/ultra-relay.service')
PROPERTIES = ('LoadState', 'ActiveState', 'MainPID', 'ControlPID')


def private(path, evidence=False):
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_uid != 0 or metadata.st_mode & (0o022 if evidence else 0o077) or metadata.st_size > 1048576:
        raise ValueError('maintenance_checkpoint_invalid')
    return json.loads(path.read_text())


def service(module, unit):
    code, output, _ = module.run_command(['systemctl', 'show'] + ['--property=' + key for key in PROPERTIES] + [unit])
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition('=')
        if not sep or key not in PROPERTIES or key in values:
            raise ValueError('maintenance_service_unavailable')
        values[key] = value
    if code or set(values) != set(PROPERTIES) or values['LoadState'] != 'loaded':
        raise ValueError('maintenance_service_unavailable')
    if values['ActiveState'] not in ('active', 'inactive') or any(not re.fullmatch('[0-9]+', values[key]) for key in ('MainPID', 'ControlPID')):
        raise ValueError('maintenance_service_ambiguous')
    return values


def hashes():
    result = {}
    for name in FILES:
        path = Path(name)
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_mode & 0o022 or metadata.st_size > 1048576:
            raise ValueError('maintenance_configuration_invalid')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def atomic(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_uid != 0 or path.parent.stat().st_mode & 0o077:
        raise ValueError('maintenance_directory_invalid')
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.maintenance-')
    try:
        with os.fdopen(fd, 'w') as target:
            json.dump(value, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    module = AnsibleModule(argument_spec={
        'id': {'type': 'str', 'required': True},
        'legacy_sha256': {'type': 'str', 'required': True},
        'phase': {'type': 'str', 'required': True, 'choices': ['checkpoint', 'recovery-ready', 'stopped', 'restore-bot', 'restore-services']},
    }, supports_check_mode=True)
    try:
        operation, sha = module.params['id'], module.params['legacy_sha256']
        if os.geteuid() != 0 or not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', operation) or not re.fullmatch(r'[a-f0-9]{64}', sha):
            raise ValueError('maintenance_identity_invalid')
        gate = private(Path('/var/lib/ultra-ansible/lifecycle.json'))
        phases = ('applying', 'checking') if module.params['phase'] == 'restore-services' else ('applying',)
        if gate.get('id') != operation or gate.get('phase') not in phases:
            raise ValueError('maintenance_reservation_not_owned')
        path = Path('/var/lib/ultra-ansible/upgrade') / operation / 'maintenance.json'
        if module.params['phase'] == 'checkpoint' and not path.exists():
            binary = Path('/usr/local/bin/ultra-relay')
            if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != sha:
                raise ValueError('maintenance_legacy_identity_changed')
            runtime = service(module, 'ultra-relay.service')
            pid = runtime['MainPID']
            executable = Path('/proc') / pid / 'exe'
            if (runtime['ActiveState'] != 'active' or pid == '0' or runtime['ControlPID'] != '0'
                    or os.readlink(executable) != str(binary) or hashlib.sha256(executable.read_bytes()).hexdigest() != sha
                    or json.loads(Path('/etc/ultra-relay/spec.json').read_text()).get('role') != 'bridge'):
                raise ValueError('maintenance_running_identity_unverified')
            code, _, _ = module.run_command(['runuser', '-u', 'ultra-relay', '--', 'test', '-r', '/etc/ultra-relay/spec.json'])
            if code:
                raise ValueError('maintenance_spec_unreadable')
            states = {unit: service(module, unit)['ActiveState'] for unit in SERVICES}
            checkpoint = {'id': operation, 'legacy_sha256': sha, 'services': states, 'configuration': hashes(), 'created_at': int(time.time())}
            if not module.check_mode:
                atomic(path, checkpoint)
        else:
            checkpoint = private(path)
        if (checkpoint.get('id') != operation or checkpoint.get('legacy_sha256') != sha
                or checkpoint.get('configuration') != hashes() or set(checkpoint.get('services', {})) != set(SERVICES)
                or any(value not in ('active', 'inactive') for value in checkpoint['services'].values())):
            raise ValueError('maintenance_checkpoint_changed')
        if module.params['phase'] == 'recovery-ready':
            # Capture is synchronous and verifies receiver delivery before writing
            # last-success. Bind that new generation to the independent primary.
            config = private(Path('/etc/ultra-recovery/reconcile.json'), evidence=True)
            backup_config = private(Path('/etc/ultra-recovery/backup.json'), evidence=True)
            topology = private(Path('/var/lib/ultra-recovery-reconcile/state.json'), evidence=True)
            status = private(Path('/var/lib/ultra-relay/recovery-reconcile-status.json'), evidence=True)
            backup = private(Path('/var/lib/ultra-recovery/last-success.json'), evidence=True)
            primary = topology['primary']
            selected = [node for node in topology['node_metadata'] if node['id'] == primary]
            targets = [target for target in backup_config['destinations'] if target.get('id') == primary and target.get('required') is True]
            now = time.time()
            if (len(selected) != 1 or len(targets) != 1 or selected[0]['provider'].lower() == config['bridge_provider'].lower()
                    or targets[0]['host'] != selected[0]['host'] or selected[0]['host'] not in backup['destinations']
                    or primary not in backup['delivered_target_ids'] or backup_config.get('independent') is not True
                    or backup.get('source') != 'bridge' or status.get('state') != 'ready' or status.get('independent') is not True
                    or status.get('primary') != primary or not 0 <= now - topology['updated_at'] <= 180
                    or not 0 <= now - status['updated_at'] <= 180 or not 0 <= now - backup['snapshot_at'] <= 300
                    or backup['snapshot_at'] < checkpoint['created_at'] or not re.fullmatch(r'[a-f0-9]{64}', backup.get('backup_sha256', ''))
                    or not re.fullmatch(r'[a-f0-9]{64}', backup.get('artifact_sha256', ''))):
                raise ValueError('maintenance_independent_generation_unavailable')
            for unit in ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'):
                values = service(module, unit)
                if values['ActiveState'] != 'inactive' or values['MainPID'] != '0' or values['ControlPID'] != '0':
                    raise ValueError('maintenance_recovery_not_idle')
        if module.params['phase'] == 'stopped':
            for unit in SERVICES + ('ultra-relay.service',):
                values = service(module, unit)
                if values['ActiveState'] != 'inactive' or values['MainPID'] != '0' or values['ControlPID'] != '0':
                    raise ValueError('maintenance_worker_not_stopped')
        if module.params['phase'] in ('restore-bot', 'restore-services') and not module.check_mode:
            units = SERVICES if module.params['phase'] == 'restore-services' else ('ultra-bot.service',)
            for unit in units:
                action = 'start' if checkpoint['services'][unit] == 'active' else 'stop'
                code, _, _ = module.run_command(['systemctl', action, unit])
                if code or service(module, unit)['ActiveState'] != checkpoint['services'][unit]:
                    raise ValueError('maintenance_services_restore_failed')
        module.exit_json(changed=False, verified=True, bot_active=checkpoint['services']['ultra-bot.service'] == 'active')
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='legacy_maintenance_barrier_failed')


if __name__ == '__main__':
    main()
