#!/usr/bin/python
"""Run a receipt-bound DNS migration on the bridge without exporting its secrets."""
import hashlib
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from ansible.module_utils.basic import AnsibleModule

ROOT = Path('/var/lib/ultra-recovery/dns-migrations')
CONFIG = Path('/etc/ultra-recovery/dns.json')
OLD_RECEIPT = Path('/etc/ultra-recovery/dns-receipt.json')
APPLICATION_NAME = 'dns-application.py'
UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\Z')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
HASH = re.compile(r'[a-f0-9]{64}\Z')
ACTIONS = {'prepare', 'promote', 'retire', 'rollback'}


def validate_request(action, operation_id, desired, acceptance_sha256):
    if action not in ACTIONS:
        raise ValueError('invalid_action')
    if not isinstance(operation_id, str) or not UUID.fullmatch(operation_id):
        raise ValueError('invalid_operation_id')
    if (not isinstance(desired, dict) or not {'subscription', 'vpn'} <= set(desired)
            or not set(desired) <= {'subscription', 'vpn', 'backend'}):
        raise ValueError('invalid_desired_labels')
    names = set()
    roles = ['subscription', 'vpn'] + (['backend'] if 'backend' in desired else [])
    for role in roles:
        item = desired[role]
        if role == 'backend' and item is None:
            continue
        if (not isinstance(item, dict) or set(item) != {'name', 'data'}
                or not isinstance(item['name'], str) or not LABEL.fullmatch(item['name'])
                or item['name'] in names):
            raise ValueError('invalid_desired_labels')
        names.add(item['name'])
        if not isinstance(item['data'], str):
            raise ValueError('invalid_desired_address')
        try:
            ipaddress.IPv4Address(item['data'])
        except (ValueError, TypeError):
            raise ValueError('invalid_desired_address') from None
    if action in {'promote', 'retire'}:
        if not isinstance(acceptance_sha256, str) or not HASH.fullmatch(acceptance_sha256):
            raise ValueError('invalid_acceptance_hash')
    elif acceptance_sha256 not in (None, ''):
        raise ValueError('unexpected_acceptance_hash')


def migration_paths(operation_id):
    if not isinstance(operation_id, str) or not UUID.fullmatch(operation_id):
        raise ValueError('invalid_operation_id')
    directory = ROOT / operation_id
    return directory / 'candidate.json', directory / 'journal.json'


def ensure_private_directory(path):
    path = Path(path)
    if path != ROOT and path.parent != ROOT:
        raise ValueError('invalid_migration_directory')
    if path.is_symlink():
        raise ValueError('migration_symlink_forbidden')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError('migration_directory_permissions')


def _digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('migration_receipt_unavailable')
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError('migration_receipt_permissions')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private_bytes(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('private_file_required')
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 1024 * 1024:
        raise ValueError('private_file_permissions')
    return path.read_bytes()


def stage_application(operation_dir, source, owner=0):
    """Pin this operation to the exact trusted DNS helper supplied by the bundle."""
    operation_dir = Path(operation_dir)
    if operation_dir.is_symlink() or not operation_dir.is_dir():
        raise ValueError('migration_directory_required')
    directory_info = operation_dir.stat()
    if directory_info.st_uid != owner or stat.S_IMODE(directory_info.st_mode) & 0o077:
        raise ValueError('migration_directory_permissions')
    if not isinstance(source, str) or not source or len(source.encode()) > 1024 * 1024:
        raise ValueError('dns_application_source_invalid')
    destination = operation_dir / APPLICATION_NAME
    raw = source.encode()
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError('dns_application_untrusted')
        info = destination.stat()
        if (info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 1024 * 1024):
            raise ValueError('dns_application_untrusted')
        if destination.read_bytes() != raw:
            raise ValueError('dns_application_conflict')
        return destination
    temporary = operation_dir / (APPLICATION_NAME + '.next')
    if temporary.exists() or temporary.is_symlink():
        if temporary.is_symlink() or not temporary.is_file():
            raise ValueError('dns_application_temporary_untrusted')
        info = temporary.stat()
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError('dns_application_temporary_untrusted')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    directory_fd = os.open(operation_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return destination


def load_application(operation_dir, source, owner=0):
    path = stage_application(operation_dir, source, owner)
    specification = importlib.util.spec_from_file_location('ultra_dns_migration_application', path)
    if specification is None or specification.loader is None:
        raise ValueError('dns_application_import_failed')
    application = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(application)
    return application


def _atomic_private(path, raw):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('private_file_symlink')
    temporary = path.with_name(path.name + '.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def finalize_retirement(candidate, operation_dir, desired, policy_path=CONFIG,
                        receipt_path=OLD_RECEIPT, acceptance_sha256=None, writer=_atomic_private):
    """Journal canonical DNS state promotion after API retirement has succeeded."""
    if not isinstance(acceptance_sha256, str) or not HASH.fullmatch(acceptance_sha256):
        raise ValueError('invalid_acceptance_hash')
    candidate, operation_dir = Path(candidate), Path(operation_dir)
    policy_path, receipt_path = Path(policy_path), Path(receipt_path)
    if operation_dir.is_symlink() or not operation_dir.is_dir():
        raise ValueError('migration_directory_required')
    lock_path = operation_dir / 'finalize.lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        candidate_bytes = _private_bytes(candidate)
        candidate_digest = hashlib.sha256(candidate_bytes).hexdigest()
        policy_bytes = _private_bytes(policy_path)
        policy = json.loads(policy_bytes)
        if not isinstance(policy, dict) or not isinstance(policy.get('config'), dict) or not isinstance(policy.get('desired'), dict):
            raise ValueError('invalid_dns_policy')
        target_desired = dict(policy['desired'])
        target_desired.update({role: dict(desired[role]) for role in ('subscription', 'vpn')})
        if 'backend' in desired:
            if desired['backend'] is None:
                target_desired.pop('backend', None)
            else:
                target_desired['backend'] = dict(desired['backend'])
        target_config = dict(policy['config'])
        target_config['subscription_name'] = target_desired['subscription']['name']
        target_config['vpn_name'] = target_desired['vpn']['name']
        source_config_digest = hashlib.sha256(json.dumps(policy['config'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        target_config_digest = hashlib.sha256(json.dumps(target_config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        marker_path = operation_dir / 'finalization.json'
        archive_path = operation_dir / 'previous-receipt.json'
        if marker_path.exists() or marker_path.is_symlink():
            marker = json.loads(_private_bytes(marker_path))
            if not isinstance(marker, dict) or source_config_digest not in (marker.get('source_config_sha256'), target_config_digest):
                raise ValueError('dns_finalization_conflict')
            if (not isinstance(marker, dict) or marker.get('version') != 1
                    or marker.get('candidate_sha256') != candidate_digest
                    or marker.get('acceptance_sha256') != acceptance_sha256
                    or marker.get('desired') != target_desired
                    or marker.get('target_config_sha256') != target_config_digest
                    or marker.get('target_config') != target_config
                    or marker.get('phase') not in ('prepared', 'complete')):
                raise ValueError('dns_finalization_conflict')
            target_desired = marker['desired']
            previous_digest = marker['previous_receipt_sha256']
            archive = _private_bytes(archive_path)
            if hashlib.sha256(archive).hexdigest() != previous_digest:
                raise ValueError('dns_finalization_archive_conflict')
        else:
            current_receipt = _private_bytes(receipt_path)
            previous_digest = hashlib.sha256(current_receipt).hexdigest()
            if archive_path.exists() or archive_path.is_symlink():
                if _private_bytes(archive_path) != current_receipt:
                    raise ValueError('dns_finalization_archive_conflict')
            else:
                writer(archive_path, current_receipt)
            marker = {'version': 1, 'phase': 'prepared',
                      'candidate_sha256': candidate_digest,
                      'acceptance_sha256': acceptance_sha256,
                      'previous_receipt_sha256': previous_digest,
                      'source_config_sha256': source_config_digest,
                      'target_config_sha256': target_config_digest,
                      'target_config': target_config,
                      'desired': target_desired}
            writer(marker_path, (json.dumps(marker, sort_keys=True, separators=(',', ':')) + '\n').encode())
        current_receipt = _private_bytes(receipt_path)
        current_digest = hashlib.sha256(current_receipt).hexdigest()
        if current_digest == previous_digest:
            writer(receipt_path, candidate_bytes)
        elif current_digest != candidate_digest:
            raise ValueError('dns_finalization_receipt_conflict')
        latest_policy_bytes = _private_bytes(policy_path)
        latest_policy = json.loads(latest_policy_bytes)
        if (not isinstance(latest_policy, dict)
                or latest_policy.get('config') not in (policy.get('config'), target_config)):
            raise ValueError('dns_finalization_policy_conflict')
        if latest_policy.get('config') != target_config:
            latest_policy['config'] = target_config
            writer(policy_path, (json.dumps(latest_policy, sort_keys=True, separators=(',', ':')) + '\n').encode())
            latest_policy = json.loads(_private_bytes(policy_path))
        if latest_policy.get('desired') != target_desired:
            latest_policy['desired'] = target_desired
            writer(policy_path, (json.dumps(latest_policy, sort_keys=True, separators=(',', ':')) + '\n').encode())
        marker['phase'] = 'complete'
        writer(marker_path, (json.dumps(marker, sort_keys=True, separators=(',', ':')) + '\n').encode())
        return candidate_digest


def retirement_finalization_started(finalization_path, migration_journal_path, acceptance_sha256):
    finalization_path = Path(finalization_path)
    if not finalization_path.exists() and not finalization_path.is_symlink():
        return False
    marker = json.loads(_private_bytes(finalization_path))
    migration_journal = json.loads(_private_bytes(migration_journal_path))
    if (not isinstance(marker, dict) or not isinstance(migration_journal, dict)
            or marker.get('phase') not in ('prepared', 'complete')
            or migration_journal.get('phase') != 'retired'
            or migration_journal.get('acceptance_sha256') != acceptance_sha256
            or marker.get('acceptance_sha256') != acceptance_sha256):
        raise ValueError('dns_finalization_not_accepted')
    return True


def perform(application, action, operation_id, desired, acceptance_sha256=None):
    validate_request(action, operation_id, desired, acceptance_sha256)
    candidate, journal = migration_paths(operation_id)
    ensure_private_directory(ROOT)
    ensure_private_directory(candidate.parent)
    policy = json.loads(application.private(CONFIG).read_text())
    config = policy['config']
    before_candidate = _digest(candidate) if candidate.exists() else None
    before_journal = _digest(journal) if journal.exists() else None
    before_policy = _digest(CONFIG)
    before_receipt = _digest(OLD_RECEIPT)
    finalization_path = candidate.parent / 'finalization.json'
    before_finalization = _digest(finalization_path) if finalization_path.exists() else None
    if action == 'retire' and retirement_finalization_started(finalization_path, journal, acceptance_sha256):
        result = {'phase': 'retired', 'active_receipt': str(candidate), 'ready': True}
    elif action == 'prepare':
        result = application.prepare_migration(config, desired, OLD_RECEIPT, candidate, journal)
    elif action == 'promote':
        result = application.promote_migration(config, desired, OLD_RECEIPT, candidate, journal, acceptance_sha256)
    elif action == 'retire':
        result = application.retire_migration(config, desired, OLD_RECEIPT, candidate, journal, acceptance_sha256)
    else:
        result = application.rollback_migration(config, desired, OLD_RECEIPT, candidate, journal)
    if result.get('active_receipt') not in (str(OLD_RECEIPT), str(candidate)):
        raise ValueError('unexpected_active_receipt')
    active = OLD_RECEIPT if result['active_receipt'] == str(OLD_RECEIPT) else candidate
    if action == 'retire' and result.get('phase') == 'retired':
        active_digest = finalize_retirement(candidate, candidate.parent, desired,
                                             acceptance_sha256=acceptance_sha256)
    else:
        active_digest = _digest(active)
    output = {'phase': result['phase'], 'active_receipt_sha256': active_digest, 'verified': result.get('ready') is True}
    changed = (before_candidate != (_digest(candidate) if candidate.exists() else None)
               or before_journal != (_digest(journal) if journal.exists() else None)
               or before_policy != _digest(CONFIG)
               or before_receipt != _digest(OLD_RECEIPT)
               or before_finalization != (_digest(finalization_path) if finalization_path.exists() else None))
    return changed, output


def main():
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'required': True, 'no_log': True},
        'operation_id': {'type': 'str', 'required': True, 'no_log': True},
        'desired': {'type': 'dict', 'required': True, 'no_log': True},
        'application_source': {'type': 'str', 'required': True, 'no_log': True},
        'acceptance_sha256': {'type': 'str', 'required': False, 'default': '', 'no_log': True},
    }, supports_check_mode=False)
    try:
        candidate, _ = migration_paths(module.params['operation_id'])
        ensure_private_directory(ROOT)
        ensure_private_directory(candidate.parent)
        application = load_application(candidate.parent, module.params['application_source'])
        changed, result = perform(application, module.params['action'], module.params['operation_id'],
                                  module.params['desired'], module.params['acceptance_sha256'] or None)
        module.exit_json(changed=changed, **result)
    except Exception:
        module.fail_json(msg='dns_migration_failed')


if __name__ == '__main__':
    main()
