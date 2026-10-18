#!/usr/bin/python
"""Validate the separate, fail-closed retirement of the legacy experimental ingress."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import pwd
from pathlib import Path
import stat
import time
from ansible.module_utils.basic import AnsibleModule

DESCRIPTOR = '/etc/ultra-relay/experimental-profile.json'
OWNED = ('/etc/ultra-experimental/spec.json', '/etc/systemd/system/ultra-experimental.service')
JOURNAL = '/var/lib/ultra-ingress/retired-experiment.json'


def trusted(path, bot=False):
    info = path.lstat()
    owners = {os.geteuid()}
    if bot:
        try:
            owners.add(pwd.getpwnam('ultra-bot').pw_uid)
        except KeyError:
            pass
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022:
        raise ValueError('retirement_untrusted_file')
    return path.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(phase, root=Path('/')):
    def path(name):
        return root / name.lstrip('/')
    receipt = json.loads(trusted(path('/var/lib/ultra-ingress/managed.json')))
    journal = path(JOURNAL)
    if journal.exists() or journal.is_symlink():
        state = json.loads(trusted(journal))
    else:
        if phase != 'prepare':
            raise ValueError('retirement_prepare_required')
        descriptor = trusted(path(DESCRIPTOR))
        if receipt.get(DESCRIPTOR) != sha(descriptor):
            raise ValueError('retirement_descriptor_unowned')
        profile = json.loads(descriptor)
        ports = {'experimental_port': profile['endpoint']['port'], 'status_port': profile['status_port']}
        deployment = json.loads(trusted(path('/etc/ultra-recovery/deployment.json')))
        recorded = deployment['ingress']
        if any(type(value) is not int or recorded.get(key) != value for key, value in ports.items()):
            raise ValueError('retirement_backup_port_metadata_required')
        state = {'version': 1, 'descriptor_sha256': sha(descriptor), 'profile': profile,
                 'prepared_at': time.time(), 'files': {}}
        for name in OWNED:
            live = path(name)
            if live.exists() or live.is_symlink():
                digest = sha(trusted(live))
                if receipt.get(name) != digest:
                    raise ValueError('retirement_file_unowned')
                state['files'][name] = digest
    if state.get('version') != 1 or set(state.get('files', {})) - set(OWNED):
        raise ValueError('retirement_journal_invalid')
    # Required backup inventory must be corrected before unlinking anything.
    backup = json.loads(trusted(path('/etc/ultra-recovery/backup.json')))
    removed = set(state['files']) | {DESCRIPTOR}
    for key in ('state_paths', 'artifact_paths'):
        items = backup.get(key, [])
        if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
            raise ValueError('retirement_backup_inventory_required')
        if any(item == name or item.startswith(name + '/') for item in items for name in removed):
            raise ValueError('retirement_required_backup_path')
    if path(DESCRIPTOR).exists() or path(DESCRIPTOR).is_symlink():
        if sha(trusted(path(DESCRIPTOR))) != state['descriptor_sha256'] or receipt.get(DESCRIPTOR) != state['descriptor_sha256']:
            raise ValueError('retirement_descriptor_drift')
    for name in set(OWNED) - set(state['files']):
        if path(name).exists() or path(name).is_symlink():
            raise ValueError('retirement_new_runtime_file')
    for name, expected in state['files'].items():
        live = path(name)
        if live.exists() or live.is_symlink():
            if sha(trusted(live)) != expected or receipt.get(name) != expected:
                raise ValueError('retirement_owned_file_drift')
        elif name in receipt:
            pending = json.loads(trusted(path('/var/lib/ultra-ingress/managed.json.pending')))
            if (pending.get('version') != 1 or pending.get('path') != name
                    or pending.get('before') != expected or pending.get('after') is not None):
                raise ValueError('retirement_owned_receipt_drift')
    if phase == 'verify':
        if path(DESCRIPTOR).exists() or path(DESCRIPTOR).is_symlink() or DESCRIPTOR in receipt:
            raise ValueError('retirement_descriptor_still_published')
        cache = path('/var/lib/ultra-bot/subscriptions.json')
        raw = trusted(cache, bot=True)
        if cache.stat().st_mtime <= state['prepared_at']:
            raise ValueError('retirement_cache_refresh_required')
        snapshot = json.loads(raw)
        if snapshot.get('version') != 1 or not isinstance(snapshot.get('entries'), dict):
            raise ValueError('retirement_cache_invalid')
        for entry in snapshot['entries'].values():
            confirmed = datetime.fromisoformat(entry['confirmed_at'].replace('Z', '+00:00')).timestamp()
            body = base64.b64decode(entry['body'], validate=True)
            if (confirmed <= state['prepared_at'] or confirmed > datetime.now(timezone.utc).timestamp() + 60
                    or 'Эксперимент'.encode() in body or b'"remarks":"Experiment' in body):
                raise ValueError('retirement_cache_refresh_required')
    return state


def persist(state, journal, check_mode=False):
    if journal.exists() or journal.is_symlink():
        return False
    if check_mode:
        return True
    temporary = journal.with_suffix('.next')
    if temporary.exists() or temporary.is_symlink():
        trusted(temporary)
        temporary.unlink()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, journal)
        directory_fd = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return True


def main():
    module = AnsibleModule(argument_spec={'phase': {'type': 'str', 'choices': ['prepare', 'verify'], 'required': True}},
                           supports_check_mode=True)
    try:
        state = inspect(module.params['phase'])
        journal = Path(JOURNAL)
        changed = persist(state, journal, module.check_mode)
        module.exit_json(changed=changed, files=list(state['files']))
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='experimental_retirement_proof_failed')


if __name__ == '__main__':
    main()
