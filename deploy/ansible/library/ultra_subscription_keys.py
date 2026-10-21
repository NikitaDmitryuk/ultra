#!/usr/bin/python
"""Install a private subscription ring without replacing any known key ID."""
import base64
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import stat
import tempfile

SOURCE = '/var/lib/ultra-ansible/subscription-keys/incoming.json'
DESTINATION = '/var/lib/ultra-relay/automation/subscription-keys.json'


def unique_object(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('subscription_keys_invalid')
        result[key] = value
    return result


def ring(raw):
    value = json.loads(raw, object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {'active', 'keys'} or not isinstance(value['keys'], dict)
            or not isinstance(value['active'], str) or value['active'] not in value['keys'] or not value['keys']):
        raise ValueError('subscription_keys_invalid')
    for key_id, encoded in value['keys'].items():
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', key_id) or not isinstance(encoded, str)
                or len(base64.b64decode(encoded, validate=True)) != 32):
            raise ValueError('subscription_keys_invalid')
    return value


def private(path, owners):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or not 1 <= info.st_size <= 1048576):
            raise ValueError('subscription_keys_untrusted')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise ValueError('subscription_keys_untrusted')
        return raw
    finally:
        os.close(fd)


def install(src, dest, root=Path('/'), relay_uid=None, relay_gid=None):
    if src != SOURCE or dest != DESTINATION:
        raise ValueError('subscription_keys_path_invalid')
    if relay_uid is None:
        relay = pwd.getpwnam('ultra-relay')
        relay_uid, relay_gid = relay.pw_uid, relay.pw_gid
    root = Path(root)
    source, target = root / src.lstrip('/'), root / dest.lstrip('/')
    for path in (source, target):
        for parent in (path.parent, *path.parent.parents):
            info = parent.lstat()
            allowed = info.st_uid == os.geteuid()
            if parent == root / 'var/lib/ultra-relay':
                # systemd StateDirectory recreates the service-owned root as
                # 0755; the keyring remains behind its private automation dir.
                allowed = allowed or (info.st_uid == relay_uid and info.st_gid == relay_gid
                                      and stat.S_IMODE(info.st_mode) in (0o700, 0o755))
            elif parent == root / 'var/lib/ultra-relay/automation':
                allowed = allowed or (info.st_uid == relay_uid and info.st_gid == relay_gid
                                      and stat.S_IMODE(info.st_mode) == 0o700)
            if not stat.S_ISDIR(info.st_mode) or not allowed or info.st_mode & 0o022:
                raise ValueError('subscription_keys_parent_untrusted')
            if parent == root:
                break
        else:
            raise ValueError('subscription_keys_parent_untrusted')
    incoming_raw = private(source, {os.geteuid()})
    incoming = ring(incoming_raw)
    try:
        old_raw = private(target, {os.geteuid(), relay_uid})
        old = ring(old_raw)
    except FileNotFoundError:
        old_raw, old = None, {'keys': {}}
    for key_id, encoded in old['keys'].items():
        if key_id in incoming['keys'] and not hmac.compare_digest(base64.b64decode(encoded), base64.b64decode(incoming['keys'][key_id])):
            raise ValueError('subscription_key_id_conflict')
    merged = {'active': incoming['active'], 'keys': dict(old['keys'], **incoming['keys'])}
    output = incoming_raw if not old['keys'] else (json.dumps(merged, sort_keys=True) + '\n').encode()
    if old.get('active') == merged['active'] and old['keys'] == merged['keys'] and target.stat().st_uid == relay_uid and target.stat().st_gid == relay_gid:
        return False
    fd, temporary = tempfile.mkstemp(prefix='.subscription-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), relay_uid, relay_gid)
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={'src': {'type': 'path', 'required': True}, 'dest': {'type': 'path', 'required': True}})
    try:
        if os.geteuid() != 0:
            raise ValueError('subscription_keys_root_required')
        changed = install(module.params['src'], module.params['dest'])
        module.exit_json(changed=changed, verified=True)
    except Exception:
        module.fail_json(msg='subscription_keys_unverified')


if __name__ == '__main__':
    main()
