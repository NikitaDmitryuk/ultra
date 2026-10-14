#!/usr/bin/python
"""Write an owned file with the existing crash-safe ownership receipt contract."""
import hashlib
import json
import os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    temporary = path.with_name(path.name + '.ultra-next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        if path.exists():
            prior = path.stat()
            os.fchown(stream.fileno(), prior.st_uid, prior.st_gid)
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync(path.parent)


def apply(target, receipt, content, mode, check=False):
    if not target.is_absolute() or not receipt.is_absolute() or target == receipt:
        raise ValueError('invalid_owned_path')
    for path in (target, receipt, receipt.with_name(receipt.name + '.pending')):
        if path.is_symlink():
            raise ValueError('owned_path_symlink')
    pending = receipt.with_name(receipt.name + '.pending')
    state = json.loads(receipt.read_text()) if receipt.exists() else {}
    if pending.exists():
        transaction = json.loads(pending.read_text())
        path = Path(transaction['path'])
        if transaction.get('version') != 1 or not path.is_absolute() or path.is_symlink():
            raise ValueError('invalid_owned_transaction')
        current = digest(path.read_bytes()) if path.exists() else None
        choices = (transaction['before'], transaction['after'])
        if current not in choices or state.get(str(path)) not in choices:
            raise ValueError('owned_transaction_drift')
        if current is None:
            state.pop(str(path), None)
        else:
            state[str(path)] = current
        if not check:
            atomic(receipt, json.dumps(state, sort_keys=True).encode())
            pending.unlink()
            sync(receipt.parent)
    before = target.read_bytes() if target.exists() else None
    if before is not None and state.get(str(target)) != digest(before):
        raise ValueError('foreign_or_modified_file')
    changed = before != content or (content is not None and target.exists() and target.stat().st_mode & 0o777 != mode)
    if not changed or check:
        return changed
    transaction = {'version': 1, 'path': str(target), 'before': digest(before) if before is not None else None, 'after': digest(content) if content is not None else None}
    atomic(pending, json.dumps(transaction, sort_keys=True).encode())
    if content is None:
        target.unlink()
        sync(target.parent)
        state.pop(str(target), None)
    else:
        atomic(target, content, mode)
        state[str(target)] = digest(content)
    atomic(receipt, json.dumps(state, sort_keys=True).encode())
    pending.unlink()
    sync(receipt.parent)
    return True


def main():
    module = AnsibleModule(argument_spec={
        'path': {'type': 'path', 'required': True},
        'receipt': {'type': 'path', 'required': True},
        'content': {'type': 'str', 'no_log': True},
        'state': {'type': 'str', 'choices': ['present', 'absent'], 'default': 'present'},
        'mode': {'type': 'str', 'default': '0644'},
    }, supports_check_mode=True)
    try:
        mode = int(module.params['mode'], 8)
        if mode < 0 or mode > 0o777:
            raise ValueError('invalid_owned_mode')
        content = module.params['content']
        if module.params['state'] == 'present' and content is None:
            raise ValueError('owned_content_required')
        changed = apply(Path(module.params['path']), Path(module.params['receipt']), content.encode() if module.params['state'] == 'present' else None, mode, module.check_mode)
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='owned_file_verification_failed')
    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
