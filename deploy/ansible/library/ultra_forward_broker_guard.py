#!/usr/bin/python
"""Read-only identity guard for the narrowly scoped forward broker bootstrap."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess

ROOT = Path('/var/lib/ultra-ansible')
UNIT = '/etc/systemd/system/ultra-ansible-controller.service'
CURRENT = Path('/opt/ultra-ansible/current')
UUID = re.compile(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}')
SHA256 = re.compile(r'[a-f0-9]{64}')


def private_json(path, limit=65536):
    source = Path(path)
    metadata = source.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o077 or metadata.st_size > limit):
        raise ValueError('forward_broker_evidence_invalid')
    return json.loads(source.read_text())


def regular_digest(path, follow=False):
    source = Path(path)
    metadata = source.stat() if follow else source.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022):
        raise ValueError('forward_broker_artifact_invalid')
    return hashlib.sha256(source.read_bytes()).hexdigest()


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False, timeout=5)
    if result.returncode:
        raise ValueError('forward_broker_service_unavailable')
    return result.stdout.decode('utf-8', errors='strict').strip()


def check_lifecycle(old_id, candidate_id):
    state = private_json(ROOT / 'lifecycle.json', 4096)
    if state != {'id': old_id, 'phase': 'applying'}:
        raise ValueError('forward_broker_lifecycle_changed')
    ledger_path = ROOT / 'lifecycle-retired.json'
    if ledger_path.exists() or ledger_path.is_symlink():
        ledger = private_json(ledger_path, 65536)
        if (set(ledger) - {'version', 'ids', 'handoff'} or ledger.get('version') != 1
                or not isinstance(ledger.get('ids'), list)
                or any(not isinstance(item, str) or not UUID.fullmatch(item) for item in ledger['ids'])
                or len(set(ledger['ids'])) != len(ledger['ids'])):
            raise ValueError('forward_broker_retirement_invalid')
        handoff = ledger.get('handoff')
        if handoff is not None:
            if (not isinstance(handoff, dict) or set(handoff) != {'old_id', 'new_id'}
                    or handoff.get('old_id') not in ledger['ids']
                    or not isinstance(handoff.get('new_id'), str)
                    or not UUID.fullmatch(handoff['new_id'])):
                raise ValueError('forward_broker_retirement_invalid')
            if {old_id, candidate_id} & {handoff['old_id'], handoff['new_id']}:
                raise ValueError('forward_broker_retirement_conflict')
        if old_id in ledger['ids'] or candidate_id in ledger['ids']:
            raise ValueError('forward_broker_retirement_conflict')


def broker_matches(identity):
    validate_identity(identity)
    directory = identity.get('directory')

    if not CURRENT.is_symlink() or os.readlink(CURRENT) != directory:
        return False
    if regular_digest(UNIT) != identity['unit_sha256']:
        return False
    if regular_digest(Path(directory) / 'ultra-install') != identity['installer_sha256']:
        return False
    marker = Path(directory) / 'runtime.sha256'
    if regular_digest(marker) != hashlib.sha256((identity['runtime_sha256'] + '\n').encode()).hexdigest():
        return False

    values = {}
    for key in ('ActiveState', 'MainPID', 'FragmentPath', 'DropInPaths', 'ControlGroup'):
        values[key] = command(['systemctl', 'show', '--property=' + key, '--value',
                               'ultra-ansible-controller.service'])
    pid = values['MainPID']
    if (values['ActiveState'] != 'active' or not pid.isdigit() or int(pid) <= 1
            or values['FragmentPath'] != UNIT or values['DropInPaths']
            or values['ControlGroup'] != '/system.slice/ultra-ansible-controller.service'):
        return False

    proc = Path('/proc') / pid
    exe = os.readlink(proc / 'exe')
    if exe != str(Path(directory) / 'ultra-install'):
        return False
    if regular_digest(proc / 'exe', follow=True) != identity['installer_sha256']:
        return False
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    argv = [item.decode('utf-8', errors='strict') for item in argv if item]
    expected = [str(Path(directory) / 'ultra-install'), 'ansible-controller', '--executable',
                str(Path(directory) / 'venv' / 'bin' / 'ansible-playbook')]
    return argv == expected


def validate_identity(identity):
    directory = identity.get('directory')
    if (set(identity) != {'directory', 'installer_sha256', 'runtime_sha256', 'unit_sha256'}
            or not isinstance(directory, str)
            or not re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}', directory)
            or any(not isinstance(identity.get(key), str) or not SHA256.fullmatch(identity[key])
                   for key in ('installer_sha256', 'runtime_sha256', 'unit_sha256'))):
        raise ValueError('forward_broker_identity_invalid')


def verify(params):
    if os.geteuid() != 0:
        raise ValueError('forward_broker_root_required')
    old_id, candidate_id, action = params['old_id'], params['candidate_id'], params['action']
    if (not UUID.fullmatch(old_id) or not UUID.fullmatch(candidate_id) or old_id == candidate_id
            or action not in ('before', 'after')):
        raise ValueError('forward_broker_identity_invalid')
    check_lifecycle(old_id, candidate_id)
    expected = params['expected_brokers']
    target = params['target_broker']
    if (not isinstance(expected, list) or not expected or not isinstance(target, dict)
            or len(expected) > 3 or any(not isinstance(item, dict) for item in expected)):
        raise ValueError('forward_broker_identity_invalid')
    for identity in [*expected, target]:
        validate_identity(identity)
    matches = [broker_matches(item) for item in expected]
    target_matches = broker_matches(target)
    if action == 'before' and not any(matches):
        raise ValueError('forward_broker_predecessor_mismatch')
    if action == 'after' and not target_matches:
        raise ValueError('forward_broker_target_mismatch')
    return {'verified': True, 'old_id': old_id, 'candidate_id': candidate_id,
            'controller_directory': target['directory'] if action == 'after' else None}


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'required': True, 'choices': ['before', 'after']},
        'old_id': {'type': 'str', 'required': True},
        'candidate_id': {'type': 'str', 'required': True},
        'expected_brokers': {'type': 'list', 'elements': 'dict', 'required': True},
        'target_broker': {'type': 'dict', 'required': True},
    }, supports_check_mode=True)
    try:
        result = verify(module.params)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError,
            subprocess.TimeoutExpired):
        module.fail_json(msg='forward_broker_identity_unverified')
    module.exit_json(changed=False, **result)


if __name__ == '__main__':
    main()
