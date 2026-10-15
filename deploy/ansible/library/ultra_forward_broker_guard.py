#!/usr/bin/python
"""Read-only identity guard for the narrowly scoped forward broker bootstrap."""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import tarfile

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


def retained_private(path, directory=False):
    """Reject links and untrusted ownership at every retained path component."""
    source = Path(path)
    metadata = source.lstat()
    valid_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if (not valid_type or metadata.st_uid != 0 or metadata.st_mode & 0o077
            or (not directory and metadata.st_nlink != 1)):
        raise ValueError('forward_broker_retained_evidence_invalid')
    return metadata


def retained_asset(release, manifest, name):
    assets = manifest.get('assets')
    if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
        raise ValueError('forward_broker_retained_evidence_invalid')
    matches = [item for item in assets if item.get('name') == name]
    if len(matches) != 1:
        raise ValueError('forward_broker_retained_evidence_invalid')
    asset = matches[0]
    digest, size = asset.get('sha256'), asset.get('size')
    if (not isinstance(digest, str) or not SHA256.fullmatch(digest)
            or type(size) is not int or not 0 < size <= 2147483648):
        raise ValueError('forward_broker_retained_evidence_invalid')
    path = release / name
    metadata = retained_private(path)
    if metadata.st_size != size or regular_digest(path) != digest:
        raise ValueError('forward_broker_retained_evidence_invalid')
    return digest


def retained_previous_identity(previous):
    # This is historical root-owned build provenance, not signature validation.
    # Only the predecessor-frozen directory and unit digest select the release.
    if not isinstance(previous, dict) or set(previous) != {'directory', 'unit_sha256'}:
        raise ValueError('forward_broker_identity_invalid')
    directory, unit_sha = previous['directory'], previous['unit_sha256']
    match = re.fullmatch(r'/opt/ultra-ansible/releases/managed-(v0[.]0[.]([0-9]+))', directory) if isinstance(directory, str) else None
    if (not match or not isinstance(unit_sha, str) or not SHA256.fullmatch(unit_sha)
            or len(match[2]) > 49):
        raise ValueError('forward_broker_identity_invalid')
    version = match[1]
    commit = format(int(match[2]), '040x')
    if len(commit) != 40 or version != 'v0.0.' + str(int(commit, 16)):
        raise ValueError('forward_broker_identity_invalid')
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if architecture is None:
        raise ValueError('forward_broker_retained_evidence_invalid')
    inputs = ROOT / 'operator-inputs'
    retained_private(ROOT, True)
    retained_private(inputs, True)
    entries = list(inputs.iterdir())
    if len(entries) > 4096:
        raise ValueError('forward_broker_retained_evidence_invalid')
    candidates = [entry for entry in entries
                  if re.fullmatch('manual-' + commit + r'-[a-f0-9]{64}', entry.name)]
    if len(candidates) != 1:
        raise ValueError('forward_broker_retained_evidence_invalid')
    retained_private(candidates[0], True)
    release = candidates[0] / 'release'
    retained_private(release, True)
    manifest_path = release / 'release-manifest.json'
    retained_private(manifest_path)
    manifest = private_json(manifest_path, 1048576)
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1 or manifest.get('version') != version
            or manifest.get('source_commit') != commit):
        raise ValueError('forward_broker_retained_evidence_invalid')
    installer = retained_asset(release, manifest, 'ultra-install-linux-' + architecture)
    runtime = retained_asset(release, manifest, 'ultra-ansible-runtime-linux-' + architecture + '.tar.gz')
    retained_asset(release, manifest, 'ultra-ansible.tar.gz')
    template_name = 'roles/controller/templates/ultra-ansible-controller.service.j2'
    templates = []
    with tarfile.open(release / 'ultra-ansible.tar.gz', 'r:gz') as archive:
        for count, member in enumerate(archive):
            if count >= 10000:
                raise ValueError('forward_broker_retained_evidence_invalid')
            if member.name == template_name:
                if not member.isfile() or not 0 < member.size <= 65536:
                    raise ValueError('forward_broker_retained_evidence_invalid')
                templates.append(archive.extractfile(member).read().decode('utf-8', errors='strict'))
    if len(templates) != 1:
        raise ValueError('forward_broker_retained_evidence_invalid')
    unit = templates[0].replace('{{ ultra_controller_directory }}', directory)
    if hashlib.sha256(unit.encode()).hexdigest() != unit_sha:
        raise ValueError('forward_broker_retained_evidence_invalid')
    return {'directory': directory, 'unit_sha256': unit_sha,
            'installer_sha256': installer, 'runtime_sha256': runtime}


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
        previous = params.get('previous_broker', {})
        if not previous or not broker_matches(retained_previous_identity(previous)):
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
        'previous_broker': {'type': 'dict', 'default': {}},
    }, supports_check_mode=True)
    try:
        result = verify(module.params)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError,
            subprocess.TimeoutExpired, tarfile.TarError, EOFError):
        module.fail_json(msg='forward_broker_identity_unverified')
    module.exit_json(changed=False, **result)


if __name__ == '__main__':
    main()
