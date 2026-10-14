#!/usr/bin/python
"""Read-only receipt adapter for an explicitly pinned heterogeneous baseline."""
import hashlib
import base64
import hmac
import json
from pathlib import Path
import re
import shlex
import stat
from ansible.module_utils.basic import AnsibleModule

ROOT_UID = 0
OWNERSHIP_ROOT = Path("/")
ADOPTION_ROOT = Path("/var/lib/ultra-ansible/adoption")


def owned(path, private=False, directory=False):
    path = Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('baseline_path_invalid')
    for ancestor in path.parents:
        info = ancestor.lstat()
        if info.st_uid != ROOT_UID or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
            raise ValueError('baseline_ancestor_ownership_invalid')
        if ancestor == OWNERSHIP_ROOT:
            break
    info = path.lstat()
    if info.st_uid != ROOT_UID or info.st_mode & (0o077 if private else 0o022) or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('baseline_ownership_invalid')
    return path


def digest(path):
    value = hashlib.sha256()
    with owned(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


def read(path):
    path = owned(path, private=True)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('baseline_document_too_large')
    return json.loads(path.read_text())


def receipt(proof, operation):
    stage = owned(proof['stage'], private=True, directory=True)
    raw = owned(stage / 'request.json', private=True).read_bytes()
    if len(raw) > 4 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != proof['request_sha256']:
        raise ValueError('baseline_request_changed')
    request, job, result = json.loads(raw), read(stage / 'job.json'), read(stage / 'receipt.json')
    # Older schema-1 bootstrap receipts omit attempt from both job and receipt.
    # Their root-owned stage path and pinned request digest remain the anchor.
    job_attempt, receipt_attempt = 'attempt' in job, 'attempt' in result
    attempt_valid = (not job_attempt and not receipt_attempt) or (
        job_attempt and receipt_attempt and type(job.get('attempt')) is int and job['attempt'] >= 1
        and result.get('attempt') == job['attempt'])
    if (job.get('schema_version') != 1 or job.get('operation') != operation
            or job.get('request_sha256') != proof['request_sha256'] or job.get('binary_sha256') != proof['request_sha256']
            or not attempt_valid
            or any(result.get(key) != job.get(key) for key in ('schema_version', 'operation', 'request_sha256', 'binary_sha256'))
            or result.get('state') != 'succeeded' or result.get('result', {}).get('verified') is not True):
        raise ValueError('baseline_receipt_unverified')
    return request, result['result']


def asset(manifest, component, architecture):
    values = [a for a in manifest['assets'] if a['name'] == component + '-linux-' + architecture]
    if len(values) != 1 or not re.fullmatch('[a-f0-9]{64}', values[0]['sha256']) or not isinstance(values[0]['size'], int) or values[0]['size'] <= 0:
        raise ValueError('baseline_asset_invalid')
    return values[0]


def pins(text, address):
    keys = set()
    candidates = (address, '[' + address + ']:22')
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[0].startswith(('#', '@')):
            continue
        for selector in fields[0].split(','):
            matched = selector in candidates
            if selector.startswith('|1|'):
                parts = selector.split('|')
                if len(parts) == 4 and parts[1] == '1':
                    try:
                        salt = base64.b64decode(parts[2], validate=True)
                        expected = base64.b64decode(parts[3], validate=True)
                    except (ValueError, base64.binascii.Error):
                        continue
                    matched = any(hmac.compare_digest(hmac.new(salt, host.encode(), hashlib.sha1).digest(), expected)
                                  for host in candidates)
            if matched:
                keys.add(tuple(fields[1:3]))
                break
    if not keys:
        raise ValueError('baseline_inventory_pins_missing')
    return keys


def verify(inputs, nodes, bridge_address):
    descriptor, manifest = inputs['descriptor'], inputs['manifest']
    root = owned(inputs['remote_release'], private=True, directory=True)
    manifest_path = root / 'release-manifest.json'
    if digest(manifest_path) != descriptor['manifest_sha256'] or read(manifest_path) != manifest:
        raise ValueError('baseline_retained_manifest_changed')
    seen = set()
    for member in manifest['assets']:
        name = member['name']
        if not isinstance(name, str) or Path(name).name != name or name in seen or name in ('.', '..'):
            raise ValueError('baseline_retained_member_invalid')
        seen.add(name)
        source = owned(root / name)
        if source.stat().st_size != member['size'] or digest(source) != member['sha256']:
            raise ValueError('baseline_retained_member_changed')
    if set(descriptor['exits']) != set(nodes):
        raise ValueError('baseline_topology_changed')
    aliases = set()
    for identity, proof in descriptor['exits'].items():
        request, result = receipt(proof, 'bootstrap-exit')
        alias = proof['alias']
        if alias in aliases or request['variables'].get('ultra_bootstrap_exit_host') != alias or result.get('exit_host') != alias:
            raise ValueError('baseline_exit_selector_changed')
        aliases.add(alias)
        inventory = request['inventory']['all']
        # bootstrap-exit is a LOCAL_OPERATION: request.inventory retains
        # application host vars; job.binary_sha256 identifies the request,
        # unlike configure-exit's staged relay binary. Never mix those contracts.
        host = inventory['children']['exits']['hosts'][alias]
        spec = host['ultra_spec']
        candidates = [asset(manifest, 'ultra-relay', arch) for arch in ('amd64', 'arm64') if any(a['name'] == 'ultra-relay-linux-' + arch for a in manifest['assets'])]
        matches = [a for a in candidates if host.get('ultra_relay_source') == str(root / a['name']) and host.get('ultra_relay_sha256') == a['sha256']]
        if len(matches) != 1:
            raise ValueError('baseline_exit_asset_unbound')
        expected = matches[0]
        if (host.get('ansible_host') != nodes[identity]['address'] or spec.get('role') != 'exit'
                or host.get('ultra_relay_source') != str(root / expected['name']) or host.get('ultra_relay_sha256') != expected['sha256']):
            raise ValueError('baseline_exit_identity_changed')
        arguments = shlex.split(host.get('ansible_ssh_common_args', inventory['vars'].get('ansible_ssh_common_args', '')))
        files = [arg.split('=', 1)[1] for arg in arguments if arg.startswith('UserKnownHostsFile=')]
        if len(files) != 1 or pins(owned(files[0]).read_text(), nodes[identity]['address']) != pins(nodes[identity]['pins'], nodes[identity]['address']):
            raise ValueError('baseline_exit_pins_changed')
    bridge, _ = receipt(descriptor['bridge'], 'rollback-adoption')
    bridge_host = bridge['inventory']['all']['children']['bridge']['hosts']['bridge']
    operation = bridge['variables']['ultra_lifecycle_id']
    checkpoint = ADOPTION_ROOT / operation / 'checkpoint.json'
    if (not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', operation)
            or bridge_host.get('ansible_host') != bridge_address or descriptor['bridge']['checkpoint'] != str(checkpoint)
            or digest(checkpoint) != descriptor['bridge']['checkpoint_sha256']):
        raise ValueError('baseline_bridge_checkpoint_unbound')
    saved = read(checkpoint)
    emergency = saved['emergency_manifest']
    expected = asset(emergency, 'ultra-relay', saved['architecture'])
    retained = owned(checkpoint.parent / 'rollback-relay', private=True)
    if saved.get('legacy') is not True or retained.stat().st_size != expected['size'] or digest(retained) != expected['sha256']:
        raise ValueError('baseline_emergency_changed')
    return {'bridge_relay': emergency, 'exits': {identity: manifest for identity in nodes}}


def main():
    module = AnsibleModule(argument_spec={'input': {'type': 'dict', 'required': True}, 'nodes': {'type': 'dict', 'required': True}, 'bridge_address': {'type': 'str', 'required': True}}, supports_check_mode=True)
    try:
        result = verify(module.params['input'], module.params['nodes'], module.params['bridge_address'])
        module.exit_json(changed=False, verified=True, baseline=result)
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='upgrade_baseline_provenance_unverified')


if __name__ == '__main__':
    main()
