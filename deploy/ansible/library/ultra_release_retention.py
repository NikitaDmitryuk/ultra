#!/usr/bin/python
"""Prove release ownership and references; Ansible alone removes proven trees.

The caller must hold the fleet infrastructure lease across planning and deletion.
Only immutable executable trees are inventoried; state and job histories never are.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

ROOTS = ('/var/lib/ultra-ansible/releases', '/opt/ultra-ansible/releases', '/opt/ultra-recovery/releases')
RECEIPTS = '/var/lib/ultra-ansible/retention'


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def private(path, directory=False):
    if any(ancestor.is_symlink() for ancestor in path.parents):
        raise ValueError('retention_path_symlink')
    info = path.lstat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('retention_private_metadata_required')


def read(path):
    private(path)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('retention_metadata_too_large')
    return json.loads(path.read_text())


def owned_path(path, roots):
    path = Path(path)
    if str(path.parent) not in roots or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', path.name):
        raise ValueError('retention_path_invalid')
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('retention_path_symlink')
    private(path, directory=True)
    return path


def inventory(path):
    result = {}
    for base, directories, files in os.walk(path, followlinks=False):
        for name in sorted(directories + files):
            item = Path(base) / name
            info = item.lstat()
            if info.st_uid != os.geteuid() or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                raise ValueError('retention_foreign_tree')
            key = str(item.relative_to(path))
            # CPython caches are reproducible derivatives of an inventoried source.
            # Other files in cache directories remain ordinary immutable members.
            if item.parent.name == '__pycache__' and stat.S_ISREG(info.st_mode):
                match = re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc', name)
                source = item.parent.parent / (match.group(1) + '.py') if match else None
                if source and source.is_file() and not source.is_symlink():
                    continue
            if name == '__pycache__' and stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISLNK(info.st_mode):
                result[key] = ['link', os.readlink(item)]
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ValueError('retention_shared_file')
                result[key] = ['file', digest(item), stat.S_IMODE(info.st_mode)]
            elif stat.S_ISDIR(info.st_mode):
                result[key] = ['directory', stat.S_IMODE(info.st_mode)]
            else:
                raise ValueError('retention_special_file')
    return result


def receipt_path(path, receipts):
    return Path(receipts) / (hashlib.sha256(str(path).encode()).hexdigest() + '.json')


def store(target, state):
    parent = target.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o700)
    private(parent, directory=True)
    fd, temporary = tempfile.mkstemp(dir=parent, prefix='.retention-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        descriptor = os.open(parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def begin(path, expected, roots=ROOTS, receipts=RECEIPTS, check=False):
    path = Path(path)
    if str(path.parent) not in roots or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', path.name):
        raise ValueError('retention_path_invalid')
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('retention_path_symlink')
    target = receipt_path(path, receipts)
    if target.exists():
        saved = read(target)
        if saved.get('path') != str(path) or saved.get('identity') != expected:
            raise ValueError('retention_intent_conflict')
        return False
    if path.exists():
        raise ValueError('retention_unowned_controller')
    if not check:
        store(target, {'schema': 1, 'path': str(path), 'identity': expected, 'pending': True})
    return True


def seal(path, expected, roots=ROOTS, receipts=RECEIPTS, controller=False, check=False, optional=()):
    path = owned_path(path, roots)
    if any(Path(name).is_absolute() or '..' in Path(name).parts for name in list(expected) + list(optional)):
        raise ValueError('retention_member_path_invalid')
    for name, checksum in expected.items():
        item = path / name
        if item.is_symlink() or not item.is_file() or digest(item) != checksum:
            raise ValueError('retention_identity_mismatch')
    identity = dict(expected)
    for name in optional:
        item = path / name
        if item.exists():
            if item.is_symlink() or not item.is_file():
                raise ValueError('retention_optional_member_invalid')
            expected = {**expected, name: digest(item)}
    target = receipt_path(path, receipts)
    prior = read(target) if target.exists() else None
    if controller and (prior is None or prior.get('identity') != identity):
        raise ValueError('retention_unowned_controller')
    contents = inventory(path)
    if not controller and {key for key, value in contents.items() if value[0] != 'directory'} != set(expected):
        raise ValueError('retention_unknown_member')
    state = {'schema': 1, 'path': str(path), 'identity': identity, 'inventory': contents}
    if prior and not prior.get('pending'):
        if prior != state:
            raise ValueError('retention_owned_tree_changed')
        return False
    if not check:
        store(target, state)
    return True


def references(value):
    result = set()
    if isinstance(value, str) and value.startswith('/'):
        result.add(os.path.normpath(value))
    elif isinstance(value, dict):
        for child in value.values():
            result.update(references(child))
    elif isinstance(value, list):
        for child in value:
            result.update(references(child))
    return result


def artifact_references(value):
    """Select executable inputs, excluding lease/policy/control metadata paths."""
    result = set()
    if isinstance(value, dict):
        for key, child in value.items():
            selected = (key in ('artifact_paths', 'controller_directory', 'release_dir', 'source',
                                'ultra_controller_directory', 'ultra_previous_controller_directory',
                                'ultra_release_probe_executable', 'ultra_restore_script_directory') or
                        (key.startswith('ultra_') and key.endswith(('_source', '_archive'))))
            if selected:
                result.update(references(child))
            elif isinstance(child, (dict, list)):
                result.update(artifact_references(child))
    elif isinstance(value, list):
        for child in value:
            result.update(artifact_references(child))
    return result


INDEPENDENT_JOBS = ('configure-exit', 'configure-replica', 'stop-replica', 'retain-artifacts')
PAYLOAD_DIRECTORIES = ('bundle', 'recovery-bundle', 'ansible-tmp', '__pycache__')


def retired_observation_valid(directory, stage):
    proof_path = stage / 'observation.retired.json'
    if not proof_path.exists():
        return False
    proof = read(proof_path)
    winner = Path(proof.get('winning_stage', ''))
    try:
        winner.relative_to(directory)
    except ValueError:
        return False
    if (proof.get('schema') != 1 or proof.get('operation_id') != str(uuid.UUID(bytes=hashlib.sha256(str(directory).encode()).digest()[:16], version=4)) or
            proof.get('stage_directory') != str(stage) or winner == stage):
        return False
    def observation(path):
        job = read(path / 'job.json')
        receipt = read(path / 'receipt.json')
        request = read(path / 'request.json')
        request_hash = digest(path / 'request.json')
        if (job.get('schema_version') != 1 or job.get('operation') not in ('verify-release', 'verify-bootstrap-automation') or
                job.get('request_sha256') != request_hash or receipt.get('request_sha256') != request_hash):
            raise ValueError('retention_observation_identity_invalid')
        variables = request.get('variables', {})
        identity = ((variables.get('ultra_release_version'), variables.get('ultra_release_manifest_sha256'))
                    if job['operation'] == 'verify-release' else
                    (variables.get('ultra_automation_version'), variables.get('ultra_automation_manifest_source')))
        return job['operation'], receipt, request_hash, digest(path / 'receipt.json'), identity
    original = observation(stage)
    accepted = observation(winner)
    return (original[0] == accepted[0] and original[1].get('state') == 'running' and original[1].get('code') == 'interrupted' and
            original[2] == proof.get('request_sha256') and original[3] == proof.get('receipt_sha256') and
            accepted[1].get('state') == 'succeeded' and accepted[1].get('result', {}).get('verified') is True and
            accepted[2] == proof.get('winning_request_sha256') and accepted[3] == proof.get('winning_receipt_sha256') and
            original[4][0] and original[4] == accepted[4])


def operation_completion(directory):
    """Authenticate durable whole-success metadata, including every child job.

    Payloads can already be absent after partial collection. Their recorded full
    inventories are checked separately immediately before scheduling deletion.
    """
    path = directory / 'operation.completed.json'
    if not path.exists():
        return None
    state = read(path)
    if (state.get('schema') != 1 or state.get('path') != str(directory) or
            state.get('kind') not in ('upgrade', 'bootstrap') or
            state.get('operation_id') != str(uuid.UUID(bytes=hashlib.sha256(str(directory).encode()).digest()[:16], version=4)) or
            not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', state.get('version', '')) or
            not re.fullmatch(r'[a-f0-9]{40}', state.get('source_commit', '')) or
            not re.fullmatch(r'[a-f0-9]{64}', state.get('manifest_sha256', '')) or
            not isinstance(state.get('metadata'), dict) or not isinstance(state.get('payloads'), dict) or
            not isinstance(state.get('bundle_receipts', {}), dict)):
        raise ValueError('retention_operation_completion_invalid')
    metadata = {}
    for base, directories, files in os.walk(directory, followlinks=False):
        directories[:] = [name for name in directories if name not in PAYLOAD_DIRECTORIES]
        for name in directories:
            if (Path(base) / name).is_symlink():
                raise ValueError('retention_operation_symlink')
        for name in files:
            item = Path(base) / name
            if item.is_symlink():
                raise ValueError('retention_operation_symlink')
            if name.endswith('.json') and name != 'operation.completed.json':
                read(item)
                metadata[str(item.relative_to(directory))] = digest(item)
        if 'job.json' in files:
            job = read(Path(base) / 'job.json')
            request = Path(base) / 'request.json'
            receipt = read(Path(base) / 'receipt.json')
            if (job.get('schema_version') != 1 or job.get('request_sha256') != digest(request) or
                    (receipt.get('state') not in ('succeeded', 'failed') and not retired_observation_valid(directory, Path(base))) or
                    receipt.get('request_sha256') != job['request_sha256']):
                raise ValueError('retention_operation_stage_incomplete')
    if metadata != state['metadata'] or not metadata.get('inventory.frozen.json') or not metadata.get('execution-mode.json'):
        raise ValueError('retention_operation_completion_changed')
    return state


def completed_parent(directory, root):
    for parent in (directory, *directory.parents):
        if parent == root:
            break
        if (parent / 'operation.completed.json').exists():
            return parent, operation_completion(parent)
    return None, None


def operation_deletion_permitted(root, path, actual, expected, check=False):
    receipts = root / 'retention'
    intent = receipts / ('operation-delete-' + hashlib.sha256(str(path).encode()).hexdigest() + '.json')
    state = {'schema': 1, 'path': str(path), 'inventory': expected}
    if not intent.exists():
        if actual != expected:
            return False
        if not check:
            store(intent, state)
        return True
    if read(intent) != state:
        return False
    for key, value in actual.items():
        member = Path(key)
        if member.parent.name == '__pycache__' and value[0] == 'file':
            match = re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc', member.name)
            source = str(member.parent.parent / (match.group(1) + '.py')) if match else None
            if source in expected and expected[source][0] == 'file':
                continue
        if key not in expected or expected[key] != value:
            return False
    return True


def completed_operations(root, versions, refs=(), retained=None, check=False):
    removals = []
    if not root.exists():
        return removals
    for base, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in PAYLOAD_DIRECTORIES + ('releases', 'retention', 'downloads')]
        if 'operation.completed.json' not in files:
            continue
        directory = Path(base)
        try:
            state = operation_completion(directory)
            payloads = dict(state['payloads'])
            for relative, receipt in state.get('bundle_receipts', {}).items():
                member = Path(relative)
                if (member.is_absolute() or '..' in member.parts or member.name != 'bundle' or
                        receipt != str(member.parent / 'bundle.retention.json')):
                    raise ValueError('retention_operation_bundle_reference_invalid')
                proof = read(directory / receipt)
                if (proof.get('schema') != 1 or proof.get('path') != str(directory / relative) or
                        proof.get('identity') != {'request_sha256': digest(directory / member.parent / 'request.json')} or
                        not isinstance(proof.get('inventory'), dict)):
                    raise ValueError('retention_operation_bundle_reference_invalid')
                expected = dict(proof['inventory'])
                for key, value in list(expected.items()):
                    part = Path(key)
                    if part.name == '__pycache__':
                        del expected[key]
                    elif part.parent.name == '__pycache__' and value[0] == 'file':
                        match = re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc', part.name)
                        source = str(part.parent.parent / (match.group(1) + '.py')) if match else None
                        if source in expected and expected[source][0] == 'file':
                            del expected[key]
                payloads[relative] = expected
            for relative, expected in payloads.items():
                member = Path(relative)
                if (member.is_absolute() or '..' in member.parts or member.name not in ('bundle', 'recovery-bundle') and relative not in ('automation-sources/tools', 'automation-sources/bootstrap_plan.py')):
                    raise ValueError('retention_operation_payload_invalid')
                payload = directory / member
                if not payload.exists() and not payload.is_symlink():
                    continue
                if any(ref == str(payload) or ref.startswith(str(payload) + '/') or str(payload).startswith(ref.rstrip('/') + '/') for ref in refs):
                    continue
                private(payload, directory=payload.is_dir())
                actual = inventory(payload) if payload.is_dir() else {'': ['file', digest(payload), stat.S_IMODE(payload.stat().st_mode)]}
                if (payload.is_symlink() or payload.stat().st_nlink != 1 and not payload.is_dir() or
                        not operation_deletion_permitted(root, payload, actual, expected, check)):
                    if retained is not None:
                        retained.append(str(payload))
                    continue
                removals.append(str(payload))
        except (ValueError, OSError):
            if retained is not None:
                retained.append(str(directory))
    return removals


def live_jobs(root):
    """Terminal history stays on disk, but does not pin every obsolete executable."""
    result = set()
    if not root.exists():
        return result
    private(root, directory=True)
    for base, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in ('bundle', 'ansible-tmp', 'releases', 'retention', 'downloads')]
        for name in directories:
            if (Path(base) / name).is_symlink():
                raise ValueError('retention_job_symlink')
        if 'job.json' not in files:
            continue
        directory = Path(base)
        private(directory, directory=True)
        job = read(directory / 'job.json')
        raw = directory / 'request.json'
        request = read(raw)
        if job.get('schema_version') != 1 or job.get('request_sha256') != digest(raw):
            raise ValueError('retention_job_identity_invalid')
        receipt = read(directory / 'receipt.json') if (directory / 'receipt.json').exists() else {}
        if receipt and receipt.get('request_sha256') != job['request_sha256']:
            raise ValueError('retention_job_receipt_invalid')
        state = receipt.get('state')
        if state not in (None, 'running', 'failed', 'succeeded'):
            raise ValueError('retention_job_state_invalid')
        _, completed = completed_parent(directory, root)
        if completed is None and (state not in ('failed', 'succeeded') or job.get('operation') not in INDEPENDENT_JOBS):
            result.update(artifact_references(request))
            result.add(str(directory / 'bundle'))
            variables = request.get('variables', {})
            version = variables.get('ultra_release_version')
            if version:
                if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
                    raise ValueError('retention_job_version_invalid')
                result.add(str(Path(root) / 'releases' / version))
    return result


def plan(keep, refs=(), roots=ROOTS, receipts=RECEIPTS, retained=None):
    keep = set(keep) | set(refs)
    removals = []
    # Validate every candidate before Ansible removes anything; unknown trees stay.
    for root_name in roots:
        root = Path(root_name)
        if not root.exists():
            continue
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('retention_foreign_root')
        for path in sorted(root.iterdir()):
            try:
                owned_path(path, roots)
            except (ValueError, OSError):
                if retained is not None:
                    retained.append(str(path))
                continue
            if any(ref == str(path) or ref.startswith(str(path) + '/') or str(path).startswith(ref.rstrip('/') + '/') for ref in keep):
                continue
            try:
                state = read(receipt_path(path, receipts))
                if state.get('schema') != 1 or state.get('path') != str(path) or state.get('inventory') != inventory(path):
                    raise ValueError('retention_owned_tree_changed')
            except (ValueError, OSError):
                if retained is not None:
                    retained.append(str(path))
                continue
            removals.append(str(path))
    return removals


def terminal_bundles(root, versions, refs=(), retained=None):
    """Drop only proven immutable payloads; all requests and receipts survive."""
    removals = []
    if not root.exists():
        return removals
    private(root, directory=True)
    for base, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in ('bundle', 'ansible-tmp', 'releases', 'retention', 'downloads')]
        if 'job.json' not in files:
            continue
        directory = Path(base)
        private(directory, directory=True)
        job = read(directory / 'job.json')
        request_path = directory / 'request.json'
        request = read(request_path)
        if job.get('schema_version') != 1 or job.get('request_sha256') != digest(request_path):
            raise ValueError('retention_job_identity_invalid')
        receipt = read(directory / 'receipt.json') if (directory / 'receipt.json').exists() else {}
        if receipt.get('state') not in ('failed', 'succeeded'):
            continue
        # Operator phases may need their original bundle after a lost reply or
        # explicit retry. Independent typed jobs and the fresh fixed collector
        # can discard their terminal payload while keeping their audit metadata.
        if job.get('operation') not in INDEPENDENT_JOBS:
            continue
        if receipt.get('request_sha256') != job['request_sha256']:
            raise ValueError('retention_job_receipt_invalid')
        variables = request.get('variables', {})
        if variables.get('ultra_release_version') in versions:
            continue
        binary = directory / 'ultra-relay'
        if job.get('operation') != 'retain-artifacts' and (binary.exists() or binary.is_symlink()):
            try:
                private(binary)
                info = binary.lstat()
                expected_hash = job.get('binary_sha256', '')
                if (info.st_nlink != 1 or not re.fullmatch(r'[a-f0-9]{64}', expected_hash) or
                        digest(binary) != expected_hash):
                    raise ValueError('retention_job_binary_changed')
                if not any(ref == str(binary) or str(binary).startswith(ref.rstrip('/') + '/') for ref in refs):
                    removals.append(str(binary))
            except (ValueError, OSError):
                if retained is not None:
                    retained.append(str(binary))
        payload = directory / 'bundle'
        if not payload.exists():
            continue
        if any(ref == str(payload) or ref.startswith(str(payload) + '/') or str(payload).startswith(ref.rstrip('/') + '/') for ref in refs):
            continue
        try:
            private(payload, directory=True)
            state = read(directory / 'bundle.retention.json')
            if (state.get('schema') != 1 or state.get('path') != str(payload) or
                    state.get('identity') != {'request_sha256': job['request_sha256']} or
                    state.get('inventory') != inventory(payload)):
                raise ValueError('retention_job_bundle_changed')
        except (OSError, ValueError):
            if retained is not None:
                retained.append(str(payload))
            continue
        removals.append(str(payload))
    return removals


def collector_plan(policy_path, retained=None):
    """Standalone collector payloads need no active application-code proof."""
    policy_path = Path(policy_path)
    policy = read(policy_path)
    if policy_path.stat().st_size > 65536:
        raise ValueError('retention_auto_policy_invalid')
    operation_root = policy.get('operation_lock_directory')
    if (not isinstance(operation_root, str) or not operation_root.startswith('/') or
            os.path.normpath(operation_root) != operation_root or
            operation_root in ('/', '/opt', '/var', '/tmp', '/etc', '/home')):
        raise ValueError('retention_auto_policy_invalid')
    root = Path(operation_root)
    private(root, directory=True)
    removals = []
    for transaction in sorted(root.iterdir()):
        if not re.fullmatch(r'retain-source-[A-Za-z0-9_-]+', transaction.name):
            continue
        directory = transaction / 'collect'
        payload = directory / 'bundle'
        try:
            private(transaction, directory=True)
            private(directory, directory=True)
            job = read(directory / 'job.json')
            if job.get('operation') != 'retain-artifacts':
                continue
            identity = job.get('request_sha256', '')
            if (job.get('schema_version') != 1 or not re.fullmatch(r'[a-f0-9]{64}', identity) or
                    not re.fullmatch(r'[a-f0-9]{64}', job.get('binary_sha256', ''))):
                raise ValueError('retention_collector_identity_invalid')
            request = directory / 'request.json'
            read(request)
            if digest(request) != identity:
                raise ValueError('retention_collector_identity_invalid')
            result = read(directory / 'receipt.json') if (directory / 'receipt.json').exists() else {}
            if result.get('state') not in (None, 'running', 'failed', 'succeeded'):
                raise ValueError('retention_collector_receipt_invalid')
            if result.get('state') not in ('failed', 'succeeded'):
                continue
            if result.get('request_sha256') != identity or result.get('binary_sha256') != job.get('binary_sha256'):
                raise ValueError('retention_collector_receipt_invalid')
            if not payload.exists() and not payload.is_symlink():
                continue
            private(payload, directory=True)
            proof = read(directory / 'bundle.retention.json')
            if (proof.get('schema') != 1 or proof.get('path') != str(payload) or
                    proof.get('identity') != {'request_sha256': identity} or proof.get('inventory') != inventory(payload)):
                raise ValueError('retention_collector_bundle_changed')
        except (ValueError, OSError, TypeError):
            if retained is not None:
                retained.append(str(payload))
            continue
        removals.append(str(payload))
    return removals


def compatible(previous, current):
    required = {'service-access-v1', 'provider-pool-quota-v1'}
    for manifest in (previous, current):
        if (not required.issubset(set(manifest.get('capabilities', []))) or
                not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', manifest.get('version', '')) or
                not isinstance(manifest.get('database_schema_min'), int) or
                not isinstance(manifest.get('database_schema_max'), int)):
            raise ValueError('retention_compatible_manifest_required')
    if not (0 < previous['database_schema_min'] <= current['database_schema_min'] <=
            current['database_schema_max'] <= previous['database_schema_max']):
        raise ValueError('retention_compatible_manifest_required')


def active_versions(policy, receipts=RECEIPTS, system_root=Path('/')):
    """Resolve code identity from bytes, never from a current symlink label."""
    physical = lambda name: system_root / name.lstrip('/')
    current_path = Path(policy['current_manifest'])
    for name in ('/usr/local/bin/ultra-relay', '/usr/local/bin/ultra-bot'):
        info = physical(name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('retention_active_code_invalid')
    current = read(current_path)
    compatible(current, current)
    matches = [asset for asset in current['assets'] if
               re.fullmatch(r'ultra-relay-linux-(amd64|arm64)', asset.get('name', '')) and
               asset.get('sha256') == digest(physical('/usr/local/bin/ultra-relay'))]
    if len(matches) != 1:
        raise ValueError('retention_active_code_invalid')
    architecture = matches[0]['name'].rsplit('-', 1)[1]
    bot = [asset for asset in current['assets'] if asset.get('name') == 'ultra-bot-linux-' + architecture]
    if len(bot) != 1 or bot[0].get('sha256') != digest(physical('/usr/local/bin/ultra-bot')):
        raise ValueError('retention_active_code_invalid')
    snapshot = physical('/var/lib/ultra-ansible/releases') / current['version']
    previous_path = snapshot / 'manifest.previous'
    if previous_path.exists():
        owned_path(snapshot, tuple(str(physical(name)) for name in ROOTS))
        proof = read(receipt_path(snapshot, receipts))
        if (proof.get('path') != str(snapshot) or proof.get('schema') != 1 or
                proof.get('inventory') != inventory(snapshot)):
            raise ValueError('retention_active_snapshot_invalid')
        previous = read(previous_path)
        fallback = snapshot / 'ultra-relay.previous'
    else:
        previous = read(physical('/usr/local/libexec/ultra-emergency-manifest.json'))
        fallback = physical('/usr/local/libexec/ultra-relay-emergency')
    compatible(previous, current)
    assets = [asset for asset in previous['assets'] if asset.get('name') == 'ultra-relay-linux-' + architecture]
    if fallback.is_symlink() or len(assets) != 1 or assets[0].get('sha256') != digest(fallback):
        raise ValueError('retention_emergency_code_invalid')
    versions = {current['version'], previous['version']}
    manifest_identities = {current['version']: (digest(current_path), current.get('source_commit')),
                           previous['version']: (digest(previous_path) if previous_path.exists() else
                                                 digest(physical('/usr/local/libexec/ultra-emergency-manifest.json')),
                                                 previous.get('source_commit'))}
    channel_path = Path(policy.get('channel_state_file') or str(Path(policy['operation_lock_directory']) / 'channel/state.json'))
    if channel_path.exists():
        channel = read(channel_path)
        if (channel.get('schema_version') != 1 or not isinstance(channel.get('failed'), dict) or
                set(channel) - {'schema_version', 'failed', 'accepted', 'pending'} or
                any(not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version) or code not in ('activation_failed', 'resume_failed')
                    for version, code in channel['failed'].items())):
            raise ValueError('retention_channel_state_invalid')
        for key in ('accepted', 'pending'):
            identity = channel.get(key)
            if identity is None:
                continue
            if (not isinstance(identity, dict) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', identity.get('version', '')) or
                    not re.fullmatch(r'[a-f0-9]{64}', identity.get('manifest_sha256', '')) or
                    not re.fullmatch(r'[a-f0-9]{40}', identity.get('source_commit', ''))):
                raise ValueError('retention_channel_identity_invalid')
            proven = manifest_identities.get(identity['version'])
            if proven and proven != (identity['manifest_sha256'], identity['source_commit']):
                raise ValueError('retention_channel_manifest_conflict')
            if key == 'pending' and identity['version'] in channel['failed']:
                continue  # Explicit failure marker preserves audit, no automatic retry.
            versions.add(identity['version'])
    return sorted(versions)


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'choices': ['begin', 'seal', 'plan', 'source-plan', 'job-plan'], 'required': True},
        'path': {'type': 'path'}, 'expected': {'type': 'dict', 'default': {}},
        'controller': {'type': 'bool', 'default': False},
        'optional': {'type': 'list', 'elements': 'str', 'default': []},
        'keep': {'type': 'list', 'elements': 'str', 'default': []},
        'job_root': {'type': 'path', 'default': '/var/lib/ultra-ansible'},
        'backup_policy': {'type': 'path'},
        'auto_policy': {'type': 'path'},
        'versions': {'type': 'list', 'elements': 'str', 'default': []},
    }, supports_check_mode=True)
    try:
        params = module.params
        if params['action'] == 'job-plan':
            if not params['auto_policy']:
                raise ValueError('retention_auto_policy_required')
            retained = []
            paths = collector_plan(params['auto_policy'], retained)
            if retained:
                module.warn('release_retention_retained_unknown: ' + str(len(retained)) + ' collector payloads retained')
            module.exit_json(changed=False, paths=paths, retained_unknown=retained)
        if params['action'] in ('begin', 'seal'):
            if not params['path'] or not params['expected']:
                raise ValueError('retention_identity_required')
            changed = (begin(params['path'], params['expected'], check=module.check_mode) if params['action'] == 'begin' else
                       seal(params['path'], params['expected'], controller=params['controller'], check=module.check_mode, optional=params['optional']))
            module.exit_json(changed=changed)
        refs = live_jobs(Path(params['job_root']))
        if params['backup_policy']:
            policy = read(Path(params['backup_policy']))
            paths = policy.get('artifact_paths')
            if not isinstance(paths, list) or not all(isinstance(path, str) and path.startswith('/') for path in paths):
                raise ValueError('retention_backup_references_invalid')
            refs.update(paths)
        retained = []
        paths = [] if params['action'] == 'source-plan' else plan(params['keep'], refs, retained=retained)
        if params['auto_policy'] and Path(params['auto_policy']).exists():
            policy = read(Path(params['auto_policy']))
            source_root = policy.get('state_directory')
            operation_root = policy.get('operation_lock_directory')
            if (not isinstance(source_root, str) or not isinstance(operation_root, str) or
                    not source_root.startswith('/') or not operation_root.startswith('/') or
                    os.path.normpath(source_root) != source_root or os.path.normpath(operation_root) != operation_root or
                    source_root in ROOTS or source_root == operation_root or source_root in ('/', '/opt', '/var', '/tmp')):
                raise ValueError('retention_auto_policy_invalid')
            versions = active_versions(policy, str(Path(operation_root) / 'retention')) if params['action'] == 'source-plan' else params['versions']
            if not versions or any(not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version) for version in versions):
                raise ValueError('retention_keep_version_invalid')
            source_keep = [str(Path(source_root) / version) for version in versions]
            source_refs = refs | live_jobs(Path(operation_root))
            paths += plan(source_keep, source_refs, (source_root,), str(Path(operation_root) / 'retention'), retained)
            paths += terminal_bundles(Path(operation_root), versions, source_refs, retained)
            paths += completed_operations(Path(operation_root), versions, source_refs, retained, check=module.check_mode)
        if params['action'] == 'source-plan' and (not params['auto_policy'] or not Path(params['auto_policy']).exists()):
            raise ValueError('retention_auto_policy_required')
        if retained:
            module.warn('release_retention_retained_unknown: ' + str(len(retained)) + ' executable trees retained')
        module.exit_json(changed=False, paths=paths, retained_unknown=retained)
    except (ValueError, KeyError, OSError, TypeError) as error:
        # Expose only our fixed invariant code, never paths or exception details.
        code = str(error)
        if not isinstance(error, ValueError) or not re.fullmatch(r'retention_[a-z_]+', code):
            code = 'retention_inspection_failed'
        module.fail_json(msg='release_retention_blocked_unknown_or_changed_identity', exception='', reason_code=code)


if __name__ == '__main__':
    main()
