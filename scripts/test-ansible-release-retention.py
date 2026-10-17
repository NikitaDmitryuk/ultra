#!/usr/bin/env python3
"""Local executable retention regressions; no SSH, secrets, or production state."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from types import ModuleType
from unittest.mock import patch

import yaml

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_release_retention.py'
spec = importlib.util.spec_from_file_location('retention', source)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def refuses(call):
    try:
        call()
    except (ValueError, OSError):
        return
    raise AssertionError('unsafe retention accepted')


def runtime_ownership_regression():
    root = source.parents[3]
    tasks = yaml.safe_load((root / 'deploy/ansible/roles/controller/tasks/runtime.yml').read_text())
    extraction = next(task['ansible.builtin.unarchive'] for task in tasks
                      if task.get('name') == 'Install offline runtime files')
    assert extraction.get('owner') == 'root' and extraction.get('group') == 'root'
    builder_spec = importlib.util.spec_from_file_location('runtime_builder', root / 'scripts/build-ansible-runtime.py')
    builder = importlib.util.module_from_spec(builder_spec)
    builder_spec.loader.exec_module(builder)
    original_header = tarfile.TarFile.gettarinfo

    def builder_header(archive, *args, **kwargs):
        member = original_header(archive, *args, **kwargs)
        member.uid = member.gid = 1000
        member.uname = member.gname = 'builder'
        return member

    def download_fixture(command, **kwargs):
        wheels = Path(command[command.index('--dest') + 1])
        (wheels / 'fixture-1-py3-none-any.whl').write_bytes(b'offline wheel fixture')

    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        output = base / 'runtime.tar.gz'
        with patch.object(builder, 'PINS', ['fixture==1']), \
                patch.object(builder.sys, 'argv', ['builder', '--architecture', 'amd64', '--output', str(output)]), \
                patch.object(builder.subprocess, 'run', side_effect=download_fixture), \
                patch.object(tarfile.TarFile, 'gettarinfo', builder_header):
            builder.main()
        controller = base / 'controllers' / 'fixture'
        runtime = controller / 'runtime'
        runtime.mkdir(parents=True, mode=0o700)
        controller.chmod(0o700)
        with tarfile.open(output) as archive:
            members = archive.getmembers()
            assert {member.name for member in members} == {'requirements.lock', 'wheels/fixture-1-py3-none-any.whl'}
            assert all((member.uid, member.gid, member.uname, member.gname) == (0, 0, 'root', 'root')
                       for member in members), 'runtime inherited builder ownership'
            archive.extractall(runtime, filter='data')
        wheel = runtime / 'wheels/fixture-1-py3-none-any.whl'
        assert wheel.read_bytes() == b'offline wheel fixture'
        assert (runtime / 'requirements.lock').read_text() == 'fixture==1 --hash=sha256:' + r.digest(wheel) + '\n'
        receipts = base / 'receipts'
        identity = {'runtime/requirements.lock': r.digest(runtime / 'requirements.lock')}
        original_lstat = Path.lstat

        def root_stat(path, *args, **kwargs):
            # Model root extraction locally without requiring chown privileges.
            values = list(original_lstat(path, *args, **kwargs))
            values[4] = values[5] = 0
            return os.stat_result(values)

        with patch.object(r.os, 'geteuid', return_value=0), patch.object(Path, 'lstat', root_stat):
            r.store(r.receipt_path(controller, receipts), {'path': str(controller), 'identity': identity, 'pending': True})
            assert r.seal(controller, identity, [str(controller.parent)], receipts, controller=True)

            def foreign_stat(path, *args, **kwargs):
                values = list(root_stat(path, *args, **kwargs))
                if path == wheel:
                    values[4] = 1000
                return os.stat_result(values)

            with patch.object(Path, 'lstat', foreign_stat):
                try:
                    r.seal(controller, identity, [str(controller.parent)], receipts, controller=True)
                except ValueError as error:
                    assert str(error) == 'retention_foreign_tree'
                else:
                    raise AssertionError('root seal accepted foreign runtime ownership')


runtime_ownership_regression()


def failure_reason_regression():
    class FakeModule:
        params = {'action': 'seal', 'path': '/fixture', 'expected': {'fixture': '0' * 64},
                  'controller': True, 'optional': []}
        check_mode = False

        def fail_json(self, **result):
            self.result = result

    for error, expected in ((ValueError('retention_foreign_tree'), 'retention_foreign_tree'),
                            (OSError('sensitive fixture path'), 'retention_inspection_failed'),
                            (ValueError('retention_foreign_tree: sensitive fixture path'), 'retention_inspection_failed')):
        module = FakeModule()
        basic = ModuleType('ansible.module_utils.basic')
        basic.AnsibleModule = lambda **kwargs: module
        with patch.dict(sys.modules, {'ansible': ModuleType('ansible'),
                                    'ansible.module_utils': ModuleType('ansible.module_utils'),
                                    'ansible.module_utils.basic': basic}), \
                patch.object(r, 'seal', side_effect=error):
            r.main()
        assert module.result == {'msg': 'release_retention_blocked_unknown_or_changed_identity', 'exception': '', 'reason_code': expected}


failure_reason_regression()


with tempfile.TemporaryDirectory() as temporary:
    base = Path(temporary)
    roots = [str(base / name) for name in ('snapshots', 'controllers', 'tools')]
    receipts = base / 'receipts'
    for root in roots:
        Path(root).mkdir(mode=0o700)
    # Adoption must not retroactively claim or overwrite an unowned legacy
    # controller, even when its installer checksum matches the release.
    legacy = Path(roots[1]) / 'v0.1.0'
    legacy.mkdir(mode=0o700)
    (legacy / 'ultra-install').write_bytes(b'fixture installer')
    (legacy / 'ultra-install').chmod(0o700)
    legacy_before = r.inventory(legacy)
    expected_controller = {'ultra-install': r.digest(legacy / 'ultra-install')}
    refuses(lambda: r.begin(legacy, expected_controller, roots, receipts, check=True))
    managed = Path(roots[1]) / 'managed-v0.1.0'
    assert r.begin(managed, expected_controller, roots, receipts)
    managed.mkdir(mode=0o700)
    shutil.copyfile(legacy / 'ultra-install', managed / 'ultra-install')
    (managed / 'ultra-install').chmod(0o700)
    assert r.seal(managed, expected_controller, roots, receipts, controller=True)
    assert not r.begin(managed, expected_controller, roots, receipts)
    assert not r.seal(managed, expected_controller, roots, receipts, controller=True)
    assert r.inventory(legacy) == legacy_before
    assert not r.receipt_path(legacy, receipts).exists()
    # Keep this separately verified controller outside subsequent fixture GC.
    shutil.rmtree(managed)
    r.receipt_path(managed, receipts).unlink()
    shutil.rmtree(legacy)
    trees = {}
    for version in ('v1.0.0', 'v2.0.0', 'v3.0.0'):
        for root in roots:
            path = Path(root) / version
            path.mkdir(mode=0o700)
            (path / 'binary').write_bytes(version.encode())
            (path / 'binary').chmod(0o600)
            expected = {'binary': r.digest(path / 'binary')}
            assert r.seal(path, expected, roots, receipts)
            assert not r.seal(path, expected, roots, receipts)
            trees[(root, version)] = path
    keep = [str(trees[(roots[0], 'v3.0.0')])] + [str(trees[(root, version)]) for root in roots[1:] for version in ('v2.0.0', 'v3.0.0')]
    before = r.plan(keep, roots=roots, receipts=receipts)
    assert len(before) == 4
    # Interrupted upgrade/restore inputs protect an otherwise obsolete runtime.
    jobs = base / 'jobs'
    job = jobs / 'operation' / 'apply'
    request = {'variables': {'ultra_previous_controller_directory': str(trees[(roots[1], 'v1.0.0')])}}
    write(job / 'request.json', request)
    jobs.chmod(0o700)
    identity = r.digest(job / 'request.json')
    write(job / 'job.json', {'schema_version': 1, 'operation': 'configure-exit', 'request_sha256': identity})
    assert len(r.plan(keep, r.live_jobs(jobs), roots, receipts)) == 3
    write(job / 'receipt.json', {'state': 'running', 'request_sha256': identity})
    assert len(r.plan(keep, r.live_jobs(jobs), roots, receipts)) == 3
    write(job / 'receipt.json', {'state': 'failed', 'request_sha256': identity})
    assert len(r.plan(keep, r.live_jobs(jobs), roots, receipts)) == 4
    # A real collector's lock/policy metadata must not pin the entire source cache.
    collector = jobs / 'retain-source' / 'operation'
    old_source = Path(roots[2]) / 'v1.0.0'
    collector_request = {'variables': {'ultra_lock_directory': str(base),
                         'ultra_retention_auto_policy': str(base / 'private-policy.json'),
                         'ultra_auto_upgrade_policy': {'operation_lock_directory': str(base),
                                                       'state_directory': roots[2],
                                                       'channel_state_file': str(base / 'channel/state.json')}}}
    write(collector / 'request.json', collector_request)
    write(collector / 'job.json', {'schema_version': 1, 'operation': 'retain-artifacts',
          'request_sha256': r.digest(collector / 'request.json')})
    assert str(old_source) in r.plan(keep, r.live_jobs(jobs), roots, receipts)
    collector_request['variables']['ultra_release_source'] = str(old_source)
    write(collector / 'request.json', collector_request)
    write(collector / 'job.json', {'schema_version': 1, 'operation': 'upgrade',
          'request_sha256': r.digest(collector / 'request.json')})
    assert str(old_source) not in r.plan(keep, r.live_jobs(jobs), roots, receipts)
    write(collector / 'receipt.json', {'state': 'failed', 'request_sha256': r.digest(collector / 'request.json')})
    # Backup's nested artifact references independently protect old runtime.
    assert len(r.plan(keep, [str(trees[(roots[1], 'v1.0.0')] / 'binary')], roots, receipts)) == 3
    # A changed or unknown owned tree blocks the complete plan, before removal.
    old = trees[(roots[0], 'v1.0.0')]
    (old / 'foreign').write_text('untouched')
    retained = []
    assert str(old) not in r.plan(keep, roots=roots, receipts=receipts, retained=retained)
    assert str(old) in retained
    (old / 'foreign').unlink()
    unknown = Path(roots[0]) / 'unknown'
    unknown.mkdir(mode=0o700)
    retained = []
    r.plan(keep, roots=roots, receipts=receipts, retained=retained)
    assert str(unknown) in retained
    unknown.rmdir()
    (old / 'binary').write_text('drift')
    assert str(old) not in r.plan(keep, roots=roots, receipts=receipts)
    (old / 'binary').write_bytes(b'v1.0.0')
    # Controller ownership cannot be retroactively claimed from one matching binary.
    controller = Path(roots[1]) / 'new'
    controller.mkdir(mode=0o700)
    (controller / 'binary').write_text('fresh')
    refuses(lambda: r.seal(controller, {'binary': r.digest(controller / 'binary')}, roots, receipts, controller=True))
    shutil.rmtree(controller)
    identity = {'binary': hashlib.sha256(b'fresh').hexdigest()}
    assert r.begin(controller, identity, roots, receipts)
    # Crash after intent and population, before sealing: exact identity resumes.
    controller.mkdir(mode=0o700)
    (controller / 'binary').write_text('fresh')
    assert not r.begin(controller, identity, roots, receipts)
    refuses(lambda: r.begin(controller, {'binary': '0' * 64}, roots, receipts))
    assert r.seal(controller, identity, roots, receipts, controller=True)
    source = controller / 'module.py'
    source.write_text('answer = 42')
    # This source predates final sealing of a second known runtime.
    second = Path(roots[1]) / 'second'
    assert r.begin(second, identity, roots, receipts)
    second.mkdir(mode=0o700)
    (second / 'binary').write_text('fresh')
    (second / 'module.py').write_text('answer = 42')
    assert r.seal(second, identity, roots, receipts, controller=True)
    cache = second / '__pycache__'
    cache.mkdir()
    (cache / 'module.cpython-312.pyc').write_bytes(b'generated')
    assert not r.seal(second, identity, roots, receipts, controller=True)
    # An unknown cache member is not hidden by its directory name.
    (cache / 'foreign').write_text('preserve')
    assert str(second) not in r.plan(keep, roots=roots, receipts=receipts)
    (cache / 'foreign').unlink()
    shutil.rmtree(controller)
    shutil.rmtree(second)
    # Terminal bundle proof preserves every small immutable source input/receipt.
    bundle = job / 'bundle'
    bundle.mkdir(mode=0o700)
    (bundle / 'controller.py').write_text('source')
    request_identity = r.digest(job / 'request.json')
    write(job / 'bundle.retention.json', {'schema': 1, 'path': str(bundle),
          'identity': {'request_sha256': request_identity}, 'inventory': r.inventory(bundle)})
    copied_binary = job / 'ultra-relay'
    copied_binary.write_bytes(b'copied-relay')
    copied_binary.chmod(0o700)
    binary_identity = hashlib.sha256(b'copied-relay').hexdigest()
    write(job / 'job.json', {'schema_version': 1, 'operation': 'configure-exit',
          'request_sha256': request_identity, 'binary_sha256': binary_identity})
    assert r.terminal_bundles(jobs, ['v3.0.0']) == [str(copied_binary), str(bundle)]
    copied_binary.write_bytes(b'unknown-relay')
    retained = []
    assert r.terminal_bundles(jobs, ['v3.0.0'], retained=retained) == [str(bundle)]
    assert str(copied_binary) in retained
    copied_binary.unlink()
    # Fixed collector attempts are unique standalone work, unlike operator stages.
    write(job / 'job.json', {'schema_version': 1, 'operation': 'retain-artifacts', 'request_sha256': request_identity})
    write(job / 'receipt.json', {'state': 'running', 'request_sha256': request_identity})
    assert not r.terminal_bundles(jobs, ['v3.0.0'])
    write(job / 'receipt.json', {'state': 'succeeded', 'request_sha256': request_identity})
    assert r.terminal_bundles(jobs, ['v3.0.0']) == [str(bundle)]
    write(job / 'receipt.json', {'state': 'failed', 'request_sha256': request_identity})
    assert r.terminal_bundles(jobs, ['v3.0.0']) == [str(bundle)]
    write(job / 'job.json', {'schema_version': 1, 'operation': 'configure-exit', 'request_sha256': request_identity})
    assert r.terminal_bundles(jobs, ['v3.0.0']) == [str(bundle)]
    write(job / 'job.json', {'schema_version': 1, 'operation': 'inspect-upgrade', 'request_sha256': request_identity})
    assert not r.terminal_bundles(jobs, ['v3.0.0']), 'lost commit reply must preserve operator bundle'
    write(job / 'job.json', {'schema_version': 1, 'operation': 'configure-exit', 'request_sha256': request_identity})
    write(job / 'receipt.json', {'state': 'running', 'request_sha256': request_identity})
    assert not r.terminal_bundles(jobs, ['v3.0.0'])
    write(job / 'receipt.json', {'state': 'failed', 'request_sha256': request_identity})
    (bundle / 'foreign').write_text('leave this')
    assert not r.terminal_bundles(jobs, ['v3.0.0'])
    (bundle / 'foreign').unlink()
    shutil.rmtree(bundle)
    assert (job / 'request.json').exists() and (job / 'receipt.json').exists()
    # An artifact directory ancestor pins every covered tree.
    assert not r.plan([], [roots[1]], [roots[1]], receipts)
    # Standard Ansible file deletion is modeled only after the complete proof.
    for path in r.plan(keep, roots=roots, receipts=receipts):
        shutil.rmtree(path)
    assert not r.plan(keep, roots=roots, receipts=receipts)
    assert (job / 'request.json').exists() and (job / 'receipt.json').exists()
    for path in keep:
        assert Path(path).is_dir()
with tempfile.TemporaryDirectory() as temporary:
    system = Path(temporary)
    installed = system / 'usr/local/bin'
    installed.mkdir(parents=True)
    (installed / 'ultra-relay').write_bytes(b'current-relay')
    (installed / 'ultra-bot').write_bytes(b'current-bot')
    def manifest(version, relay):
        return {'version': version, 'source_commit': 'f' * 40,
                'database_schema_min': 1, 'database_schema_max': 24,
                'capabilities': ['service-access-v1', 'provider-pool-quota-v1'],
                'assets': [{'name': 'ultra-relay-linux-amd64', 'sha256': hashlib.sha256(relay).hexdigest()},
                           {'name': 'ultra-bot-linux-amd64', 'sha256': hashlib.sha256(b'current-bot').hexdigest()}]}
    current = system / 'opt/ultra-recovery/release-manifest.json'
    write(current, manifest('v3.0.0', b'current-relay'))
    snapshot_root = system / 'var/lib/ultra-ansible/releases'
    snapshot = snapshot_root / 'v3.0.0'
    snapshot.mkdir(parents=True, mode=0o700)
    write(snapshot / 'manifest.previous', manifest('v2.0.0', b'previous-relay'))
    (snapshot / 'ultra-relay.previous').write_bytes(b'previous-relay')
    receipts = system / 'receipts'
    r.seal(snapshot, {name: r.digest(snapshot / name) for name in ('manifest.previous', 'ultra-relay.previous')},
           (str(snapshot_root),), receipts)
    operation_root = system / 'jobs'
    operation_root.mkdir(mode=0o700)
    policy = {'current_manifest': str(current), 'operation_lock_directory': str(operation_root)}
    assert r.active_versions(policy, receipts, system) == ['v2.0.0', 'v3.0.0']
    channel = operation_root / 'channel/state.json'
    pending = {'version': 'v4.0.0', 'source_commit': 'a' * 40, 'manifest_sha256': 'b' * 64}
    write(channel, {'schema_version': 1, 'failed': {}, 'pending': pending})
    assert r.active_versions(policy, receipts, system) == ['v2.0.0', 'v3.0.0', 'v4.0.0'], 'terminal phases cannot unpin pending transaction'
    write(channel, {'schema_version': 1, 'failed': {'v4.0.0': 'activation_failed'}, 'pending': pending})
    assert r.active_versions(policy, receipts, system) == ['v2.0.0', 'v3.0.0']
    write(channel, {'schema_version': 1, 'failed': {}, 'pending': {**pending, 'manifest_sha256': 'invalid'}})
    refuses(lambda: r.active_versions(policy, receipts, system))
    write(channel, {'schema_version': 1, 'failed': {}})
    # Old collector cleanup remains possible even when active code identity drifts.
    policy_path = operation_root / 'policy.json'
    write(policy_path, policy)
    def collector_fixture(name, state):
        transaction = operation_root / name
        transaction.mkdir(mode=0o700)
        attempt = transaction / 'collect'
        write(attempt / 'request.json', {'variables': {'ultra_retention_auto_policy': str(policy_path)}})
        transaction_id = r.digest(attempt / 'request.json')
        write(attempt / 'job.json', {'schema_version': 1, 'operation': 'retain-artifacts',
              'request_sha256': transaction_id, 'binary_sha256': transaction_id})
        write(attempt / 'receipt.json', {'state': state, 'request_sha256': transaction_id,
              'binary_sha256': transaction_id})
        payload = attempt / 'bundle'
        payload.mkdir(mode=0o700)
        (payload / 'controller.py').write_text('fixture')
        write(attempt / 'bundle.retention.json', {'schema': 1, 'path': str(payload),
              'identity': {'request_sha256': transaction_id}, 'inventory': r.inventory(payload)})
        return payload
    prior_collector = collector_fixture('retain-source-prior', 'succeeded')
    current_collector = collector_fixture('retain-source-current', 'running')
    assert r.collector_plan(policy_path) == [str(prior_collector)]
    (installed / 'ultra-relay').write_bytes(b'identity-drift')
    refuses(lambda: r.active_versions(policy, receipts, system))
    assert r.collector_plan(policy_path) == [str(prior_collector)]
    assert current_collector.is_dir()
    (installed / 'ultra-relay').write_bytes(b'current-relay')
    # Changed bundles and policy metadata remain intact rather than being guessed.
    (prior_collector / 'unknown').write_text('keep')
    retained = []
    assert not r.collector_plan(policy_path, retained)
    assert str(prior_collector) in retained
    (prior_collector / 'unknown').unlink()
    write(policy_path, {**policy, 'operation_lock_directory': '/tmp'})
    refuses(lambda: r.collector_plan(policy_path))
    write(policy_path, {**policy, 'padding': 'x' * 65536})
    refuses(lambda: r.collector_plan(policy_path))
    write(policy_path, policy)
    policy_path.chmod(0o644)
    refuses(lambda: r.collector_plan(policy_path))
    policy_path.chmod(0o600)
    (snapshot / 'ultra-relay.previous').write_bytes(b'foreign')
    refuses(lambda: r.active_versions(policy, receipts, system))
    # Initial adopted installations use the exact verified emergency binary.
    shutil.rmtree(snapshot)
    emergency = system / 'usr/local/libexec'
    emergency.mkdir(parents=True)
    write(emergency / 'ultra-emergency-manifest.json', manifest('v3.0.0', b'current-relay'))
    (emergency / 'ultra-relay-emergency').write_bytes(b'current-relay')
    assert r.active_versions(policy, receipts, system) == ['v3.0.0']
# Regression: all old operator payloads were previously skipped by the typed
# terminal-job allowlist (four committed releases yielded zero removals).
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    operations = []
    for version in ('v1.0.0', 'v2.0.0', 'v3.0.0', 'v4.0.0'):
        operation = root / ('operation-' + version)
        write(operation / 'inventory.frozen.json', {'all': {}})
        write(operation / 'execution-mode.json', {'target': 'fixture'})
        payloads = {}
        for name in ('inspect', 'verify-failed', 'commit'):
            job = operation / name
            write(job / 'request.json', {'variables': {'ultra_release_version': version}})
            identity = r.digest(job / 'request.json')
            write(job / 'job.json', {'schema_version': 1, 'operation': name, 'request_sha256': identity})
            write(job / 'receipt.json', {'state': 'failed' if name == 'verify-failed' else 'succeeded', 'request_sha256': identity})
            payload = job / 'bundle'
            payload.mkdir(mode=0o700)
            (payload / 'controller.py').write_text('fixture')
            if name == 'verify-failed':
                (payload / '__pycache__').mkdir(mode=0o700)
                (payload / '__pycache__' / 'controller.cpython-312.pyc').write_bytes(b'cache')
            write(job / 'bundle.retention.json', {'schema': 1, 'path': str(payload), 'identity': {'request_sha256': identity}, 'inventory': r.inventory(payload)})
            payloads[str(payload.relative_to(operation))] = r.inventory(payload)
        recovery = operation / 'recovery-bundle'
        recovery.mkdir(mode=0o700)
        (recovery / 'recovery.py').write_text('fixture')
        payloads['recovery-bundle'] = r.inventory(recovery)
        metadata = {str(path.relative_to(operation)): r.digest(path) for path in operation.rglob('*.json')}
        write(operation / 'operation.completed.json', {'schema': 1, 'path': str(operation),
              'operation_id': str(r.uuid.UUID(bytes=hashlib.sha256(str(operation).encode()).digest()[:16], version=4)),
              'kind': 'upgrade', 'version': version, 'source_commit': 'a' * 40,
              'manifest_sha256': 'b' * 64, 'metadata': metadata, 'payloads': payloads})
        operations.append(operation)
    assert r.terminal_bundles(root, ['v3.0.0', 'v4.0.0']) == [], 'before: operator allowlist skips all stages'
    paths = r.completed_operations(root, ['v3.0.0', 'v4.0.0'])
    assert len(paths) == 16, 'after: completed copies are collectable even for current/emergency versions'
    (operations[0] / 'verify-failed' / 'bundle' / 'controller.py').unlink()
    assert str(operations[0] / 'verify-failed' / 'bundle') in r.completed_operations(root, ['v3.0.0', 'v4.0.0']), 'durable deletion intent resumes a partial tree'
    assert not r.live_jobs(root), 'whole success releases historical executable inputs'
    # Superseded observations preserve the interrupted receipt; their narrow
    # retirement proof authenticates the later same-release successful check.
    operation = operations[0]
    observer_jobs = []
    for name, state in (('verify-interrupted', 'running'), ('verify-later', 'succeeded')):
        job = operation / name
        write(job / 'request.json', {'variables': {'ultra_release_version': 'v1.0.0', 'ultra_release_manifest_sha256': 'b' * 64}})
        identity = r.digest(job / 'request.json')
        write(job / 'job.json', {'schema_version': 1, 'operation': 'verify-release', 'request_sha256': identity})
        write(job / 'receipt.json', {'state': state, 'code': 'interrupted' if state == 'running' else '', 'request_sha256': identity, 'result': {'verified': state == 'succeeded'}})
        observer_jobs.append(job)
    original, winner = observer_jobs
    state = r.read(operation / 'operation.completed.json')
    write(original / 'observation.retired.json', {'schema': 1, 'operation_id': state['operation_id'], 'stage_directory': str(original),
          'request_sha256': r.digest(original / 'request.json'), 'receipt_sha256': r.digest(original / 'receipt.json'),
          'winning_stage': str(winner), 'winning_request_sha256': r.digest(winner / 'request.json'), 'winning_receipt_sha256': r.digest(winner / 'receipt.json')})
    state['metadata'] = {str(path.relative_to(operation)): r.digest(path) for path in operation.rglob('*.json') if path.name != 'operation.completed.json'}
    write(operation / 'operation.completed.json', state)
    assert r.operation_completion(operation)
    assert not r.live_jobs(root), 'retired cancelled observer cannot pin historical code forever'

    # Partial collection and repeated planning preserve durable completion.
    shutil.rmtree(operations[0] / 'inspect' / 'bundle')
    assert len(r.completed_operations(root, ['v3.0.0', 'v4.0.0'])) == 15
    assert r.operation_completion(operations[0])
    (operations[1] / 'operation.completed.json').unlink()
    assert len(r.completed_operations(root, ['v3.0.0', 'v4.0.0'])) == 11
    assert str(operations[1] / 'commit' / 'bundle') in r.live_jobs(root), 'terminal children cannot complete a transaction'
    # In-flight consumers keep a completed parent's linked source bundle.
    linked = root / 'unfinished' / 'apply'
    write(linked / 'request.json', {'variables': {'ultra_restore_script_directory': str(operations[0] / 'commit' / 'bundle')}})
    write(linked / 'job.json', {'schema_version': 1, 'operation': 'bootstrap', 'request_sha256': r.digest(linked / 'request.json')})
    assert str(operations[0] / 'commit' / 'bundle') not in r.completed_operations(root, [], r.live_jobs(root))
    (operations[0] / 'recovery-bundle' / 'foreign').write_text('preserve')
    retained = []
    assert str(operations[0] / 'recovery-bundle') not in r.completed_operations(root, [], retained=retained)
    assert str(operations[0] / 'recovery-bundle') in retained
print('release retention regressions passed')
