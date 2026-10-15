#!/usr/bin/env python3
"""Fixture and mocked tests only; never contact a deployment host."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import hashlib
import shutil
import signal
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('manual_deploy', Path(__file__).with_name('manual-deploy.py'))
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class ManualDeploy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.root = self.repo / 'state'
        self.root.mkdir(mode=0o700)
        self.config = self.repo / 'install.config'
        self.original = b'# keep\nINSTALL_SCHEMA_VERSION=2\nOTHER="literal $() ${HOME}"\nULTRA_AUTOMATION_VERSION=v1.2.3\nULTRA_AUTOMATION_RELEASE_DIR=/old\n'
        self.config.write_bytes(self.original)
        self.config.chmod(0o600)
        self.commit = 'a' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.bundle = self.root / self.version
        self.bundle.mkdir()
        (self.bundle / 'release-manifest.json').write_bytes(b'fixture-manifest')
        self.calls = []

    def run_fixture(self, command, cwd, stage, capture=False, env=None):
        self.calls.append((stage, command))

    def rollout(self, adopt=False, runner=None, config_path=None, retry_failed=False, probe_env_file=None, forward_only=False, continue_forward_only=False):
        with patch.object(D, 'run', runner or self.run_fixture), patch.object(D.platform, 'system', return_value='Linux'), patch.object(D.platform, 'machine', return_value='x86_64'), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            D.rollout(self.repo, self.root, self.bundle, self.commit, self.version, adopt, config_path, retry_failed, probe_env_file, forward_only, continue_forward_only)

    def probe_env(self, value=b'https://old.example.com/sub/fixture-token'):
        path = self.repo / '.env'
        path.write_bytes(b'IGNORED_SECRET="$(must-not-execute)\xff\nULTRA_SUBSCRIPTION_PROBE_URL=' + value + b'\n')
        path.chmod(0o600)
        return path

    def test_probe_env_allowlist_literals_and_invalid_inputs(self):
        path = self.probe_env(b'"https://old.example.com/sub/fixture-token" # comment')
        self.assertEqual(D.subscription_probe_from_env(path), b'https://old.example.com/sub/fixture-token')
        for value in (b'', b'http://old.example.com/sub/token', b'https://old.example.com/sub/token?secret=1',
                      b'https://old.example.com/sub/token#fragment', b'https://user@old.example.com/sub/token',
                      b'https://old.example.com:443/sub/token', b'"$(secret)"', b'"unterminated', b'\xff',
                      b'https://old.example.com/sub/token\nULTRA_SUBSCRIPTION_PROBE_URL=https://old.example.com/sub/other'):
            with self.subTest(value=value):
                self.probe_env(value)
                with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_invalid$'):
                    D.subscription_probe_from_env(path)
        path.write_bytes(b'OTHER=private-value\n')
        self.assertIsNone(D.subscription_probe_from_env(path, optional=True))
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_key_missing$'):
            D.subscription_probe_from_env(path)
        path.unlink()
        self.assertIsNone(D.subscription_probe_from_env(path, optional=True))
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_file_missing$'):
            D.subscription_probe_from_env(path)

    def test_local_probe_snapshot_argv_secrecy_cleanup_and_replay_binding(self):
        secret = b'https://old.example.com/sub/fixture-token'
        self.probe_env(secret)
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            self.assertNotIn(secret.decode(), repr(command))
            if stage == 'upgrade':
                snapshot = Path(command[command.index('--subscription-probe-url-file') + 1])
                self.assertEqual(D.subscription_probe_input(snapshot), secret)
        self.rollout(runner=runner)
        self.assertFalse((self.root / 'subscription-probe-url').exists())
        self.assertNotIn(secret, self.config.read_bytes())
        self.assertEqual(next(self.root.glob('probe-binding-*')).read_bytes(), D.sha(secret).encode())
        self.probe_env(b'https://old.example.com/sub/replacement')
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_probe_changed$'):
            self.rollout()

    def test_local_dispatched_probe_retry_preserves_frozen_inputs_until_migration(self):
        path = self.probe_env()
        def failed(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_failed'):
            self.rollout(runner=failed)
        before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        self.probe_env(b'https://old.example.com/sub/replacement')
        for retry in (False, True):
            with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
                self.rollout(probe_env_file=path, retry_failed=retry)
        path.unlink()
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            self.rollout(retry_failed=True)
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}, before)

    def test_killed_manual_parent_cannot_retry_with_detached_worker_alive(self):
        worker = '''import os,pathlib,sys,time
root=pathlib.Path(sys.argv[1])
(root/'worker-started').write_text(str(os.getpid()))
for _ in range(500):
    if (root/'allow-worker').exists():
        (root/'old-worker-mutation').write_text('late')
        break
    time.sleep(.01)
'''
        helper = '''import importlib.util,pathlib,subprocess,sys
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('manual_fixture',sys.argv[1])
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
repo,root,bundle=map(pathlib.Path,sys.argv[2:5])
def run(command,cwd,stage,**kwargs):
    if stage=='upgrade':
        subprocess.run([sys.executable,'-I','-c',sys.argv[7],str(root)],
                       start_new_session=True,check=True)
with patch.object(d,'run',side_effect=run),patch.object(d,'subscription_probe_from_env',return_value=None):
    d.rollout(repo,root,bundle,sys.argv[5],sys.argv[6],False)
'''
        parent = subprocess.Popen([D.sys.executable, '-I', '-c', helper, D.__file__, str(self.repo),
                                   str(self.root), str(self.bundle), self.commit, self.version, worker],
                                  env={'PATH': '/usr/bin:/bin'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def wait_for(name):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if (self.root / name).exists():
                    return
                time.sleep(.01)
            self.fail('fixture timeout: ' + name)
        try:
            wait_for('worker-started')
            parent.kill()
            self.assertEqual(parent.wait(timeout=5), -signal.SIGKILL)
            journal = (self.root / 'operation.json').read_bytes()
            self.assertTrue(json.loads(journal)['mutator_dispatched'])
            for retry in (False, True):
                with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
                    self.rollout(retry_failed=retry)
            self.assertEqual(self.calls, [])
            self.assertEqual((self.root / 'operation.json').read_bytes(), journal)
            (self.root / 'allow-worker').write_text('finish bounded fixture')
            wait_for('old-worker-mutation')
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=5)
            (self.root / 'allow-worker').write_text('finish bounded fixture')

    def test_probe_read_only_failure_cleans_snapshot_and_binding(self):
        self.probe_env()
        def failed(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('fixture_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failed)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'subscription-probe-url').exists())
        self.assertFalse(list(self.root.glob('probe-binding-*')))

    def test_invalid_probe_env_fails_before_canonical_update(self):
        path = self.probe_env(b'not-a-url')
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_invalid$'):
            self.rollout(probe_env_file=path)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertFalse(list(self.root.glob('install.config.before-*')))

    def test_probe_default_uses_canonical_config_directory_outside_checkout(self):
        canonical = self.repo / 'canonical'
        canonical.mkdir()
        config = canonical / 'install.config'
        D.atomic_write(config, self.original)
        secret = b'https://old.example.com/sub/canonical-token'
        D.atomic_write(canonical / '.env', b'ULTRA_SUBSCRIPTION_PROBE_URL=' + secret + b'\n')
        self.probe_env(b'https://old.example.com/sub/wrong-checkout-token')
        def runner(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                snapshot = Path(command[command.index('--subscription-probe-url-file') + 1])
                self.assertEqual(snapshot.read_bytes(), secret)
        self.rollout(config_path=config, runner=runner)

    def test_numeric_version_exact_commit_round_trip_and_path_limit(self):
        self.assertRegex(self.version, r'^v[0-9]+\.[0-9]+\.[0-9]+$')
        self.assertEqual(int(self.version[5:]), int(self.commit, 16))
        self.assertLess(len(self.version), 95)

    def test_subscription_probe_requires_explicit_private_regular_file(self):
        probe = self.repo / 'probe'
        raw = b'https://old.example.com/sub/fixture-token\n'
        probe.write_bytes(raw)
        probe.chmod(0o600)
        self.assertEqual(D.subscription_probe_input(probe), raw)
        for mode in (0o644, 0o400):
            probe.chmod(mode)
            with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
                D.subscription_probe_input(probe)
        probe.chmod(0o600)
        hardlink = self.repo / 'hardlink'
        os.link(probe, hardlink)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(probe)
        hardlink.unlink()
        link = self.repo / 'link'
        link.symlink_to(probe)
        with self.assertRaises(OSError):
            D.subscription_probe_input(link)
        for data in (b'', b'x' * 4097):
            probe.write_bytes(data)
            with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
                D.subscription_probe_input(probe)

    def test_subscription_probe_rejects_directory_fifo_and_parent_symlink(self):
        fifo = self.repo / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(fifo)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(self.repo)
        alias = self.repo / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        probe = self.root / 'probe'
        probe.write_bytes(b'https://old.example.com/sub/fixture-token')
        probe.chmod(0o600)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(alias / 'probe')
        info = probe.stat()
        foreign = SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1, st_nlink=1, st_size=info.st_size)
        with patch.object(D.os, 'fstat', return_value=foreign):
            with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
                D.subscription_probe_input(probe)
        path = self.probe_env()
        path.write_bytes(b'x' * (1024 * 1024 + 1))
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_from_env(path)

    def test_canonical_config_lock_is_shared_across_worktree_path_aliases(self):
        alias = self.repo / 'other-worktree'
        alias.symlink_to(self.repo, target_is_directory=True)
        self.assertEqual(D.canonical_config_lock(self.config), D.canonical_config_lock(alias / 'install.config'))

    def test_only_two_canonical_values_change_without_shell_evaluation(self):
        self.rollout()
        raw = self.config.read_bytes()
        self.assertIn(b'OTHER="literal $() ${HOME}"\n', raw)
        self.assertIn(self.version.encode(), raw)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)
        self.assertEqual([stage for stage, _ in self.calls], ['doctor', 'upgrade', 'status'])
        self.assertIn('operator-upgrade', self.calls[1][1])
        self.assertIn('--source-commit', self.calls[1][1])
        self.assertIn('--manifest-sha256', self.calls[1][1])
        self.assertIn('--config-sha256', self.calls[1][1])
        self.assertFalse((self.root / 'operation.json').exists())

    def test_success_removes_one_time_baseline_setting_and_preserves_readable_mode(self):
        self.config.chmod(0o644)
        self.config.write_bytes(self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n')
        original = self.config.read_bytes()
        self.rollout()
        self.assertNotIn(b'ULTRA_UPGRADE_BASELINE_FILE=', self.config.read_bytes())
        self.assertEqual(D.config_values(self.config.read_bytes())['ULTRA_AUTOMATION_VERSION'], self.version)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), original)

    def test_failed_upgrade_retains_one_time_baseline_setting(self):
        self.config.write_bytes(self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n')
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.assertIn(b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json', self.config.read_bytes())

    def test_completed_legacy_journal_cannot_assert_authoritative_drain(self):
        desired = D.config_candidate(self.original, self.version, self.bundle)
        pending = desired + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n'
        completed = D.remove_config_key(pending, 'ULTRA_UPGRADE_BASELINE_FILE')
        record = {'schema': 1, 'commit': self.commit, 'version': self.version, 'adopt': False,
                  'backup': 'install.config.before-' + self.version + '-1', 'previous_sha256': D.sha(self.original),
                  'config_sha256': D.sha(pending), 'stage': 'completed', 'mutator_dispatched': True,
                  'transport_binding': None, 'manifest_sha256': None, 'final_config_sha256': D.sha(completed),
                  'remote_attempt': None}
        self.config.write_bytes(completed)
        D.atomic_write(self.root / 'operation.json', json.dumps(record).encode())
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            self.rollout()
        self.assertTrue((self.root / 'operation.json').exists())
        self.assertEqual(self.config.read_bytes(), completed)
        self.assertEqual(self.calls, [])

    def test_signed_upgrade_baseline_cannot_prove_legacy_worker_drain(self):
        journal = {'schema': 1, 'commit': self.commit, 'version': 'v2.4.2', 'remote_attempt': 'a' * 64,
                   'manifest_sha256': None, 'mutator_dispatched': True}
        manifest = {'source_commit': self.commit, 'version': 'v2.4.2',
                    'assets': [{'name': 'asset-' + str(i)} for i in range(14)]}
        manifest_raw = json.dumps(manifest, sort_keys=True).encode()
        journal['manifest_sha256'] = D.sha(manifest_raw)
        journal_raw = json.dumps(journal, sort_keys=True).encode()
        old_release = self.repo / 'old-release'
        old_release.mkdir()
        manifest_path = old_release / 'release-manifest.json'
        journal_path = self.repo / 'old-operation.json'
        descriptor_path = self.repo / 'baseline.json'
        manifest_path.write_bytes(manifest_raw); manifest_path.chmod(0o600)
        journal_path.write_bytes(journal_raw); journal_path.chmod(0o600)
        descriptor = {'schema': 1, 'journal': str(journal_path), 'journal_sha256': D.sha(journal_raw),
                      'manifest': str(manifest_path), 'manifest_sha256': D.sha(manifest_raw),
                      'bridge': {}, 'exits': {}}
        descriptor_path.write_text(json.dumps(descriptor)); descriptor_path.chmod(0o600)
        config = self.original + ('ULTRA_UPGRADE_BASELINE_FILE=' + str(descriptor_path) + '\n').encode()
        remote_root = Path('/var/lib/ultra-ansible/operator-inputs/manual-new-attempt')
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            D.stage_upgrade_baseline(config, self.version, remote_root)
        self.assertEqual(journal_path.read_bytes(), journal_raw)
        journal_path.write_bytes(journal_raw + b' ')
        with self.assertRaisesRegex(D.DeployError, 'baseline_local_pin_changed'):
            D.stage_upgrade_baseline(config, self.version, remote_root)

    def test_staging_archive_contains_only_the_two_baseline_inputs(self):
        manifest = {'source_commit': self.commit, 'version': self.version,
                    'assets': [{'name': 'fixture', 'sha256': D.sha(b'fixture'), 'size': 7}]}
        raw_manifest = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw_manifest)
        (self.bundle / 'fixture').write_bytes(b'fixture')
        config = self.original
        extras = {'baseline/descriptor.json': b'{"schema":1}',
                  'baseline/operator-journal.json': b'{"schema":1}'}
        def process(command, **kwargs):
            with tarfile.open(fileobj=kwargs['stdin'], mode='r|') as archive:
                members = [(member.name, archive.extractfile(member).read()) for member in archive]
            self.assertEqual([name for name, _ in members], ['release/release-manifest.json', 'release/fixture',
                'install.config', 'baseline/descriptor.json', 'baseline/operator-journal.json'])
            return subprocess.CompletedProcess(command, 0, json.dumps({'architecture': 'arm64',
                'manifest_sha256': D.sha(raw_manifest), 'config_sha256': D.sha(config),
                'attempt': D.remote_attempt(config, self.version)}).encode())
        with patch.object(D.subprocess, 'run', process):
            receipt = D.stage_remote(self.repo, self.root, self.bundle, config,
                ['ssh', '-F', '/dev/null', 'root@192.0.2.10'], self.commit, self.version,
                D.sha(raw_manifest), extras)
        self.assertEqual(receipt['architecture'], 'arm64')

    def test_legacy_dispatch_blocks_before_any_input_or_transport_access(self):
        for stage in ('prepared', 'bridge_staging', 'doctor', 'adoption_apply', 'upgrade', 'status', 'completed'):
            for retry in (False, True):
                with self.subTest(stage=stage, retry=retry):
                    record = {'schema': 1, 'commit': 'b8b8126' + '0' * 33,
                              'stage': stage, 'mutator_dispatched': True,
                              'quiescent': True, 'drained': True, 'execution_safety_protocol': 999,
                              'quiescence_evidence': {'verified': True}}
                    raw = json.dumps(record).encode()
                    D.atomic_write(self.root / 'operation.json', raw)
                    with patch.object(D, 'canonical_file', side_effect=AssertionError('config reopened')), \
                         patch.object(D, 'operator_transport', side_effect=AssertionError('transport reopened')), \
                         patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('credential reopened')):
                        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
                            self.rollout(retry_failed=retry)
                    self.assertEqual((self.root / 'operation.json').read_bytes(), raw)
                    self.assertEqual(self.config.read_bytes(), self.original)
                    self.assertEqual(self.calls, [])

    def test_retry_failed_is_explicitly_forwarded_to_operator_upgrade(self):
        self.rollout(retry_failed=True)
        command = self.calls[1][1]
        self.assertIn('operator-upgrade', command)
        self.assertIn('--retry-failed', command)

    def test_forward_only_archives_dispatched_upgrade_and_is_explicitly_forwarded(self):
        old = {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def failed_forward(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'upgrade':
                self.assertIn('--forward-only', command)
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, '^fixture_failed$'):
            self.rollout(forward_only=True, runner=failed_forward)
        archived = list(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(len(archived), 1)
        self.assertEqual(json.loads(archived[0].read_bytes()), old)
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertTrue(record['forward_only'])
        self.assertIn('--forward-only', self.calls[1][1])

    def test_forward_only_requires_exact_failed_upgrade_and_rejects_conflicts(self):
        with self.assertRaisesRegex(D.DeployError, '^manual_forward_only_requires_dispatched_upgrade$'):
            self.rollout(forward_only=True)
        old = {'schema': 1, 'commit': 'b' * 40, 'version': 'v0.0.2', 'stage': 'completed',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        with self.assertRaisesRegex(D.DeployError, '^manual_forward_only_requires_dispatched_upgrade$'):
            self.rollout(forward_only=True)
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes()), old)
        old['stage'] = 'upgrade'
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        with self.assertRaisesRegex(D.DeployError, '^manual_forward_only_upgrade_only$'):
            self.rollout(forward_only=True, retry_failed=True)

    def test_readable_canonical_config_keeps_its_mode(self):
        self.config.chmod(0o644)
        self.rollout(config_path=self.config)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertIn(self.version.encode(), self.config.read_bytes())

    def test_explicit_adoption_compares_then_applies_without_redundant_upgrade(self):
        self.rollout(adopt=True)
        self.assertEqual([stage for stage, _ in self.calls], ['doctor', 'adoption_check', 'adoption_apply', 'status'])
        self.assertIn('--adopt-runtime', self.calls[1][1])
        self.assertIn('--adopt-runtime', self.calls[2][1])

    def test_preflight_failure_restores_previous_config(self):
        for failing in ['doctor', 'adoption_check']:
            with self.subTest(stage=failing):
                def runner(command, cwd, stage, capture=False, env=None):
                    if stage == failing:
                        raise D.DeployError('fixture_failure')
                with self.assertRaises(D.DeployError):
                    self.rollout(adopt=True, runner=runner)
                self.assertEqual(self.config.read_bytes(), self.original)
                self.assertFalse((self.root / 'operation.json').exists())

    def test_mutating_dispatch_failure_retains_config_and_blocks_other_commit(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.assertIn(self.version.encode(), self.config.read_bytes())
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertEqual(record['stage'], 'upgrade')
        record['commit'] = '0' * 40
        (self.root / 'operation.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_retry_dispatched_operation_is_blocked_and_keeps_original_backup(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.calls.clear()
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            self.rollout(retry_failed=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)

    def test_retry_preflight_failure_never_restores_after_prior_mutator_dispatch(self):
        def failing_upgrade(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failing_upgrade)
        updated = self.config.read_bytes()
        def failing_doctor(command, cwd, stage, capture=False, env=None):
            raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failing_doctor)
        self.assertEqual(self.config.read_bytes(), updated)
        self.assertTrue((self.root / 'operation.json').exists())

    def test_edited_config_during_failed_operation_is_rejected(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.config.write_bytes(self.config.read_bytes() + b'CHANGED=1\n')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_prepared_journal_recovers_crash_before_config_update(self):
        desired = D.config_candidate(self.original, self.version, self.bundle)
        record = {'schema': 1, 'commit': self.commit, 'version': self.version, 'adopt': False,
                  'backup': 'install.config.before-' + self.version + '-1', 'previous_sha256': D.sha(self.original), 'config_sha256': D.sha(desired), 'stage': 'prepared'}
        D.atomic_write(self.root / 'operation.json', json.dumps(record).encode())
        D.atomic_write(self.root / record['backup'], self.original)
        self.rollout()
        self.assertEqual(self.config.read_bytes(), desired)

    def test_private_config_and_symlink_requirements(self):
        self.config.chmod(0o640)
        with self.assertRaisesRegex(D.DeployError, 'readable_file'):
            self.rollout()
        self.config.unlink()
        self.config.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(D.DeployError, 'readable_file'):
            self.rollout()

    def test_duplicate_release_keys_fail_closed(self):
        with self.assertRaisesRegex(D.DeployError, 'duplicate'):
            D.config_candidate(self.original + b'ULTRA_AUTOMATION_VERSION=v9.9.9\n', self.version, self.bundle)

    def test_attempt_identity_normalizes_derived_fields_without_recursion(self):
        for raw in [self.original, b'BRIDGE=192.0.2.10\n']:
            attempt = D.remote_attempt(raw, self.version)
            derived = D.config_candidate(raw, self.version, '/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + attempt + '/release')
            self.assertEqual(D.remote_attempt(derived, self.version), attempt)
            self.assertNotEqual(D.remote_attempt(derived + b'CORRECTION=1\n', self.version), attempt)

    def test_completed_baseline_keeps_attempt_only_for_unchanged_config(self):
        baseline = self.repo / 'baseline.json'
        configured = self.original.replace(b'OTHER="literal $() ${HOME}"\n',
            ('ULTRA_UPGRADE_BASELINE_FILE=' + str(baseline) + '\n').encode() + b'OTHER="literal $() ${HOME}"\n')
        attempt = D.remote_attempt(configured, self.version)
        release = '/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + attempt + '/release'
        installed = D.config_candidate(configured, self.version, release)
        completed = D.remove_config_key(installed, 'ULTRA_UPGRADE_BASELINE_FILE')
        backup = self.root / ('install.config.before-' + self.version + '-1')
        D.atomic_write(backup, configured)
        def staged_config(raw, version, remote_root):
            return D.config_candidate(raw, version, remote_root / 'release', remote_root / 'baseline/descriptor.json'), {'baseline/descriptor.json': b'{}'}
        with patch.object(D, 'stage_upgrade_baseline', side_effect=staged_config):
            replay = D.completed_baseline_replay(self.root, completed, self.version, self.commit)
        self.assertEqual(replay[0], attempt)
        self.assertEqual(D.remove_config_key(replay[1], 'ULTRA_UPGRADE_BASELINE_FILE'), completed)
        changed = completed + b'CORRECTED_POLICY=1\n'
        with patch.object(D, 'stage_upgrade_baseline', side_effect=staged_config):
            self.assertIsNone(D.completed_baseline_replay(self.root, changed, self.version, self.commit))

    def test_nested_lock_fails_closed(self):
        with D.lock(self.root / 'lock'):
            with self.assertRaisesRegex(D.DeployError, 'already_running'):
                with D.lock(self.root / 'lock'):
                    self.fail('conflicting lock accepted')

    def test_subprocess_output_is_suppressed_on_failure(self):
        with patch.object(D.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            with self.assertRaisesRegex(D.DeployError, '^upgrade_failed_exit_7$'):
                D.run(['fixture'], self.repo, 'upgrade')
        self.assertEqual(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)

    def test_dirty_tree_fails_before_build_or_deploy(self):
        with patch.object(D, '__file__', str(self.repo / 'scripts/manual-deploy.py')), patch.object(D.shutil, 'which', return_value='/fixture'), patch.object(D.sys, 'argv', ['manual-deploy.py']), patch.object(D, 'run', side_effect=[' M tracked']) as run:
            with self.assertRaisesRegex(D.DeployError, 'tracked_tree_dirty'):
                D.main()
        self.assertEqual(run.call_count, 1)

    def test_bundle_identity_mismatch_fails_before_loading_contract(self):
        manifest = {'version': 'v9.9.9', 'source_commit': self.commit}
        (self.bundle / 'release-manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(D.DeployError, 'candidate_identity_mismatch'):
            D.verify_bundle(self.repo, self.bundle, self.commit, self.version)

    def test_build_and_existing_candidate_use_exact_isolated_source(self):
        validations = []
        def runner(command, cwd, stage, capture=False, env=None):
            self.calls.append((stage, command))
            if stage == 'source_clone':
                Path(command[-1]).mkdir()
            if stage == 'release_build':
                (cwd / 'dist').mkdir()
                (cwd / 'dist/release-manifest.json').write_text('{}')
                (cwd / 'dist/ultra-install-linux-amd64').write_bytes(b'fixture')
        (self.bundle / 'release-manifest.json').unlink()
        self.bundle.rmdir()
        with patch.object(D, 'prepare_runtime_environment', return_value={}), patch.object(D, 'run', runner), patch.object(D, 'verify_bundle', side_effect=lambda *args: validations.append(args)):
            bundle = D.build_candidate(self.repo, self.root, self.commit, self.version)
            self.assertEqual(bundle, self.bundle)
            self.assertEqual((bundle / 'ultra-install-linux-amd64').stat().st_mode & 0o777, 0o500)
            self.assertEqual((bundle / 'release-manifest.json').stat().st_mode & 0o777, 0o400)
            D.build_candidate(self.repo, self.root, self.commit, self.version)
            self.assertEqual([s for s, _ in self.calls].count('release_build'), 1)
            self.assertEqual([cmd[-1] for stage, cmd in self.calls if stage == 'source_checkout'], [self.commit, self.commit])
            (bundle / 'candidate.json').chmod(0o600)
            (bundle / 'candidate.json').write_text('{}')
            with self.assertRaisesRegex(D.DeployError, 'candidate_identity_mismatch'):
                D.build_candidate(self.repo, self.root, self.commit, self.version)
        bundle.chmod(0o700)  # allow fixture cleanup
        self.assertGreaterEqual(len(validations), 3)
        self.assertFalse(list(self.root.glob('.source-*')))


class NativeDeploy(unittest.TestCase):
    rollout = ManualDeploy.rollout
    probe_env = ManualDeploy.probe_env
    run_fixture = ManualDeploy.run_fixture

    def setUp(self):
        ManualDeploy.setUp(self)
        self.operator = self.repo / 'adopt-fixture' / 'compare'
        self.operator.mkdir(parents=True, mode=0o700)
        self.identity = self.repo / 'operator-key'
        self.identity.write_bytes(b'PRIVATE KEY MUST NOT BE READ BY WRAPPER')
        self.identity.chmod(0o600)
        self.pins = self.repo / 'pins'
        self.pins.write_bytes(b'fixture pins')
        self.pins.chmod(0o600)
        self.inventory = {'all': {'vars': {'ansible_user': 'root',
            'ansible_ssh_private_key_file': str(self.identity),
            'ansible_ssh_common_args': '-F /dev/null -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=' + str(self.pins)},
            'children': {'bridge': {'hosts': {'bridge': {'ansible_host': '192.0.2.10'}}},
                         'exits': {'hosts': {'exit_0': {'ansible_host': '192.0.2.20'}}}}}}
        self.original += b'BRIDGE=192.0.2.10\nBRIDGE_SSH_HOST=192.0.2.10\nULTRA_AUTOMATION_STATIC_NODES=\'[{"address":"192.0.2.20"}]\'\nSECRETS_ENV_FILE=/etc/ultra-relay/.env\n'
        self.config.write_bytes(self.original)
        self.write_inventory()
        self.manifest = json.dumps({'source_commit': self.commit, 'version': self.version, 'assets': []}).encode()
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest)
        self.environment = patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY': str(self.operator / 'inventory.json')})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.pin_probe = patch.object(D.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0))
        self.pin_probe.start()
        self.addCleanup(self.pin_probe.stop)
        def staged_receipt(*args):
            config, version, manifest_sha = args[3], args[6], args[7]
            return {'architecture': 'arm64', 'manifest_sha256': manifest_sha, 'config_sha256': D.sha(config),
                    'attempt': D.remote_attempt(config, version)}
        self.staged_receipt = staged_receipt
        self.stage = patch.object(D, 'stage_remote', side_effect=staged_receipt)
        self.stage_mock = self.stage.start()
        self.addCleanup(self.stage.stop)

    def write_inventory(self):
        request = json.dumps({'inventory': self.inventory, 'variables': {}}).encode()
        for name, data in [('inventory.json', json.dumps(self.inventory).encode()), ('request.json', request),
                           ('job.json', json.dumps({'operation': 'adopt', 'request_sha256': D.sha(request)}).encode())]:
            D.atomic_write(self.operator / name, data)

    def test_native_contract_and_server_canonical_path(self):
        self.rollout(adopt=True)
        expected = '/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + D.remote_attempt(self.original, self.version) + '/release'
        self.assertIn(expected.encode(), self.config.read_bytes())
        self.assertNotIn(str(self.bundle).encode(), self.config.read_bytes())
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy', 'doctor', 'adoption_check', 'adoption_apply', 'status'])
        self.assertEqual(self.calls[0][1][1:3], ['plan', '--config'])
        for stage, command in self.calls[1:]:
            self.assertEqual(command[:3], ['ssh', '-F', '/dev/null'])
            proxy = command[command.index('-o', command.index('22') + 1) + 1]
            self.assertIn('ProxyCommand=ssh -F /dev/null', proxy)
            self.assertIn('-W %h:%p root@192.0.2.20', proxy)
            remote = D.shlex.split(command[-1])
            self.assertEqual(remote[:3], ['python3', '-I', '-c'])
            self.assertEqual(remote[4:11], ['run', self.commit, self.version, D.sha(self.manifest), D.sha(self.stage_mock.call_args.args[3]), D.remote_attempt(self.original, self.version), 'arm64'])
            self.assertEqual(remote[11], stage)
            self.assertEqual(remote[12], '0')
        self.assertIn("'--bridge-native'", D.REMOTE_PROGRAM)
        self.assertIn("'upgrade':['operator-upgrade'", D.REMOTE_PROGRAM)

    def test_native_retry_failed_is_bound_to_upgrade_handoff(self):
        self.rollout(retry_failed=True)
        command = next(command for stage, command in self.calls if stage == 'upgrade')
        remote = D.shlex.split(command[-1])
        self.assertEqual(remote[11], 'upgrade')
        self.assertEqual(remote[12], '1')

    def test_forward_only_transport_options_are_confined_to_upgrade(self):
        old = {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        self.rollout(forward_only=True)
        calls = {stage: D.shlex.split(command[-1]) for stage, command in self.calls if stage in ('doctor', 'upgrade', 'status')}
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        forward_sha = D.sha(archived.read_bytes())
        self.assertEqual(calls['doctor'][13], '0')
        self.assertEqual(calls['doctor'][15], forward_sha)
        self.assertEqual(calls['upgrade'][13], '1')
        self.assertEqual(calls['upgrade'][15], forward_sha)
        self.assertEqual(calls['status'][13], '0')
        self.assertEqual(calls['status'][15], forward_sha)

    def failed_forward_fixture(self):
        old_commit = 'b' * 40
        old = {'schema': 1, 'commit': old_commit, 'version': 'v0.0.' + str(int(old_commit, 16)),
               'stage': 'upgrade', 'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def fail(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_failed'):
            self.rollout(forward_only=True, runner=fail)
        self.calls.clear()
        self.stage_mock.reset_mock()
        return old

    def continuation_runner(self, old, change=None):
        record = json.loads((self.root / 'operation.json').read_bytes())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'forward_continuation_attestation':
                state = Path('/var/lib/ultra-ansible') / ('upgrade-' + old['version'])
                receipt = {'architecture': 'arm64', 'manifest_sha256': record['manifest_sha256'],
                    'config_sha256': record['staged_config_sha256'], 'attempt': record['remote_attempt'],
                    'forward_journal_sha256': record['forward_journal_sha256'],
                    'lifecycle_id': str(D.uuid.UUID(bytes=hashlib.sha256(str(state).encode()).digest()[:16], version=4))}
                receipt.update(change or {})
                return json.dumps(receipt)
        return runner

    def test_continue_forward_only_retains_original_proof_and_exact_candidate(self):
        old = self.failed_forward_fixture()
        original_proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        config = self.config.read_bytes()
        with patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('must not read env')):
            self.rollout(continue_forward_only=True, runner=self.continuation_runner(old))
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-abandoned-*.json')], [original_proof])
        upgrade = D.shlex.split(next(command for stage, command in self.calls if stage == 'upgrade')[-1])
        self.assertEqual(upgrade[13], '1')
        self.assertEqual(upgrade[15], D.sha(original_proof))
        self.assertEqual(upgrade[16], '1')
        self.assertNotIn('--retry-failed', upgrade)

    def new_candidate_fixture(self):
        self.commit = 'c' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.bundle = self.root / self.version
        self.bundle.mkdir()
        self.manifest = json.dumps({'source_commit': self.commit, 'version': self.version, 'assets': []}).encode()
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest)

    def test_continue_new_head_archives_failed_candidate_as_history_preserving_production_proof(self):
        old = self.failed_forward_fixture()
        failed_raw = (self.root / 'operation.json').read_bytes()
        failed = json.loads(failed_raw)
        proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        def runner(command, cwd, stage, **kwargs):
            response = attest(command, cwd, stage, **kwargs)
            if stage == 'upgrade':
                record = json.loads((self.root / 'operation.json').read_bytes())
                self.assertEqual(record['commit'], self.commit)
                self.assertNotEqual(record['commit'], failed['commit'])
                self.assertNotEqual(record['version'], failed['version'])
                self.assertEqual(record['forward_journal_sha256'], D.sha(proof))
                self.assertNotEqual(record['forward_journal_sha256'], D.sha(failed_raw))
                history = self.root / record['forward_retry_history']
                self.assertEqual(history.read_bytes(), failed_raw)
                self.assertEqual(history.stat().st_mode & 0o777, 0o600)
                self.assertEqual(record['forward_retry_history_sha256'], D.sha(failed_raw))
                raise D.DeployError('new_failure')
            return response
        canonical = self.repo / 'canonical.config'
        self.config.rename(canonical)
        canonical.chmod(0o644)
        with patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('must not read env')):
            with self.assertRaisesRegex(D.DeployError, 'new_failure'):
                self.rollout(config_path=canonical, continue_forward_only=True, runner=runner)
        self.assertEqual(canonical.stat().st_mode & 0o777, 0o644)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.stage_mock.call_args.args[8]['forward-operation.json'], proof)
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-abandoned-*.json')], [proof])
        self.assertEqual(len(list(self.root.glob('operation.forward-only-retry-*.json'))), 1)
        self.assertEqual([s for s, _ in self.calls].count('forward_continuation_attestation'), 2)

    def test_continue_new_head_doctor_failure_restores_failed_operation_and_frozen_probe(self):
        self.probe_env()
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        probe = (self.root / 'subscription-probe-url').read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        def runner(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('doctor_failed_exit_1')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'doctor_failed_exit_1'):
            self.rollout(continue_forward_only=True, runner=runner)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual((self.root / 'subscription-probe-url').read_bytes(), probe)

    def test_continue_new_head_second_attestation_failure_restores_original_recovery_state(self):
        self.probe_env()
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        probe = (self.root / 'subscription-probe-url').read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        attestations = 0
        def runner(command, cwd, stage, **kwargs):
            nonlocal attestations
            if stage == 'forward_continuation_attestation':
                attestations += 1
                if attestations == 2:
                    pending = json.loads((self.root / 'operation.json').read_bytes())
                    self.assertEqual(pending['stage'], 'forward_continuation_preflight')
                    self.assertIs(pending['mutator_dispatched'], False)
                    raise D.DeployError('second_attestation_failed')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'second_attestation_failed'):
            self.rollout(continue_forward_only=True, runner=runner)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual((self.root / 'subscription-probe-url').read_bytes(), probe)
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-retry-*.json')], [before])
        self.assertFalse(any(stage == 'upgrade' for stage, _ in self.calls))
        self.rollout(continue_forward_only=True, runner=attest)

    def test_continue_new_head_write_failures_restore_or_recover_at_every_local_boundary(self):
        # Exercise both errors before replacement and death after a durable
        # replacement, including recovery interrupted while restoring config.
        for boundary in ['history', 'backup', 'probe', 'journal', 'config', 'binding', 'bridge_staging', 'doctor', 'forward_continuation_preflight']:
            for after in [False, True]:
                with self.subTest(boundary=boundary, after=after):
                    fixture = NativeDeploy(methodName='runTest')
                    fixture.setUp()
                    try:
                        fixture.probe_env()
                        old = fixture.failed_forward_fixture()
                        before = (fixture.root / 'operation.json').read_bytes()
                        config = fixture.config.read_bytes()
                        probe = (fixture.root / 'subscription-probe-url').read_bytes()
                        attest = fixture.continuation_runner(old)
                        fixture.new_candidate_fixture()
                        real_write = D.atomic_write
                        injected = False
                        def write(path, raw, **kwargs):
                            nonlocal injected
                            selected = ((boundary == 'history' and path.name.startswith('operation.forward-only-retry-')) or
                                (boundary == 'backup' and path.name.startswith('install.config.before-' + fixture.version)) or
                                (boundary == 'probe' and path.name == 'subscription-probe-url') or
                                (boundary == 'journal' and path.name == 'operation.json' and json.loads(raw).get('stage') == 'prepared') or
                                (boundary == 'config' and path == fixture.config) or
                                (boundary == 'binding' and path.name.startswith('probe-binding-' + fixture.commit)) or
                                (boundary in ['bridge_staging', 'doctor', 'forward_continuation_preflight'] and
                                 path.name == 'operation.json' and json.loads(raw).get('stage') == boundary))
                            if selected and not injected:
                                injected = True
                                if after:
                                    real_write(path, raw, **kwargs)
                                raise OSError('injected_write_failure')
                            return real_write(path, raw, **kwargs)
                        with patch.object(D, 'atomic_write', side_effect=write):
                            # Simulate process death preventing in-process
                            # restoration; the next invocation must recover.
                            with patch.object(D, 'restore_forward_preflight', side_effect=OSError('interrupted_recovery')):
                                with self.assertRaises(OSError):
                                    fixture.rollout(continue_forward_only=True, runner=attest)
                        self.assertTrue(injected)
                        self.assertFalse(any(stage == 'upgrade' for stage, _ in fixture.calls))
                        recovered = False
                        def check_recovered(command, cwd, stage, **kwargs):
                            nonlocal recovered
                            if stage == 'canonical_policy':
                                self.assertEqual((fixture.root / 'operation.json').read_bytes(), before)
                                self.assertEqual(fixture.config.read_bytes(), config)
                                self.assertEqual((fixture.root / 'subscription-probe-url').read_bytes(), probe)
                                recovered = True
                            return attest(command, cwd, stage, **kwargs)
                        fixture.rollout(continue_forward_only=True, runner=check_recovered)
                        self.assertTrue(recovered)
                    finally:
                        fixture.doCleanups()

    def test_continue_recovers_when_config_restored_but_old_journal_restore_was_interrupted(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        real_write = D.atomic_write
        def fail_restore(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('doctor_failure')
            return attest(command, cwd, stage, **kwargs)
        def write(path, raw, **kwargs):
            if path == self.root / 'operation.json' and raw == before:
                self.assertEqual(self.config.read_bytes(), config)
                raise OSError('journal_restore_interrupted')
            return real_write(path, raw, **kwargs)
        with patch.object(D, 'atomic_write', side_effect=write):
            with self.assertRaisesRegex(OSError, 'journal_restore_interrupted'):
                self.rollout(continue_forward_only=True, runner=fail_restore)
        self.assertIs(json.loads((self.root / 'operation.json').read_bytes())['mutator_dispatched'], False)
        self.assertEqual(self.config.read_bytes(), config)
        pending = (self.root / 'operation.json').read_bytes()
        for arguments in [{'forward_only': True}, {'retry_failed': True}, {'adopt': True},
                          {'probe_env_file': self.repo / 'unused-private-input'}]:
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_arguments_invalid'):
                    self.rollout(continue_forward_only=True, **arguments)
                self.assertEqual((self.root / 'operation.json').read_bytes(), pending)
                self.assertEqual(self.config.read_bytes(), config)
        self.rollout(continue_forward_only=True, runner=attest)

    def test_ordinary_retry_rejects_all_unfinished_forward_journals_without_touching_recovery_state(self):
        self.probe_env()
        self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        original = json.loads(journal.read_bytes())
        config = self.config.read_bytes()
        probe = (self.root / 'subscription-probe-url').read_bytes()
        proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        for stage, dispatched in [('prepared', False), ('bridge_staging', False), ('doctor', False),
                                  ('forward_continuation_preflight', False), ('upgrade', True), ('status', True)]:
            for retry in [False, True]:
                with self.subTest(stage=stage, retry=retry):
                    pending = json.dumps(dict(original, stage=stage, mutator_dispatched=dispatched)).encode()
                    D.atomic_write(journal, pending)
                    self.calls.clear()
                    self.stage_mock.reset_mock()
                    with patch.object(D, 'atomic_write', side_effect=AssertionError('must not write')):
                        with self.assertRaisesRegex(D.DeployError, 'manual_forward_operation_requires_explicit_continuation'):
                            self.rollout(retry_failed=retry)
                    self.assertEqual(journal.read_bytes(), pending)
                    self.assertEqual(self.config.read_bytes(), config)
                    self.assertEqual((self.root / 'subscription-probe-url').read_bytes(), probe)
                    self.assertEqual(next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes(), proof)
                    self.assertEqual(self.calls, [])
                    self.assertFalse(self.stage_mock.called)

    def test_continue_preflight_recovery_rejects_unrelated_or_changed_journals(self):
        old = self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        before = journal.read_bytes()
        config = self.config.read_bytes()
        original = json.loads(before)
        for change in [{'stage': 'prepared', 'mutator_dispatched': False},
                       {'stage': 'prepared', 'mutator_dispatched': False, 'forward_retry_history': '../operation.json'},
                       {'stage': 'upgrade', 'mutator_dispatched': False}]:
            raw = json.dumps(dict(original, **change)).encode()
            D.atomic_write(journal, raw)
            with self.assertRaises(D.DeployError):
                self.rollout(continue_forward_only=True)
            self.assertEqual(journal.read_bytes(), raw)
            self.assertEqual(self.config.read_bytes(), config)
        D.atomic_write(journal, before)

    def test_continue_new_head_attestation_failure_leaves_config_journal_and_archives_unchanged(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        attest = self.continuation_runner(old, {'lifecycle_id': 'foreign'})
        self.new_candidate_fixture()
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_receipt_invalid'):
            self.rollout(continue_forward_only=True, runner=attest)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertFalse(self.stage_mock.called)
        self.assertFalse(list(self.root.glob('operation.forward-only-retry-*.json')))

    def test_forward_only_cannot_archive_failed_forward_candidate_as_predecessor(self):
        self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_operation_requires_explicit_continuation'):
            self.rollout(forward_only=True)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(len(list(self.root.glob('operation.forward-only-abandoned-*.json'))), 1)
        self.assertFalse(self.stage_mock.called)

    def test_continue_forward_only_doctor_failure_retains_retryable_original_journal(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        attest = self.continuation_runner(old)
        def runner(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('doctor_failed_exit_1')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'doctor_failed_exit_1'):
            self.rollout(continue_forward_only=True, runner=runner)
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes()), json.loads(before))
        self.assertFalse(self.stage_mock.called)

    def test_continue_forward_only_rejects_changed_receipt_without_replacing_journal(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        for change in ({'forward_journal_sha256': 'f' * 64}, {'lifecycle_id': 'foreign'},
                       {'config_sha256': 'f' * 64}, {'attempt': 'f' * 64}, {'architecture': 'amd64'}):
            with self.subTest(change=change):
                with self.assertRaises(D.DeployError):
                    self.rollout(continue_forward_only=True, runner=self.continuation_runner(old, change))
                self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertFalse(self.stage_mock.called)

    def test_continue_forward_only_rejects_changed_local_bindings(self):
        self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        before = journal.read_bytes()
        base = json.loads(before)
        for key, value in [('commit', 'f' * 40), ('manifest_sha256', 'f' * 64),
                           ('remote_attempt', 'f' * 64), ('staged_config_sha256', 'f' * 64),
                           ('transport_binding', {}), ('forward_journal_sha256', 'f' * 64),
                           ('forward_only', False)]:
            with self.subTest(key=key):
                D.atomic_write(journal, json.dumps(dict(base, **{key: value})).encode())
                with self.assertRaises(D.DeployError):
                    self.rollout(continue_forward_only=True)
        D.atomic_write(journal, before)
        proof = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        proof.write_bytes(b'{}')
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_proof_changed'):
            self.rollout(continue_forward_only=True)
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.calls, [])

    def legacy_record(self):
        attempt = D.remote_attempt(self.original, self.version)
        release = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + self.commit + '-' + attempt) / 'release'
        self.original = D.config_candidate(self.original, self.version, release)
        self.config.write_bytes(self.original)
        _, binding = D.operator_transport(str(self.operator / 'inventory.json'), self.original)
        return {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
                'mutator_dispatched': True, 'remote_attempt': D.remote_attempt(self.original, self.version), 'manifest_sha256': 'd' * 64,
                'config_sha256': D.sha(self.original), 'transport_binding': binding}

    def test_legacy_forward_only_archives_attested_hash_and_preserves_original_fields(self):
        old = self.legacy_record()
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'legacy_operation_attestation':
                self.assertTrue(kwargs['capture'])
                self.assertEqual(command[:3], ['ssh', '-F', '/dev/null'])
                return json.dumps(dict(old, staged_config_sha256=old['config_sha256']))
        self.rollout(forward_only=True, runner=runner)
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(json.loads(archived.read_bytes()), dict(old, staged_config_sha256=old['config_sha256']))
        self.assertEqual(self.calls[0][0], 'legacy_operation_attestation')

    def test_legacy_forward_only_attests_exact_baseline_relocation(self):
        # The old local baseline files no longer need to exist for this read.
        self.original += b'ULTRA_UPGRADE_BASELINE_FILE=/nonexistent/private-baseline.json\n'
        old = self.legacy_record()
        old_root = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + self.commit + '-' + old['remote_attempt'])
        expected = D.config_candidate(self.original, self.version, old_root / 'release', old_root / 'baseline/descriptor.json')
        self.assertNotEqual(D.sha(expected), old['config_sha256'])
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'legacy_operation_attestation':
                self.assertEqual(D.shlex.split(command[-1])[-1], D.sha(expected))
                return json.dumps(dict(old, staged_config_sha256=D.sha(expected)))
        self.rollout(forward_only=True, runner=runner)
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(json.loads(archived.read_bytes()), dict(old, staged_config_sha256=D.sha(expected)))

    def test_legacy_forward_only_rejection_preserves_config_and_journal(self):
        for kind in ('transport', 'config', 'attempt', 'version', 'release', 'failure', 'receipt', 'digest', 'malformed'):
            with self.subTest(kind=kind):
                old = self.legacy_record()
                if kind == 'transport': old['transport_binding'] = 'x' * 64
                if kind == 'config': old['config_sha256'] = 'f' * 64
                if kind == 'attempt': old['remote_attempt'] = 'f' * 64
                if kind in ('version', 'release'):
                    self.original = D.config_candidate(self.original, 'v0.0.1' if kind == 'version' else self.version,
                        '/wrong' if kind == 'release' else D.config_values(self.original)['ULTRA_AUTOMATION_RELEASE_DIR'])
                    self.config.write_bytes(self.original)
                    old['config_sha256'] = D.sha(self.original)
                raw = json.dumps(old).encode()
                D.atomic_write(self.root / 'operation.json', raw)
                def runner(command, cwd, stage, **kwargs):
                    if stage == 'legacy_operation_attestation':
                        if kind == 'failure': raise D.DeployError('fixture_ssh_failure')
                        if kind == 'malformed': return 'not json'
                        receipt = dict(old, staged_config_sha256=old['config_sha256'])
                        if kind == 'receipt': receipt['commit'] = 'f' * 40
                        if kind == 'digest': receipt['staged_config_sha256'] = 'f' * 64
                        return json.dumps(receipt)
                with self.assertRaises(D.DeployError):
                    self.rollout(forward_only=True, runner=runner)
                self.assertEqual((self.root / 'operation.json').read_bytes(), raw)
                self.assertEqual(self.config.read_bytes(), self.original)
                self.assertFalse(list(self.root.glob('operation.forward-only-abandoned-*')))
                self.assertFalse(list(self.root.glob('install.config.before-*')))
                self.stage_mock.assert_not_called()

    def test_native_probe_archive_handoff_preserves_dispatched_cleanup_journal(self):
        secret = b'https://old.example.com/sub/fixture-token'
        self.probe_env(secret)
        original_run = self.run_fixture
        def failed_cleanup(command, cwd, stage, **kwargs):
            original_run(command, cwd, stage)
            self.assertNotIn(secret.decode(), repr(command))
            if stage == 'probe_cleanup':
                raise D.DeployError('fixture_cleanup_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_cleanup_failed'):
            self.rollout(runner=failed_cleanup)
        extra = self.stage_mock.call_args.args[8]
        self.assertEqual(extra['subscription-probe-url'], secret)
        self.assertEqual(extra['subscription-probe.sha256'], D.sha(secret).encode())
        upgrade = next(command for stage, command in self.calls if stage == 'upgrade')
        self.assertEqual(D.shlex.split(upgrade[-1])[14], D.sha(secret))
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertEqual(record['stage'], 'completed')
        self.assertEqual(record['probe_sha256'], D.sha(secret))
        self.assertNotIn(secret, (self.root / 'operation.json').read_bytes())
        self.probe_env(b'https://old.example.com/sub/new-token')
        self.calls.clear()
        self.rollout()
        self.assertEqual([stage for stage, _ in self.calls], ['canonical_policy', 'probe_cleanup'])
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertFalse((self.root / 'subscription-probe-url').exists())

    def test_native_predispatch_failure_cleans_private_copies(self):
        self.probe_env()
        def failed(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'doctor':
                raise D.DeployError('fixture_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failed)
        self.assertEqual([stage for stage, _ in self.calls], ['canonical_policy', 'doctor', 'probe_cleanup'])
        self.assertFalse((self.root / 'subscription-probe-url').exists())
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_stage_remote_probe_sends_exact_pair_without_env_or_credential_argv(self):
        secret = b'https://old.example.com/sub/fixture-token'
        manifest = {'source_commit': self.commit, 'version': self.version, 'assets': []}
        raw = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw)
        files = {'subscription-probe-url': secret, 'subscription-probe.sha256': D.sha(secret).encode()}
        def process(command, **kwargs):
            self.assertNotIn(secret.decode(), repr(command))
            with tarfile.open(fileobj=kwargs['stdin'], mode='r|') as archive:
                entries = {member.name: archive.extractfile(member).read() for member in archive}
            self.assertEqual(entries, {'release/release-manifest.json': raw, 'install.config': self.original, **files})
            self.assertEqual(D.shlex.split(command[-1])[-1], D.sha(secret))
            return subprocess.CompletedProcess(command, 0, json.dumps({'architecture': 'arm64',
                'manifest_sha256': D.sha(raw), 'config_sha256': D.sha(self.original),
                'attempt': D.remote_attempt(self.original, self.version)}).encode())
        with patch.object(D.subprocess, 'run', process):
            D.stage_remote(self.repo, self.root, self.bundle, self.original, ['ssh', 'fixture'],
                           self.commit, self.version, D.sha(raw), files)

    def test_native_interrupted_staging_is_retryable_without_dispatch(self):
        self.stage_mock.side_effect = D.DeployError('bridge_staging_failed')
        with self.assertRaisesRegex(D.DeployError, 'bridge_staging_failed'):
            self.rollout(adopt=True)
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy'])
        self.stage_mock.side_effect = self.staged_receipt
        self.rollout(adopt=True)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)

    def test_native_same_commit_replay_keeps_remote_attempt_after_baseline_cleanup(self):
        self.config.write_bytes(self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n')
        baseline_setting = self.config.read_bytes()
        original_prepare = D.stage_upgrade_baseline
        def prepared(config, version, remote_root):
            if not D.config_values(config).get('ULTRA_UPGRADE_BASELINE_FILE'):
                return original_prepare(config, version, remote_root)
            staged = D.config_candidate(config, version, remote_root / 'release', remote_root / 'baseline/descriptor.json')
            return staged, {'baseline/descriptor.json': b'{}', 'baseline/operator-journal.json': b'{}'}
        with patch.object(D, 'stage_upgrade_baseline', side_effect=prepared):
            first_attempt = D.remote_attempt(baseline_setting, self.version)
            self.rollout()
            self.assertNotIn(b'ULTRA_UPGRADE_BASELINE_FILE=', self.config.read_bytes())
            first_config = self.stage_mock.call_args.args[3]
            self.rollout()
        first, second = self.stage_mock.call_args_list
        self.assertEqual(first.args[3], first_config)
        self.assertEqual(second.args[3], first_config)
        with patch.object(D, 'stage_upgrade_baseline', side_effect=prepared):
            self.assertEqual(D.completed_baseline_replay(self.root, self.config.read_bytes(), self.version, self.commit)[0], first_attempt)
        self.assertEqual(first.args[1], second.args[1])
        self.assertEqual(D.remote_attempt(first.args[3], self.version), D.remote_attempt(second.args[3], self.version))

    def test_native_changed_transport_or_manifest_rejects_resume(self):
        def failure(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('upgrade_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failure)
        self.pins.write_bytes(b'new pins')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()
        self.pins.write_bytes(b'fixture pins')
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest + b' ')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_native_wrong_topology_and_provenance_fail_before_config_change(self):
        self.inventory['all']['children']['bridge']['hosts']['bridge']['ansible_host'] = '192.0.2.99'
        self.write_inventory()
        with self.assertRaisesRegex(D.DeployError, 'topology_changed'):
            self.rollout()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.stage_mock.call_count, 0)
        self.inventory['all']['children']['bridge']['hosts']['bridge']['ansible_host'] = '192.0.2.10'
        self.write_inventory()
        D.atomic_write(self.operator / 'job.json', b'{"operation":"adopt","request_sha256":"wrong"}')
        with self.assertRaisesRegex(D.DeployError, 'provenance_invalid'):
            self.rollout()

    def test_native_stale_exit_set_fails_before_staging(self):
        self.inventory['all']['children']['exits']['hosts']['exit_0']['ansible_host'] = '192.0.2.99'
        self.write_inventory()
        with self.assertRaisesRegex(D.DeployError, 'topology_changed'):
            self.rollout()
        self.assertFalse(self.stage_mock.called)

    def test_native_missing_key_pins_or_endpoint_pin_fails_before_staging(self):
        for path in [self.identity, self.pins]:
            raw = path.read_bytes()
            path.unlink()
            with self.assertRaises(OSError):
                self.rollout()
            path.write_bytes(raw)
            path.chmod(0o600)
        with patch.object(D.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(D.DeployError, 'endpoint_pin_missing'):
                self.rollout()
        self.assertFalse(self.stage_mock.called)

    def test_native_wrapper_does_not_read_identity_contents(self):
        original = Path.read_bytes
        def read(path):
            if path == self.identity:
                raise AssertionError('wrapper read private key')
            return original(path)
        with patch.object(Path, 'read_bytes', read):
            self.rollout()

    def test_native_identity_replacement_and_mode_change_fail_resume(self):
        def failure(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('upgrade_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failure)
        self.identity.chmod(0o644)
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()
        self.identity.chmod(0o600)
        self.identity.write_bytes(b'replaced credential')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_native_forbidden_secrets_fail_before_any_copy_or_stage(self):
        for key in ['TELEGRAM_BOT_TOKEN', 'MINISIGN_SECRET_KEY', 'MINISIGN_PASSWORD',
                    'MINISIGN_PRIVATE_KEY_FILE', 'ULTRA_RELEASE_SIGNING_PRIVATE_KEY',
                    'RELEASE_SIGNING_PASSPHRASE', 'ultra_db_dsn',
                    'ULTRA_CUTOVER_SUBSCRIPTION_URL']:
            with self.subTest(key=key):
                raw = self.original + key.encode() + b'=sensitive-fixture\n'
                self.config.write_bytes(raw)
                with self.assertRaisesRegex(D.DeployError, '^canonical_config_contains_forbidden_secret$'):
                    self.rollout()
                self.assertFalse(self.stage_mock.called)
                self.assertEqual(self.calls, [])
                self.assertEqual(self.config.read_bytes(), raw)
                self.assertFalse(list(self.root.glob('install.config.before-*')))

    def test_native_go_policy_rejection_precedes_backup_and_staging(self):
        def reject(command, cwd, stage, **kwargs):
            self.assertEqual(stage, 'canonical_policy')
            self.assertEqual(command[1], 'plan')
            raise D.DeployError('canonical_policy_failed_exit_1')
        with self.assertRaisesRegex(D.DeployError, 'canonical_policy_failed_exit_1'):
            self.rollout(runner=reject)
        self.assertFalse(self.stage_mock.called)
        self.assertFalse(list(self.root.glob('install.config.before-*')))
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_native_staging_sends_only_manifest_assets_and_exact_config(self):
        manifest = {'source_commit': self.commit, 'version': self.version,
                    'assets': [{'name': 'fixture', 'sha256': D.sha(b'fixture'), 'size': 7}]}
        raw_manifest = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw_manifest)
        (self.bundle / 'fixture').write_bytes(b'fixture')
        secret = self.repo / '.env'
        secret.write_bytes(b'not-to-be-read')
        real_read = Path.read_bytes
        def read(path):
            if path == secret:
                raise AssertionError('local .env read')
            return real_read(path)
        def process(command, **kwargs):
            stream = kwargs['stdin']
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                members = [(member.name, archive.extractfile(member).read()) for member in archive]
            self.assertEqual(members, [('release/release-manifest.json', raw_manifest),
                                      ('release/fixture', b'fixture'), ('install.config', self.original)])
            self.assertEqual(D.shlex.split(command[-1])[4], 'stage')
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            return subprocess.CompletedProcess(command, 0, json.dumps({'architecture': 'arm64',
                'manifest_sha256': D.sha(raw_manifest), 'config_sha256': D.sha(self.original),
                'attempt': D.remote_attempt(self.original, self.version)}).encode())
        with patch.object(Path, 'read_bytes', read), patch.object(D.subprocess, 'run', process):
            architecture = D.stage_remote(self.repo, self.root, self.bundle, self.original,
                ['ssh', '-F', '/dev/null', 'root@192.0.2.10'], self.commit, self.version, D.sha(raw_manifest))
        self.assertEqual(architecture['architecture'], 'arm64')

    def test_native_canonical_route_survives_deleted_adopt_directory(self):
        shutil.rmtree(self.operator.parent)
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY': '', 'ULTRA_OPERATOR_IDENTITY': str(self.identity),
                                     'ULTRA_OPERATOR_KNOWN_HOSTS': str(self.pins)}):
            self.rollout(adopt=True)
        staged = self.stage_mock.call_args.args[3]
        self.assertEqual(staged, self.config.read_bytes())
        self.assertNotIn(str(self.identity).encode(), staged)
        self.assertNotIn(str(self.pins).encode(), staged)
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy', 'doctor', 'adoption_check', 'adoption_apply', 'status'])
        transport = self.stage_mock.call_args.args[4]
        self.assertEqual(transport[-1], 'root@192.0.2.10')
        self.assertTrue(any('ProxyCommand=ssh -F /dev/null' in token and '-W %h:%p root@192.0.2.20' in token for token in transport))

    def test_native_canonical_route_requires_both_local_references(self):
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY': '', 'ULTRA_OPERATOR_IDENTITY': str(self.identity),
                                     'ULTRA_OPERATOR_KNOWN_HOSTS': ''}):
            with self.assertRaisesRegex(D.DeployError, 'identity_and_pins_required'):
                self.rollout()
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_native_read_only_failure_then_config_correction_changes_attempt(self):
        def reject(command, cwd, stage, **kwargs):
            if stage == 'adoption_check':
                raise D.DeployError('adoption_check_failed_exit_1')
        with self.assertRaisesRegex(D.DeployError, 'adoption_check_failed_exit_1'):
            self.rollout(adopt=True, runner=reject)
        first_config = self.stage_mock.call_args.args[3]
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'operation.json').exists())
        self.config.write_bytes(self.original + b'CORRECTED_POLICY=1\n')
        self.rollout(adopt=True)
        corrected = self.stage_mock.call_args.args[3]
        self.assertNotEqual(D.config_values(first_config)['ULTRA_AUTOMATION_RELEASE_DIR'],
                            D.config_values(corrected)['ULTRA_AUTOMATION_RELEASE_DIR'])


class RemoteProgram(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.parent = self.directory / 'state' / 'inputs'
        self.parent.parent.mkdir(mode=0o700)
        self.parent.mkdir(mode=0o700)
        self.commit = 'a' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.result = self.directory / 'executed.json'
        self.architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}[D.platform.machine()]
        binary = ('#!/usr/bin/env python3\nimport json,sys\nopen(' + repr(str(self.result)) + ',"w").write(json.dumps(sys.argv[1:]))\n').encode()
        self.assets = {'ultra-install-linux-' + self.architecture: binary}
        self.assets.update({'fixture-' + str(i): b'fixture' for i in range(13)})
        self.manifest = json.dumps({'source_commit': self.commit, 'version': self.version,
            'assets': [{'name': name, 'size': len(raw), 'sha256': D.sha(raw)} for name, raw in self.assets.items()]}).encode()
        self.config = b'SECRETS_ENV_FILE=/etc/ultra-relay/.env\n'
        # Run the actual remote implementation against a temporary local root;
        # adapt only the production root/UID checks for an unprivileged fixture.
        self.program = D.REMOTE_PROGRAM.replace("Path('/var/lib/ultra-ansible/operator-inputs')", 'Path(' + repr(str(self.parent)) + ')')
        self.program = self.program.replace('need(os.geteuid()==0)', 'need(True)').replace('info.st_uid==0', 'info.st_uid==os.geteuid()')
        self.root = self.parent / ('manual-' + self.commit + '-' + D.remote_attempt(self.config, self.version))

    def archive(self, mutate=None, forward_journal=None):
        entries = [('release/release-manifest.json', self.manifest)]
        entries += [('release/' + name, data) for name, data in self.assets.items()]
        entries += [('install.config', self.config)]
        if forward_journal is not None:
            entries.append(('forward-operation.json', forward_journal))
        if mutate:
            entries = mutate(entries)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w|') as archive:
            for name, raw in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        return stream.getvalue()

    def execute(self, mode, data=None, *args, probe_sha='', forward_only=False, forward_sha=''):
        if mode == 'run':
            args = (*args, *(['0'] * max(0, 4 - len(args))))
            args = (*args[:3], '1' if forward_only else '0', *args[4:])
            if forward_sha:
                args = (*args, probe_sha, forward_sha)
            elif probe_sha:
                args = (*args, probe_sha)
        else:
            if forward_sha:
                args = (*args, probe_sha, forward_sha)
            elif probe_sha:
                args = (*args, probe_sha)
        return subprocess.run([D.sys.executable, '-I', '-c', self.program, mode, self.commit, self.version,
            D.sha(self.manifest), D.sha(self.config), D.remote_attempt(self.config, self.version), *args], input=data, capture_output=True)

    def test_continuation_attests_existing_inputs_and_pre_handoff_lifecycle(self):
        old_commit = 'b' * 40
        old_version = 'v0.0.' + str(int(old_commit, 16))
        proof = json.dumps({'commit': old_commit, 'version': old_version}).encode()
        digest = D.sha(proof)
        staged = self.execute('stage', self.archive(forward_journal=proof), forward_sha=digest)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        operation = self.parent.parent / ('upgrade-' + self.version)
        operation.mkdir(mode=0o700)
        for name in ['operator-plan.json', 'execution-mode.json']:
            D.atomic_write(operation / name, b'{}')
        old_directory = self.parent.parent / ('upgrade-' + old_version)
        old_id = str(D.uuid.UUID(bytes=hashlib.sha256(str(old_directory).encode()).digest()[:16], version=4))
        lifecycle = self.parent.parent / 'lifecycle.json'
        D.atomic_write(lifecycle, json.dumps({'id': old_id, 'phase': 'applying'}).encode())
        receipt = self.execute('continue', forward_sha=digest)
        self.assertEqual(receipt.returncode, 0, receipt.stderr)
        self.assertEqual(json.loads(receipt.stdout)['lifecycle_id'], old_id)
        self.assertFalse(self.result.exists())
        dispatched = self.execute('run', None, self.architecture, 'upgrade', '0', '1', '', digest, '1', forward_only=True)
        self.assertEqual(dispatched.returncode, 0, dispatched.stderr)
        self.assertIn('--forward-only', json.loads(self.result.read_bytes()))
        self.result.unlink()
        for mutation in ['activate', 'lifecycle', 'proof', 'asset']:
            with self.subTest(mutation=mutation):
                if mutation == 'activate':
                    (operation / 'activate').mkdir()
                elif mutation == 'lifecycle':
                    D.atomic_write(lifecycle, b'{"id":"foreign","phase":"applying"}')
                elif mutation == 'proof':
                    D.atomic_write(self.root / 'forward-operation.json', b'{}')
                else:
                    D.atomic_write(self.root / 'release' / 'fixture-0', b'changed')
                rejected = self.execute('continue', forward_sha=digest)
                self.assertNotEqual(rejected.returncode, 0)
                dispatched = self.execute('run', None, self.architecture, 'upgrade', '0', '1', '', digest, '1', forward_only=True)
                self.assertNotEqual(dispatched.returncode, 0)
                self.assertFalse(self.result.exists())
                if mutation == 'activate':
                    (operation / 'activate').rmdir()
                elif mutation == 'lifecycle':
                    D.atomic_write(lifecycle, json.dumps({'id': old_id, 'phase': 'applying'}).encode())
                elif mutation == 'proof':
                    D.atomic_write(self.root / 'forward-operation.json', proof)

    def test_remote_probe_exact_archive_private_argv_cleanup_and_replay(self):
        secret = b'https://old.example.com/sub/fixture-token'
        probe_sha = D.sha(secret)
        def archive(raw=secret, binding=probe_sha.encode()):
            return self.archive(lambda rows: rows + [('subscription-probe-url', raw),
                                                    ('subscription-probe.sha256', binding)])
        staged = self.execute('stage', archive(), probe_sha=probe_sha)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertNotIn(secret, staged.stdout + staged.stderr)
        path = self.root / 'subscription-probe-url'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_bytes(), secret)
        upgraded = self.execute('run', None, self.architecture, 'upgrade', '1', probe_sha=probe_sha)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        argv = json.loads(self.result.read_bytes())
        self.assertEqual(argv[argv.index('--subscription-probe-url-file') + 1], str(path))
        self.assertNotIn(secret.decode(), repr(argv))
        for _ in range(2):
            cleaned = self.execute('cleanup', probe_sha=probe_sha)
            self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
            self.assertFalse(path.exists())
        self.assertEqual((self.root / 'subscription-probe.sha256').read_bytes(), probe_sha.encode())
        missing = self.execute('run', None, self.architecture, 'upgrade', probe_sha=probe_sha)
        self.assertNotEqual(missing.returncode, 0)
        replay = self.execute('stage', archive(), probe_sha=probe_sha)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(path.read_bytes(), secret)
        replacement = b'https://old.example.com/sub/replacement'
        rejected = self.execute('stage', archive(replacement, D.sha(replacement).encode()), probe_sha=D.sha(replacement))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(path.read_bytes(), secret)
        for data in (archive(b'changed'), self.archive(lambda rows: rows + [('subscription-probe.sha256', probe_sha.encode())]),
                     archive(binding=b'x' * 64)):
            rejected = self.execute('stage', data, probe_sha=probe_sha)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertNotIn(secret, rejected.stdout + rejected.stderr)
        path.chmod(0o644)
        self.assertNotEqual(self.execute('run', None, self.architecture, 'upgrade', probe_sha=probe_sha).returncode, 0)

    def test_actual_stage_native_commands_and_no_secret_copy(self):
        staged = self.execute('stage', self.archive())
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {'release', 'install.config'})
        self.assertEqual((self.root / 'install.config').read_bytes(), self.config)
        self.assertEqual(json.loads(staged.stdout)['architecture'], self.architecture)
        for action, expected in [('doctor', ['doctor']), ('adoption_check', ['adopt', '--adopt-runtime', '--bridge-native', '--check']),
                                 ('adoption_apply', ['apply', '--adopt-runtime', '--bridge-native']),
                                 ('upgrade', ['operator-upgrade', '--release-dir', str(self.root / 'release'),
                                              '--source-commit', self.commit, '--version', self.version,
                                              '--manifest-sha256', D.sha(self.manifest), '--config-sha256', D.sha(self.config)]),
                                 ('status', ['status'])]:
            run = self.execute('run', None, self.architecture, action)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv = json.loads(self.result.read_bytes())
            self.assertEqual(argv[:len(expected)], expected)
            self.assertEqual(argv[-2:], ['--config', str(self.root / 'install.config')])
        retried = self.execute('run', None, self.architecture, 'upgrade', '1')
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertIn('--retry-failed', json.loads(self.result.read_bytes()))
        journal = b'{"stage":"upgrade"}'
        journal_sha = D.sha(journal)
        staged_forward = self.execute('stage', self.archive(forward_journal=journal), forward_sha=journal_sha)
        self.assertEqual(staged_forward.returncode, 0, staged_forward.stderr)
        self.assertEqual((self.root / 'forward-operation.json').read_bytes(), journal)
        doctor = self.execute('run', None, self.architecture, 'doctor', forward_sha=journal_sha)
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertEqual(json.loads(self.result.read_bytes())[0], 'doctor')
        forwarded = self.execute('run', None, self.architecture, 'upgrade', forward_only=True, forward_sha=journal_sha)
        self.assertEqual(forwarded.returncode, 0, forwarded.stderr)
        forwarded_argv = json.loads(self.result.read_bytes())
        self.assertIn('--forward-only', forwarded_argv)
        self.assertEqual(forwarded_argv[forwarded_argv.index('--forward-journal-file') + 1], str(self.root / 'forward-operation.json'))
        self.assertEqual(forwarded_argv[forwarded_argv.index('--forward-journal-sha256') + 1], journal_sha)
        status = self.execute('run', None, self.architecture, 'status', forward_sha=journal_sha)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(self.result.read_bytes())[0], 'status')
        cleaned = self.execute('cleanup', forward_sha=journal_sha)
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse((self.root / 'forward-operation.json').exists())
        again = self.execute('stage', self.archive())
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_actual_stage_rejects_legacy_baseline_before_same_commit_replay(self):
        local_state = self.directory / 'local-state'
        local_state.mkdir(mode=0o700)
        old_commit, old_attempt = 'b' * 40, 'c' * 64
        old_assets = [{'name': 'asset-' + str(i)} for i in range(14)]
        old_manifest = json.dumps({'source_commit': old_commit, 'version': 'v2.4.2',
                                   'assets': old_assets}, sort_keys=True).encode()
        old_manifest_path = local_state / 'release-manifest.json'
        old_manifest_path.write_bytes(old_manifest); old_manifest_path.chmod(0o400)
        journal = {'schema': 1, 'commit': old_commit, 'version': 'v2.4.2', 'remote_attempt': old_attempt,
                   'manifest_sha256': D.sha(old_manifest), 'mutator_dispatched': True}
        journal_raw = json.dumps(journal, sort_keys=True).encode()
        journal_path = local_state / 'operation.json'
        journal_path.write_bytes(journal_raw); journal_path.chmod(0o600)
        descriptor_path = local_state / 'upgrade-baseline.json'
        descriptor = {'schema': 1, 'journal': str(journal_path), 'journal_sha256': D.sha(journal_raw),
                      'manifest': str(old_manifest_path), 'manifest_sha256': D.sha(old_manifest)}
        descriptor_path.write_text(json.dumps(descriptor, sort_keys=True)); descriptor_path.chmod(0o600)
        original = (b'SECRETS_ENV_FILE=/etc/ultra-relay/.env\n'
                    + ('ULTRA_UPGRADE_BASELINE_FILE=' + str(descriptor_path) + '\n').encode()
                    + b'POLICY=unchanged\n')
        attempt = D.remote_attempt(original, self.version)
        self.root = self.parent / ('manual-' + self.commit + '-' + attempt)
        production_root = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + self.commit + '-' + attempt)
        prepare_baseline = D.stage_upgrade_baseline
        def fixture_prepare(raw_config, version, remote_root):
            self.assertEqual(remote_root, production_root)
            staged, files = prepare_baseline(raw_config, version, production_root)
            staged = staged.replace(str(production_root / 'baseline/descriptor.json').encode(),
                                    str(self.root / 'baseline/descriptor.json').encode())
            staged_descriptor = json.loads(files['baseline/descriptor.json'])
            staged_descriptor['manifest'] = staged_descriptor['manifest'].replace(
                '/var/lib/ultra-ansible/operator-inputs', str(self.parent))
            staged_descriptor['journal'] = staged_descriptor['journal'].replace(
                str(production_root), str(self.root))
            files['baseline/descriptor.json'] = (json.dumps(staged_descriptor, sort_keys=True, separators=(',', ':')) + '\n').encode()
            return staged, files
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            D.stage_upgrade_baseline(original, self.version, production_root)
        self.assertFalse(self.root.exists())

    def test_actual_stage_baseline_requires_exact_private_inventory_and_rechecks_it(self):
        old_commit, old_attempt, old_manifest_sha = 'b' * 40, 'c' * 64, 'd' * 64
        journal = {'schema': 1, 'commit': old_commit, 'remote_attempt': old_attempt,
                   'manifest_sha256': old_manifest_sha, 'mutator_dispatched': True}
        journal_raw = json.dumps(journal, sort_keys=True).encode()
        self.config += b'ULTRA_UPGRADE_BASELINE_FILE=' + (str(self.parent / 'baseline/descriptor.json')).encode() + b'\n'
        self.root = self.parent / ('manual-' + self.commit + '-' + D.remote_attempt(self.config, self.version))
        old_release = self.parent / ('manual-' + old_commit + '-' + old_attempt) / 'release'
        descriptor = {'schema': 1, 'journal': str(self.root / 'baseline/operator-journal.json'),
                      'journal_sha256': D.sha(journal_raw),
                      'manifest': str(old_release / 'release-manifest.json'),
                      'manifest_sha256': old_manifest_sha}
        descriptor_raw = json.dumps(descriptor, sort_keys=True).encode()
        entries = [('release/release-manifest.json', self.manifest)]
        entries += [('release/' + name, data) for name, data in self.assets.items()]
        entries += [('install.config', self.config), ('baseline/descriptor.json', descriptor_raw),
                    ('baseline/operator-journal.json', journal_raw)]
        def archive_with(rows):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w|') as archive:
                for name, raw in rows:
                    entry = tarfile.TarInfo(name); entry.size = len(raw)
                    archive.addfile(entry, io.BytesIO(raw))
            return stream.getvalue()
        staged = self.execute('stage', archive_with(entries))
        self.assertNotEqual(staged.returncode, 0)
        self.assertIn(b'manual_operation_quiescence_migration_required', staged.stderr)
        self.assertFalse(self.root.exists())
        self.assertFalse(list(self.parent.glob('.manual-*')))
        self.assertFalse(self.result.exists())

    def test_bad_asset_incomplete_stage_and_unexpected_files_never_publish(self):
        for mutate in [lambda rows: rows[:-1], lambda rows: rows + [('../escape', b'bad')],
                       lambda rows: rows + [('.env', b'never')],
                       lambda rows: [(n, b'changed' if n == 'release/fixture-0' else raw) for n, raw in rows]]:
            with self.subTest(mutation=mutate):
                result = self.execute('stage', self.archive(mutate))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.root.exists())
                self.assertFalse(list(self.parent.glob('.manual-*')))
                self.assertFalse(self.result.exists())
        # A genuinely interrupted stream must also fail without publishing.
        result = self.execute('stage', self.archive()[:1024])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.root.exists())

    def test_reverify_before_mutator_and_frozen_config_identity(self):
        self.assertEqual(self.execute('stage', self.archive()).returncode, 0)
        (self.root / 'release' / 'fixture-0').write_bytes(b'changed')
        result = self.execute('run', None, self.architecture, 'adoption_apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.result.exists())
        (self.root / 'release' / 'fixture-0').write_bytes(b'fixture')
        (self.root / 'install.config').write_bytes(b'changed')
        result = self.execute('run', None, self.architecture, 'upgrade')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.result.exists())
        self.assertNotEqual(self.execute('stage', self.archive()).returncode, 0)

    def test_wrong_commit_and_manifest_hash_fail_closed(self):
        altered = self.manifest.replace(self.commit.encode(), b'b' * 40)
        result = self.execute('stage', self.archive(lambda rows: [(n, altered if n.endswith('release-manifest.json') else raw) for n, raw in rows]))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.root.exists())

    def test_corrected_config_same_commit_gets_new_immutable_attempt(self):
        self.assertEqual(self.execute('stage', self.archive()).returncode, 0)
        old_root, old_config = self.root, self.config
        self.config += b'CORRECTED_POLICY=1\n'
        result = self.execute('stage', self.archive())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((old_root / 'install.config').read_bytes(), old_config)
        staged = [p for p in self.parent.glob('manual-*') if p.is_dir()]
        self.assertEqual(len(staged), 2)
        new_root = next(p for p in staged if p != old_root)
        self.assertEqual((new_root / 'install.config').read_bytes(), self.config)


class RuntimeReuse(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.source = self.repo / 'source'
        (self.source / 'scripts').mkdir(parents=True)
        (self.source / 'deploy/ansible').mkdir(parents=True)
        self.requirements = self.source / 'deploy/ansible/requirements.txt'
        self.requirements.write_text('fixture==1.0\n')
        self.helper = Path(__file__).with_name('manual-deploy-runtime.py')
        shutil.copyfile(self.helper, self.source / 'scripts/manual-deploy-runtime.py')
        self.cache = self.repo / 'dist'
        self.cache.mkdir()
        self.members = {'requirements.lock': b'fixture==1.0 --hash=sha256:' + hashlib.sha256(b'wheel').hexdigest().encode() + b'\n',
                        'wheels/fixture-1.0-py3-none-any.whl': b'wheel'}
        self.write_pair()
        spec = importlib.util.spec_from_file_location('runtime_test', self.helper)
        self.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runtime)

    def write_pair(self):
        for architecture in ['amd64', 'arm64']:
            with tarfile.open(self.cache / ('ultra-ansible-runtime-linux-' + architecture + '.tar.gz'), 'w:gz') as archive:
                for name, raw in self.members.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
        names = ['ultra-ansible-runtime-linux-' + architecture + '.tar.gz' for architecture in ['amd64', 'arm64']]
        names += ['fixture-' + str(n) for n in range(11)]
        for name in names[2:]:
            (self.cache / name).write_bytes(b'fixture')
        checksums = ''.join(hashlib.sha256((self.cache / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
        (self.cache / 'checksums.txt').write_text(checksums)
        rows = [{'name': name, 'size': len((self.cache / name).read_bytes()), 'sha256': hashlib.sha256((self.cache / name).read_bytes()).hexdigest()} for name in names + ['checksums.txt']]
        (self.cache / 'release-manifest.json').write_text(json.dumps({'schema_version': 1, 'source_commit': 'a' * 40, 'assets': rows}))

    def test_verified_pair_works_without_pip_and_is_frozen_inside_source(self):
        with patch.object(D, 'run', side_effect=AssertionError('pip must not run')):
            environment = D.prepare_runtime_environment(self.repo, self.source)
        frozen = Path(environment['ULTRA_VERIFIED_RUNTIME_DIR'])
        self.assertEqual(frozen.parent, self.source)
        self.runtime.validate_pair(frozen, self.requirements)
        self.assertEqual((frozen / 'ultra-ansible-runtime-linux-amd64.tar.gz').read_bytes(),
                         (self.cache / 'ultra-ansible-runtime-linux-amd64.tar.gz').read_bytes())

    def test_real_make_runtime_hook_copies_verified_archives_without_pip(self):
        # Execute the actual checked-in ansible-dist recipe in a disposable tree.
        makefile = Path(__file__).resolve().parents[1] / 'Makefile'
        text = makefile.read_text()
        recipe = text[text.index('ansible-dist:\n'):text.index('\ntest-ansible:', text.index('ansible-dist:\n'))]
        (self.source / 'Makefile').write_text(recipe + '\n')
        ansible = self.source / 'deploy/ansible'
        for name in ['ansible.cfg', 'controller.py']:
            (ansible / name).write_text('fixture')
        for name in ['playbooks', 'roles', 'library', 'callback_plugins']:
            (ansible / name).mkdir()
        environment = os.environ.copy()
        environment['ULTRA_VERIFIED_RUNTIME_DIR'] = str(self.cache)
        result = subprocess.run(['make', 'ansible-dist'], cwd=self.source, env=environment, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        for architecture in ['amd64', 'arm64']:
            name = 'ultra-ansible-runtime-linux-' + architecture + '.tar.gz'
            self.assertEqual((self.source / 'dist' / name).read_bytes(), (self.cache / name).read_bytes())

    def test_missing_cache_requires_pip_and_discards_inherited_override(self):
        (self.cache / 'release-manifest.json').unlink()
        with patch.dict(os.environ, {'ULTRA_VERIFIED_RUNTIME_DIR': '/unverified'}), patch.object(D, 'run') as run:
            environment = D.prepare_runtime_environment(self.repo, self.source)
        self.assertNotIn('ULTRA_VERIFIED_RUNTIME_DIR', environment)
        self.assertEqual(run.call_args.args[0][-2:], ['pip', '--version'])

    def test_archive_hash_tampering_is_rejected(self):
        with (self.cache / 'ultra-ansible-runtime-linux-amd64.tar.gz').open('ab') as stream:
            stream.write(b'tamper')
        with self.assertRaisesRegex(AssertionError, 'hash mismatch'):
            self.runtime.validate_pair(self.cache, self.requirements)

    def test_different_exact_requirements_are_rejected_without_network_fallback(self):
        self.requirements.write_text('fixture==2.0\n')
        with patch.object(D, 'run', side_effect=AssertionError('network fallback forbidden')):
            with self.assertRaisesRegex(AssertionError, 'pins mismatch'):
                D.prepare_runtime_environment(self.repo, self.source)

    def test_wheel_hash_mismatch_is_rejected(self):
        self.members['wheels/fixture-1.0-py3-none-any.whl'] = b'changed'
        self.write_pair()
        with self.assertRaisesRegex(AssertionError, 'wheel hash mismatch'):
            self.runtime.validate_pair(self.cache, self.requirements)

    def test_wrong_architecture_and_missing_python_abis_are_rejected(self):
        raw = self.members.pop('wheels/fixture-1.0-py3-none-any.whl')
        self.members['wheels/fixture-1.0-cp312-cp312-manylinux2014_aarch64.whl'] = raw
        self.write_pair()
        with self.assertRaisesRegex(AssertionError, 'architecture mismatch'):
            self.runtime.validate_pair(self.cache, self.requirements)
        self.members['wheels/fixture-1.0-cp312-cp312-manylinux2014_x86_64.whl'] = self.members.pop('wheels/fixture-1.0-cp312-cp312-manylinux2014_aarch64.whl')
        self.write_pair()
        with self.assertRaisesRegex(AssertionError, 'Python ABI missing'):
            self.runtime.validate_pair(self.cache, self.requirements)

    def test_unsafe_archive_paths_are_rejected(self):
        self.members['../escape.whl'] = b'escape'
        self.write_pair()
        with self.assertRaisesRegex(ValueError, 'unsafe runtime archive'):
            self.runtime.validate_pair(self.cache, self.requirements)


class LegacyForwardAttestation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / 'state'
        self.state.mkdir(mode=0o700)
        self.parent = self.state / 'operator-inputs'
        self.parent.mkdir(mode=0o700)
        D.atomic_write(self.parent / 'manual-deploy.lock', b'')
        self.commit = 'a' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.attempt = 'b' * 64
        self.config = b'INSTALL_SCHEMA_VERSION=2\n'
        self.manifest = {'source_commit': self.commit, 'version': self.version, 'assets': []}
        self.manifest_raw = json.dumps(self.manifest).encode()
        self.root = self.parent / ('manual-' + self.commit + '-' + self.attempt)
        self.root.mkdir(mode=0o700)
        (self.root / 'release').mkdir(mode=0o700)
        D.atomic_write(self.root / 'install.config', self.config)
        D.atomic_write(self.root / 'release/release-manifest.json', self.manifest_raw)
        self.directory = self.state / ('upgrade-' + self.version)
        self.directory.mkdir(mode=0o700)
        self.activate = self.directory / 'activate'
        self.activate.mkdir(mode=0o700)
        import uuid
        operation_id = str(uuid.UUID(bytes=hashlib.sha256(str(self.directory).encode()).digest()[:16], version=4))
        request = {'inventory': {'all': {'children': {'bridge': {'hosts': {'bridge': {}}}, 'exits': {'hosts': {'exit_0': {}}}}}},
                   'variables': {'ultra_lifecycle_id': operation_id, 'ultra_release_manifest_sha256': D.sha(self.manifest_raw),
                                 'ultra_release_manifest': self.manifest}}
        self.request_raw = json.dumps(request).encode()
        D.atomic_write(self.activate / 'request.json', self.request_raw)
        self.job = {'schema_version': 1, 'operation': 'upgrade', 'request_sha256': D.sha(self.request_raw)}
        for name in ('job.json', 'receipt.json'):
            D.atomic_write(self.activate / name, json.dumps(self.job).encode())
        self.program = D.REMOTE_LEGACY_ATTEST.replace("Path('/var/lib/ultra-ansible')", 'Path(' + repr(str(self.state)) + ')')
        self.program = self.program.replace('os.geteuid()==0', 'True').replace('info.st_uid==0', 'info.st_uid==os.geteuid()')

    def execute(self):
        return subprocess.run([D.sys.executable, '-I', '-c', self.program, self.commit, self.version,
                               self.attempt, D.sha(self.manifest_raw), D.sha(self.config)], capture_output=True)

    def test_attestation_returns_only_exact_identities_without_writing(self):
        before = {str(p): p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'schema': 1, 'commit': self.commit, 'version': self.version,
            'remote_attempt': self.attempt, 'manifest_sha256': D.sha(self.manifest_raw), 'staged_config_sha256': D.sha(self.config)})
        self.assertEqual({str(p): p.read_bytes() for p in self.state.rglob('*') if p.is_file()}, before)
        self.assertNotIn(self.config, result.stdout)

    def test_attestation_rejects_changed_config_manifest_request_job_receipt(self):
        for path in (self.root / 'install.config', self.root / 'release/release-manifest.json',
                     self.activate / 'request.json', self.activate / 'job.json', self.activate / 'receipt.json'):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                D.atomic_write(path, b'{}')
                self.assertNotEqual(self.execute().returncode, 0)
                D.atomic_write(path, original)

    def test_attestation_rejects_cross_operation_and_unbound_request_receipts(self):
        for key, value in (('ultra_lifecycle_id', 'other-operation'), ('ultra_release_manifest_sha256', 'c' * 64),
                           ('ultra_release_manifest', dict(self.manifest, source_commit='c' * 40))):
            request = json.loads(self.request_raw)
            request['variables'][key] = value
            raw = json.dumps(request).encode()
            D.atomic_write(self.activate / 'request.json', raw)
            for name in ('job.json', 'receipt.json'):
                D.atomic_write(self.activate / name, json.dumps(dict(self.job, request_sha256=D.sha(raw))).encode())
            self.assertNotEqual(self.execute().returncode, 0)

    def test_attestation_rejects_public_symlink_missing_and_busy_evidence(self):
        path = self.root / 'install.config'
        path.chmod(0o644)
        self.assertNotEqual(self.execute().returncode, 0)
        path.chmod(0o600)
        target = self.root / 'copy.config'
        path.rename(target)
        path.symlink_to(target)
        self.assertNotEqual(self.execute().returncode, 0)
        path.unlink()
        self.assertNotEqual(self.execute().returncode, 0)
        target.rename(path)
        with D.lock(self.parent / 'manual-deploy.lock'):
            self.assertNotEqual(self.execute().returncode, 0)


if __name__ == '__main__':
    unittest.main()
