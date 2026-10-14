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
import unittest
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
        self.commit = 'abcdef123456789012345678901234567890abcdef'
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.bundle = self.root / self.version
        self.bundle.mkdir()
        (self.bundle / 'release-manifest.json').write_bytes(b'fixture-manifest')
        self.calls = []

    def run_fixture(self, command, cwd, stage, capture=False, env=None):
        self.calls.append((stage, command))

    def rollout(self, adopt=False, runner=None, config_path=None, retry_failed=False):
        with patch.object(D, 'run', runner or self.run_fixture), patch.object(D.platform, 'system', return_value='Linux'), patch.object(D.platform, 'machine', return_value='x86_64'), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            D.rollout(self.repo, self.root, self.bundle, self.commit, self.version, adopt, config_path, retry_failed)

    def test_numeric_version_exact_commit_round_trip_and_path_limit(self):
        self.assertRegex(self.version, r'^v[0-9]+\.[0-9]+\.[0-9]+$')
        self.assertEqual(int(self.version[5:]), int(self.commit, 16))
        self.assertLess(len(self.version), 95)

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

    def test_retry_failed_is_explicitly_forwarded_to_operator_upgrade(self):
        self.rollout(retry_failed=True)
        command = self.calls[1][1]
        self.assertIn('operator-upgrade', command)
        self.assertIn('--retry-failed', command)

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
        with self.assertRaisesRegex(D.DeployError, 'conflicting_unfinished'):
            self.rollout()

    def test_retry_same_operation_keeps_original_backup(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.rollout()
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
        with self.assertRaisesRegex(D.DeployError, 'canonical_config_changed'):
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
        self.stage = patch.object(D, 'stage_remote', return_value='arm64')
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
            self.assertEqual(remote[4:11], ['run', self.commit, self.version, D.sha(self.manifest), D.sha(self.config.read_bytes()), D.remote_attempt(self.original, self.version), 'arm64'])
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

    def test_native_interrupted_staging_is_retryable_without_dispatch(self):
        self.stage_mock.side_effect = D.DeployError('bridge_staging_failed')
        with self.assertRaisesRegex(D.DeployError, 'bridge_staging_failed'):
            self.rollout(adopt=True)
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy'])
        self.stage_mock.side_effect = None
        self.rollout(adopt=True)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)

    def test_native_changed_transport_or_manifest_rejects_resume(self):
        def failure(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('upgrade_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failure)
        self.pins.write_bytes(b'new pins')
        with self.assertRaisesRegex(D.DeployError, 'transport_or_manifest_changed'):
            self.rollout()
        self.pins.write_bytes(b'fixture pins')
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest + b' ')
        with self.assertRaisesRegex(D.DeployError, 'transport_or_manifest_changed'):
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
        with self.assertRaisesRegex(D.DeployError, 'identity_private_required'):
            self.rollout()
        self.identity.chmod(0o600)
        self.identity.write_bytes(b'replaced credential')
        with self.assertRaisesRegex(D.DeployError, 'transport_or_manifest_changed'):
            self.rollout()

    def test_native_forbidden_secrets_fail_before_any_copy_or_stage(self):
        for key in ['TELEGRAM_BOT_TOKEN', 'MINISIGN_SECRET_KEY', 'MINISIGN_PASSWORD',
                    'MINISIGN_PRIVATE_KEY_FILE', 'ULTRA_RELEASE_SIGNING_PRIVATE_KEY',
                    'RELEASE_SIGNING_PASSPHRASE', 'ultra_db_dsn']:
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
        self.assertEqual(architecture, 'arm64')

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

    def archive(self, mutate=None):
        entries = [('release/release-manifest.json', self.manifest)]
        entries += [('release/' + name, data) for name, data in self.assets.items()]
        entries += [('install.config', self.config)]
        if mutate:
            entries = mutate(entries)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w|') as archive:
            for name, raw in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        return stream.getvalue()

    def execute(self, mode, data=None, *args):
        return subprocess.run([D.sys.executable, '-I', '-c', self.program, mode, self.commit, self.version,
            D.sha(self.manifest), D.sha(self.config), D.remote_attempt(self.config, self.version), *args], input=data, capture_output=True)

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
        again = self.execute('stage', self.archive())
        self.assertEqual(again.returncode, 0, again.stderr)

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


if __name__ == '__main__':
    unittest.main()
