#!/usr/bin/env python3
"""Local wrapper contracts; candidate builds and deployment calls are mocked."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('manual_deploy', Path(__file__).with_name('manual-deploy.py'))
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class ManualReplacement(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        (self.repo / 'scripts').mkdir()
        self.config = self.repo / 'install.config'
        self.original = b'# keep operator configuration\nULTRA_AUTOMATION_VERSION="old"\nULTRA_UPGRADE_BASELINE_FILE="/obsolete"\nDATABASE_DUMP="/obsolete.dump"\n'
        self.config.write_bytes(self.original)
        self.config.chmod(0o600)
        self.manual_root = self.repo / 'dist' / 'manual'
        self.manual_root.mkdir(parents=True)
        self.manual_root.chmod(0o700)
        self.last_deployed = self.manual_root / 'last-deployed.config'
        self.attempts = self.manual_root / 'replacement-attempts'
        self.attempts.mkdir(mode=0o700)
        self.previous_deployed_config = self.original.replace(b'keep operator', b'last deployed')
        self.last_deployed.write_bytes(self.previous_deployed_config)
        self.last_deployed.chmod(0o600)
        self.bundle = self.repo / 'candidate'
        self.bundle.mkdir()
        (self.bundle / 'release-manifest.json').write_bytes(b'{"fixture":true}')
        self.commit = 'a' * 40
        self.calls = []
        self.previous_configs_seen = []

    def run_main(self, arguments=(), fail=False, dispatched=True):
        def run(command, cwd, stage, **kwargs):
            self.calls.append((stage, command))
            if stage in ('source_commit', 'source_commit_recheck'):
                return self.commit
            if stage.startswith('tracked_tree_'):
                return ''
            if stage == 'replace_production':
                self.previous_configs_seen = [Path(command[index + 1]).read_bytes()
                                              for index, value in enumerate(command[:-1])
                                              if value == '--previous-config']
                with D.lock(D.canonical_config_lock(self.config)):
                    pass
            if fail and stage == 'replace_production':
                if dispatched:
                    state = Path(command[command.index('--state-dir') + 1])
                    state.mkdir(mode=0o700)
                    (state / 'stage.json').write_text('{"stage":"fence-bridge"}')
                raise D.DeployError('replace_production_failed_exit_1')
        with patch.object(D, '__file__', str(self.repo / 'scripts/manual-deploy.py')), \
                patch.object(D.sys, 'argv', ['manual-deploy.py', *arguments]), \
                patch.object(D, 'run', side_effect=run), \
                patch.object(D, 'build_candidate', return_value=self.bundle), \
                patch.object(D.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(D.platform, 'machine', return_value='x86_64'), \
                contextlib.redirect_stdout(io.StringIO()):
            D.main()

    def test_build_only_preserves_config_and_avoids_replacement(self):
        self.run_main(['--build-only'])
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertNotIn('replace_production', [stage for stage, _ in self.calls])

    def test_first_deploy_uses_current_config_as_only_known_inventory(self):
        self.last_deployed.unlink()
        self.run_main()
        self.assertEqual(len(self.previous_configs_seen), 1)
        self.assertIn(b'ULTRA_AUTOMATION_RELEASE_DIR=', self.previous_configs_seen[0])
        self.assertEqual(self.last_deployed.read_bytes(), self.config.read_bytes())

    def test_deploy_pins_canonical_config_and_invokes_only_replacement(self):
        self.run_main()
        raw = self.config.read_bytes()
        self.assertIn(str(self.bundle).encode(), raw)
        self.assertNotIn(b'ULTRA_UPGRADE_BASELINE_FILE', raw)
        self.assertNotIn(b'DATABASE_DUMP=', raw)
        self.assertIn(b'# keep operator configuration', raw)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        command = next(command for stage, command in self.calls if stage == 'replace_production')
        self.assertEqual(command[:2], [str(self.bundle / 'ultra-install-linux-amd64'), 'replace-production'])
        flags = dict(zip(command[2::2], command[3::2]))
        self.assertEqual(set(flags), {'--config', '--source-commit', '--manifest-sha256', '--previous-config', '--state-dir'})
        self.assertEqual(flags['--manifest-sha256'], hashlib.sha256(b'{"fixture":true}').hexdigest())
        self.assertEqual(len(self.previous_configs_seen), 2)
        self.assertIn(self.previous_deployed_config, self.previous_configs_seen)
        self.assertTrue(any(b'ULTRA_AUTOMATION_RELEASE_DIR=' in config for config in self.previous_configs_seen))
        self.assertEqual(list(self.attempts.iterdir()), [])
        self.assertEqual(self.last_deployed.read_bytes(), raw)
        state = Path(flags['--state-dir'])
        self.assertEqual(state.parent, self.repo / 'dist/manual')
        self.assertFalse(state.exists())

    def test_failed_replacement_preserves_candidate_config(self):
        with self.assertRaisesRegex(D.DeployError, 'replace_production_failed_exit_1'):
            self.run_main(fail=True)
        self.assertIn(str(self.bundle).encode(), self.config.read_bytes())
        self.assertEqual(self.last_deployed.read_bytes(), self.previous_deployed_config)
        self.assertEqual(len(list(self.attempts.glob('*.config'))), 1)

    def test_pre_dispatch_failure_does_not_poison_next_corrected_config(self):
        with self.assertRaisesRegex(D.DeployError, 'replace_production_failed_exit_1'):
            self.run_main(fail=True, dispatched=False)
        self.assertEqual(list(self.attempts.iterdir()), [])
        self.run_main()
        self.assertEqual(list(self.attempts.iterdir()), [])

    def test_failed_attempt_inventory_is_passed_on_following_replacement(self):
        failed = self.original.replace(b'keep operator', b'failed attempt')
        D.atomic_write(self.attempts / (hashlib.sha256(failed).hexdigest() + '.config'), failed)
        self.run_main()
        self.assertIn(failed, self.previous_configs_seen)
        self.assertIn(self.previous_deployed_config, self.previous_configs_seen)
        self.assertEqual(list(self.attempts.iterdir()), [])

    def test_failed_attempt_inventories_accumulate_until_success(self):
        with self.assertRaises(D.DeployError):
            self.run_main(fail=True)
        first_attempt = next(self.attempts.glob('*.config')).read_bytes()
        D.atomic_write(self.config, self.config.read_bytes() + b'ULTRA_EXIT_2_HOST="192.0.2.12"\n')
        with self.assertRaises(D.DeployError):
            self.run_main(fail=True)
        attempted = list(self.attempts.glob('*.config'))
        self.assertEqual(len(attempted), 2)
        second_attempt = next(path.read_bytes() for path in attempted if path.read_bytes() != first_attempt)
        self.run_main()
        self.assertIn(first_attempt, self.previous_configs_seen)
        self.assertIn(second_attempt, self.previous_configs_seen)
        self.assertEqual(list(self.attempts.iterdir()), [])

    def test_canonical_symlink_rejected_before_build_or_dispatch(self):
        other = self.repo / 'other.config'
        self.config.rename(other)
        self.config.symlink_to(other)
        with self.assertRaises(D.DeployError):
            self.run_main()
        self.assertEqual(self.calls, [])

    def test_duplicate_candidate_key_rejected(self):
        with self.assertRaises(D.DeployError):
            D.config_candidate(b'ULTRA_AUTOMATION_VERSION=a\nULTRA_AUTOMATION_VERSION=b\n', 'v1', self.bundle)

    def test_legacy_retry_flag_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self.run_main(['--retry-failed'])
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
