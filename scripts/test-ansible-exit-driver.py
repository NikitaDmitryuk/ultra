#!/usr/bin/env python3
"""Rootless driver guard/cleanup tests. No Docker, SSH, or real systemd actions."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('exit_driver', ROOT / 'scripts/test-ansible-exit.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.namespace = self.root / 'canonical'
        self.addCleanup(patch.stopall)
        patch.object(D, 'NAMESPACE', self.namespace).start()
        patch.object(D, 'MANAGED_UNIT_FILES', ()).start()
        self.installer = self.root / 'source-installer'
        self.installer.write_bytes(b'synthetic executable fixture')
        self.argv = ['fixture', '--installer', str(self.installer), '--ansible-playbook', '/fixture/ansible-playbook']

    def model_owned_root_files(self):
        """Model root ownership only inside our temporary fixture tree."""
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == self.root or self.root in path.parents:
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_size=info.st_size)
            return info
        patch.object(Path, 'lstat', lstat).start()

    def test_nonroot_or_preexisting_namespace_stops_before_any_driver_mutation(self):
        for root_user, exists in [(False, False), (True, True)]:
            with self.subTest(root=root_user, exists=exists):
                if exists:
                    self.namespace.mkdir(mode=0o700)
                    (self.namespace / 'foreign-record').write_text('preserve')
                with patch.object(D.os, 'geteuid', return_value=0 if root_user else 1000), \
                     patch.object(__import__('sys'), 'argv', self.argv), \
                     patch.object(D, 'run') as run, patch.object(D, 'fixture_workspace') as workspace:
                    with self.assertRaisesRegex(ValueError, 'fixture_'):
                        D.main()
                    run.assert_not_called()
                    workspace.assert_not_called()
                if exists:
                    self.assertEqual((self.namespace / 'foreign-record').read_text(), 'preserve')
                else:
                    self.assertFalse(self.namespace.exists())

    def test_existing_managed_unit_or_missing_manager_refuses_before_docker(self):
        # Establish trusted-runtime premises without depending on this host's
        # package-manager ownership/modes; all systemd calls remain mocked.
        original = Path.lstat
        def trusted_runtime(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode & ~0o022)
        with patch.object(D.os, 'geteuid', return_value=0), \
             patch.object(Path, 'lstat', trusted_runtime), \
             patch.object(__import__('sys'), 'argv', self.argv), \
             patch.object(D, 'fixture_workspace') as workspace:
            for results in [[''], ['systemd-fixture', 'LoadState=loaded'],
                            ['systemd-fixture', 'LoadState=not-found', 'ultra-execution-foreign.service loaded active running']]:
                with self.subTest(results=results), patch.object(D, 'run', side_effect=results) as run:
                    with self.assertRaisesRegex(ValueError, 'fixture_(actual_systemd_manager_required|managed_controller_preexists|existing_ultra_unit)'):
                        D.main()
                    self.assertTrue(all(call.args[0][0] == '/usr/bin/systemctl' for call in run.call_args_list))
                    workspace.assert_not_called()
                    self.assertFalse(self.namespace.exists())

    def test_unloaded_managed_unit_file_refuses_without_manager_or_docker(self):
        unit = self.root / 'ultra-ansible-controller.service'
        unit.write_text('unloaded foreign controller unit')
        with patch.object(D.os, 'geteuid', return_value=0), \
             patch.object(D, 'MANAGED_UNIT_FILES', (unit,)), \
             patch.object(__import__('sys'), 'argv', self.argv), \
             patch.object(D, 'run') as run, patch.object(D, 'fixture_workspace') as workspace:
            with self.assertRaisesRegex(ValueError, 'managed_controller_preexists'):
                D.main()
            run.assert_not_called()
            workspace.assert_not_called()
        self.assertEqual(unit.read_text(), 'unloaded foreign controller unit')
        self.assertFalse(self.namespace.exists())

    def test_workspace_failure_preserves_own_evidence_and_private_copy(self):
        directory = self.root / 'workspace'
        directory.mkdir(mode=0o700)
        with patch.object(D.tempfile, 'mkdtemp', return_value=str(directory)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(RuntimeError, 'synthetic failure'):
                with D.fixture_workspace(self.installer) as observed:
                    self.assertEqual(observed, directory)
                    self.assertEqual((directory / 'ultra-install').read_bytes(), self.installer.read_bytes())
                    self.assertEqual((directory / 'ultra-install').stat().st_mode & 0o777, 0o700)
                    (self.namespace / 'execution-fence.json').write_text('uncertain fixture evidence')
                    raise RuntimeError('synthetic failure')
        self.assertIn('evidence retained', output.getvalue())
        self.assertTrue(directory.exists())
        self.assertEqual((self.namespace / 'execution-fence.json').read_text(), 'uncertain fixture evidence')

    def cleanup_fixture(self):
        directory = self.root / 'workspace'
        job = directory / 'state' / '11111111-2222-3333-4444-555555555555'
        job.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
        self.namespace.mkdir(mode=0o700)
        owner = {'schema': 1, 'directory': str(directory), 'identity': 'owned-fixture'}
        self.write(self.namespace / '.fixture-owner.json', owner)
        self.write(self.namespace / 'execution-admission.lock', {})
        generation = 'a' * 32
        fence = {'job_directory': str(job), 'generation': generation}
        receipt = {'state': 'succeeded', 'execution_generation': generation}
        self.write(job / 'receipt.json', receipt)
        completion = {'fence': fence, 'local_cleanup': True,
                      'receipt_sha256': hashlib.sha256((job / 'receipt.json').read_bytes()).hexdigest()}
        self.write(job / 'execution-completion.json', completion)
        proof = {'mode': 'transient', 'fence': fence, 'unit': 'ultra-execution-' + generation + '.service'}
        self.write(job / 'execution-containment.json', proof)
        self.write(job / ('execution-drain-' + generation + '.json'), {
            'proof': proof, 'completion_sha256': hashlib.sha256((job / 'execution-completion.json').read_bytes()).hexdigest()})
        return directory, owner, job

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def test_cleanup_rejects_foreign_fence_wrong_marker_and_changed_receipt(self):
        directory, owner, job = self.cleanup_fixture()
        self.model_owned_root_files()
        with patch.object(D, 'run') as run:
            fence = self.namespace / 'execution-fence.json'
            self.write(fence, {'unknown': True})
            with self.assertRaisesRegex(ValueError, 'uncertain_or_foreign'):
                D.cleanup_owned_fixture(directory, owner)
            self.assertTrue(fence.exists())
            fence.unlink()
            self.write(self.namespace / '.fixture-owner.json', {**owner, 'identity': 'foreign'})
            with self.assertRaisesRegex(ValueError, 'ownership_changed'):
                D.cleanup_owned_fixture(directory, owner)
            self.write(self.namespace / '.fixture-owner.json', owner)
            self.write(job / 'receipt.json', {'state': 'failed'})
            with self.assertRaisesRegex(ValueError, 'normal_cleanup_unverified'):
                D.cleanup_owned_fixture(directory, owner)
            run.assert_not_called()
            self.assertTrue(directory.exists())
            self.assertTrue(self.namespace.exists())

    def test_cleanup_requires_actual_inactive_empty_unit_before_deleting_own_state(self):
        directory, owner, job = self.cleanup_fixture()
        self.model_owned_root_files()
        with patch.object(D, 'run', return_value='LoadState=loaded\nActiveState=active') as run:
            with self.assertRaisesRegex(ValueError, 'unit_not_drained'):
                D.cleanup_owned_fixture(directory, owner)
            self.assertEqual(run.call_args.args[0][0], '/usr/bin/systemctl')
            self.assertIn('ultra-execution-' + 'a' * 32 + '.service', run.call_args.args[0])
            self.assertTrue(job.exists())
        original_exists, original_text = Path.exists, Path.read_text
        def exists(path):
            return True if str(path).startswith('/sys/fs/cgroup/system.slice/ultra-execution-') else original_exists(path)
        def text(path, *args, **kwargs):
            return 'populated 1\n' if str(path).startswith('/sys/fs/cgroup/system.slice/ultra-execution-') else original_text(path, *args, **kwargs)
        with patch.object(D, 'run', return_value='LoadState=loaded\nActiveState=inactive'), \
             patch.object(Path, 'exists', exists), patch.object(Path, 'read_text', text):
            with self.assertRaisesRegex(ValueError, 'cgroup_not_empty'):
                D.cleanup_owned_fixture(directory, owner)
            self.assertTrue(directory.exists())
        with patch.object(D, 'run', return_value='LoadState=not-found\nActiveState=inactive'):
            D.cleanup_owned_fixture(directory, owner)
        self.assertFalse(directory.exists())
        self.assertFalse(self.namespace.exists())

    def test_cli_failure_surfaces_classification_without_arbitrary_output(self):
        command = ['/fixture/ultra-install', 'ansible-exit']
        result = subprocess.CompletedProcess(command, 1, b'sensitive-result',
                                              b'execution_containment_unverified private-secret-value')
        with patch.object(D.subprocess, 'run', return_value=result), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(subprocess.CalledProcessError):
                D.run(command)
        self.assertIn('execution_containment_unverified', output.getvalue())
        self.assertNotIn('private-secret-value', output.getvalue())
        self.assertNotIn('sensitive-result', output.getvalue())


if __name__ == '__main__':
    unittest.main()
