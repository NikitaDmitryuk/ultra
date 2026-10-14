#!/usr/bin/env python3
"""Transferred lifecycle durability/readiness guarantees, using synthetic inputs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


controller = load('controller_contract', ROOT / 'deploy/ansible/controller.py')
state = load('release_state_contract', ROOT / 'deploy/ansible/roles/release/files/state.py')


class Contracts(unittest.TestCase):
    def test_atomic_receipt_syncs_data_then_rename_then_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            events = []
            sync, replace = os.fsync, os.replace
            def observed_sync(fd):
                events.append('directory_sync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_sync')
                sync(fd)
            def observed_replace(source, target):
                replace(source, target)
                events.append('rename')
            with patch.object(controller.os, 'fsync', side_effect=observed_sync), patch.object(controller.os, 'replace', side_effect=observed_replace):
                controller.atomic(path, {'state': 'succeeded'})
            self.assertEqual(events, ['file_sync', 'rename', 'directory_sync'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            real = Path(directory) / 'real';real.write_text('keep')
            link = Path(directory) / 'link';link.symlink_to(real)
            with self.assertRaises(ValueError):
                controller.atomic(link, {'state': 'changed'})
            self.assertEqual(real.read_text(), 'keep')

    def test_activation_needs_new_backup_and_monitor_evidence(self):
        values = {'reconcile.json': {'database': 'fixture'},
                  'recovery-reconcile-status.json': {'state': 'ready', 'independent': True, 'updated_at': 100},
                  'last-success.json': {'snapshot_at': 100}, 'release-manifest.json': {'version': 'v9.0.0'}}
        digest = hashlib.sha256(b'[]').hexdigest()
        def result(argv, **kwargs):
            output = b'25:25' if 'schema_migrations' in argv[-1] else b't'
            return types.SimpleNamespace(stdout=output, returncode=0)
        fake_reconcile = types.SimpleNamespace(desired_nodes=lambda *args: ([], set()), discover=lambda *args: [])
        with patch.dict(sys.modules, {'reconcile': fake_reconcile}), patch.object(state, 'read', side_effect=lambda path: values[Path(path).name]), patch.object(state.time, 'time', return_value=110), patch.object(state.subprocess, 'run', side_effect=result), patch.object(sys, 'argv', ['state.py', '--status', '--expected', digest, '--not-before', '100']):
            with self.assertRaisesRegex(ValueError, 'post_activation_evidence_required'):
                state.main()
            values['recovery-reconcile-status.json']['updated_at'] = 101
            with self.assertRaisesRegex(ValueError, 'post_activation_evidence_required'):
                state.main()
            values['last-success.json']['snapshot_at'] = 101
            with patch('builtins.print') as output:
                state.main()
            self.assertTrue(json.loads(output.call_args.args[0])['ready'])


if __name__ == '__main__':
    unittest.main()
