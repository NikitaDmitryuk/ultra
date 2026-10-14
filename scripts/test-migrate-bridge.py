#!/usr/bin/env python3
"""Read-only inventory regressions; native lifecycle guards have Go tests.

Encrypted journal/archive integrity and PG role preservation are verified by
recovery/test_restore.py and test_bootstrap_plan.py; deployment is owned by roles.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('migration_state', ROOT / 'deploy/ansible/roles/bridge_migration/files/state.py')
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)


class Inventory(unittest.TestCase):
    def test_rejects_broad_or_system_state(self):
        for path in ('/', '/etc', '/var/lib', '/etc/shadow', '/etc/ssh/key', '/opt/../etc/key'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                state.safe_path(path)

    def test_environment_files_override_directives_and_disable_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            normal, paused = Path(directory) / 'normal.env', Path(directory) / 'paused.env'
            normal.write_text('ULTRA_REPLICATION_KEY_FILE=/opt/ultra/key\nULTRA_VULTR_KEY_FILE=/opt/ultra/token\n')
            paused.write_text('ULTRA_REPLICATION_KEY_FILE=\nULTRA_VULTR_KEY_FILE=\n')
            def run(*args, **kwargs):
                output = 'ULTRA_REPLICATION_KEY_FILE=/another/key'
                if 'EnvironmentFiles' in args:
                    output = f'{normal} (ignore_errors=no) {paused} (ignore_errors=no)'
                return mock.Mock(stdout=output)
            with mock.patch.object(state, 'run', side_effect=run):
                values = state.environment()
            self.assertEqual(values['ULTRA_REPLICATION_KEY_FILE'], '')
            self.assertEqual(values['ULTRA_VULTR_KEY_FILE'], '')

    def test_remote_or_ambiguous_database_is_rejected_before_freeze(self):
        for dsn in ('postgres://member:key@192.0.2.40/ultra', 'postgres://member:key@127.0.0.1:6543/ultra',
                    'host=127.0.0.1 dbname=ultra', 'postgres://member@127.0.0.1/ultra'):
            with mock.patch.object(state, 'spec', return_value={'database': {'dsn': dsn}}), self.assertRaises(ValueError):
                state.database()
        with mock.patch.object(state, 'spec', return_value={'database': {'dsn': 'postgres://member:key@127.0.0.1/ultra'}}):
            self.assertEqual(state.database(), ('ultra', 'member'))


if __name__ == '__main__':
    unittest.main()
