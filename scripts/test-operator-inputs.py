#!/usr/bin/env python3
"""Offline tests for explicit operator-input ownership migration."""
import fcntl
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('operator_inputs', Path(__file__).with_name('operator-inputs.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class OperatorInputsMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / 'install.config'
        self.file.write_bytes(b'fixture bytes\n')
        self.file.chmod(0o600)

    def test_dry_run_checks_exact_file_and_preserves_bytes_and_mode(self):
        before = (self.file.read_bytes(), self.file.stat().st_mode, self.file.stat().st_uid)
        with patch.object(M.os, 'geteuid', return_value=0):
            M.migrate(self.file, before[2], False)
        after = (self.file.read_bytes(), self.file.stat().st_mode, self.file.stat().st_uid)
        self.assertEqual(after, before)

    def test_symlink_and_group_writable_inputs_are_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.file)
        with self.assertRaises(OSError):
            M.migrate(link, os.geteuid(), False)
        self.file.chmod(0o620)
        with self.assertRaisesRegex(M.MigrationError, 'operator_input_group_world_write_forbidden'):
            M.migrate(self.file, os.geteuid(), False)

    def test_busy_manual_lock_cannot_be_migrated(self):
        for name in ('manual-deploy.lock', 'deploy.lock', '.install.config.manual-deploy.lock'):
            with self.subTest(name=name):
                lock = self.root / name
                lock.write_bytes(b'')
                lock.chmod(0o600)
                held = os.open(lock, os.O_RDWR)
                try:
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    before = (lock.stat().st_uid, lock.stat().st_mode, lock.read_bytes())
                    with self.assertRaisesRegex(M.MigrationError, 'operator_lock_busy'):
                        M.migrate(lock, os.geteuid(), True)
                    self.assertEqual((lock.stat().st_uid, lock.stat().st_mode, lock.read_bytes()), before)
                finally:
                    os.close(held)

    def test_root_staging_sets_group_and_owner_to_root(self):
        before = self.file.stat()
        after = type('Stat', (), {'st_uid': 0, 'st_mode': (before.st_mode & ~0o777) | 0o600})()
        with patch.object(M.os, 'geteuid', return_value=0), \
             patch.object(M.os, 'fchown') as fchown, \
             patch.object(M.os, 'fstat', side_effect=[before, after]):
            M.migrate(self.file, before.st_uid, True)
        self.assertEqual(fchown.call_args.args[1:], (0, 0))

    def test_fifo_is_rejected_without_blocking(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(M.MigrationError,
                                    'operator_input_regular_single_link_or_directory_required'):
            M.migrate(fifo, os.geteuid(), True)


if __name__ == '__main__':
    unittest.main()
