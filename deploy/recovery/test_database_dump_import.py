import tempfile
import unittest
from unittest import mock
import hashlib
import contextlib
import io
import json
import subprocess
from pathlib import Path

import database_dump_import as importer


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.archive = Path(self.temp.name) / 'dump.custom'
        self.archive.write_bytes(b'synthetic archive bytes')
        self.calls = []
        self.receipt = Path(self.temp.name) / 'state' / 'receipt.json'
        self.receipt_patch = mock.patch.object(importer, 'RECEIPT', self.receipt)
        self.receipt_patch.start()

    def tearDown(self):
        self.temp.cleanup()
        self.receipt_patch.stop()

    def fake_call(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == 'psql':
            value = '123456:42' if 'pg_control_system' in argv[-1] else '' if argv[-1] == importer.MARKER_SQL else '0'
            return type('Result', (), {'stdout': value})()
        return type('Result', (), {'stdout': ''})()

    def test_validates_then_restores_empty_database(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        result = importer.run({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest},
                              environ={'PGPASSWORD': 'secret'}, call=self.fake_call)
        self.assertEqual(result['size'], len(b'synthetic archive bytes'))
        self.assertEqual([call[0][0] for call in self.calls], ['pg_restore', 'psql', 'psql', 'psql', 'pg_restore', 'psql'])
        restore = self.calls[-2][0]
        self.assertIn('--exit-on-error', restore)
        self.assertIn('--no-owner', restore)
        self.assertIn('--no-acl', restore)
        self.assertIn('--single-transaction', self.calls[-1][0])
        self.assertIn('--file=-', self.calls[-1][0])
        self.assertEqual([kwargs['timeout'] for _, kwargs in self.calls], [60, 60, 60, 60, 600, 600])
        self.assertEqual([kwargs['env']['PGPASSWORD'] for _, kwargs in self.calls], ['secret'] * 6)

    def test_rejects_nonempty_database_without_restore(self):
        def nonempty(argv, **kwargs):
            self.calls.append((argv, kwargs))
            value = '123456:42' if 'pg_control_system' in argv[-1] else '1'
            return type('Result', (), {'stdout': value})()
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'target_database_not_empty'):
            importer.run({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest}, call=nonempty)
        self.assertEqual([call[0][0] for call in self.calls], ['pg_restore', 'psql', 'psql', 'psql'])

    def test_matching_receipt_allows_safe_retry_without_restore(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.receipt.parent.mkdir()
        self.receipt.write_text('{"database":"ultra","database_oid":"42","sha256":"' + digest + '","system_identifier":"123456","user":"ultra"}')
        def existing(argv, **kwargs):
            self.calls.append((argv, kwargs))
            value = '123456:42' if 'pg_control_system' in argv[-1] else '1'
            return type('Result', (), {'stdout': value})()
        result = importer.run({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest}, call=existing)
        self.assertTrue(result['already_imported'])
        self.assertEqual([call[0][0] for call in self.calls], ['pg_restore', 'psql', 'psql', 'psql'])

    def test_retry_recovers_commit_ack_and_receipt_failures_from_database(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        plan = {'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest}
        evidence = {'database': 'ultra', 'database_oid': '42', 'sha256': digest, 'system_identifier': '123456', 'user': 'ultra'}
        for failure in ('commit_ack', 'receipt'):
            with self.subTest(failure=failure):
                self.receipt.unlink(missing_ok=True)
                committed = []
                def call(argv, **kwargs):
                    if argv[0] == 'pg_restore':
                        if '--file=-' in argv:
                            kwargs['stdout'].write(b'SELECT 1;\n')
                        return type('Result', (), {'stdout': ''})()
                    if '--file=-' in argv:
                        committed.append(True)
                        if failure == 'commit_ack':
                            raise subprocess.TimeoutExpired('psql', 600)
                        return type('Result', (), {'stdout': ''})()
                    statement = argv[-1]
                    value = ('123456:42' if 'pg_control_system' in statement else
                             importer.marker(evidence) if statement == importer.MARKER_SQL and committed else
                             '' if statement == importer.MARKER_SQL else '1' if committed else '0')
                    return type('Result', (), {'stdout': value})()
                with mock.patch.object(importer, 'atomic_receipt', side_effect=OSError('fixture disk fault')):
                    with self.assertRaises((OSError, subprocess.TimeoutExpired)):
                        importer.run(plan, call=call)
                self.assertFalse(self.receipt.exists())
                self.assertTrue(importer.run(plan, call=call)['already_imported'])
                self.assertEqual(len(committed), 1)
                self.assertEqual(json.loads(self.receipt.read_text()), evidence)
                with mock.patch.object(importer.shutil, 'which', return_value='/usr/bin/fixture'):
                    self.assertFalse(importer.preflight(plan, call=call, cluster_state='online')['fresh_database_target'])

    def test_rejects_oversized_archive_before_subprocess(self):
        with mock.patch.object(importer, 'MAX_ARCHIVE_BYTES', 2):
            with self.assertRaisesRegex(ValueError, 'archive_size_out_of_bounds'):
                importer.run({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': '0' * 64}, call=self.fake_call)
        self.assertEqual(self.calls, [])

    def test_preflight_clean_host_passes_after_archive_validation(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        result = importer.preflight({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest},
                                    call=self.fake_call, cluster_state='absent')
        self.assertTrue(result['fresh_database_target'])
        self.assertEqual([item[0][0] for item in self.calls], ['pg_restore'])
        self.assertEqual(self.calls[0][1]['timeout'], 60)

    def test_preflight_inspects_online_cluster_through_maintenance_database(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        def inspect(argv, **kwargs):
            self.calls.append((argv, kwargs))
            command = argv[-1] if argv[0] == 'runuser' else ''
            value = '1' if 'EXISTS' in command or 'count(*) FROM pg_class' in command else '123456:42'
            return type('Result', (), {'stdout': value})()
        with mock.patch.object(importer.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name):
            with self.assertRaisesRegex(ValueError, 'target_database_not_empty'):
                importer.preflight({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest},
                                   call=inspect, cluster_state='online')
        self.assertEqual([item[0][0] for item in self.calls], ['pg_restore', 'runuser', 'runuser', 'runuser', 'runuser'])
        self.assertIn('postgres', self.calls[1][0])

    def test_preflight_fails_closed_for_unavailable_existing_cluster(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'postgresql_state_unavailable'):
            importer.preflight({'archive': str(self.archive), 'database': 'ultra', 'user': 'ultra', 'sha256': digest},
                               call=self.fake_call, cluster_state='unavailable')

    def test_cluster_detection_is_read_only_and_uses_cluster_status(self):
        def status(argv, **kwargs):
            self.calls.append((argv, kwargs))
            return type('Result', (), {'stdout': '16 main 5432 online postgres /var/lib/postgresql/16/main /var/log/postgresql/log'})()
        with mock.patch.object(importer.shutil, 'which', side_effect=lambda name: '/usr/bin/pg_lsclusters' if name == 'pg_lsclusters' else None):
            self.assertEqual(importer.detect_cluster_state(status), 'online')
        self.assertEqual(self.calls[0][0], ['/usr/bin/pg_lsclusters', '--no-header'])
        self.assertEqual(self.calls[0][1]['timeout'], 60)

    def test_cluster_detection_allows_clean_host_without_server_artifacts(self):
        with mock.patch.object(importer.shutil, 'which', return_value=None):
            with mock.patch.object(Path, 'glob', return_value=[]):
                self.assertEqual(importer.detect_cluster_state(self.fake_call), 'absent')
        self.assertEqual(self.calls, [])

    def test_timeout_error_is_stable_and_does_not_expose_tool_output(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(importer.sys, 'stdin', io.StringIO('{}')):
            with mock.patch.object(importer.sys, 'argv', ['database_dump_import.py']):
                with mock.patch.object(importer, 'run', side_effect=subprocess.TimeoutExpired('pg_restore', 600, output='sensitive-data')):
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        result = importer.main()
        self.assertEqual(result, 1)
        self.assertNotIn('sensitive-data', out.getvalue() + err.getvalue())
        self.assertEqual(json.loads(err.getvalue()), {'error': 'database_import_timeout'})


if __name__ == '__main__':
    unittest.main()
