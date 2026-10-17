import hashlib
import io
import json
import stat
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import restore_database


class DedicatedDatabaseRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.restore_id = 'a' * 64
        self.directory = self.root / (self.restore_id + '-database')
        self.directory.mkdir(mode=0o700)
        self.dump = b'fixture custom archive'
        self.archive = self.directory / 'stage.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as output:
            item = tarfile.TarInfo('database.dump')
            item.size = len(self.dump)
            output.addfile(item, io.BytesIO(self.dump))
        self.archive.chmod(0o600)
        self.plan = {'restore_id': self.restore_id, 'database': {'name': 'ultra_db', 'user': 'ultra_app'},
                     'database_host': '192.0.2.30', 'stage_sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                     'dump_sha256': hashlib.sha256(self.dump).hexdigest(), 'schema_min': 10, 'schema_max': 20}
        plan_path = self.directory / 'plan.json'
        plan_path.write_text(json.dumps(self.plan))
        plan_path.chmod(0o600)
        self.root_patch = mock.patch.object(restore_database, 'RESTORE_ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.root_guard = mock.patch.object(restore_database, 'require_root')
        self.root_guard.start()
        self.addCleanup(self.root_guard.stop)

    def test_restore_only_imports_into_empty_database_with_atomic_transaction(self):
        def sql(statement, database='postgres'):
            if 'pg_control_system' in statement: return '1000001:16384'
            if 'server_version_num' in statement: return '16'
            if 'pg_is_in_recovery' in statement: return 'f'
            if 'pg_database WHERE NOT datistemplate' in statement: return '0'
            if 'FROM pg_roles' in statement: return '1'
            if 'pg_get_userbyid' in statement: return 'ultra_app'
            if 'FROM pg_tables' in statement: return '0'
            if 'max(version)' in statement: return '12'
            raise AssertionError(statement)
        imported = []
        def restore_run(argv, **kwargs):
            if argv[0] == 'pg_restore':
                return b'1; TABLE public.users\n'
            self.assertEqual(argv[:5], ['runuser', '-u', 'postgres', '--', 'pg_restore'])
            self.assertNotIn(str(self.directory / 'database.dump'), argv)
            stream = kwargs['stdin']
            self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(Path(stream.name).stat().st_mode), 0o600)
            imported.append(stream.read())
            return b''
        with mock.patch.object(restore_database, 'sql', side_effect=sql), \
                mock.patch.object(restore_database, 'run', side_effect=restore_run) as run:
            result = restore_database.restore(self.directory, self.plan)
        self.assertEqual(imported, [self.dump])
        self.assertEqual(result, {'verified': True, 'database': 'ultra_db', 'schema': 12})
        argv = run.call_args.args[0]
        self.assertIn('--single-transaction', argv)
        self.assertIn('--role=ultra_app', argv)
        self.assertTrue((self.directory / 'database-result.json').exists())

    def test_private_dump_descriptor_is_readable_by_restore_subprocess(self):
        dump = self.directory / 'private.dump'
        dump.write_bytes(self.dump)
        dump.chmod(0o600)
        with dump.open('rb') as stream:
            output = restore_database.run(
                [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                stdin=stream)
        self.assertEqual(output.encode(), self.dump)
        self.assertEqual(stat.S_IMODE(dump.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_complete_database_playbook_can_repeat_after_activation_failure(self):
        imported = []
        identity = {'value': '1000001:16384'}
        def sql(statement, database='postgres'):
            if 'pg_control_system' in statement: return identity['value']
            if 'server_version_num' in statement: return '16'
            if 'pg_is_in_recovery' in statement: return 'f'
            if 'pg_database WHERE NOT datistemplate' in statement: return '0'
            if 'FROM pg_roles' in statement: return '1'
            if 'pg_get_userbyid' in statement: return 'ultra_app'
            if 'FROM pg_tables' in statement: return '1' if imported else '0'
            if 'max(version)' in statement: return '12'
            raise AssertionError(statement)
        def restore_run(argv, **kwargs):
            if argv[0] == 'pg_restore': return '1; TABLE public.users'
            imported.append(kwargs['stdin'].read())
            return ''
        with mock.patch.object(restore_database, 'sql', side_effect=sql), \
                mock.patch.object(restore_database, 'run', side_effect=restore_run), \
                mock.patch.object(restore_database.shutil, 'which', return_value=None):
            self.assertTrue(restore_database.check(self.directory, self.plan)['empty'])
            self.assertTrue(restore_database.restore(self.directory, self.plan)['verified'])
            with mock.patch.object(restore_database, 'extract_dump', side_effect=AssertionError('must not reimport')):
                self.assertTrue(restore_database.check(self.directory, self.plan)['resumed'])
                self.assertTrue(restore_database.restore(self.directory, self.plan)['resumed'])
            self.assertEqual(imported, [self.dump])
            for changed_identity in ('2000002:16384', '1000001:24576'):
                identity['value'] = changed_identity
                with self.subTest(identity=changed_identity), self.assertRaisesRegex(ValueError, 'restored_database_identity_changed'):
                    restore_database.check(self.directory, self.plan)
            identity['value'] = '1000001:16384'
            changed = dict(self.plan, database_host='192.0.2.31')
            with self.assertRaisesRegex(ValueError, 'restore_database_receipt_conflict'):
                restore_database.check(self.directory, changed)

    def test_interrupted_extraction_reuses_only_verified_private_dump(self):
        args = (self.archive, self.directory, self.plan['stage_sha256'], self.plan['dump_sha256'])
        first = restore_database.extract_dump(*args, verify_toc=False)
        self.assertEqual(restore_database.extract_dump(*args, verify_toc=False), first)
        first.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'restore_database_dump_digest_mismatch'):
            restore_database.extract_dump(*args, verify_toc=False)

    def test_stage_has_independent_state_and_artifact_bounds_and_unchanged_dump_bound(self):
        for dump_size,state_size,artifact_size,accepted in (
                (10,40,100,True), (10,41,100,False), (10,40,101,False), (11,39,100,False)):
            with self.subTest(dump=dump_size,state=state_size,artifacts=artifact_size):
                dump=b'd'*dump_size
                with tarfile.open(self.archive,'w:gz') as output:
                    for name,payload in (('database.dump',dump),('manifest.json',b's'*state_size),
                                         ('artifacts/binary',b'a'*artifact_size)):
                        item=tarfile.TarInfo(name);item.size=len(payload)
                        output.addfile(item,io.BytesIO(payload))
                args=(self.archive,self.directory,restore_database.digest(self.archive),hashlib.sha256(dump).hexdigest())
                with mock.patch.object(restore_database,'MAX_STATE_BYTES',50),mock.patch.object(restore_database,'MAX_ARTIFACT_BYTES',100),mock.patch.object(restore_database,'MAX_DUMP_BYTES',10):
                    if accepted:
                        path=restore_database.extract_dump(*args,verify_toc=False)
                        self.assertEqual(path.read_bytes(),dump)
                        path.unlink()
                    else:
                        with self.assertRaisesRegex(ValueError,'restore_stage_exceeds_bounds|restore_database_dump_missing'):
                            restore_database.extract_dump(*args,verify_toc=False)
                        self.assertFalse((self.directory/'database.dump').exists())

    def test_stage_transport_allows_more_than_old_one_gib_cap(self):
        # Sparse transport checks the physical-file limit without allocating or
        # parsing a multi-gigabyte fixture; expanded limits are tested separately.
        with self.archive.open('wb') as stream:
            stream.truncate(1024**3+1)
        self.assertEqual(restore_database.private_file(self.archive,restore_database.MAX_ARCHIVE_BYTES),self.archive)
        self.assertEqual(restore_database.MAX_STATE_BYTES,512*1024**2)
        self.assertEqual(restore_database.MAX_ARTIFACT_BYTES,1024**3)
        self.assertEqual(restore_database.MAX_DUMP_BYTES,512*1024**2)

    def test_populated_database_is_never_overwritten(self):
        def sql(statement, database='postgres'):
            if 'pg_control_system' in statement: return '1000001:16384'
            if 'server_version_num' in statement: return '16'
            if 'pg_is_in_recovery' in statement: return 'f'
            if 'pg_database WHERE NOT datistemplate' in statement: return '0'
            if 'FROM pg_roles' in statement: return '1'
            if 'pg_get_userbyid' in statement: return 'ultra_app'
            if 'FROM pg_tables' in statement: return '1'
            raise AssertionError(statement)
        with mock.patch.object(restore_database, 'sql', side_effect=sql), mock.patch.object(restore_database, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'dedicated_database_not_empty'):
                restore_database.restore(self.directory, self.plan)
        run.assert_not_called()

    def test_stage_digest_mismatch_rejected_before_database_mutation(self):
        self.plan['stage_sha256'] = '0' * 64
        def sql(statement, database='postgres'):
            if 'pg_control_system' in statement: return '1000001:16384'
            if 'server_version_num' in statement: return '16'
            if 'pg_is_in_recovery' in statement: return 'f'
            if 'pg_database WHERE NOT datistemplate' in statement: return '0'
            if 'FROM pg_roles' in statement: return '1'
            if 'pg_get_userbyid' in statement: return 'ultra_app'
            if 'FROM pg_tables' in statement: return '0'
            raise AssertionError(statement)
        with mock.patch.object(restore_database, 'sql', side_effect=sql), mock.patch.object(restore_database, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'restore_stage_digest_mismatch'):
                restore_database.restore(self.directory, self.plan)
        run.assert_not_called()

    def test_preflight_accepts_new_host_without_postgres_and_validates_dump(self):
        with mock.patch.object(restore_database.shutil, 'which', return_value=None):
            result = restore_database.check(self.directory, self.plan)
        self.assertEqual(result, {'verified': True, 'empty': True})
        self.assertFalse((self.directory / 'database.dump').exists())

    def test_preflight_rejects_populated_target_before_provisioning(self):
        with mock.patch.object(restore_database.shutil, 'which', return_value='/usr/bin/psql'), \
                mock.patch.object(restore_database, 'sql', return_value='2') as sql:
            with self.assertRaisesRegex(ValueError, 'dedicated_database_host_not_empty'):
                restore_database.check(self.directory, self.plan)
        sql.assert_called_once()

    def test_preflight_fails_closed_when_existing_server_is_unavailable(self):
        with mock.patch.object(restore_database.shutil, 'which', return_value='/usr/bin/psql'), \
                mock.patch.object(restore_database, 'sql', side_effect=OSError('not reachable')):
            with self.assertRaisesRegex(ValueError, 'dedicated_database_preflight_failed'):
                restore_database.check(self.directory, self.plan)


if __name__ == '__main__':
    unittest.main()
