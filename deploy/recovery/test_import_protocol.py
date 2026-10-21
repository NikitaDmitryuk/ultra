"""Real private-cluster checks for the transaction boundary (opt-in)."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import import_protocol as protocol


class GenerationTests(unittest.TestCase):
    def test_generation_failure_cannot_dispatch_partial_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'dump'
            archive.write_bytes(b'fixture')
            calls = []
            def fail(argv, **kwargs):
                calls.append(argv)
                kwargs['stdout'].write(b'CREATE TABLE partial(v int);')
                raise subprocess.CalledProcessError(1, argv)
            with self.assertRaises(subprocess.CalledProcessError):
                protocol.import_transaction(archive, 'target', {'system_identifier': '123', 'database_oid': '42'}, ['psql'], call=fail)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], 'pg_restore')

    def test_sql_uses_private_descriptor_and_one_psql_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'dump'
            archive.write_bytes(b'fixture')
            seen = []
            evidence = {'system_identifier': '123', 'database_oid': '42'}
            def call(argv, **kwargs):
                if argv[0] == 'pg_restore':
                    self.assertEqual(kwargs['stdin'].read(), b'fixture')
                    kwargs['stdout'].write(b'CREATE TABLE public.payload(v int);\n')
                else:
                    self.assertIn('--single-transaction', argv)
                    self.assertIn('--file=-', argv)
                    self.assertEqual(os.fstat(kwargs['stdin'].fileno()).st_mode & 0o777, 0o600)
                    seen.append(kwargs['stdin'].read().decode())
            protocol.import_transaction(archive, 'target', evidence, ['psql'], call=call, role='app', schema_bounds=(10, 20))
            stream = seen[0]
            self.assertLess(stream.index('import_target_changed'), stream.index('CREATE TABLE'))
            self.assertLess(stream.index('CREATE TABLE'), stream.index('restored_database_schema_missing'))
            self.assertLess(stream.index('restored_database_schema_missing'), stream.index('COMMENT ON DATABASE'))
            self.assertIn(protocol.marker(evidence), stream)
            self.assertIn('FROM public.schema_migrations', stream)


@unittest.skipUnless(os.environ.get('ULTRA_IMPORT_PROTOCOL_PG_TEST') == '1', 'private PostgreSQL test is opt-in')
class TransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ultra-import-pg-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.env = {'PATH': os.defpath, 'PGHOST': cls.temp.name,
                   'PGPORT': '55439', 'PGUSER': 'import_test'}
        for command in ('initdb', 'pg_ctl', 'psql', 'pg_dump', 'pg_restore'):
            if not shutil.which(command):
                raise unittest.SkipTest(command + ' unavailable')
        cls.env['PATH'] = str(Path(shutil.which('initdb')).parent) + os.pathsep + os.defpath
        subprocess.run(['initdb', '-D', str(cls.root / 'data'), '-U', 'import_test', '-A', 'trust', '--no-locale'],
                       check=True, env=cls.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['pg_ctl', '-D', str(cls.root / 'data'), '-l', str(cls.root / 'log'),
                        '-o', "-h '' -k " + cls.temp.name + ' -p 55439', '-w', 'start'],
                       check=True, env=cls.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.addClassCleanup(subprocess.run, ['pg_ctl', '-D', str(cls.root / 'data'), '-m', 'immediate', '-w', 'stop'],
                            check=True, env=cls.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.psql('postgres', 'CREATE ROLE app_test LOGIN; CREATE DATABASE source OWNER app_test;', separate=True)
        cls.psql('source', 'CREATE TABLE schema_migrations(version bigint); INSERT INTO schema_migrations VALUES (12); CREATE TABLE payload(v text); INSERT INTO payload VALUES (\'exact data\');')
        cls.archive = cls.root / 'dump.custom'
        subprocess.run(['pg_dump', '-Fc', '--no-owner', '-f', str(cls.archive), 'source'], check=True, env=cls.env)

    @classmethod
    def psql(cls, database, command, separate=False):
        if separate:
            for statement in command.split(';'):
                if statement.strip():
                    cls.psql(database, statement)
            return
        return subprocess.run(['psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', command],
                              check=True, env=cls.env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True).stdout.strip()

    def setUp(self):
        self.psql('postgres', 'DROP DATABASE IF EXISTS target')
        self.psql('postgres', 'CREATE DATABASE target OWNER app_test')
        cluster, oid = self.psql('target', protocol.IDENTITY_SQL).split(':')
        self.evidence = {'database': 'target', 'database_identity': {'system_identifier': cluster, 'database_oid': oid},
                         'plan_sha256': 'a' * 64, 'dump_sha256': 'b' * 64}
        self.command = ['psql', '-Xq', '-v', 'ON_ERROR_STOP=1', '-d', 'target']

    def import_dump(self, **kwargs):
        protocol.import_transaction(self.archive, 'target', self.evidence, self.command,
                                    env=self.env, role='app_test', schema_bounds=kwargs.pop('schema_bounds', (10, 20)), **kwargs)

    def test_data_schema_and_marker_commit_together(self):
        # COMMENT is allowed to the DB owner, independently of superuser restore.
        self.command += ['-U', 'app_test']
        self.psql('postgres', 'GRANT EXECUTE ON FUNCTION pg_control_system() TO app_test')
        self.import_dump()
        self.assertEqual(self.psql('target', 'SELECT v FROM payload'), 'exact data')
        self.assertEqual(self.psql('target', protocol.MARKER_SQL), protocol.marker(self.evidence))

    def test_schema_failure_rolls_back_data_and_marker(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.import_dump(schema_bounds=(13, 20))
        self.assertEqual(self.psql('target', "SELECT count(*) FROM pg_tables WHERE schemaname='public'"), '0')
        self.assertEqual(self.psql('target', protocol.MARKER_SQL), '')

    def test_lost_commit_ack_still_has_exact_database_evidence(self):
        def lost_ack(argv, **kwargs):
            result = subprocess.run(argv, **kwargs)
            if argv[0] == 'psql':
                raise subprocess.TimeoutExpired(argv, 600)
            return result
        with self.assertRaises(subprocess.TimeoutExpired):
            self.import_dump(call=lost_ack)
        self.assertEqual(self.psql('target', protocol.MARKER_SQL), protocol.marker(self.evidence))
        self.assertEqual(self.psql('target', 'SELECT v FROM payload'), 'exact data')

    def test_foreign_comment_and_changed_identity_abort_without_import(self):
        for comment in ('foreign comment', None):
            with self.subTest(comment=comment):
                self.psql('target', 'COMMENT ON DATABASE target IS ' + (protocol.literal(comment) if comment else 'NULL'))
                if comment is None:
                    self.evidence['database_identity']['database_oid'] = '1'
                with self.assertRaises(subprocess.CalledProcessError):
                    self.import_dump()
                self.assertEqual(self.psql('target', "SELECT count(*) FROM pg_tables WHERE schemaname='public'"), '0')

    def test_literal_quotes_cannot_escape_marker(self):
        self.evidence['opaque'] = "'; COMMIT; -- \\ $ultra_import_guard$"
        self.import_dump()
        self.assertEqual(self.psql('target', protocol.MARKER_SQL), protocol.marker(self.evidence))

    def test_target_populated_after_preflight_is_rejected_in_transaction(self):
        self.psql('target', 'CREATE TABLE foreign_data(v text)')
        with self.assertRaises(subprocess.CalledProcessError):
            self.import_dump()
        self.assertEqual(self.psql('target', "SELECT count(*) FROM pg_tables WHERE schemaname='public'"), '1')
        self.assertEqual(self.psql('target', protocol.MARKER_SQL), '')


if __name__ == '__main__':
    unittest.main()
