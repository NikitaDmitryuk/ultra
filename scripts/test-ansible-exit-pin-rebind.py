#!/usr/bin/env python3
"""Local synthetic exit-pin recovery tests; never use DATABASE_URL or real data."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('exit_pin_rebind', ROOT / 'deploy/ansible/library/ultra_exit_pin_rebind.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
OLD, NEW = 'a' * 64, 'b' * 64
IDS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002']


def fixture():
    routes = [dict(id=identifier, name='exit-' + str(i), address='192.0.2.' + str(i),
                   port=443, priority=i, enabled=True, created_at='2026-01-01T00:00:00+00:00',
                   updated_at='2026-01-01T00:00:00+00:00', country_code='', country_name='',
                   city='', display_name='', tunnel_uuid_sha256=hashlib.sha256(identifier.encode()).hexdigest(),
                   pinned_peer_cert_sha256=OLD) for i, identifier in enumerate(IDS, 1)]
    return dict(version=1, database='ultra_pin_test', system_identifier='1234', database_oid='123',
                routes=routes, topology_sha256=m.topology_hash(routes))


def pins():
    return [dict(id=identifier, pinned_peer_cert_sha256=NEW) for identifier in IDS]


class Inputs(unittest.TestCase):
    def test_hash_stable_and_order_independent(self):
        snap = fixture()
        self.assertEqual(m.topology_hash(snap['routes']), m.topology_hash(list(reversed(snap['routes']))))
        self.assertEqual(m.validate_snapshot(snap), snap)

    def test_rejects_invalid_or_incomplete_snapshot(self):
        edits = [lambda s: s.pop('system_identifier'), lambda s: s.update(system_identifier=1234),
                 lambda s: s.update(database_oid='0'), lambda s: s.update(version=True),
                 lambda s: s.update(topology_sha256='0' * 64), lambda s: s.update(routes=[]),
                 lambda s: s['routes'][0].update(enabled=False),
                 lambda s: s['routes'][0].update(port=True),
                 lambda s: s['routes'][0].update(name='x' * 1025),
                 lambda s: s['routes'][0].pop('tunnel_uuid_sha256'),
                 lambda s: s['routes'][0].update(pinned_peer_cert_sha256=''),
                 lambda s: s['routes'].append(copy.deepcopy(s['routes'][0]))]
        for edit in edits:
            with self.subTest(edit=edits.index(edit)):
                snap = fixture()
                edit(snap)
                with self.assertRaisesRegex(ValueError, '^exit_pin_invalid_input$'):
                    m.validate_snapshot(snap)

    def test_rejects_missing_extra_duplicate_pins_and_wrong_database(self):
        for new in [[], pins()[:1], pins() + pins()[:1], [pins()[0], pins()[0]],
                    [pins()[0], dict(id=IDS[1], pinned_peer_cert_sha256='invalid')]]:
            with self.assertRaisesRegex(ValueError, '^exit_pin_invalid_input$'):
                m.payload('ultra_pin_test', fixture(), new)
        with self.assertRaises(ValueError):
            m.payload('different', fixture(), pins())

    def test_ambiguous_normalized_endpoint_is_rejected(self):
        snap = fixture()
        snap['routes'][0]['address'] = '2001:db8::1'
        snap['routes'][1]['address'] = '2001:db8:0:0:0:0:0:1'
        snap['topology_sha256'] = m.topology_hash(snap['routes'])
        with self.assertRaises(ValueError):
            m.validate_snapshot(snap)

    def test_subprocess_fixed_environment_and_no_credential_argv(self):
        def call(argv, **kw):
            self.assertNotIn('synthetic-password', argv)
            self.assertEqual(kw['env']['PGPASSWORD'], 'synthetic-password')
            self.assertEqual(set(kw['env']), {'PATH', 'PGCONNECT_TIMEOUT', 'PGPASSWORD'})
            self.assertTrue(kw['check'])
            self.assertEqual(kw['timeout'], 30)
            return SimpleNamespace(stdout='true\n')
        self.assertTrue(m.execute('apply', 'ultra_pin_test', 'synthetic', 'synthetic-password', fixture(), pins(), call)['changed'])

    def test_sql_restricted_to_one_pin_update(self):
        sql = m.statement(m.payload('ultra_pin_test', fixture(), pins()))
        self.assertEqual(sql.count('UPDATE ONLY public.exit_nodes SET '), 1)
        self.assertIn('SET pinned_peer_cert_sha256=', sql)
        self.assertNotIn('CREATE ', sql)
        self.assertIn('LOCK TABLE public.exit_nodes IN SHARE ROW EXCLUSIVE MODE', sql)
        self.assertIn('GET DIAGNOSTICS amount = ROW_COUNT', sql)
        self.assertNotIn(IDS[0], sql)

    def test_failure_output_never_echoes_exception_or_sql(self):
        for error in [ValueError('password SQL /private/path'),
                      subprocess.CalledProcessError(1, ['psql'], stderr='SQL synthetic-password'),
                      RuntimeError('synthetic-password')]:
            self.assertEqual(m.safe_failure_code(error), 'exit_pin_database_failed')
        self.assertEqual(m.safe_failure_code(subprocess.TimeoutExpired('psql', 30)), 'exit_pin_database_timeout')


@unittest.skipUnless(all(shutil.which(x) for x in ('initdb', 'pg_ctl', 'psql')) and os.getuid() != 0,
                     'requires local PostgreSQL binaries and non-root user')
class PostgreSQL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='ultra-pin-synthetic-')
        cls.path = Path(cls.tmp.name)
        cls.environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}
        cls.started = False
        try:
            subprocess.run(['initdb', '-D', str(cls.path / 'data'), '-A', 'trust', '-U', 'synthetic'],
                           env=cls.environment, capture_output=True, check=True)
            subprocess.run(['pg_ctl', '-D', str(cls.path / 'data'), '-l', str(cls.path / 'postgres.log'),
                            '-o', "-k " + str(cls.path) + " -c listen_addresses='' -c fsync=off", '-w', 'start'],
                           env=cls.environment, capture_output=True, check=True)
            cls.started = True
            cls.sql('CREATE DATABASE ultra_pin_test', database='postgres')
        except Exception:
            if (cls.path / 'postgres.log').exists():
                print((cls.path / 'postgres.log').read_text())
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.started:
            subprocess.run(['pg_ctl', '-D', str(cls.path / 'data'), '-m', 'immediate', '-w', 'stop'],
                           env=cls.environment, capture_output=True, check=True)
        cls.tmp.cleanup()

    @classmethod
    def sql(cls, sql, database='ultra_pin_test'):
        return subprocess.run(['psql', '-X', '-h', str(cls.path), '-U', 'synthetic', '-d', database,
                               '-qAt', '-v', 'ON_ERROR_STOP=1'], input=sql, text=True,
                              env=cls.environment, capture_output=True, check=True).stdout.strip()

    @classmethod
    def call(cls, argv, **kwargs):
        # Replace only the module's loopback host with this test's isolated Unix socket.
        argv = list(argv)
        argv[argv.index('--host') + 1] = str(cls.path)
        return subprocess.run(argv, **kwargs)

    def setUp(self):
        self.sql('''DROP SCHEMA public CASCADE; CREATE SCHEMA public;
CREATE TABLE public.exit_nodes (
 id uuid PRIMARY KEY, name text NOT NULL, address text NOT NULL, port integer NOT NULL,
 tunnel_uuid text NOT NULL, priority integer NOT NULL, enabled boolean NOT NULL,
 created_at timestamptz NOT NULL DEFAULT '2026-01-01 UTC', updated_at timestamptz NOT NULL DEFAULT '2026-01-01 UTC',
 country_code text NOT NULL DEFAULT '', country_name text NOT NULL DEFAULT '', city text NOT NULL DEFAULT '',
 display_name text NOT NULL DEFAULT '', pinned_peer_cert_sha256 text NOT NULL);
CREATE TABLE public.users (id integer PRIMARY KEY, marker text);
INSERT INTO public.users VALUES(1,'preserve');''')
        for i, identifier in enumerate(IDS, 1):
            self.sql("INSERT INTO public.exit_nodes(id,name,address,port,tunnel_uuid,priority,enabled,pinned_peer_cert_sha256) VALUES ('%s','exit-%d','192.0.2.%d',443,'%s',%d,true,'%s')" % (identifier, i, i, identifier, i, OLD))
        self.snapshot = self.execute('snapshot')['snapshot']

    def execute(self, mode, snapshot=None, new_pins=None):
        return m.execute(mode, 'ultra_pin_test', 'synthetic', '', snapshot, new_pins, self.call)

    def state(self):
        return self.sql("SELECT jsonb_agg(to_jsonb(n) ORDER BY id)::text FROM exit_nodes n")

    def apply(self, snapshot=None):
        return self.execute('apply', snapshot or self.snapshot, pins())

    def rejected_without_changes(self):
        before = self.state()
        with self.assertRaises(subprocess.CalledProcessError):
            self.apply()
        self.assertEqual(before, self.state())

    def test_success_preserves_every_other_field_users_and_tables_and_is_idempotent(self):
        before = json.loads(self.state())
        self.assertTrue(self.apply()['changed'])
        after = json.loads(self.state())
        for row in before:
            row['pinned_peer_cert_sha256'] = NEW
        self.assertEqual(before, after)
        self.assertEqual(self.sql('SELECT marker FROM users'), 'preserve')
        self.assertEqual(self.sql("SELECT string_agg(tablename,',' ORDER BY tablename) FROM pg_tables WHERE schemaname='public'"), 'exit_nodes,users')
        self.assertFalse(self.apply()['changed'])
        self.assertNotIn('tunnel_uuid', self.snapshot['routes'][0])

    def test_snapshot_is_bounded_and_read_only(self):
        before = self.state()
        self.execute('snapshot')
        self.assertEqual(before, self.state())
        self.sql("UPDATE exit_nodes SET display_name=repeat('x',300000)")
        before = self.state()
        with self.assertRaisesRegex(ValueError, '^exit_pin_invalid_input$'):
            self.execute('snapshot')
        self.assertEqual(before, self.state())

    def test_route_order_is_canonical(self):
        snap = copy.deepcopy(self.snapshot)
        snap['routes'].reverse()
        self.assertTrue(self.apply(snap)['changed'])

    def test_wrong_cluster_and_database_oid(self):
        for key in ('system_identifier', 'database_oid'):
            snap = copy.deepcopy(self.snapshot)
            snap[key] = str(int(snap[key]) + 1)
            with self.assertRaises(subprocess.CalledProcessError):
                self.apply(snap)
        self.assertEqual({r['pinned_peer_cert_sha256'] for r in json.loads(self.state())}, {OLD})

    def test_missing_route(self):
        self.sql("DELETE FROM exit_nodes WHERE id='%s'" % IDS[1])
        self.rejected_without_changes()

    def test_extra_route(self):
        self.sql("INSERT INTO exit_nodes SELECT '00000000-0000-4000-8000-000000000003','extra','192.0.2.3',443,'00000000-0000-4000-8000-000000000003',3,true,created_at,updated_at,country_code,country_name,city,display_name,pinned_peer_cert_sha256 FROM exit_nodes LIMIT 1")
        self.rejected_without_changes()

    def test_disabled_route(self):
        self.sql("UPDATE exit_nodes SET enabled=false WHERE id='%s'" % IDS[1])
        self.rejected_without_changes()

    def test_every_nonpin_field_change_rejected(self):
        updates = ["address='192.0.2.99'", 'port=8443', "tunnel_uuid='changed'", 'priority=777',
                   "name='changed'", "country_code='ZZ'", "country_name='changed'", "city='changed'",
                   "display_name='changed'", "created_at='2026-02-01 UTC'", "updated_at='2026-02-01 UTC'"]
        for update in updates:
            with self.subTest(update=update):
                self.sql('BEGIN; UPDATE exit_nodes SET ' + update + " WHERE id='%s'; COMMIT;" % IDS[0])
                self.rejected_without_changes()
                self.setUp()

    def test_unknown_pin_and_partial_final_state_rejected(self):
        for pin in ('c' * 64, NEW):
            self.sql("UPDATE exit_nodes SET pinned_peer_cert_sha256='%s' WHERE id='%s'" % (pin, IDS[0]))
            self.rejected_without_changes()

    def test_disabled_alias_rejected(self):
        self.sql("INSERT INTO exit_nodes SELECT '00000000-0000-4000-8000-000000000003','disabled',address,port,'different',3,false,created_at,updated_at,country_code,country_name,city,display_name,pinned_peer_cert_sha256 FROM exit_nodes LIMIT 1")
        self.rejected_without_changes()

    def test_trigger_side_effects_rejected(self):
        self.sql("""CREATE FUNCTION forbidden() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET marker='changed'; RETURN NEW; END $$;
CREATE TRIGGER side_effect BEFORE UPDATE ON exit_nodes FOR EACH ROW EXECUTE FUNCTION forbidden();""")
        self.rejected_without_changes()
        self.assertEqual(self.sql('SELECT marker FROM users'), 'preserve')

    def test_inherited_child_row_trigger_cannot_escape_pin_only_update(self):
        # A child row looks identical through the parent's inherited SELECT.
        # Its UPDATE trigger writes users while the parent has no user trigger.
        self.sql("""CREATE TABLE inherited_exit () INHERITS (exit_nodes);
INSERT INTO inherited_exit SELECT * FROM ONLY exit_nodes WHERE id='%s';
DELETE FROM ONLY exit_nodes WHERE id='%s';
CREATE FUNCTION child_side_effect() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN UPDATE users SET marker='changed-by-child'; RETURN NEW; END $$;
CREATE TRIGGER child_write BEFORE UPDATE ON inherited_exit
 FOR EACH ROW EXECUTE FUNCTION child_side_effect();""" % (IDS[1], IDS[1]))
        self.assertEqual(self.sql('SELECT count(*) FROM ONLY inherited_exit'), '1')
        self.assertEqual(self.sql('SELECT count(*) FROM exit_nodes'), '2')
        self.assertEqual(self.sql("SELECT count(*) FROM pg_trigger WHERE tgrelid='exit_nodes'::regclass AND NOT tgisinternal"), '0')
        # Verify the reproduced bypass has an actual observable side effect;
        # roll back this synthetic proof before exercising the guarded module.
        self.sql("BEGIN; UPDATE exit_nodes SET pinned_peer_cert_sha256='%s' WHERE id='%s'; "
                 "DO $$ BEGIN IF (SELECT marker FROM users WHERE id=1)<>'changed-by-child' "
                 "THEN RAISE EXCEPTION 'synthetic child trigger did not execute'; END IF; END $$; ROLLBACK;" % (NEW, IDS[1]))
        before = self.state()
        for mode in ('snapshot', 'apply'):
            with self.subTest(mode=mode):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    self.execute(mode, self.snapshot if mode == 'apply' else None,
                                 pins() if mode == 'apply' else None)
                self.assertIn('exit_pin_topology_ambiguous', caught.exception.stderr)
                self.assertEqual(before, self.state())
                self.assertEqual(self.sql('SELECT marker FROM users'), 'preserve')

    def test_exit_nodes_as_inheritance_child_rejected_in_both_modes(self):
        self.sql('CREATE TABLE ancestor_exit (LIKE exit_nodes); ALTER TABLE exit_nodes INHERIT ancestor_exit')
        before = self.state()
        for mode in ('snapshot', 'apply'):
            with self.subTest(mode=mode):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    self.execute(mode, self.snapshot if mode == 'apply' else None,
                                 pins() if mode == 'apply' else None)
                self.assertIn('exit_pin_topology_ambiguous', caught.exception.stderr)
                self.assertEqual(before, self.state())
                self.assertEqual(self.sql('SELECT marker FROM users'), 'preserve')

    def test_atomic_rollback_on_later_constraint_failure(self):
        self.sql("ALTER TABLE exit_nodes ADD CONSTRAINT synthetic_fail CHECK (id<>'%s' OR pinned_peer_cert_sha256<>'%s')" % (IDS[1], NEW))
        self.rejected_without_changes()

    def test_lock_blocks_concurrent_topology_changes(self):
        holder = subprocess.Popen(['psql', '-X', '-h', str(self.path), '-U', 'synthetic', '-d', 'ultra_pin_test', '-qAt'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, env=self.environment)
        try:
            holder.stdin.write('BEGIN; LOCK TABLE exit_nodes IN SHARE ROW EXCLUSIVE MODE; SELECT 42;\n')
            holder.stdin.flush()
            self.assertEqual(holder.stdout.readline().strip(), '42')
            with self.assertRaises(subprocess.CalledProcessError):
                self.sql("SET lock_timeout='100ms'; UPDATE exit_nodes SET port=8443")
        finally:
            holder.communicate('ROLLBACK;\n', timeout=10)
        self.assertTrue(self.apply()['changed'])


if __name__ == '__main__':
    unittest.main()
