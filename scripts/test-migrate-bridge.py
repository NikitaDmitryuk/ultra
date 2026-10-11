import os
import importlib.util
import io
import json
import base64
import re
import pathlib
import stat
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "migrate-bridge.sh"


FAKE_SSH = r'''#!/usr/bin/env python3
import os, sys, shlex, json, subprocess

args=sys.argv[1:]
payload=sys.stdin.buffer.read()
text=payload.decode('utf-8', errors='ignore')
dest=next((x for x in args if '@old' in x or '@new' in x), '')
cmd=args[-1] if args else ''
with open(os.environ['FAKE_LOG'],'a') as f:
    f.write(json.dumps({'dest':dest,'cmd':cmd,'text':text})+'\n')
if 'bash -s' in cmd and text:
    syntax=subprocess.run(['bash','-n'],input=payload,capture_output=True)
    if syntax.returncode:
        sys.stderr.buffer.write(syntax.stderr)
        sys.exit(99)

if "python3 -" in text and "ULTRA_MIGRATE_HELPER" in text and "'validate'" in cmd:
    if os.environ.get('FAKE_VALIDATE_FAIL'): sys.exit(72)
    print('EXTRA_STATE_BYTES=10485760')
    print('LOCATIONS=["/etc/ultra-relay"]')
elif 'ULTRA_MIGRATE_SOURCE_INVENTORY' in text:
    values={
        'OS_ID':'ubuntu','OS_VERSION':'24.04','ARCH':'x86_64','CPU_COUNT':'2',
        'MACHINE_ID':'source-machine',
        'MEM_BYTES':'2147483648','DB_LOCAL':'yes','DB_NAME':'ultra_db','DB_USER':'ultra',
        'PUBLIC_HOST':'198.51.100.10','PUBLIC_PORTS':'443,8445','ADMIN_LOOPBACK':'yes',
        'DB_BYTES':'104857600','STATE_BYTES':'10485760','DUMP_BYTES':'1048576',
        'DUMP_SECONDS':'2','PG_MAJOR':'16','BOT_ENABLED':'yes','BOT_DOMAIN':'bot.example.test',
        'BOT_PORT':'8444','HAS_VULTR':'yes','HAS_SOCKS_USERS':'yes',
    }
    for k,v in values.items(): print(f'{k}={v}')
elif 'ULTRA_MIGRATE_TARGET_INVENTORY' in text:
    print('OS_ID=ubuntu')
    print('OS_VERSION=24.04')
    print('ARCH='+os.environ.get('FAKE_TARGET_ARCH','x86_64'))
    print('MACHINE_ID='+os.environ.get('FAKE_TARGET_MACHINE_ID','target-machine'))
    print('CPU_COUNT=2')
    print('MEM_BYTES=2147483648')
    print('FREE_BYTES='+os.environ.get('FAKE_TARGET_FREE','10737418240'))
    print('TARGET_STATE='+os.environ.get('FAKE_TARGET_STATE','empty'))
    print('PG_MAJOR='+os.environ.get('FAKE_TARGET_PG','16'))
elif 'ULTRA_MIGRATE_IMPORT_TEMP' in text:
    print('/var/tmp/ultra-migrate-import.fake')
elif 'ULTRA_MIGRATE_MARKER_STATE' in text:
    if os.environ.get('FAKE_PAIR_FAIL'): sys.exit(80)
    print(os.environ.get('FAKE_MARKER_STATE','staged'))
elif 'ULTRA_MIGRATE_SET_MARKER' in text:
    if os.environ.get('FAKE_MARKER_FAIL'): sys.exit(81)
elif 'ULTRA_MIGRATE_FREEZE_SOURCE' in text:
    if os.environ.get('FAKE_STOP_SOURCE_FAIL'): sys.exit(82)
elif 'ULTRA_MIGRATE_STOP_TARGET' in text:
    if os.environ.get('FAKE_STOP_TARGET_FAIL'): sys.exit(83)
elif 'ULTRA_MIGRATE_START_RELAY' in text:
    if os.environ.get('FAKE_RELAY_FAIL'): sys.exit(84)
elif 'ULTRA_MIGRATE_START_BOT' in text:
    if os.environ.get('FAKE_BOT_FAIL'): sys.exit(85)
elif 'ULTRA_MIGRATE_API_CHECK' in text:
    if os.environ.get('FAKE_API_FAIL'): sys.exit(87)
elif 'ULTRA_VERIFY_HELPER' in text:
    if '/client' in cmd:
        import base64
        cfg={'inbounds':[{'protocol':'socks','port':10808}],'outbounds':[]}
        print(json.dumps({'full_xray_config_base64':base64.b64encode(json.dumps(cfg).encode()).decode()}))
    else:
        print(json.dumps([{'uuid':'test-user-uuid','kind':'vless','is_active':True}]))
elif 'cat /etc/machine-id' in text:
    print('source-machine' if '@old' in dest else 'target-machine')
elif "'export'" in cmd:
    if os.environ.get('FAKE_STATE_FAIL'): sys.exit(86)
    sys.stdout.buffer.write(b'fake-state-archive')
elif "'database-fingerprint'" in cmd:
    print('a'*64 if '@old' in dest or not os.environ.get('FAKE_DB_MISMATCH') else 'b'*64)
elif "SHOW server_version_num" in text:
    print('16')
elif 'ULTRA_MIGRATE_STATE_EXPORT' in text:
    sys.stdout.buffer.write(b'fake-state-archive')
elif 'pg_dump -Fc --no-owner --no-acl' in cmd:
    if os.environ.get('FAKE_DUMP_FAIL') == '1':
        sys.exit(70)
    sys.stdout.buffer.write(b'fake-database-dump')
elif 'pg_restore --exit-on-error' in cmd:
    if os.environ.get('FAKE_RESTORE_FAIL'): sys.exit(73)
    if not payload.startswith(b'fake-database-dump'):
        sys.exit(71)
elif 'python3 - "$spec" "$mode"' in text:
    if os.environ.get('FAKE_PREPARE_FAIL'): sys.exit(74)
    print('ultra_db\tultra')
sys.exit(0)
'''


class BridgeMigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.fake_ssh = root / "ssh"
        self.fake_ssh.write_text(FAKE_SSH)
        self.fake_ssh.chmod(self.fake_ssh.stat().st_mode | stat.S_IXUSR)
        self.known_hosts = root / "known_hosts"
        self.known_hosts.write_text("old ssh-ed25519 AAAA\nnew ssh-ed25519 BBBB\n")
        self.log = root / 'calls.jsonl'
        self.bin = root
        self.ready = root / 'client-ready'
        for name, payload in {
            'curl': '''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['FAKE_LOG'],'a') as f: f.write(json.dumps({'dest':'local','cmd':'client-probe','text':'LOCAL_CLIENT_PROBE'})+'\\n')
if os.environ.get('FAKE_CURL_FAIL'): sys.exit(22)
print(os.environ.get('FAKE_EXTERNAL_IP','203.0.113.8'))
''',
            'nc': '''#!/usr/bin/env python3
import os,sys
sys.exit(0 if os.path.exists(os.environ['FAKE_READY']) else 1)
''',
            'xray': '''#!/usr/bin/env python3
import os,pathlib,sys,time,stat
cfg=pathlib.Path(sys.argv[-1]); directory=cfg.parent
assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in directory.iterdir() if p.is_file())
pathlib.Path(os.environ['FAKE_READY']).touch()
time.sleep(60)
''',
        }.items():
            (root/name).write_text(payload)
            (root/name).chmod(0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, command, *extra, env=None):
        actual = os.environ.copy()
        actual["ULTRA_MIGRATE_SSH_BIN"] = str(self.fake_ssh)
        actual['FAKE_LOG'] = str(self.log)
        actual['FAKE_READY'] = str(self.ready)
        actual['PATH'] = str(self.bin) + os.pathsep + actual['PATH']
        if env:
            actual.update(env)
        args = [
            str(SCRIPT), command,
            "--source-host", "old",
            "--target-host", "new",
            "--known-hosts", str(self.known_hosts),
            *extra,
        ]
        return subprocess.run(args, cwd=ROOT, env=actual, text=True, capture_output=True)

    def test_inventory_memory_output_is_valid_shell_arithmetic(self):
        result = self.run_script('preflight')
        self.assertEqual(result.returncode, 0, result.stderr)
        inventories = [call for call in self.calls() if
                       'ULTRA_MIGRATE_SOURCE_INVENTORY' in call['text'] or
                       'ULTRA_MIGRATE_TARGET_INVENTORY' in call['text']]
        self.assertEqual(len(inventories), 2)
        for call in inventories:
            with self.subTest(host=call['dest']):
                expression = re.search(r"awk '([^']*MemTotal[^']*)' /proc/meminfo", call['text'])
                self.assertIsNotNone(expression)
                output = subprocess.run(['awk', expression.group(1)],
                                        input='MemTotal: 2000000 kB\n', text=True,
                                        capture_output=True, check=True).stdout
                self.assertEqual(output.strip(), '2048000000')
                arithmetic = subprocess.run(['bash', '-c',
                                             'set -u; memory=$1; (( memory == 2048000000 ))',
                                             'memory-check', output.strip()],
                                            text=True, capture_output=True)
                self.assertEqual(arithmetic.returncode, 0, arithmetic.stderr)

    def test_preflight_reports_capacity_and_ports_without_secrets(self):
        result = self.run_script("preflight", "--new-public-host", "203.0.113.20", "--new-bridge-ip", "203.0.113.20")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("preflight OK", result.stdout)
        self.assertIn("10810-10899", result.stdout)
        self.assertNotIn("password", result.stdout.lower())
        self.assertNotIn("token", result.stdout.lower())

    def test_rejects_same_endpoint_before_ssh(self):
        result = subprocess.run(
            [str(SCRIPT), "preflight", "--source-host", "same", "--target-host", "same", "--known-hosts", str(self.known_hosts)],
            cwd=ROOT,
            env={**os.environ, "ULTRA_MIGRATE_SSH_BIN": str(self.fake_ssh), 'FAKE_LOG': str(self.log)},
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source and target must differ", result.stderr)

    def test_rejects_aliases_that_resolve_to_same_machine(self):
        result = self.run_script("preflight", env={"FAKE_TARGET_MACHINE_ID": "source-machine"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same machine", result.stderr)

    def test_rejects_insufficient_disk(self):
        result = self.run_script("preflight", env={"FAKE_TARGET_FREE": "1000"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("insufficient target disk", result.stderr)

    def test_rejects_architecture_mismatch(self):
        result = self.run_script("preflight", env={"FAKE_TARGET_ARCH": "aarch64"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("architecture mismatch", result.stderr)

    def test_rejects_unrelated_target_state(self):
        result = self.run_script("preflight", env={"FAKE_TARGET_STATE": "foreign"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated Ultra state", result.stderr)

    def test_stage_is_repeatable_for_existing_marker(self):
        env = {"FAKE_TARGET_STATE": "staged"}
        for _ in range(2):
            result = self.run_script("stage", "--new-public-host", "203.0.113.20", "--new-bridge-ip", "203.0.113.20", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("stage complete", result.stdout)

    def test_stage_fails_when_database_dump_fails(self):
        result = self.run_script(
            "stage",
            "--new-public-host", "203.0.113.20",
            "--new-bridge-ip", "203.0.113.20",
            env={"FAKE_DUMP_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("stage complete", result.stdout)

    def test_sensitive_remote_files_are_locked_down(self):
        source = SCRIPT.read_text()
        self.assertIn('chmod 600 "$tmp"', source)
        self.assertIn('umask 077', source)
        self.assertIn("StrictHostKeyChecking=yes", source)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_forbids_stage_after_cutover(self):
        for state in ('freezing', 'frozen', 'activating', 'activated', 'activation_failed', 'rollback_pending', 'rolled_back'):
            result = self.run_script('stage', env={'FAKE_TARGET_STATE':'staged', 'FAKE_MARKER_STATE':state})
            self.assertNotEqual(result.returncode, 0, state)
            self.assertIn('stage is forbidden', result.stderr)
        self.assertFalse(any("'export'" in c['cmd'] for c in self.calls()))

    def test_stage_rejects_pair_mismatch(self):
        result = self.run_script('stage', env={'FAKE_PAIR_FAIL':'1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("'export'" in c['cmd'] for c in self.calls()))

    def test_rejects_postgres_major_mismatch(self):
        result = self.run_script('preflight', env={'FAKE_TARGET_PG':'15'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PostgreSQL major must match', result.stderr)

    def test_freeze_transfers_final_files_then_database(self):
        result = self.run_script('freeze', '--confirm', 'FREEZE', env={'FAKE_TARGET_STATE':'staged'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls=self.calls()
        stopped=next(i for i,c in enumerate(calls) if 'ULTRA_MIGRATE_FREEZE_SOURCE' in c['text'])
        files=next(i for i,c in enumerate(calls) if "'export'" in c['cmd'])
        dump=next(i for i,c in enumerate(calls) if 'pg_dump -Fc' in c['cmd'])
        self.assertLess(stopped, files)
        self.assertLess(files, dump)
        self.assertTrue(any("'database-fingerprint'" in c['cmd'] for c in calls))

    def test_freeze_failure_recovers_source(self):
        for failure in ('FAKE_PREPARE_FAIL','FAKE_DUMP_FAIL','FAKE_RESTORE_FAIL','FAKE_STATE_FAIL','FAKE_STOP_SOURCE_FAIL','FAKE_MARKER_FAIL','FAKE_DB_MISMATCH'):
            with self.subTest(failure=failure):
                self.log.write_text('')
                result=self.run_script('freeze','--confirm','FREEZE',env={'FAKE_TARGET_STATE':'staged',failure:'1'})
                self.assertNotEqual(result.returncode,0)
                self.assertTrue(any('ULTRA_MIGRATE_RESTART_SOURCE' in c['text'] for c in self.calls()))

    def test_unconfirmed_target_stop_never_restarts_source(self):
        result=self.run_script('freeze','--confirm','FREEZE',env={'FAKE_STOP_TARGET_FAIL':'1'})
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any('ULTRA_MIGRATE_RESTART_SOURCE' in c['text'] for c in self.calls()))

    def test_rollback_requires_network_confirmation(self):
        result=self.run_script('rollback','--confirm','ROLLBACK',env={'FAKE_MARKER_STATE':'frozen'})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any('ULTRA_MIGRATE_RESTART_SOURCE' in c['text'] for c in self.calls()))

    def test_nonroot_uses_noninteractive_sudo(self):
        result=self.run_script('stage','--source-user','operator','--target-user','deploy')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(any('sudo -n bash -s' in c['cmd'] for c in self.calls()))

    def test_bad_ip_rejected_before_ssh(self):
        result=self.run_script('preflight','--new-bridge-ip','1.2.3.4\nULTRA_VULTR_KEY_FILE=secret')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.log.exists())

    def activate(self, **env):
        self.ready.unlink(missing_ok=True)
        return self.run_script('activate','--confirm','ACTIVATE','--network-ready',
                               '--expected-exit-ip','203.0.113.8','--verify-ip-url','https://probe.example.test/plain-ip',
                               '--target-public-ip','203.0.113.20',env={'FAKE_MARKER_STATE':'frozen',**env})

    def test_activation_errors_stop_target_without_starting_source(self):
        for failure in ('FAKE_RELAY_FAIL','FAKE_API_FAIL','FAKE_CURL_FAIL','FAKE_BOT_FAIL'):
            with self.subTest(failure=failure):
                self.log.write_text('')
                result=self.activate(**{failure:'1'})
                self.assertNotEqual(result.returncode,0)
                self.assertTrue(any('ULTRA_MIGRATE_STOP_TARGET' in c['text'] for c in self.calls()))
                self.assertFalse(any('ULTRA_MIGRATE_RESTART_SOURCE' in c['text'] for c in self.calls()))

    def test_wrong_external_ip_never_starts_bot(self):
        result=self.activate(FAKE_EXTERNAL_IP='198.51.100.100')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('does not match expected exit',result.stderr)
        self.assertIn('198.51.100.100',result.stderr)
        self.assertIn('203.0.113.8',result.stderr)
        self.assertFalse(any('ULTRA_MIGRATE_START_BOT' in c['text'] for c in self.calls()))

    def test_successful_activation_probes_client_before_bot(self):
        result=self.activate()
        self.assertEqual(result.returncode,0,result.stderr)
        calls=self.calls()
        probe=next(i for i,c in enumerate(calls) if 'LOCAL_CLIENT_PROBE' in c['text'])
        bot=next(i for i,c in enumerate(calls) if 'ULTRA_MIGRATE_START_BOT' in c['text'])
        self.assertLess(probe,bot)
        self.assertNotIn('synthetic-token',result.stdout+result.stderr)


class StateArchiveTest(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('migration_state', ROOT/'scripts/bridge-migration-state.py')
        self.state=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.state)

    def test_roundtrip_preserves_keys_and_removes_stale_files_with_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            source=pathlib.Path(directory)/'source'; target=pathlib.Path(directory)/'target'
            for root in (source,target):
                (root/'etc/ultra-relay').mkdir(parents=True)
                (root/'var/lib/ultra-relay').mkdir(parents=True)
                (root/'var/tmp').mkdir(parents=True)
            (source/'etc/ultra-relay/key').write_text('synthetic-secret')
            (target/'etc/ultra-relay/stale').write_text('old-state')
            output=io.BytesIO()
            with mock.patch.object(self.state,'paths',return_value=[source/'etc/ultra-relay',source/'var/lib/ultra-relay']), mock.patch.object(self.state.sys,'stdout',mock.Mock(buffer=output)):
                self.state.export(source)
            actual_run=self.state.run
            def run(*args,**kwargs):
                if args[0]=='tar': return actual_run(*args,**kwargs)
                return mock.Mock(returncode=0)
            with mock.patch.object(self.state.sys,'stdin',mock.Mock(buffer=io.BytesIO(output.getvalue()))), mock.patch.object(self.state,'run',side_effect=run):
                self.state.import_state(target)
            self.assertEqual((target/'etc/ultra-relay/key').read_text(),'synthetic-secret')
            self.assertEqual(stat.S_IMODE((target/'etc/ultra-relay/key').stat().st_mode),0o600)
            self.assertFalse((target/'etc/ultra-relay/stale').exists())
            self.assertEqual(len(list((target/'var/backups/ultra-bridge-migration').glob('*/state.tar.gz'))),1)
            self.assertEqual(list((target/'var/tmp').iterdir()),[])

    def test_rejects_broad_and_system_paths(self):
        for path in ('/', '/etc', '/var/lib', '/etc/shadow', '/etc/ssh/key', '/opt/../etc/key'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.state.safe_path(path)

    def test_invalid_archive_is_cleaned_without_overwriting_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            (root/'var/tmp').mkdir(parents=True)
            with mock.patch.object(self.state.sys,'stdin',mock.Mock(buffer=io.BytesIO(b'bad dump'))), self.assertRaises(Exception):
                self.state.import_state(root)
            self.assertEqual(list((root/'var/tmp').iterdir()),[])

    def test_effective_environment_files_override_directives(self):
        with tempfile.TemporaryDirectory() as directory:
            normal=pathlib.Path(directory)/'normal.env'
            paused=pathlib.Path(directory)/'paused.env'
            normal.write_text('ULTRA_REPLICATION_KEY_FILE=/opt/ultra/key\nULTRA_VULTR_KEY_FILE=/opt/ultra/token\n')
            paused.write_text('ULTRA_REPLICATION_KEY_FILE=\nULTRA_VULTR_KEY_FILE=\n')
            def run(*args,**kwargs):
                output='ULTRA_REPLICATION_KEY_FILE=/another/key'
                if 'EnvironmentFiles' in args:
                    output=f'{normal} (ignore_errors=no) {paused} (ignore_errors=no)'
                return mock.Mock(stdout=output)
            with mock.patch.object(self.state,'run',side_effect=run):
                env=self.state.environment()
            self.assertEqual(env['ULTRA_REPLICATION_KEY_FILE'],'')
            self.assertEqual(env['ULTRA_VULTR_KEY_FILE'],'')


@unittest.skipUnless(os.environ.get('ULTRA_MIGRATE_TEST_PG_PORT'), 'requires an explicitly allocated temporary PostgreSQL cluster')
class DatabaseMigrationTest(unittest.TestCase):
    def test_recovery_role_restores_existing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            key=pathlib.Path(directory)/'replication.json'
            config={'user':'ultra_recovery','password':'a'*64,'port':int(os.environ['ULTRA_MIGRATE_TEST_PG_PORT'])}
            key.write_text(json.dumps(config)); key.chmod(0o600)
            shim=pathlib.Path(directory)/'bin'; shim.mkdir()
            (shim/'runuser').write_text('#!/bin/sh\nshift 3\nexec "$@"\n'); (shim/'runuser').chmod(0o700)
            env={**os.environ,'PATH':str(shim)+os.pathsep+os.environ['PATH'],
                 'PGHOST':'127.0.0.1','PGPORT':os.environ['ULTRA_MIGRATE_TEST_PG_PORT'],'PGUSER':'postgres',
                 'ULTRA_RECOVERY_CONFIG_FILE':str(key)}
            payload=re.search(r"python3 - <<'PY'\n(.*?)\nPY",(ROOT/'internal/install/scripts/recovery-primary.sh').read_text(),re.S).group(1)
            result=subprocess.run(['python3','-'],input=payload,env=env,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(key.read_text()),config)
            rights=subprocess.run(['psql','-XAtq','-d','postgres','-c',"SELECT rolcanlogin AND rolreplication AND pg_has_role('ultra_recovery','pg_monitor','member') FROM pg_roles WHERE rolname='ultra_recovery';"],env=env,text=True,capture_output=True,check=True)
            self.assertEqual(rights.stdout.strip(),'t')
            subprocess.run(['psql','-d','postgres','-c','DROP ROLE ultra_recovery'],env=env,capture_output=True,check=True)

    def test_repeated_restore_backup_permissions_and_dump_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            shim=root/'bin'; shim.mkdir()
            (shim/'runuser').write_text('#!/bin/sh\nshift 3\nexec "$@"\n')
            (shim/'systemctl').write_text('#!/bin/sh\nexit 0\n')
            for path in shim.iterdir(): path.chmod(0o700)
            env={**os.environ, 'PATH':str(shim)+os.pathsep+os.environ['PATH'],
                 'PGHOST':'127.0.0.1','PGPORT':os.environ['ULTRA_MIGRATE_TEST_PG_PORT'],'PGUSER':'postgres'}
            dbname='ultra_migration_backup_test'; role='ultra_migration_app_test'
            config=root/'spec.json'
            config.write_text(json.dumps({'database':{'dsn':f'postgres://{role}:synthetic-password@127.0.0.1:5432/{dbname}?sslmode=disable'}}))
            backup=root/'backup'; backup.mkdir(mode=0o700)
            payload=re.search(r"python3 - \"\$spec\" \"\$mode\" \"\$backup_root\" <<'PY'\n(.*?)\nPY", SCRIPT.read_text(),re.S).group(1)
            def prepare():
                return subprocess.run(['python3','-',str(config),'reset',str(backup)],input=payload,text=True,capture_output=True,env=env)
            def sql(query):
                return subprocess.run(['psql','-XAtq','-v','ON_ERROR_STOP=1','-d',dbname,'-c',query],env=env,text=True,capture_output=True,check=True).stdout.strip()
            first=prepare(); self.assertEqual(first.returncode,0,first.stderr)
            sql("CREATE TABLE users(uuid text PRIMARY KEY, token text); INSERT INTO users VALUES ('old-uuid','synthetic-token');")
            second=prepare(); self.assertEqual(second.returncode,0,second.stderr)
            dumps=list(backup.glob('*.dump'))
            self.assertEqual(len(dumps),1)
            self.assertEqual(stat.S_IMODE(dumps[0].stat().st_mode),0o600)
            restored=subprocess.run(['pg_restore','--exit-on-error','--no-owner','--no-acl','--role='+role,'-d',dbname,str(dumps[0])],env=env,capture_output=True)
            self.assertEqual(restored.returncode,0,restored.stderr)
            self.assertEqual(sql('SELECT uuid FROM users'),'old-uuid')
            (shim/'pg_dump').write_text('#!/bin/sh\necho synthetic-token >&2\nexit 70\n'); (shim/'pg_dump').chmod(0o700)
            failed=prepare(); self.assertNotEqual(failed.returncode,0)
            self.assertNotIn('synthetic-token',failed.stderr+failed.stdout)
            self.assertEqual(sql('SELECT uuid FROM users'),'old-uuid')
            subprocess.run(['dropdb',dbname],env=env,check=True,capture_output=True)
            subprocess.run(['psql','-d','postgres','-c',f'DROP ROLE {role}'],env=env,check=True,capture_output=True)


if __name__ == "__main__":
    unittest.main()
