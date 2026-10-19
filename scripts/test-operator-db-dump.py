#!/usr/bin/env python3
"""Local subprocess fixtures only: no SSH connection or production input reads."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('operator-db-dump.py')
spec = importlib.util.spec_from_file_location('operator_dump', SOURCE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['FIXTURE_LOG'], 'a') as log:
    log.write(json.dumps([name, args]) + '\n')
failure = os.environ.get('FIXTURE_FAILURE', '')
if name == 'age-keygen':
    print('age1fixture')
elif name == 'ssh-keygen':
    text = pathlib.Path(args[args.index('-f') + 1]).read_text()
    host = args[args.index('-F') + 1]
    matches = [line for line in text.splitlines() if line.split()[0] == host]
    print('\n'.join(matches), end='')
    sys.exit(0 if matches else 1)
elif name == 'ssh':
    if failure in ('dump', 'unexpected-pin'):
        sys.stdout.buffer.write(b'partial dump')
        print('DO-NOT-PRINT-SECRET remote failure', file=sys.stderr)
        sys.exit(41)
    sys.stdout.buffer.write(b'PGDMP complete fixture archive')
elif name == 'age' and '-d' not in args:
    data = sys.stdin.buffer.read()
    sys.stdout.buffer.write(b'ENCRYPTED:' + data)
    if failure == 'encrypt':
        print('DO-NOT-PRINT-SECRET encryption', file=sys.stderr)
        sys.exit(42)
elif name == 'age':
    data = pathlib.Path(args[-1]).read_bytes()
    sys.stdout.buffer.write(data.removeprefix(b'ENCRYPTED:'))
    if failure == 'auth':
        print('DO-NOT-PRINT-SECRET auth', file=sys.stderr)
        sys.exit(43)
elif name == 'pg_restore':
    assert args[0] == '--list'
    assert pathlib.Path(args[1]).read_bytes() == b'PGDMP complete fixture archive'
    assert pathlib.Path(args[1]).stat().st_mode & 0o777 == 0o600
    if failure == 'restore':
        print('DO-NOT-PRINT-SECRET restore', file=sys.stderr)
        sys.exit(44)
else:
    sys.exit(99)
'''


class OperatorDumpTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'dist/manual'
        self.output.mkdir(parents=True)
        self.pins = self.output / 'bootstrap-known_hosts'
        self.pins.write_text('192.0.2.30 ssh-ed25519 fixture-key\n192.0.2.20 ssh-ed25519 other-key\n')
        self.key = self.root / 'ssh key'
        self.key.write_text('DO-NOT-PRINT-SECRET SSH')
        self.key.chmod(0o600)
        self.identity = self.root / 'age identity'
        self.identity.write_text('DO-NOT-PRINT-SECRET AGE')
        self.identity.chmod(0o600)
        self.config = self.root / 'install.config'
        self.config.write_text('DATABASE_IP="192.0.2.30" # comment\nDATABASE_SSH_KEY=' +
                               repr(str(self.key)) + '\nBRIDGE_IP="192.0.2.20"\nBRIDGE_SSH_KEY=' +
                               repr(str(self.key)) + '\nDB_NAME=\'fixture_db\'\nULTRA_AUTOMATION_AGE_RECIPIENT=age1fixture\n')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('ssh', 'age', 'pg_restore', 'ssh-keygen', 'age-keygen'):
            path = self.bin / name
            path.write_text(MOCK)
            path.chmod(0o700)
        self.log = self.root / 'commands.jsonl'
        environment = {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                       'FIXTURE_LOG': str(self.log), 'FIXTURE_FAILURE': ''}
        for context in (patch.object(tool, 'ROOT', self.root), patch.dict(os.environ, environment)):
            context.start()
            self.addCleanup(context.stop)

    def invoke(self, failure='', arguments=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {'FIXTURE_FAILURE': failure}), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = tool.main(['--identity', str(self.identity)] if arguments is None else arguments)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn('DO-NOT-PRINT-SECRET', combined)
        self.assertNotIn('age1fixture', combined)
        self.assertNotIn('192.0.2.30', combined)
        return code, stdout.getvalue(), stderr.getvalue()

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def assert_clean(self):
        self.assertEqual([path.name for path in self.output.iterdir()], ['bootstrap-known_hosts'])

    def test_success_permissions_output_and_fixed_ssh_command(self):
        code, stdout, stderr = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(stderr, '')
        fields = dict(line.split('=', 1) for line in stdout.splitlines())
        result = Path(fields['path'])
        self.assertTrue(result.is_absolute())
        self.assertEqual(result.parent, self.output)
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
        self.assertEqual(result.read_bytes(), b'ENCRYPTED:PGDMP complete fixture archive')
        self.assertEqual(fields['size_bytes'], str(result.stat().st_size))
        self.assertEqual(fields['sha256'], hashlib.sha256(result.read_bytes()).hexdigest())
        self.assertRegex(fields['snapshot_started_utc'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        self.assertEqual(fields['exit_code'], '0')
        commands = self.commands()
        ssh = next(args for name, args in commands if name == 'ssh')
        self.assertEqual(ssh[:3], ['-F', '/dev/null', '-T'])
        for option in ('StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null', 'UpdateHostKeys=no',
                       'IdentityAgent=none', 'IdentitiesOnly=yes', 'ForwardAgent=no'):
            self.assertIn(option, ssh)
        proxy = next((option[len('ProxyCommand='):]
                      for option in ssh if option.startswith('ProxyCommand=')), '')
        self.assertIn('root@192.0.2.20', proxy)
        self.assertLess(proxy.index('-W'), proxy.index('root@192.0.2.20'))
        self.assertIn('192.0.2.30:22', proxy)
        self.assertEqual(ssh[-2], 'root@192.0.2.30')
        self.assertEqual(ssh[-1], 'runuser -u postgres -- pg_dump -Fc --no-owner --no-acl --dbname fixture_db')
        self.assertNotIn('ProxyJump=none', ' '.join(ssh))
        self.assertEqual([name for name, args in commands][-2:], ['age', 'pg_restore'])
        self.assertEqual(len(list(self.output.iterdir())), 2)

    def test_missing_pin_file_stops_before_ssh(self):
        self.pins.unlink()
        code, _, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn('stage=host-key pins preflight', stderr)
        self.assertEqual(self.commands(), [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_no_database_pin_stops_before_ssh(self):
        self.pins.write_text('192.0.2.20 ssh-ed25519 other-key\n')
        code, _, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn('stage=host-key pin', stderr)
        self.assertFalse(any(name == 'ssh' for name, _ in self.commands()))
        self.assert_clean()

    def test_no_bridge_pin_stops_before_ssh(self):
        self.pins.write_text('192.0.2.30 ssh-ed25519 fixture-key\n')
        code, _, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn('stage=host-key pin', stderr)
        self.assertFalse(any(name == 'ssh' for name, _ in self.commands()))
        self.assert_clean()

    def test_unexpected_server_pin_and_all_partial_failures_cleanup(self):
        for failure, stage in [('unexpected-pin', 'pg_dump / encryption'), ('dump', 'pg_dump / encryption'),
                               ('encrypt', 'pg_dump / encryption'), ('auth', 'age decrypt/authentication'),
                               ('restore', 'pg_restore --list')]:
            with self.subTest(failure=failure):
                self.log.unlink(missing_ok=True)
                code, stdout, stderr = self.invoke(failure)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, '')
                self.assertIn('stage=' + stage, stderr)
                self.assertIn('exit_code=1', stderr)
                self.assert_clean()
                if failure == 'auth':
                    self.assertFalse(any(name == 'pg_restore' for name, _ in self.commands()))

    def test_automation_recipient_mismatch_uses_local_identity(self):
        self.config.write_text(self.config.read_text().replace('age1fixture', 'age1different'))
        code, stdout, stderr = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(stderr, '')
        commands = self.commands()
        encrypt = next(args for name, args in commands if name == 'age' and '-d' not in args)
        self.assertEqual(encrypt, ['-r', 'age1fixture'])
        self.assertNotIn('age1different', json.dumps(commands))
        fields = dict(line.split('=', 1) for line in stdout.splitlines())
        self.assertTrue(Path(fields['path']).exists())
        self.assertEqual([name for name, args in commands][-2:], ['age', 'pg_restore'])

    def test_literal_config_quotes_and_no_evaluation(self):
        self.config.write_text('DB_NAME="name with spaces" # ignored\nLITERAL=\'$(never-run) `never-run` $HOME\'\nEMPTY=\n')
        self.assertEqual(tool.config_values(self.config), {'DB_NAME': 'name with spaces',
                        'LITERAL': '$(never-run) `never-run` $HOME', 'EMPTY': ''})
        for invalid in ('DB_NAME=a b\n', 'DB_NAME=a\nDB_NAME=b\n', 'DB_NAME="unterminated\n'):
            self.config.write_text(invalid)
            with self.assertRaises((ValueError, tool.DumpError)):
                tool.config_values(self.config)

    def test_database_connection_strings_and_unsafe_permissions_rejected(self):
        original = self.config.read_text()
        for name in ('postgresql://host/db', 'host=other', '-other'):
            self.config.write_text(original.replace("'fixture_db'", repr(name)))
            code, _, _ = self.invoke()
            self.assertEqual(code, 1)
            self.assertEqual(self.commands(), [])
        self.config.write_text(original)
        for path in (self.key, self.identity):
            path.chmod(0o644)
            code, _, _ = self.invoke()
            self.assertEqual(code, 1)
            path.chmod(0o600)
        self.assert_clean()

    def test_publication_failure_removes_result(self):
        with patch.object(tool, 'sync_directory', side_effect=OSError('DO-NOT-PRINT-SECRET')):
            code, stdout, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertEqual(stdout, '')
        self.assertIn('stage=publication', stderr)
        self.assert_clean()

    def test_database_default_for_missing_empty_and_whitespace(self):
        original = self.config.read_text()
        for replacement in ('', 'DB_NAME=\n', 'DB_NAME="   "\n'):
            with self.subTest(replacement=replacement):
                self.config.write_text(original.replace("DB_NAME='fixture_db'\n", replacement))
                self.log.unlink(missing_ok=True)
                code, _, _ = self.invoke()
                self.assertEqual(code, 0)
                ssh = next(args for name, args in self.commands() if name == 'ssh')
                self.assertTrue(ssh[-1].endswith('--dbname ultra_db'))
                for path in self.output.glob('*.dump.age'):
                    path.unlink()

    def test_identity_priority_cli_config_home_default(self):
        home = self.root / 'home'
        default = home / '.local/share/ultra/recovery/age-identity.txt'
        default.parent.mkdir(parents=True)
        default.write_text('DO-NOT-PRINT-SECRET DEFAULT')
        default.chmod(0o600)
        original = self.config.read_text()
        configured = original + 'ULTRA_OPERATOR_AGE_IDENTITY_FILE=' + repr(str(self.identity)) + '\n'
        cases = [(original, [], default), (configured, [], self.identity),
                 (configured, ['--identity', str(default)], default),
                 (original + 'ULTRA_OPERATOR_AGE_IDENTITY_FILE="   "\n', [], default)]
        with patch.object(tool.Path, 'home', return_value=home):
            for config, arguments, expected in cases:
                with self.subTest(expected=expected, arguments=arguments):
                    self.config.write_text(config)
                    self.log.unlink(missing_ok=True)
                    code, _, _ = self.invoke(arguments=arguments)
                    self.assertEqual(code, 0)
                    commands = self.commands()
                    self.assertIn(['age-keygen', ['-y', str(expected)]], commands)
                    decrypt = next(args for name, args in commands if name == 'age' and '-d' in args)
                    self.assertEqual(decrypt[decrypt.index('-i') + 1], str(expected))
                    ssh = next(args for name, args in commands if name == 'ssh')
                    self.assertNotIn(str(expected), ssh)
                    for path in self.output.glob('*.dump.age'):
                        path.unlink()


if __name__ == '__main__':
    unittest.main()
