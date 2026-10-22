#!/usr/bin/env python3
"""Local fixtures for the operator backup bundle exporter."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).with_name('operator-db-dump.py')
spec = importlib.util.spec_from_file_location('operator_dump', SOURCE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
sys.path.insert(0, str(SOURCE.resolve().parents[1] / 'deploy' / 'recovery'))
import ssh_policy

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
if name == 'age-keygen': print('age1fixture')
elif name == 'ssh-keygen': print('fixture host pin')
elif name == 'ssh':
    pathlib.Path(os.environ['FIXTURE_LOG']).write_text(json.dumps(args))
    sys.stdout.buffer.write(b'PGDMP fixture dump')
elif name == 'age' and '-r' in args: sys.stdout.buffer.write(b'AGE:' + sys.stdin.buffer.read())
elif name == 'age': sys.stdout.buffer.write(pathlib.Path(args[-1]).read_bytes()[4:])
elif name == 'pg_restore':
    assert args[0] == '--file=/dev/null'
    assert pathlib.Path(args[1]).read_bytes() == b'PGDMP fixture dump'
else: sys.exit(99)
'''


class OperatorDumpTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'output'
        self.output.mkdir(mode=0o700)
        self.pins = self.output / 'bootstrap-known_hosts'
        self.pins.write_text('192.0.2.30 ssh-ed25519 fixture\n192.0.2.20 ssh-ed25519 fixture\n')
        self.key = self.root / 'ssh-key'
        self.identity = self.root / 'age-identity'
        self.config = self.root / 'install.config'
        for path in (self.key, self.identity):
            path.write_text('fixture')
            path.chmod(0o600)
        self.config.write_text('DATABASE_IP=192.0.2.30\nBRIDGE_IP=192.0.2.20\nDB_NAME=fixture_db\n'
                               'DATABASE_SSH_KEY=' + str(self.key) + '\nBRIDGE_SSH_KEY=' + str(self.key) + '\n')
        for path in (self.pins, self.config):
            path.chmod(0o600)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('ssh', 'age', 'pg_restore', 'ssh-keygen', 'age-keygen'):
            executable = self.bin / name
            executable.write_text(MOCK)
            executable.chmod(0o700)
        self.log = self.root / 'commands.json'
        self.env = patch.dict(os.environ, {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                                           'FIXTURE_LOG': str(self.log)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def invoke(self, *extra):
        args = ['--config', str(self.config), '--identity', str(self.identity), '--output-dir', str(self.output), *extra]
        return tool.main(args)

    def test_current_effective_user_can_publish_encrypted_bundle(self):
        self.assertEqual(self.invoke(), 0)
        outputs = list(self.output.glob('primary-db-*.backup.tar.age'))
        self.assertEqual(len(outputs), 1)
        result = outputs[0]
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
        self.assertTrue(result.name.endswith('.backup.tar.age'))
        encrypted = result.read_bytes()
        self.assertTrue(encrypted.startswith(b'AGE:'))
        with tarfile.open(fileobj=io.BytesIO(encrypted[4:]), mode='r:') as bundle:
            members = bundle.getmembers()
            self.assertEqual([member.name for member in members], ['manifest.json', 'primary.dump'])
            manifest_raw = bundle.extractfile(members[0]).read()
            manifest = json.loads(manifest_raw)
            stamp = result.name[len('primary-db-'):len('primary-db-') + 16]
            snapshot = datetime.strptime(stamp, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
            expected = {
                'version': 1,
                'snapshot_started_utc': snapshot.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'source_sha256': hashlib.sha256(b'192.0.2.30\0fixture_db').hexdigest(),
                'database': 'fixture_db',
                'dump_sha256': hashlib.sha256(b'PGDMP fixture dump').hexdigest(),
            }
            self.assertEqual(manifest, expected)
            self.assertEqual(list(manifest), list(expected))
            self.assertEqual(manifest_raw, json.dumps(expected, separators=(',', ':')).encode())
            self.assertEqual(bundle.extractfile(members[1]).read(), b'PGDMP fixture dump')
        ssh_args = json.loads(self.log.read_text())
        shared = ssh_policy.ssh_options('probe')
        self.assertEqual(ssh_args[5:5 + len(shared)], shared)
        proxy_arg = next(arg for arg in ssh_args if arg.startswith('ProxyCommand='))
        proxy_args = shlex.split(proxy_arg.split('=', 1)[1])
        self.assertEqual(proxy_args[6:6 + len(shared)], shared)

    def test_requires_explicit_absolute_paths(self):
        self.assertEqual(tool.main(['--config', str(self.config), '--identity', 'relative',
                                    '--output-dir', str(self.output)]), 1)
        self.assertFalse(list(self.output.glob('primary-db-*')))

    def test_rejects_unsafe_input_permissions_and_output_directory(self):
        self.config.chmod(0o644)
        self.assertEqual(self.invoke(), 1)
        self.config.chmod(0o600)
        self.output.chmod(0o755)
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(list(self.output.glob('primary-db-*')))

    def test_rejects_fifo_config_without_blocking(self):
        fifo = self.root / 'config.fifo'
        os.mkfifo(fifo, 0o600)
        command = [sys.executable, str(SOURCE), '--config', str(fifo), '--identity', str(self.identity),
                   '--output-dir', str(self.output)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'unsafe protected input file', result.stderr)

    def test_rejects_oversized_protected_config(self):
        self.config.write_bytes(b'X' * (tool.MAX_PROTECTED_FILE_BYTES + 1))
        self.config.chmod(0o600)
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(list(self.output.glob('primary-db-*')))

    def test_rejects_hardlinked_protected_inputs(self):
        os.link(self.key, self.root / 'key-alias')
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(list(self.output.glob('primary-db-*')))

    def test_tilde_ssh_key_paths_are_rejected_without_home_expansion(self):
        original = self.config.read_text()
        self.config.write_text(original.replace('DATABASE_SSH_KEY=' + str(self.key),
                                               'DATABASE_SSH_KEY=~/.ssh/key'))
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(self.log.exists())

    def test_foreign_owned_protected_input_and_output_directory_are_rejected(self):
        real_fstat = os.fstat

        def foreign_owner(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1, st_nlink=info.st_nlink)

        with patch.object(tool.os, 'fstat', side_effect=foreign_owner):
            self.assertEqual(self.invoke(), 1)

        output_path = str(self.output.resolve())

        def foreign_output(fd):
            info = real_fstat(fd)
            actual_path = os.path.realpath('/proc/self/fd/' + str(fd))
            if actual_path == output_path:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1, st_nlink=info.st_nlink)
            return info

        with patch.object(tool.os, 'fstat', side_effect=foreign_output):
            self.assertEqual(self.invoke(), 1)
        self.assertFalse(list(self.output.glob('primary-db-*')))


if __name__ == '__main__':
    unittest.main()
