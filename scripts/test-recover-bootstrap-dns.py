#!/usr/bin/env python3
"""Offline tests: no SSH, DNS provider or production files are used."""
import array
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parent.parent
helper = load('recover_dns', ROOT / 'scripts/recover-bootstrap-dns.py')
dns = load('dns_application', ROOT / 'deploy/recovery/dns.py')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.config = {'provider': 'vultr', 'zone': 'example.com', 'ttl': 300,
                       'api_key_file': '/etc/ultra-recovery/dns-api-key'}
        self.desired = {role: {'name': role, 'data': '192.0.2.' + str(n)}
                        for n, role in enumerate(('subscription', 'vpn', 'tunnel'), 1)}
        self.rows = [{'id': role + '-id', 'name': row['name'], 'data': row['data'], 'type': 'A', 'ttl': 300}
                     for role, row in self.desired.items()]
        self.payload = {'operation': '11111111-2222-4333-8444-555555555555',
                        'config': self.config, 'desired': self.desired}
        self.held = False
        self.calls = 0

    @contextmanager
    def lease(self, operation):
        self.assertEqual(operation, self.payload['operation'])
        self.assertFalse(self.held)
        self.held = True
        try:
            yield
        finally:
            self.held = False

    def application(self, batches=None):
        test = self
        class API:
            def __init__(self, config):
                test.assertEqual(config, test.config)
            def records(self):
                test.assertTrue(test.held)
                result = test.rows if batches is None else batches[min(test.calls, len(batches) - 1)]
                test.calls += 1
                return copy.deepcopy(result)
            def write(self, *args):
                raise AssertionError('provider mutation')
        return type('Application', (), {'API': API, 'matching': staticmethod(dns.matching), 'same': staticmethod(dns.same)})

    def recover(self, application=None, lease=None):
        # Host is root-only in production; map filesystem ownership to the test UID.
        uid, original = os.geteuid(), helper.trusted
        def trusted(path, directory=False, uid=None, private=True):
            return original(path, directory, os.getuid(), private)
        with patch.object(helper.os, 'geteuid', return_value=0), patch.object(helper, 'trusted', trusted):
            return helper.recover_host(self.payload, application or self.application(), self.root, lease or self.lease)

    def test_inspect_accept_and_permissions(self):
        result = self.recover()
        self.assertFalse(result['created'])
        self.assertEqual(set(result['records']), {'subscription', 'vpn', 'tunnel'})
        self.assertFalse((self.root / 'dns-receipt.json').exists())
        self.payload['accept'] = result['records_sha256']
        result = self.recover()
        self.assertTrue(result['created'])
        path = self.root / 'dns-receipt.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(helper.sha(helper.canonical(json.loads(path.read_bytes()))), self.payload['accept'])
        self.assertEqual(self.calls, 3)

    def test_mismatch_duplicate_and_changed_records(self):
        good = copy.deepcopy(self.rows)
        digest = self.recover()['records_sha256']
        for field, value in [('type', 'AAAA'), ('data', '192.0.2.99'), ('ttl', 301), ('name', 'foreign')]:
            with self.subTest(field=field):
                self.rows = copy.deepcopy(good)
                self.rows[0][field] = value
                with self.assertRaises(ValueError):
                    self.recover()
        self.rows = good + [copy.deepcopy(good[0])]
        with self.assertRaisesRegex(ValueError, 'conflicting_records'):
            self.recover()
        self.rows = good
        changed = copy.deepcopy(good)
        changed[0]['id'] = 'different-id'
        self.payload['accept'] = digest
        self.calls = 0
        with self.assertRaisesRegex(ValueError, 'records_changed'):
            self.recover(self.application([good, changed]))
        self.assertFalse((self.root / 'dns-receipt.json').exists())

    def test_acceptance_required_and_bad_acceptance(self):
        self.payload['accept'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'acceptance_mismatch'):
            self.recover()
        self.assertFalse((self.root / 'dns-receipt.json').exists())

    def test_existing_receipt_pending_and_symlink_never_overwritten(self):
        self.payload['accept'] = self.recover()['records_sha256']
        path = self.root / 'dns-receipt.json'
        for contents in ({'pending': {'role': 'tunnel'}}, {'version': 1}, {}):
            raw = helper.canonical(contents)
            path.write_bytes(raw)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'reconciliation_not_authorized'):
                self.recover()
            self.assertEqual(path.read_bytes(), raw)
            path.unlink()
        path.symlink_to(self.root / 'absent')
        with self.assertRaisesRegex(ValueError, 'reconciliation_not_authorized'):
            self.recover()
        path.unlink()
        pending = Path(str(path) + '.next')
        pending.write_text('pending')
        with self.assertRaisesRegex(ValueError, 'receipt_already_present'):
            self.recover()

    def test_locking_permissions_and_exclusive_publication(self):
        lock = self.root / 'lock'
        with helper.locked(lock):
            with self.assertRaises(BlockingIOError):
                with helper.locked(lock):
                    self.fail('concurrent lock')
        lock.chmod(0o644)
        with self.assertRaises(ValueError):
            with helper.locked(lock):
                self.fail('unsafe permissions')
        path = self.root / 'receipt'
        helper.create_only(path, b'first')
        with self.assertRaises(FileExistsError):
            helper.create_only(path, b'second')
        self.assertEqual(path.read_bytes(), b'first')

    def test_denied_lease_never_reads_api(self):
        @contextmanager
        def denied(operation):
            raise ValueError('lifecycle_not_active')
            yield
        with self.assertRaisesRegex(ValueError, 'lifecycle_not_active'):
            self.recover(lease=denied)

    def test_broker_descriptor_and_wrong_identity(self):
        # Exercise the real SCM_RIGHTS protocol using an isolated Unix socket.
        lock = self.root / 'infrastructure.lock'
        with helper.locked(lock) as descriptor:
            for state, wrong in [('applying', False), ('released', False), ('applying', True)]:
                client, server = socket.socketpair()
                other = os.open(self.root / 'other', os.O_CREAT | os.O_RDWR, 0o600)
                def respond():
                    with server as connection:
                        request = json.loads(connection.recv(4096))
                        self.assertEqual(request, {'action': 'lease-attach', 'id': self.payload['operation']})
                        rights = array.array('i', [other if wrong else descriptor])
                        connection.sendmsg([helper.canonical({'state': state}) + b'\n'],
                                           [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                worker = threading.Thread(target=respond)
                worker.start()
                original = helper.trusted
                def trusted(path, directory=False, uid=None, private=True):
                    return original(path, directory, os.getuid(), private)
                # Only credential UID is substituted; real descriptor/inode/flock checks run.
                real_unpack = helper.struct.unpack
                def unpack(fmt, value):
                    pid, uid, gid = real_unpack(fmt, value)
                    return pid, 0, gid
                class Transport:
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        client.close()
                    def connect(self, path):
                        pass
                    def getsockopt(self, *args):
                        return helper.struct.pack('3i', os.getpid(), 0, os.getgid())
                    def __getattr__(self, name):
                        return getattr(client, name)
                with patch.object(helper, 'trusted', trusted), patch.object(helper.struct, 'unpack', unpack), \
                        patch.object(helper.socket, 'socket', return_value=Transport()):
                    if state != 'applying' or wrong:
                        with self.assertRaises(ValueError):
                            with helper.active_lease(self.payload['operation'], '/unused', str(lock)):
                                self.fail('unauthorized lease')
                    else:
                        with helper.active_lease(self.payload['operation'], '/unused', str(lock)):
                            pass
                worker.join(3)
                self.assertFalse(worker.is_alive())
                os.close(other)

    def frozen_fixture(self):
        root = self.root
        (root / 'operator').mkdir(mode=0o700)
        plan = root / 'bootstrap-abc'
        plan.mkdir(mode=0o700)
        attempt = plan / 'attempt-abc'
        attempt.mkdir(mode=0o700)
        stage = attempt / 'bootstrap-postgres'
        stage.mkdir(mode=0o700)
        host = {'ansible_host': '192.0.2.10', 'ansible_user': 'root',
                'ultra_dns_config': self.config, 'ultra_dns_desired': self.desired,
                'ultra_dns_source_content': 'frozen DNS source'}
        request = {'inventory': {'all': {'vars': {}, 'children': {'bridge': {'hosts': {'bridge': host}}}}},
                   'variables': {'ultra_lock_directory': str(root)}}
        raw = helper.canonical(request)
        digest = helper.sha(raw)
        job = {'schema_version': 1, 'operation': 'bootstrap-postgres', 'request_sha256': digest,
               'binary_sha256': digest}
        receipt = dict(job, state='failed')
        mode = {'schema_version': 1, 'target': '192.0.2.10|192.0.2.10', 'lock_directory': str(root),
                'operator_lock_directory': str(root / 'operator'), 'bootstrap_engine': 'components-v1'}
        def save(path, value):
            path.write_bytes(helper.canonical(value))
            path.chmod(0o600)
        save(stage / 'request.json', request)
        save(stage / 'job.json', job)
        save(stage / 'receipt.json', receipt)
        save(attempt / 'execution-mode.json', mode)
        save(plan / 'attempt.json', {'active': attempt.name, 'complete': False})
        return stage, job, mode, save

    def test_frozen_binding_and_active_attempt(self):
        stage, job, mode, save = self.frozen_fixture()
        root, originals, host, payload, binding = helper.frozen_inputs(stage)
        self.assertEqual(root, self.root)
        self.assertEqual(binding['request_sha256'], job['request_sha256'])
        self.assertEqual(payload['desired'], self.desired)
        self.assertEqual(len(originals), 5)
        wrong = dict(job, request_sha256='0' * 64)
        save(stage / 'job.json', wrong)
        with self.assertRaisesRegex(ValueError, 'invalid_job'):
            helper.frozen_inputs(stage)
        save(stage / 'job.json', job)
        save(stage.parent / 'execution-mode.json', dict(mode, local=True))
        with self.assertRaisesRegex(ValueError, 'unsupported_execution_mode'):
            helper.frozen_inputs(stage)
        save(stage.parent / 'execution-mode.json', mode)
        save(stage.parent.parent / 'attempt.json', {'active': stage.parent.name, 'complete': True})
        with self.assertRaisesRegex(ValueError, 'inactive_attempt'):
            helper.frozen_inputs(stage)

    def test_pinned_transport_rejects_extra_options_and_unsafe_key(self):
        pins, key = self.root / 'known_hosts', self.root / 'identity'
        pins.write_text('fixture pin')
        pins.chmod(0o600)
        key.write_text('fixture key')
        key.chmod(0o600)
        options = '-F /dev/null -o ControlMaster=no -o ControlPath=none -o UpdateHostKeys=no ' \
                  '-o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + str(pins)
        host = {'ansible_ssh_common_args': options, 'ansible_ssh_private_key_file': str(key),
                'ansible_host': '192.0.2.10'}
        args = helper.ssh_arguments(host)
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertEqual(args[-1], 'root@192.0.2.10')
        with self.assertRaisesRegex(ValueError, 'unsupported_ssh_options'):
            helper.ssh_arguments(dict(host, ansible_ssh_common_args=options + ' -o ProxyCommand=anything'))
        with self.assertRaisesRegex(ValueError, 'unsupported_ssh_override'):
            helper.ssh_arguments(dict(host, ansible_ssh_args='-o ProxyCommand=anything'))
        key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'untrusted_file'):
            helper.ssh_arguments(host)

    def test_operator_audit_and_original_files_unchanged(self):
        stage, job, mode, save = self.frozen_fixture()
        originals = {path: path.read_bytes() for path in stage.parent.rglob('*.json')}
        record_set = {'version': 1, 'zone': self.config['zone'],
                      'records': {row['name']: row for row in self.rows}}
        digest = helper.sha(helper.canonical(record_set))
        result = {'records_sha256': digest, 'records': record_set['records'], 'created': True, 'reconciled': False}
        def run(args, **kwargs):
            payload = json.loads(kwargs['input'])
            self.assertEqual(payload['accept'], digest)
            # Both Go-compatible operator locks remain held at SSH execution.
            for lock in (self.root / 'infrastructure.lock', self.root / 'operator/infrastructure.lock'):
                with self.assertRaises(BlockingIOError):
                    with helper.locked(lock):
                        self.fail('lock was not held')
            audit = self.root / 'dns-ownership-recovery' / job['request_sha256'] / digest
            intent = json.loads((audit / 'intent.json').read_bytes())
            self.assertEqual(intent['request_sha256'], job['request_sha256'])
            self.assertEqual(intent['records_sha256'], digest)
            return SimpleNamespace(returncode=0, stdout=helper.canonical(result))
        with patch.object(helper, 'ssh_arguments', return_value=['ssh', 'fixture']), \
                patch.object(helper.subprocess, 'run', side_effect=run):
            self.assertEqual(helper.operator(stage, digest), result)
        for path, before in originals.items():
            self.assertEqual(path.read_bytes(), before)
        completed = self.root / 'dns-ownership-recovery' / job['request_sha256'] / digest / 'completed.json'
        audit = json.loads(completed.read_bytes())
        self.assertEqual(audit['records'], result['records'])
        self.assertEqual(completed.stat().st_mode & 0o777, 0o600)

    def test_timeout_after_commit_reconciles_exact_intent_and_completion(self):
        stage, job, mode, save = self.frozen_fixture()
        originals = {path: path.read_bytes() for path in stage.parent.rglob('*.json')}
        record_set = {'version': 1, 'zone': self.config['zone'],
                      'records': {row['name']: row for row in self.rows}}
        digest = helper.sha(helper.canonical(record_set))
        audit = self.root / 'dns-ownership-recovery' / job['request_sha256'] / digest
        remote_calls = 0
        def run(args, **kwargs):
            nonlocal remote_calls
            remote_calls += 1
            self.payload = json.loads(kwargs['input'])
            for lock in (self.root / 'infrastructure.lock', self.root / 'operator/infrastructure.lock'):
                with self.assertRaises(BlockingIOError):
                    with helper.locked(lock):
                        self.fail('operator lock released during reconciliation')
            result = self.recover()
            if remote_calls == 1:
                self.assertNotIn('reconcile', self.payload)
                self.assertTrue(result['created'])
                raise subprocess.TimeoutExpired('fixture SSH', 90)
            self.assertEqual(self.payload['reconcile'], json.loads((audit / 'intent.json').read_bytes()))
            self.assertFalse(result['created'])
            self.assertTrue(result['reconciled'])
            return SimpleNamespace(returncode=0, stdout=helper.canonical(result))
        with patch.object(helper, 'ssh_arguments', return_value=['ssh', 'fixture']), \
                patch.object(helper.subprocess, 'run', side_effect=run):
            with self.assertRaises(subprocess.TimeoutExpired):
                helper.operator(stage, digest)
            receipt = self.root / 'dns-receipt.json'
            raw, before = receipt.read_bytes(), receipt.stat()
            self.assertFalse((audit / 'completed.json').exists())
            result = helper.operator(stage, digest)
            self.assertTrue(result['reconciled'])
            completed = (audit / 'completed.json').read_bytes()
            helper.operator(stage, digest)
            self.assertEqual((audit / 'completed.json').read_bytes(), completed)
            self.assertEqual(receipt.read_bytes(), raw)
            self.assertEqual((receipt.stat().st_ino, receipt.stat().st_mtime_ns),
                             (before.st_ino, before.st_mtime_ns))
        self.assertEqual(self.calls, 6)  # Two API GETs on create and each reconciliation.
        for path, raw in originals.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_reconciliation_rejects_receipt_drift_pending_and_permissions(self):
        result = self.recover()
        self.payload['accept'] = result['records_sha256']
        self.recover()
        path = self.root / 'dns-receipt.json'
        raw = path.read_bytes()
        self.payload['reconcile'] = {'request_sha256': 'a' * 64, 'job_sha256': 'b' * 64,
                                    'operation': self.payload['operation'],
                                    'records_sha256': self.payload['accept']}
        for mutate in (lambda receipt: receipt.update(pending={}),
                       lambda receipt: receipt.update(version=2),
                       lambda receipt: receipt.update(zone='other.example'),
                       lambda receipt: receipt['records'].pop('tunnel'),
                       lambda receipt: receipt['records']['tunnel'].update(id='different'),
                       lambda receipt: receipt['records']['tunnel'].update(ttl=301),
                       lambda receipt: receipt['records']['tunnel'].update(data='192.0.2.99')):
            receipt = json.loads(raw)
            mutate(receipt)
            changed = helper.canonical(receipt)
            path.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.recover()
            self.assertEqual(path.read_bytes(), changed)
        path.write_bytes(raw)
        self.payload['reconcile']['operation'] = 'different'
        with self.assertRaisesRegex(ValueError, 'reconciliation_not_authorized'):
            self.recover()
        self.payload['reconcile']['operation'] = self.payload['operation']
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.recover()
        path.chmod(0o600)
        pending = Path(str(path) + '.next')
        pending.write_text('pending')
        with self.assertRaisesRegex(ValueError, 'receipt_pending'):
            self.recover()
        pending.unlink()
        path.unlink()
        target = self.root / 'other-receipt'
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.recover()
        self.assertEqual(target.read_bytes(), raw)

    def test_retry_rejects_wrong_intent_or_completion_before_ssh(self):
        stage, job, mode, save = self.frozen_fixture()
        _, _, _, payload, binding = helper.frozen_inputs(stage)
        records = {row['name']: row for row in self.rows}
        digest = helper.sha(helper.canonical({'version': 1, 'zone': self.config['zone'], 'records': records}))
        audit = helper.audit_directory(self.root, binding, digest)
        expected = dict(binding, operation=payload['operation'], records_sha256=digest)
        for field in ('request_sha256', 'job_sha256', 'operation', 'records_sha256'):
            wrong = dict(expected, **{field: 'different'})
            save(audit / 'intent.json', wrong)
            with patch.object(helper.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'audit_binding_changed'):
                    helper.operator(stage, digest)
                run.assert_not_called()
        save(audit / 'intent.json', expected)
        (audit / 'intent.json').write_bytes(helper.canonical(expected) + b'\n')
        for mutate in (lambda value: value.update(operation='different'),
                       lambda value: value.update(job_sha256='different'),
                       lambda value: value['records']['tunnel'].update(id='different')):
            completion = dict(expected, records=copy.deepcopy(records))
            mutate(completion)
            save(audit / 'completed.json', completion)
            raw = (audit / 'completed.json').read_bytes()
            with patch.object(helper.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'audit_completion_changed'):
                    helper.operator(stage, digest)
                run.assert_not_called()
            self.assertEqual((audit / 'completed.json').read_bytes(), raw)

    def interrupted_publication(self):
        self.payload['accept'] = self.recover()['records_sha256']
        self.payload['reconcile'] = {'request_sha256': 'a' * 64, 'job_sha256': 'b' * 64,
                                    'operation': self.payload['operation'],
                                    'records_sha256': self.payload['accept']}
        receipt = {'version': 1, 'zone': self.config['zone'],
                   'records': {row['name']: row for row in self.rows}}
        raw = helper.canonical(receipt) + b'\n'
        path = self.root / 'dns-receipt.json'
        pending = self.crash_publication(path, raw)
        self.calls = 0
        return path, pending, raw

    def crash_publication(self, path, raw):
        # A real process death bypasses create_only's finally, after link(2)
        # succeeds but before unlink(2) can remove the staging name.
        program = '''
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('helper', sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
link = os.link
def crash(*args, **kwargs):
    link(*args, **kwargs)
    os._exit(73)
helper.os.link = crash
helper.create_only(Path(sys.argv[2]), sys.stdin.buffer.read())
'''
        process = subprocess.run([sys.executable, '-c', program, str(Path(helper.__file__)), str(path)],
                                 input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(process.returncode, 73, process.stderr)
        pending, = path.parent.glob(helper.publication_prefix(path, raw) + '*')
        self.assertEqual(path.stat().st_nlink, 2)
        self.assertEqual(path.stat().st_ino, pending.stat().st_ino)
        return pending

    def test_local_intent_and_completion_publication_crash_resume(self):
        stage, job, mode, save = self.frozen_fixture()
        _, _, _, payload, binding = helper.frozen_inputs(stage)
        records = {row['name']: row for row in self.rows}
        digest = helper.sha(helper.canonical({'version': 1, 'zone': self.config['zone'], 'records': records}))
        audit = helper.audit_directory(self.root, binding, digest)
        accepted = dict(binding, operation=payload['operation'], records_sha256=digest)
        intent = audit / 'intent.json'
        completed = audit / 'completed.json'
        for path, value in ((intent, accepted), (completed, dict(accepted, records=records))):
            with self.subTest(path=path.name):
                raw = helper.canonical(value) + b'\n'
                pending = self.crash_publication(path, raw)
                before = path.stat()
                result = {'records_sha256': digest, 'records': records, 'created': False, 'reconciled': True}
                def run(args, **kwargs):
                    self.assertEqual(json.loads(kwargs['input'])['reconcile'], accepted)
                    self.assertFalse(pending.exists())
                    self.assertEqual(path.stat().st_nlink, 1)
                    return SimpleNamespace(returncode=0, stdout=helper.canonical(result))
                with patch.object(helper, 'ssh_arguments', return_value=['ssh', 'fixture']), \
                        patch.object(helper.subprocess, 'run', side_effect=run):
                    self.assertTrue(helper.operator(stage, digest)['reconciled'])
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns),
                                 (before.st_ino, before.st_mtime_ns))
                # First pass completed the audit; remove only its synthetic
                # completion before exercising interrupted completion itself.
                completed.unlink()

    def test_local_interrupted_publication_rejects_wrong_binding_without_cleanup(self):
        stage, job, mode, save = self.frozen_fixture()
        _, _, _, payload, binding = helper.frozen_inputs(stage)
        records = {row['name']: row for row in self.rows}
        digest = helper.sha(helper.canonical({'version': 1, 'zone': self.config['zone'], 'records': records}))
        audit = helper.audit_directory(self.root, binding, digest)
        accepted = dict(binding, operation=payload['operation'], records_sha256=digest)
        for filename in ('intent.json', 'completed.json'):
            with self.subTest(filename=filename):
                if filename == 'completed.json':
                    save(audit / 'intent.json', accepted)
                    (audit / 'intent.json').write_bytes(helper.canonical(accepted) + b'\n')
                wrong = dict(accepted, operation='different')
                if filename == 'completed.json':
                    wrong['records'] = records
                path = audit / filename
                raw = helper.canonical(wrong) + b'\n'
                pending = self.crash_publication(path, raw)
                with patch.object(helper.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'audit_.*_changed'):
                        helper.operator(stage, digest)
                    run.assert_not_called()
                self.assertTrue(pending.exists())
                self.assertEqual(path.stat().st_nlink, 2)
                self.assertEqual(path.read_bytes(), raw)
                path.unlink()
                pending.unlink()

    def test_interrupted_publication_reconciles_exact_inode_after_two_gets(self):
        path, pending, raw = self.interrupted_publication()
        before = path.stat()
        application = self.application()
        records = application.API.records
        def observe(api):
            self.assertTrue(pending.exists())
            self.assertEqual(path.stat().st_nlink, 2)
            return records(api)
        with patch.object(application.API, 'records', observe):
            result = self.recover(application)
        self.assertTrue(result['reconciled'])
        self.assertFalse(result['created'])
        self.assertEqual(self.calls, 2)
        self.assertFalse(pending.exists())
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns),
                         (before.st_ino, before.st_mtime_ns))
        self.assertTrue(self.recover()['reconciled'])

    def test_interrupted_publication_keeps_links_when_provider_or_binding_changes(self):
        path, pending, raw = self.interrupted_publication()
        changed = copy.deepcopy(self.rows)
        changed[0]['id'] = 'changed-id'
        with self.assertRaisesRegex(ValueError, 'records_changed'):
            self.recover(self.application([self.rows, changed]))
        self.assertEqual(self.calls, 2)
        self.payload['reconcile']['operation'] = 'different'
        with self.assertRaisesRegex(ValueError, 'reconciliation_not_authorized'):
            self.recover()
        self.assertTrue(pending.exists())
        self.assertEqual(path.stat().st_nlink, 2)
        self.assertEqual(path.read_bytes(), raw)

    def test_interrupted_publication_rejects_extra_or_mismatched_links(self):
        path, pending, raw = self.interrupted_publication()
        extra = self.root / 'extra'
        os.link(path, extra)
        with self.assertRaisesRegex(ValueError, 'untrusted_file'):
            self.recover()
        extra.unlink()
        # Same bytes and expected basename are insufficient without same inode.
        os.rename(pending, extra)
        pending.write_bytes(raw)
        pending.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'receipt_publication_invalid'):
            self.recover()
        pending.unlink()
        pending.symlink_to(extra)
        with self.assertRaisesRegex(ValueError, 'receipt_publication_invalid'):
            self.recover()
        pending.unlink()
        # An arbitrary second link, even in the private directory, is rejected.
        with self.assertRaisesRegex(ValueError, 'receipt_publication_invalid'):
            self.recover()
        os.rename(extra, pending)
        # Changing both linked contents retains inode identity but loses the
        # publication's exact content-addressed basename and accepted receipt.
        path.write_bytes(raw + b' ')
        with self.assertRaisesRegex(ValueError, 'receipt_publication_invalid'):
            self.recover()
        self.assertEqual(self.calls, 0)
        self.assertTrue(pending.exists())

    def test_interrupted_publication_rejects_unsafe_metadata_and_symlink(self):
        path, pending, raw = self.interrupted_publication()
        path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, 'untrusted_file'):
            self.recover()
        path.chmod(0o600)
        real_lstat = Path.lstat
        def wrong_owner(item):
            info = real_lstat(item)
            if item == path:
                values = list(info)
                values[4] = os.getuid() + 1
                return os.stat_result(values)
            return info
        with patch.object(Path, 'lstat', wrong_owner):
            with self.assertRaisesRegex(ValueError, 'untrusted_file'):
                self.recover()
        path.unlink()
        path.symlink_to(pending)
        with self.assertRaisesRegex(ValueError, 'untrusted_file'):
            self.recover()
        self.assertEqual(pending.read_bytes(), raw)
        self.assertEqual(self.calls, 0)


if __name__ == '__main__':
    unittest.main()
