"""Local-only projection of the controller's private safe sidecars."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import reconcile


class AnsibleDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / 'diagnostics'
        self.logs.mkdir(mode=0o700)
        self.attempt = self.root / 'attempt-test'
        self.config = {'state_dir': str(self.root / 'state'), 'ssh_identity_file': '/fixture/identity'}
        self.node = {'id': 'fixture', 'address': '192.0.2.1', 'known_hosts': '/fixture/known_hosts'}
        patch = mock.patch.object(reconcile, 'ansible_diagnostic_root', return_value=self.logs)
        patch.start()
        self.addCleanup(patch.stop)

    def event(self, event='task_failed', **fields):
        return {'schema_version': 1, 'event': event, 'time_ns': time.time_ns(),
                'host': 'receiver', 'task': {'source': 'roles/recovery/tasks/main.yml',
                                          'line': 42, 'action': 'ansible.builtin.copy'},
                'censored': False, 'rc': 7, **fields}

    def session(self, attempt=None, current=None, first=None, suffix='a' * 32):
        attempt = attempt or self.attempt
        name = hashlib.sha256(str(attempt.absolute()).encode()).hexdigest() + '-' + suffix
        session = self.logs / name
        session.mkdir(mode=0o700)
        reconcile.atomic_json(session / 'current.json', current or self.event(operation='reconcile'))
        if first is not None:
            reconcile.atomic_json(session / 'first-failure.json', first)
        return session

    def launch(self, arguments, **kwargs):
        self.attempt = Path(arguments[arguments.index('--state-dir') + 1])
        self.attempt.mkdir(mode=0o700, exist_ok=True)
        inventory = json.loads(Path(arguments[arguments.index('--inventory') + 1]).read_text())
        variables = json.loads(Path(arguments[arguments.index('--variables') + 1]).read_text())
        reconcile.atomic_json(self.attempt / 'request.json', {'inventory': inventory, 'variables': variables})
        reconcile.atomic_json(self.attempt / 'job.json', {'operation': 'reconcile'})
        reconcile.atomic_json(self.attempt / 'receipt.json', {'state': 'failed', 'code': 'ansible_failed'})
        self.session()
        return mock.Mock(wait=mock.Mock(return_value=1))

    def failure(self):
        return json.loads((self.attempt.parent / 'last-failure.json').read_text())

    def test_failed_attempt_projects_first_failure_and_preserves_sealed_diagnostic(self):
        def launch(arguments, **kwargs):
            process = self.launch(arguments, **kwargs)
            session = next(self.logs.iterdir())
            first = self.event()
            reconcile.atomic_json(session / 'first-failure.json', first)
            reconcile.atomic_json(session / 'current.json', self.event(
                'controller_failed', operation='reconcile', task={'source': 'playbooks/reconcile.yml', 'line': 2}, rc=99))
            reconcile.atomic_json(self.attempt / 'diagnostic.json', {'stage': 'legacy', 'node': 'receiver', 'code': 'task_failed'})
            return process
        with mock.patch.object(reconcile.subprocess, 'Popen', side_effect=launch) as process:
            with self.assertRaisesRegex(ValueError, 'ansible_reconcile_failed'):
                reconcile.ansible_apply(self.config, self.node, {'fixture_secret': 'DO-NOT-RECORD'})
        failure = self.failure()
        self.assertEqual(failure['phase'], 'task_failed')
        self.assertEqual(failure['host'], 'receiver')
        self.assertEqual(failure['task']['line'], 42)
        self.assertEqual(failure['rc'], 7)
        self.assertEqual(failure['receipt_code'], 'ansible_failed')
        self.assertEqual(json.loads((self.attempt / 'diagnostic.json').read_text())['stage'], 'legacy')
        self.assertNotIn('DO-NOT-RECORD', json.dumps(failure))
        self.assertEqual(process.call_args.kwargs, {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL})

    def test_timeout_and_budget_interruption_have_null_rc(self):
        for error in (subprocess.TimeoutExpired('fixture', 450),
                      reconcile.ReconcileBlocked('reconcile_budget_exhausted'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                def launch(arguments, **kwargs):
                    process = self.launch(arguments, **kwargs)
                    process.wait.side_effect = [error, 1]
                    return process
                with mock.patch.object(reconcile.subprocess, 'Popen', side_effect=launch):
                    with self.assertRaises((reconcile.ReconcileBlocked, KeyboardInterrupt)):
                        reconcile.ansible_apply(self.config, self.node, {})
                self.assertEqual(self.failure()['phase'], 'task_failed')
                self.assertIsNone(self.failure()['rc'])
                # Reset this synthetic terminal attempt between cases.
                shutil.rmtree(self.config['state_dir'])
                for session in self.logs.iterdir():
                    shutil.rmtree(session)

    def test_interrupted_receipt_uses_checkpoint_with_null_rc(self):
        def launch(arguments, **kwargs):
            process = self.launch(arguments, **kwargs)
            reconcile.atomic_json(self.attempt / 'receipt.json', {'state': 'running', 'code': 'interrupted'})
            return process
        with mock.patch.object(reconcile.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(reconcile.ReconcileBlocked, 'ansible_attempt_pending'):
                reconcile.ansible_apply(self.config, self.node, {})
        self.assertIsNone(self.failure()['rc'])

    def test_censored_and_controller_timeout_never_publish_rc(self):
        session = self.session(current=self.event(censored=True, operation='reconcile'))
        self.assertIsNone(reconcile.ansible_failure_summary(self.attempt)['rc'])
        reconcile.atomic_json(session / 'current.json', self.event('controller_timeout', operation='reconcile'))
        self.assertIsNone(reconcile.ansible_failure_summary(self.attempt)['rc'])

    def test_unrelated_stale_and_ambiguous_sessions_are_rejected(self):
        self.session(attempt=self.root / 'unrelated')
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        self.session()
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt, started_ns=time.time_ns()), {})
        self.session(suffix='b' * 32)
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})

    def test_invalid_schema_and_secret_fields_are_rejected(self):
        session = self.session()
        invalid = [{'schema_version': True}, {'schema_version': 2}, {'event': 'other'}, {'time_ns': True},
                   {'operation': 'upgrade'}, {'rc': True}, {'rc': 256}, {'host': 'secret-value'},
                   {'task': {'name': 'secret'}}, {'task': {'source': 'roles/../private.yml', 'line': 1}},
                   {'task': {'source': 'roles/main.yml', 'line': True}}, {'stdout': 'secret'},
                   {'args': 'secret'}, {'censored': 'false'}]
        for fields in invalid:
            with self.subTest(fields=fields):
                reconcile.atomic_json(session / 'current.json', self.event(operation='reconcile', **fields)
                                      if 'operation' not in fields else self.event(**fields))
                self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        (session / 'current.json').write_bytes(b'x' * 4097)
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"schema_version":NaN}', b'{"schema_version":'):
            (session / 'current.json').write_bytes(raw)
            self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})

    def test_missing_or_oversized_root_and_root_inside_attempt_are_rejected(self):
        with mock.patch.object(reconcile, 'ansible_diagnostic_root', return_value=self.root / 'missing'):
            self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        with mock.patch.object(reconcile.os, 'geteuid', return_value=os.geteuid() + 1):
            self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        self.session()
        with mock.patch.object(reconcile, 'ansible_diagnostic_root', return_value=Path('relative')):
            self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        with mock.patch.object(reconcile, 'ansible_diagnostic_root', return_value=self.root):
            self.assertEqual(reconcile.ansible_failure_summary(self.root), {})
        for index in range(129):
            (self.logs / str(index)).touch(mode=0o600)
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})

    def test_unsafe_roots_sessions_and_files_are_rejected(self):
        session = self.session()
        current = session / 'current.json'
        for path in (self.logs, session, current):
            with self.subTest(path=path.name):
                original = path.stat().st_mode & 0o777
                path.chmod(0o755)
                self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
                path.chmod(original)
        os.link(current, session / 'hardlink')
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        (session / 'hardlink').unlink()
        current.rename(session / 'saved')
        current.symlink_to(session / 'saved')
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        current.unlink()
        os.mkfifo(current, 0o600)
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        alias = self.root / 'alias'
        alias.symlink_to(self.logs, target_is_directory=True)
        with mock.patch.object(reconcile, 'ansible_diagnostic_root', return_value=alias):
            self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
        current.unlink()
        (session / 'saved').rename(current)
        saved = self.root / 'saved-session'
        session.rename(saved)
        session.symlink_to(saved, target_is_directory=True)
        self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})

    def test_unsafe_first_failure_is_not_replaced_with_current(self):
        for first in (self.event(ignored=True), self.event('task_start'), self.event(args='secret')):
            with self.subTest(first=first):
                session = self.session(first=first)
                self.assertEqual(reconcile.ansible_failure_summary(self.attempt), {})
                shutil.rmtree(session)


if __name__ == '__main__':
    unittest.main()
