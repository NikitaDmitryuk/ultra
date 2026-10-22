#!/usr/bin/env python3
"""Safe observations survive cancellation without changing authorization receipts."""
import hashlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTROLLER_PATH = ROOT / 'deploy/ansible/controller.py'
CONTROLLER = load('controller', CONTROLLER_PATH)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.spool = self.root / 'logs'
        self.namespace = self.root / 'execution'
        self.job = self.root / 'job'
        self.job.mkdir(mode=0o700)

    def journal(self):
        value = CONTROLLER.SafeJournal.create(self.spool, self.job, 'reconcile')
        self.addCleanup(value.close)
        return value

    def test_private_external_sessions_and_bounded_checkpoint(self):
        journal = self.journal()
        task = {'source': 'roles/recovery/tasks/main.yml', 'line': 3, 'action': 'ansible.builtin.apt'}
        with patch.object(CONTROLLER.SafeJournal, 'MAX_BYTES', 350):
            for _ in range(20):
                journal.emit('task_start', task=task, host='receiver')
            journal.emit('task_failed', task=task, host='receiver', code='task_failed')
            journal.emit('controller_interrupted')
        self.assertLessEqual((journal.path / 'events.jsonl').stat().st_size, 350)
        checkpoint = json.loads((journal.path / 'current.json').read_text())
        self.assertTrue(checkpoint['truncated'])
        self.assertEqual(checkpoint['task'], task)
        self.assertEqual(checkpoint['event'], 'controller_interrupted')
        self.assertEqual(json.loads((journal.path / 'first-failure.json').read_text())['code'], 'task_failed')
        self.assertEqual(list(self.job.iterdir()), [])
        self.assertEqual(journal.path.stat().st_mode & 0o777, 0o700)
        for path in journal.path.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(journal.path.name.startswith(hashlib.sha256(str(self.job).encode()).hexdigest()))

    def test_links_permissions_and_oversized_events_are_rejected(self):
        journal = self.journal()
        outside = self.root / 'untouched'
        outside.write_text('do-not-truncate')
        outside.chmod(0o600)
        for filename in ('events.jsonl', 'current.json', 'current.next', 'write.lock'):
            target = journal.path / filename
            original = target.read_bytes() if target.exists() else None
            target.unlink(missing_ok=True)
            target.symlink_to(outside)
            self.assertFalse(journal.best_effort('task_start'))
            target.unlink()
            if original is not None:
                target.write_bytes(original)
                target.chmod(0o600)
            self.assertEqual(outside.read_text(), 'do-not-truncate')
        (journal.path / 'current.next').hardlink_to(outside)
        self.assertFalse(journal.best_effort('task_start'))
        self.assertEqual(outside.read_text(), 'do-not-truncate')
        (journal.path / 'current.next').unlink()
        (journal.path / 'events.jsonl').chmod(0o644)
        self.assertFalse(journal.best_effort('task_start'))
        with self.assertRaisesRegex(ValueError, 'too_large'):
            journal.emit('task_start', task={'source': 'x' * 5000})
        link = self.root / 'linked-spool'
        link.symlink_to(self.spool)
        with self.assertRaises(ValueError):
            CONTROLLER.SafeJournal.create(link, self.job, 'reconcile')
        with self.assertRaisesRegex(ValueError, 'inside_job'):
            CONTROLLER.SafeJournal.create(self.job / 'logs', self.job, 'reconcile')

    def test_retention_bounds_count_and_age_but_preserves_active_sessions(self):
        active = self.journal()
        old = self.journal()
        old.close()
        os.utime(old.path, (0, 0))
        newest = self.journal()
        self.assertFalse(old.path.exists())
        self.assertTrue(active.path.exists())
        with patch.object(CONTROLLER.SafeJournal, 'MAX_SESSIONS', 2):
            with self.assertRaisesRegex(ValueError, 'session_limit'):
                self.journal()
        newest.close()
        with patch.object(CONTROLLER.SafeJournal, 'MAX_SESSIONS', 2):
            replacement = self.journal()
        self.assertFalse(newest.path.exists())
        self.assertTrue(active.path.exists())
        self.assertTrue(replacement.path.exists())

    def test_stale_checkpoint_temp_and_write_failure_do_not_replace_outcome(self):
        journal = self.journal()
        temporary = journal.path / 'current.next'
        temporary.write_text('incomplete')
        temporary.chmod(0o600)
        journal.emit('task_start', task={'source': 'playbooks/reconcile.yml', 'line': 1})
        checkpoint = (journal.path / 'current.json').read_bytes()
        with patch.object(journal, 'checkpoint', side_effect=OSError('sensitive-error-do-not-persist')):
            self.assertFalse(journal.best_effort('controller_failed'))
        self.assertEqual((journal.path / 'current.json').read_bytes(), checkpoint)
        self.assertNotIn('sensitive-error', (journal.path / 'current.json').read_text())
        self.assertTrue(journal.best_effort('controller_failed'))
        values = [json.loads(line) for line in (journal.path / 'events.jsonl').read_text().splitlines()]
        self.assertEqual(values[-2]['event'], 'logging_degraded')
        self.assertNotIn('sensitive-error', (journal.path / 'events.jsonl').read_text())
        (journal.path / 'current.json').write_text('[]')
        self.assertFalse(journal.best_effort('controller_failed'))

    def test_partial_append_enospc_repairs_only_the_unfinished_line(self):
        journal = self.journal()
        events = journal.path / 'events.jsonl'
        completed = events.read_bytes()
        checkpoint = (journal.path / 'current.json').read_bytes()
        original_fdopen = CONTROLLER.os.fdopen
        class ShortWrite:
            def __init__(self, fd):
                self.fd = fd
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def write(self, raw):
                os.write(self.fd, raw[:25])
                raise OSError(errno.ENOSPC, 'synthetic disk full')
        def fdopen(fd, mode='r', **kwargs):
            return ShortWrite(fd) if mode == 'ab' else original_fdopen(fd, mode, **kwargs)
        with patch.object(CONTROLLER.os, 'fdopen', side_effect=fdopen):
            self.assertFalse(journal.best_effort('task_start'))
        self.assertEqual(len(events.read_bytes()), len(completed) + 25)
        self.assertEqual((journal.path / 'current.json').read_bytes(), checkpoint)
        self.assertTrue(journal.best_effort('controller_failed'))
        recovered = events.read_bytes()
        self.assertTrue(recovered.startswith(completed))
        values = [json.loads(line) for line in recovered.splitlines()]
        self.assertEqual([value['event'] for value in values[-2:]],
                         ['logging_degraded', 'controller_failed'])
        # A new writer after an abrupt death also repairs the tail, without an
        # in-memory degraded flag from the writer that died.
        with events.open('ab') as stream:
            stream.write(b'{"schema_version":')
        restarted = CONTROLLER.SafeJournal(journal.path)
        self.addCleanup(restarted.close)
        restarted.emit('controller_succeeded')
        final = events.read_bytes()
        self.assertTrue(final.startswith(recovered))
        self.assertEqual(json.loads(final.splitlines()[-1])['event'], 'controller_succeeded')

    def fixture(self):
        raw = json.dumps({'inventory': {}, 'variables': {}}).encode()
        (self.job / 'request.json').write_bytes(raw)
        (self.job / 'job.json').write_text(json.dumps({
            'schema_version': 1, 'operation': 'reconcile',
            'request_sha256': hashlib.sha256(raw).hexdigest(), 'binary_sha256': '0' * 64,
        }))
        for path in self.job.iterdir():
            path.chmod(0o600)
        executable = self.root / 'runner'
        executable.write_text('#!' + sys.executable + '\n' +
            'import importlib.util,os,time\n'
            'from pathlib import Path\n'
            f's=importlib.util.spec_from_file_location("journal", {str(CONTROLLER_PATH)!r})\n'
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
            'j=m.SafeJournal(Path(os.environ["ULTRA_ANSIBLE_EVENTS_DIR"]))\n'
            'j.emit("task_start", task={"source":"roles/recovery/tasks/receiver.yml","line":23}, host="receiver")\n'
            'print("secret-output-must-not-be-persisted",flush=True)\n'
            'time.sleep(20)\n')
        executable.chmod(0o700)
        return executable

    def checkpoint(self):
        paths = list(self.spool.glob('*/current.json'))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text())

    def test_initialization_failure_aborts_before_playbook(self):
        executable = self.fixture()
        self.spool.mkdir(mode=0o755)
        with patch.object(CONTROLLER, 'run_playbook') as run:
            with self.assertRaisesRegex(ValueError, 'unsafe_diagnostic_directory'):
                CONTROLLER.execute(self.job, executable, ROOT / 'deploy/ansible', self.spool, self.namespace)
            run.assert_not_called()

    def test_real_runner_timeout_retains_last_task_and_legacy_receipt(self):
        executable = self.fixture()
        original = CONTROLLER.run_playbook
        def short_run(arguments, bundle, environment, timeout):
            return original(arguments, bundle, environment, timeout=.5)
        with patch.object(CONTROLLER, 'run_playbook', side_effect=short_run):
            receipt = CONTROLLER.execute(self.job, executable, ROOT / 'deploy/ansible', self.spool, self.namespace)
        self.assertEqual((receipt['state'], receipt['code']), ('failed', 'execution_failed'))
        self.assertNotIn('diagnostic', receipt)
        self.assertNotIn('task', receipt)
        self.assertEqual(self.checkpoint()['event'], 'controller_timeout')
        self.assertEqual(self.checkpoint()['task']['line'], 23)
        for path in self.spool.glob('*/*'):
            self.assertNotIn(b'secret-output', path.read_bytes())

    def test_sigterm_retains_last_task_and_interrupted_receipt(self):
        executable = self.fixture()
        # Exercise the real CLI/signals and unchanged source bundle in a private
        # test namespace. No production CLI/env namespace override is introduced.
        bootstrap = (
            'import importlib.util,sys;from pathlib import Path;'
            's=importlib.util.spec_from_file_location("fixture_controller",sys.argv[1]);'
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
            'm.EXECUTION_ROOT=Path(sys.argv[2]);sys.argv=[sys.argv[1],*sys.argv[3:]];m.main()')
        process = subprocess.Popen([sys.executable, '-c', bootstrap, str(CONTROLLER_PATH),
            str(self.namespace), '--job', str(self.job), '--bundle', str(ROOT / 'deploy/ansible'),
            '--executable', str(executable), '--diagnostics-root', str(self.spool)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                paths = list(self.spool.glob('*/current.json'))
                if paths and json.loads(paths[0].read_text())['event'] == 'task_start':
                    break
                if process.poll() is not None:
                    self.fail('controller exited before runner task start')
                time.sleep(.01)
            else:
                self.fail('runner did not start')
            process.send_signal(signal.SIGTERM)
            output = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 1, output)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        receipt = json.loads((self.job / 'receipt.json').read_text())
        self.assertEqual((receipt['state'], receipt['code']), ('running', 'interrupted'))
        self.assertNotIn('finished_at', receipt)
        self.assertEqual(self.checkpoint()['event'], 'controller_interrupted')
        self.assertEqual(self.checkpoint()['task']['line'], 23)


class CallbackTests(unittest.TestCase):
    setUp = JournalTests.setUp
    journal = JournalTests.journal

    def test_interleaved_host_and_task_starts_keep_independent_durations(self):
        with patch.dict(os.environ, {'ANSIBLE_LOCAL_TEMP': str(self.root / 'ansible-tmp')}):
            module = load('safe_result', ROOT / 'deploy/ansible/callback_plugins/safe_result.py')
        callback = module.CallbackModule()
        journal = self.journal()
        callback._journal = journal
        task = SimpleNamespace(action='ansible.builtin.command', no_log=False, _uuid='first')
        other = SimpleNamespace(action='ansible.builtin.command', no_log=False, _uuid='second')
        bridge, receiver = SimpleNamespace(name='bridge'), SimpleNamespace(name='receiver')
        with patch.object(module.time, 'monotonic', side_effect=[10, 11, 12, 14, 16, 19]):
            callback.v2_runner_on_start(bridge, task)
            callback.v2_runner_on_start(receiver, task)
            callback.v2_runner_on_start(bridge, other)
            callback.v2_runner_on_ok(SimpleNamespace(_host=bridge, _task=task, _result={}))
            callback.v2_runner_on_ok(SimpleNamespace(_host=receiver, _task=task, _result={}))
            callback.v2_runner_on_failed(SimpleNamespace(_host=bridge, _task=other, _result={}), True)
        values = [json.loads(line) for line in (journal.path / 'events.jsonl').read_text().splitlines()]
        self.assertEqual([value['duration_ms'] for value in values[-3:]], [4000, 5000, 7000])
        self.assertEqual(callback._task_started, {})

    def test_real_ansible_events_observe_no_log_tasks_without_results(self):
        executable = shutil.which('ansible-playbook')
        self.assertIsNotNone(executable, 'ansible-playbook is required')
        playbook = self.root / 'playbooks/probe.yml'
        playbook.parent.mkdir()
        playbook.write_text(
            '- hosts: localhost\n'
            '  connection: local\n'
            '  gather_facts: false\n'
            '  tasks:\n'
            '    - name: rendered-secret-task-name\n'
            '      ansible.builtin.debug:\n'
            '        msg: secret-debug-result\n'
            '      no_log: true\n'
            '    - name: ordinary static failure\n'
            '      ansible.builtin.fail:\n'
            '        msg: secret-failure-result\n')
        journal = self.journal()
        environment = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': str(self.root), 'TMPDIR': str(self.root),
            'ANSIBLE_LOCAL_TEMP': str(self.root / 'local'),
            'ANSIBLE_REMOTE_TEMP': str(self.root / 'remote'),
            'ANSIBLE_CALLBACK_PLUGINS': str(ROOT / 'deploy/ansible/callback_plugins'),
            'ANSIBLE_CALLBACKS_ENABLED': 'safe_result',
            'ULTRA_ANSIBLE_EVENTS_DIR': str(journal.path),
            'ULTRA_ANSIBLE_SOURCE_ROOT': str(self.root),
        }
        result = subprocess.run([executable, '-i', 'localhost,', str(playbook)],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        text = (journal.path / 'events.jsonl').read_text()
        self.assertNotIn('secret-', text)
        events = [json.loads(line) for line in text.splitlines()]
        task_events = events[1:]
        self.assertEqual([value['event'] for value in task_events],
                         ['task_start', 'task_ok', 'task_start', 'task_failed'])
        self.assertEqual(task_events[0]['task']['source'], 'playbooks/probe.yml')
        self.assertTrue(task_events[1]['censored'])
        self.assertNotIn('changed', task_events[1])
        self.assertEqual(json.loads((journal.path / 'first-failure.json').read_text())['event'], 'task_failed')
    def test_no_log_terminal_proof_uses_only_known_static_execution_metadata(self):
        with patch.dict(os.environ, {'ANSIBLE_LOCAL_TEMP': str(self.root / 'ansible-tmp')}):
            module = load('safe_result_censored', ROOT / 'deploy/ansible/callback_plugins/safe_result.py')
        host = SimpleNamespace(name='bridge')
        stats = SimpleNamespace(processed={'bridge': 1},
                                summarize=lambda host: {'failures': 1, 'unreachable': 0})
        for name, attributes, safe in [
                ('synchronous', {'async_val': 0, 'delegate_to': None}, True),
                ('asynchronous', {'async_val': 30, 'delegate_to': None}, False),
                ('delegated', {'async_val': 0, 'delegate_to': 'receiver'}, False),
                ('templated_async', {'async_val': '{{ secret }}', 'delegate_to': None}, False),
                ('unknown_async', {'delegate_to': None}, False),
                ('unknown_delegate', {'async_val': 0}, False),
                ('async_status', {'async_val': 0, 'delegate_to': None,
                                  'action': 'ansible.builtin.async_status'}, False)]:
            with self.subTest(name=name):
                callback = module.CallbackModule()
                callback._journal = None
                values = {'no_log': True, '_uuid': name, 'action': 'ansible.builtin.command', **attributes}
                task = SimpleNamespace(**values)
                class Censored:
                    _task = task
                    _host = host
                    @property
                    def _result(self):
                        raise AssertionError('no_log result must never be inspected')
                target = self.root / (name + '-terminal.json')
                with patch.dict(os.environ, {'ULTRA_EXECUTION_TERMINAL_FILE': str(target),
                                             'ULTRA_EXECUTION_BINDING': '{"generation":"fixture"}'}):
                    callback.v2_runner_on_start(host, task)
                    callback.v2_runner_on_failed(Censored(), ignore_errors=True)
                    callback.v2_playbook_on_stats(stats)
                self.assertEqual(target.exists(), safe)
                if safe:
                    self.assertFalse(json.loads(target.read_text())['unmanaged_async'])

    def test_lifecycle_redaction_and_static_source_coordinates(self):
        # Ansible imports initialize their own local scratch directory.
        with patch.dict(os.environ, {'ANSIBLE_LOCAL_TEMP': str(self.root / 'ansible-tmp')}):
            callback_module = load('safe_result', ROOT / 'deploy/ansible/callback_plugins/safe_result.py')
        journal = self.journal()
        callback = callback_module.CallbackModule()
        callback._journal = journal
        task = SimpleNamespace(name='rendered-secret-password', action='ansible.builtin.command', no_log=False,
            get_path=lambda: str(ROOT / 'deploy/ansible/roles/recovery/tasks/receiver.yml') + ':23')
        host = SimpleNamespace(name='secret-inventory-alias')
        result = SimpleNamespace(_host=host, _task=task, _result={
            'msg': 'secret-msg', 'stdout': 'secret-stdout', 'stderr': 'secret-stderr',
            'invocation': {'args': 'secret-args'}, 'diff': 'secret-diff', 'item': 'secret-item',
            'exception': 'secret-exception', 'rc': 1, 'changed': False,
            'ultra_safe_failure_code': 'ingress_tls_timeout',
        })
        with patch.dict(os.environ, {'ULTRA_ANSIBLE_SOURCE_ROOT': str(ROOT / 'deploy/ansible')}):
            callback.v2_runner_on_start(host, task)
            callback.v2_runner_retry(result)
            callback.v2_runner_on_failed(result, ignore_errors=True)
            callback.v2_runner_on_ok(result)
            callback.v2_runner_on_skipped(result)
            task.no_log = True
            class Censored:
                _task = task
                _host = host
                @property
                def _result(self):
                    raise AssertionError('no_log result must not even be accessed')
            callback.v2_runner_on_start(host, task)
            callback.v2_runner_on_failed(Censored(), ignore_errors=True)
        text = (journal.path / 'events.jsonl').read_text()
        self.assertNotIn('secret-', text)
        values = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(values[1]['task']['source'], 'roles/recovery/tasks/receiver.yml')
        self.assertEqual(values[2]['detail'], 'ingress_tls_timeout')
        self.assertIn('duration_ms', values[2])
        self.assertTrue(values[-1]['censored'])
        self.assertNotIn('detail', values[-1])
        self.assertNotIn('rc', values[-1])


if __name__ == '__main__':
    unittest.main()
