#!/usr/bin/env python3
"""Durable cross-job fence, including actual controller SIGKILL."""
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('controller_fence', ROOT / 'deploy/ansible/controller.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ExecutionFence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.namespace = self.root / 'shared'
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir(mode=0o700)
        (self.bundle / 'controller.py').write_text('# pinned fixture\n')
        self.logs = self.root / 'logs'
        self.marker = self.root / 'calls'
        self.stub = self.root / 'ansible-playbook'
        self.stub.write_text('#!' + sys.executable + '\n' +
            'import json,os,pathlib,sys,time\n' +
            'v=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/"variables.json").read_text())\n' +
            'pathlib.Path(' + repr(str(self.marker)) + ').write_text(str(os.getpid()))\n' +
            'time.sleep(float(v.get("sleep",0)))\n' +
            'p=pathlib.Path(v["ultra_result_file"]);p.write_text("{\\"verified\\":true}");p.chmod(0o600)\n')
        self.stub.chmod(0o700)

    def job(self, name, operation='bootstrap', delay=0):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        raw = json.dumps({'inventory': {}, 'variables': {'sleep': delay}}).encode()
        digest = hashlib.sha256(raw).hexdigest()
        C.atomic(directory / 'request.json', json.loads(raw))
        raw = (directory / 'request.json').read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        C.atomic(directory / 'job.json', {'schema_version': 1, 'operation': operation,
                 'request_sha256': digest, 'binary_sha256': digest})
        return directory

    def run_job(self, directory):
        return C.execute(directory, self.stub, self.bundle, self.logs, self.namespace)

    def test_runtime_limit_is_attempt_bound_and_never_normal_completion(self):
        directory = self.job('runtime-limit', delay=30)
        request = C.load_private(directory / 'request.json')
        request['execution_timeout_seconds'] = 1
        C.atomic(directory / 'request.json', request)
        job = C.load_private(directory / 'job.json')
        job['request_sha256'] = hashlib.sha256((directory / 'request.json').read_bytes()).hexdigest()
        C.atomic(directory / 'job.json', job)
        state = self.run_job(directory)
        self.assertEqual((state['state'], state['code']), ('failed', 'execution_runtime_limit'))
        generation = state['execution_generation']
        evidence = directory / ('execution-runtime-limit-' + generation + '.json')
        value = C.load_private(evidence)
        self.assertEqual(value['fence'], C.load_private(self.namespace / 'execution-fence.json'))
        self.assertEqual(value['timeout_seconds'], 1)
        self.assertFalse((directory / 'execution-completion.json').exists())
        self.assertFalse((directory / ('execution-drain-' + generation + '.json')).exists())
        pid = int(self.marker.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        # Saved timeout evidence is immutable and cannot become retry authority.
        before = evidence.read_bytes()
        with self.assertRaisesRegex(ValueError, 'execution_runtime_limit_conflict'):
            C.exclusive_atomic(evidence, {**value, 'timeout_seconds': 2})
        self.assertEqual(evidence.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, 'execution_uncertain'):
            self.run_job(self.job('next-job'))

    def test_execution_timeout_validation_precedes_dispatch(self):
        for index, value in enumerate((0, -1, True, 1.5, '1')):
            directory = self.job('invalid-timeout-' + str(index))
            request = C.load_private(directory / 'request.json')
            request['execution_timeout_seconds'] = value
            C.atomic(directory / 'request.json', request)
            with self.assertRaisesRegex(ValueError, 'invalid_execution_timeout'):
                self.run_job(directory)
        self.assertFalse(self.marker.exists())

    def test_current_bootstrap_operations_use_common_budget(self):
        for operation in ('bootstrap', 'bootstrap-automation'):
            directory = self.job('budget-' + operation, operation=operation)
            budgets = []
            def runner(*args, **kwargs):
                budgets.append(kwargs['timeout'])
                C.atomic(directory / 'result.json', {'verified': True})
                return 0
            with patch.object(C, 'run_playbook', runner):
                self.run_job(directory)
            self.assertEqual(budgets, [1200])

    def test_live_cgroup_worker_prevents_cleanup_completion_publication(self):
        library = self.bundle / 'library'
        library.mkdir(mode=0o700)
        (library / 'ultra_execution_containment.py').write_text(
            'def completion_containment(directory,fence):\n'
            ' raise ValueError("execution_containment_workers_live")\n')
        directory = self.job('escaped-worker')
        job = C.load_private(directory / 'job.json')
        raw = C.load_private(directory / 'request.json', raw=True)
        fence = C.execution_binding(directory, self.bundle, job, raw)
        fence['generation'] = 'a' * 32
        C.atomic(directory / 'receipt.json', {'state': 'succeeded',
                 'execution_generation': fence['generation']})
        with patch.object(C, 'EXECUTION_ROOT', self.namespace), \
             patch.dict(C.os.environ, {'ULTRA_OPERATOR_STATE_DIRECTORY': str(self.namespace)}), \
             self.assertRaisesRegex(ValueError, 'workers_live'):
            C.finish_execution(directory, self.bundle, self.namespace, fence)
        self.assertFalse((directory / 'execution-completion.json').exists())
        self.assertFalse((directory / 'execution-containment.json').exists())
        self.assertEqual(list(self.bundle.rglob('*.pyc')), [])

    def test_containment_import_preserves_frozen_bundle_digest(self):
        library=self.bundle/'library';library.mkdir(mode=0o700)
        (library/'ultra_execution_containment.py').write_text(
            'def require_containment(directory,generation):\n'
            ' raise ValueError("fixture_containment_probe")\n')
        directory=self.job('import-probe')
        job=C.load_private(directory/'job.json')
        raw=C.load_private(directory/'request.json',raw=True)
        before=C.execution_binding(directory,self.bundle,job,raw)
        # Exercise the canonical-only helper import without accessing the real
        # production namespace or claiming an execution generation.
        with patch.object(C, 'EXECUTION_ROOT', self.namespace), \
             patch.dict(C.os.environ, {'ULTRA_OPERATOR_STATE_DIRECTORY': str(self.namespace)}), \
             self.assertRaisesRegex(ValueError,'fixture_containment_probe'):
            C.begin_execution(directory,self.bundle,job,raw,self.namespace)
        self.assertEqual(C.execution_binding(directory,self.bundle,job,raw),before)
        self.assertEqual(list(self.bundle.rglob('*.pyc')),[])
        self.assertFalse((self.namespace/'execution-fence.json').exists())

    def test_sigkill_blocks_same_job_and_different_job(self):
        first = self.job('one', delay=20)
        second = self.job('two')
        child = multiprocessing.get_context("fork").Process(target=self.run_job, args=(first,))
        child.start()
        worker = None
        try:
            deadline = time.monotonic() + 8
            while not self.marker.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(self.marker.exists(), 'actual runner never started')
            worker = int(self.marker.read_text())
            os.kill(child.pid, signal.SIGKILL)
            child.join(3)
            self.assertEqual(child.exitcode, -signal.SIGKILL)
            fence = C.load_private(self.namespace / 'execution-fence.json')
            for job in (first, second):
                with self.assertRaisesRegex(ValueError, 'execution_uncertain'):
                    self.run_job(job)
            # Even exact generation possession cannot redispatch a consumed claim.
            with patch.dict(os.environ, {'ULTRA_EXECUTION_GENERATION': fence['generation']}):
                with self.assertRaises(FileExistsError):
                    self.run_job(first)
            self.assertEqual(int(self.marker.read_text()), worker)
        finally:
            if child.is_alive():
                child.kill()
                child.join()
            if worker:
                try:
                    os.killpg(worker, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_normal_success_has_bound_completion_and_releases(self):
        job = self.job('one')
        self.assertEqual(self.run_job(job)['state'], 'succeeded')
        self.assertFalse((self.namespace / 'execution-fence.json').exists())
        completion = C.load_private(job / 'execution-completion.json')
        self.assertTrue(completion['local_cleanup'])
        self.assertEqual(completion['receipt_sha256'], hashlib.sha256(
            (job / 'receipt.json').read_bytes()).hexdigest())
        self.assertEqual(self.run_job(self.job('two'))['state'], 'succeeded')

    def test_lost_receipt_cannot_redispatch_completed_attempt(self):
        job = self.job('one')
        self.assertEqual(self.run_job(job)['state'], 'succeeded')
        original_worker = self.marker.read_text()
        (job / 'receipt.json').unlink()
        with self.assertRaisesRegex(ValueError, 'legacy_execution_uncertain'):
            self.run_job(job)
        self.assertEqual(self.marker.read_text(), original_worker)
        self.assertTrue((self.namespace / 'execution-fence.json').exists())

    def test_failure_keeps_fence_but_readonly_works(self):
        job = self.job('one')
        result = C.execute(job, '/bin/false', self.bundle, self.logs, self.namespace)
        self.assertEqual(result['state'], 'failed')
        self.assertTrue((self.namespace / 'execution-fence.json').exists())
        with self.assertRaisesRegex(ValueError, 'execution_uncertain'):
            self.run_job(self.job('two'))
        self.assertEqual(self.run_job(self.job('inspect', 'inspect-bootstrap'))['state'], 'succeeded')


class TerminalProof(unittest.TestCase):
    def test_callback_requires_every_terminal_ack_and_rejects_async_unreachable(self):
        base = types.ModuleType('ansible.plugins.callback')
        base.CallbackBase = object
        with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'),
                                     'ansible.plugins': types.ModuleType('ansible.plugins'),
                                     'ansible.plugins.callback': base}):
            spec = importlib.util.spec_from_file_location('safe_result_fixture',
                ROOT / 'deploy/ansible/callback_plugins/safe_result.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        for terminal, asynchronous, unreachable, expected in (
                (True, False, 0, True), (False, False, 0, False),
                (True, True, 0, False), (True, False, 1, False)):
            with self.subTest(terminal=terminal, asynchronous=asynchronous, unreachable=unreachable):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / 'terminal.json'
                    callback = module.CallbackModule()
                    host = types.SimpleNamespace(name='localhost')
                    task = types.SimpleNamespace(_uuid='one', async_val=int(asynchronous))
                    callback.execution_task(host, task)
                    if terminal:
                        callback.execution_task(host, task, True)
                    stats = types.SimpleNamespace(processed={'localhost': 1},
                        summarize=lambda host: {'failures': 1, 'unreachable': unreachable})
                    with patch.dict(os.environ, {'ULTRA_EXECUTION_TERMINAL_FILE': str(target),
                                               'ULTRA_EXECUTION_BINDING': '{"generation":"fixture"}'}):
                        callback.v2_playbook_on_stats(stats)
                    self.assertEqual(target.exists(), expected)


if __name__ == '__main__':
    unittest.main()
