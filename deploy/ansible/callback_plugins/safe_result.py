"""Persist only fixed task metadata; never serialize module results or inputs."""
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import time
from ansible.plugins.callback import CallbackBase

INGRESS_FAILURE_CODES = {
    'ingress_tls_hostname_mismatch',
    'ingress_tls_certificate_verification_failed',
    'ingress_tls_listener_unavailable',
    'ingress_tls_timeout',
    'ingress_tls_handshake_failed',
    'ingress_tls_probe_failed',
    'ingress_probe_failed',
}
IDENTITY_FAILURE_CODES = {
    'invalid_dump_exit_identity_input', 'database_import_receipt_mismatch',
    'invalid_dump_exit_identity_route', 'invalid_dump_exit_identity_pin',
    'duplicate_dump_exit_identity_route', 'database_import_identity_mismatch',
    'dump_exit_identity_binding_mismatch', 'dump_exit_identity_mapping_not_unique',
    'dump_exit_identity_route_disabled', 'dump_exit_identity_membership_changed',
    'dump_exit_identity_changed', 'database_reconciliation_timeout', 'database_reconciliation_failed',
}


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'safe_result'
    CALLBACK_NEEDS_ENABLED = True

    def journal(self):
        if hasattr(self, '_journal'):
            return self._journal
        self._journal = None
        target = os.environ.get('ULTRA_ANSIBLE_EVENTS_DIR')
        if target:
            # controller.py deliberately imports only the standard library: its
            # supervisor runs outside the pinned Ansible virtual environment.
            spec = importlib.util.spec_from_file_location(
                'ultra_safe_journal', Path(__file__).resolve().parent.parent / 'controller.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            try:
                self._journal = module.SafeJournal(Path(target))
            except (OSError, ValueError):
                pass
        return self._journal

    def task_metadata(self, task):
        """Use original bundle coordinates, never a rendered task name/args."""
        root = os.environ.get('ULTRA_ANSIBLE_SOURCE_ROOT')
        if not root:
            return {}
        try:
            filename, _, number = task.get_path().rpartition(':')
            source = Path(filename)
            relative = source.resolve().relative_to(Path(root).resolve()).as_posix()
            line = int(number)
            if (source.is_symlink() or not source.is_file() or not 1 <= line <= 100000
                    or not re.fullmatch(r'(?:roles|playbooks)/[A-Za-z0-9_./-]{1,240}\.yml', relative)):
                return {}
            value = {'source': relative, 'line': line}
            action = task.action
            if isinstance(action, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,95}', action):
                value['action'] = action
            return value
        except (AttributeError, OSError, TypeError, ValueError):
            return {}

    def event(self, event, host, task, result=None, code=None, ignored=False):
        journal = self.journal()
        if journal is None:
            return
        alias = host.name
        # Dynamic inventory aliases can themselves contain sensitive material.
        node = alias if alias in {'bridge', 'exit', 'database', 'receiver', 'localhost'} else hashlib.sha256(alias.encode()).hexdigest()[:16]
        metadata = self.task_metadata(task)
        fields = {'task': metadata, 'host': node, 'censored': bool(getattr(task, 'no_log', False))}
        if not hasattr(self, '_task_started'):
            self._task_started = {}
        identity = (alias, str(getattr(task, '_uuid', id(task))))
        started = self._task_started.get(identity)
        if event == 'task_start':
            # Bound memory even if a worker never returns its terminal callback.
            if len(self._task_started) >= 1024 and identity not in self._task_started:
                self._task_started.pop(next(iter(self._task_started)))
            self._task_started[identity] = time.monotonic()
        elif started is not None:
            fields['duration_ms'] = max(0, int((time.monotonic() - started) * 1000))
            if event != 'task_retry':
                self._task_started.pop(identity, None)
        if result is not None and not fields['censored']:
            data = getattr(result, '_result', {})
            if isinstance(data, dict):
                fields['censored'] = bool(data.get('_ansible_no_log', False))
                if not fields['censored']:
                    for key in ('changed', 'skipped'):
                        if type(data.get(key)) is bool:
                            fields[key] = data[key]
                    if type(data.get('rc')) is int and -255 <= data['rc'] <= 255:
                        fields['rc'] = data['rc']
                    safe_code = data.get('ultra_safe_failure_code')
                    if isinstance(safe_code, str) and safe_code in INGRESS_FAILURE_CODES | IDENTITY_FAILURE_CODES:
                        fields['detail'] = safe_code
        if code is not None:
            fields['code'] = code
        if ignored:
            fields['ignored'] = True
        journal.best_effort(event, **fields)

    def execution_task(self, host, task, terminal=False, result=None):
        if not hasattr(self, '_execution_pending'):
            self._execution_pending = set()
            self._execution_hosts = set()
            self._execution_unsafe = False
        identity = (host.name, str(getattr(task, '_uuid', id(task))))
        self._execution_hosts.add(host.name)
        if getattr(task, 'async_val', 0):
            self._execution_unsafe = True
        data = getattr(result, '_result', {}) if result is not None else {}
        if isinstance(data, dict) and 'ansible_job_id' in data:
            self._execution_unsafe = True
        if terminal:
            self._execution_pending.discard(identity)
        else:
            self._execution_pending.add(identity)
        if len(self._execution_pending) > 100000:
            self._execution_unsafe = True

    def v2_playbook_on_stats(self, stats):
        target = os.environ.get('ULTRA_EXECUTION_TERMINAL_FILE')
        binding = os.environ.get('ULTRA_EXECUTION_BINDING')
        if not target or not binding:
            return
        try:
            hosts = set(stats.processed)
            if (not hosts or hosts != getattr(self, '_execution_hosts', set())
                    or getattr(self, '_execution_pending', {True})
                    or getattr(self, '_execution_unsafe', True)):
                return
            summaries = [stats.summarize(host) for host in hosts]
            if any(value.get('unreachable', 0) for value in summaries):
                return
            if not any(value.get('failures', 0) for value in summaries):
                return
            value = {'fence': json.loads(binding), 'outcome': 'failed',
                     'contacted_hosts': len(hosts), 'pending_tasks': 0,
                     'unreachable_hosts': 0, 'unmanaged_async': False}
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream)
                stream.flush()
                os.fsync(stream.fileno())
            parent = os.open(Path(target).parent, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except (OSError, ValueError, TypeError, AttributeError):
            return  # Missing/invalid proof remains fenced.

    def v2_runner_on_start(self, host, task):
        self.execution_task(host, task)
        self.event('task_start', host, task)

    def v2_runner_on_ok(self, result):
        self.execution_task(result._host, result._task, True, result)
        self.event('task_ok', result._host, result._task, result)

    def v2_runner_on_skipped(self, result):
        self.execution_task(result._host, result._task, True, result)
        self.event('task_skipped', result._host, result._task, result)

    def v2_runner_retry(self, result):
        self.event('task_retry', result._host, result._task, result)

    def record(self, result, code):
        target = os.environ.get('ULTRA_ANSIBLE_DIAGNOSTIC_FILE')
        if not target:
            return
        name = result._task.name
        if '{{' in name or '{%' in name:
            name = result._task.action
        value = {'stage': name, 'node': result._host.name, 'code': code}
        result_data = {} if getattr(result._task, 'no_log', False) else getattr(result, '_result', {})
        safe_failure = result_data.get('ultra_safe_failure_code') if isinstance(result_data, dict) else None
        if isinstance(safe_failure, str) and safe_failure in INGRESS_FAILURE_CODES:
            value['code'] = safe_failure
        if isinstance(safe_failure, str) and safe_failure in IDENTITY_FAILURE_CODES:
            value['detail'] = safe_failure
        path = Path(target)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.execution_task(result._host, result._task, True, result)
        self.event('task_failed', result._host, result._task, result, 'task_failed', ignore_errors)
        if not ignore_errors:
            self.record(result, 'task_failed')

    def v2_runner_on_unreachable(self, result):
        self.execution_task(result._host, result._task, True, result)
        self._execution_unsafe = True
        # Classify known failures without persisting the possibly sensitive message.
        text = '' if getattr(result._task, 'no_log', False) else result._result.get('msg', '')
        code = 'host_unreachable'
        for fragment, candidate in [('Host key verification failed', 'ssh_pin_mismatch'),
                                    ('Permission denied', 'ssh_authentication_failed'),
                                    ('Timeout during banner exchange', 'ssh_banner_timeout'),
                                    ('Connection refused', 'ssh_connection_refused'),
                                    ('Connection timed out', 'ssh_connect_timeout'),
                                    ('Connection reset by peer', 'ssh_connection_reset'),
                                    ('too long for Unix domain socket', 'ssh_control_path_too_long'),
                                    ('Failed to create temporary directory', 'ssh_temporary_directory_failed')]:
            if fragment in text:
                code = candidate
                break
        self.event('task_unreachable', result._host, result._task, result, code)
        self.record(result, code)
