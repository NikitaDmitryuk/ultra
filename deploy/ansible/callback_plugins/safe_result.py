"""Persist only fixed task metadata; never serialize module results or inputs."""
import json
import os
from pathlib import Path
from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'safe_result'
    CALLBACK_NEEDS_ENABLED = True

    def record(self, result, code):
        target = os.environ.get('ULTRA_ANSIBLE_DIAGNOSTIC_FILE')
        if not target:
            return
        name = result._task.name
        if '{{' in name or '{%' in name:
            name = result._task.action
        value = {'stage': name, 'node': result._host.name, 'code': code}
        result_data = getattr(result, '_result', {})
        safe_failure = result_data.get('ultra_safe_failure_code') if isinstance(result_data, dict) else None
        if isinstance(safe_failure, str) and safe_failure in {
            'invalid_dump_exit_identity_input',
            'database_import_receipt_mismatch',
            'invalid_dump_exit_identity_route',
            'invalid_dump_exit_identity_pin',
            'duplicate_dump_exit_identity_route',
            'database_import_identity_mismatch',
            'dump_exit_identity_binding_mismatch',
            'dump_exit_identity_mapping_not_unique',
            'dump_exit_identity_route_disabled',
            'dump_exit_identity_membership_changed',
            'dump_exit_identity_changed',
            'database_reconciliation_timeout',
            'database_reconciliation_failed',
        }:
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
        if not ignore_errors:
            self.record(result, 'task_failed')

    def v2_runner_on_unreachable(self, result):
        # Classify known failures without persisting the possibly sensitive message.
        text = result._result.get('msg', '')
        code = 'host_unreachable'
        for fragment, candidate in [('Connection refused', 'ssh_connection_refused'),
                                    ('Permission denied', 'ssh_authentication_failed'),
                                    ('too long for Unix domain socket', 'ssh_control_path_too_long'),
                                    ('Host key verification failed', 'ssh_pin_mismatch'),
                                    ('Failed to create temporary directory', 'ssh_temporary_directory_failed')]:
            if fragment in text:
                code = candidate
                break
        self.record(result, code)
