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
        path = Path(target)
        temporary = path.with_suffix('.next')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

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
