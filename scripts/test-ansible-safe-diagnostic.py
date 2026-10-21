#!/usr/bin/env python3
"""Ensure Ansible rescue failures do not hide the original failing task."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'deploy/ansible/callback_plugins/safe_result.py'
spec = importlib.util.spec_from_file_location('safe_result', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
callback = module.CallbackModule()


def read_diagnostic(target, result):
    if not target.exists():
        raise AssertionError(
            f"diagnostic not produced; rc={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return json.loads(target.read_text())

identity_source = ROOT / 'deploy/ansible/library/ultra_dump_exit_identity.py'
identity_spec = importlib.util.spec_from_file_location('ultra_dump_exit_identity', identity_source)
identity = importlib.util.module_from_spec(identity_spec)
identity_spec.loader.exec_module(identity)

assert identity.safe_failure_code(ValueError('dump_exit_identity_route_disabled')) == 'dump_exit_identity_route_disabled'
assert identity.safe_failure_code(ValueError('password=do-not-log')) == 'database_reconciliation_failed'
assert identity.safe_failure_code(subprocess.TimeoutExpired('psql', 30)) == 'database_reconciliation_timeout'
assert identity.safe_failure_code(subprocess.CalledProcessError(1, 'psql', stderr='ERROR: dump_exit_identity_mapping_not_unique')) == 'dump_exit_identity_mapping_not_unique'
assert identity.safe_failure_code(subprocess.CalledProcessError(1, 'psql', stderr='password=do-not-log')) == 'database_reconciliation_failed'

with tempfile.TemporaryDirectory(prefix='ultra-ansible-diagnostic-') as directory:
    target = Path(directory) / 'diagnostic.json'
    os.environ['ULTRA_ANSIBLE_DIAGNOSTIC_FILE'] = str(target)
    try:
        callback.record(SimpleNamespace(_task=SimpleNamespace(name='original failure', action='assert'),
                                       _host=SimpleNamespace(name='bridge')), 'task_failed')
        callback.record(SimpleNamespace(_task=SimpleNamespace(name='rescue failure', action='fail'),
                                       _host=SimpleNamespace(name='bridge')), 'task_failed')
    finally:
        os.environ.pop('ULTRA_ANSIBLE_DIAGNOSTIC_FILE', None)
    saved = json.loads(target.read_text())
    assert saved == {'stage': 'original failure', 'node': 'bridge', 'code': 'task_failed'}, saved

with tempfile.TemporaryDirectory(prefix='ultra-ansible-diagnostic-') as directory:
    target = Path(directory) / 'diagnostic.json'
    os.environ['ULTRA_ANSIBLE_DIAGNOSTIC_FILE'] = str(target)
    try:
        result = SimpleNamespace(_task=SimpleNamespace(name='identity reconciliation', action='ultra_dump_exit_identity'),
                                 _host=SimpleNamespace(name='database'),
                                 _result={'ultra_safe_failure_code': 'dump_exit_identity_route_disabled',
                                          'msg': 'password=do-not-log'})
        callback.record(result, 'task_failed')
    finally:
        os.environ.pop('ULTRA_ANSIBLE_DIAGNOSTIC_FILE', None)
    saved = json.loads(target.read_text())
    assert saved == {'stage': 'identity reconciliation', 'node': 'database', 'code': 'task_failed',
                     'detail': 'dump_exit_identity_route_disabled'}, saved

with tempfile.TemporaryDirectory(prefix='ultra-ansible-diagnostic-') as directory:
    target = Path(directory) / 'diagnostic.json'
    os.environ['ULTRA_ANSIBLE_DIAGNOSTIC_FILE'] = str(target)
    try:
        result = SimpleNamespace(_task=SimpleNamespace(name='identity reconciliation', action='ultra_dump_exit_identity'),
                                 _host=SimpleNamespace(name='database'),
                                 _result={'ultra_safe_failure_code': 'password=do-not-log'})
        callback.record(result, 'task_failed')
    finally:
        os.environ.pop('ULTRA_ANSIBLE_DIAGNOSTIC_FILE', None)
    saved = json.loads(target.read_text())
    assert 'detail' not in saved and 'do-not-log' not in target.read_text(), saved

with tempfile.TemporaryDirectory(prefix='ultra-ansible-diagnostic-') as directory:
    target = Path(directory) / 'diagnostic.json'
    os.environ['ULTRA_ANSIBLE_DIAGNOSTIC_FILE'] = str(target)
    try:
        result = SimpleNamespace(_task=SimpleNamespace(name='ordinary task', action='command'),
                                 _host=SimpleNamespace(name='bridge'),
                                 _result={'msg': 'Timeout during banner exchange',
                                          'ultra_safe_failure_code': 'ssh_banner_timeout'})
        callback.v2_runner_on_failed(result)
    finally:
        os.environ.pop('ULTRA_ANSIBLE_DIAGNOSTIC_FILE', None)
    assert json.loads(target.read_text())['code'] == 'task_failed'

for message, expected in [
        ('Timeout during banner exchange private-host.example:22', 'ssh_banner_timeout'),
        ('Connection timed out private-host.example:22', 'ssh_connect_timeout'),
        ('Connection reset by peer private-host.example:22', 'ssh_connection_reset'),
        ('Timeout during banner exchange; Permission denied (publickey)', 'ssh_authentication_failed'),
        ('Connection timed out; Host key verification failed', 'ssh_pin_mismatch'),
        ('connect to host private-host.example:22: Network is unreachable', 'host_unreachable')]:
    with tempfile.TemporaryDirectory(prefix='ultra-ansible-diagnostic-') as directory:
        target = Path(directory) / 'diagnostic.json'
        os.environ['ULTRA_ANSIBLE_DIAGNOSTIC_FILE'] = str(target)
        try:
            result = SimpleNamespace(_task=SimpleNamespace(name='SSH probe', action='command'),
                                     _host=SimpleNamespace(name='bridge'), _result={'msg': message})
            callback.v2_runner_on_unreachable(result)
        finally:
            os.environ.pop('ULTRA_ANSIBLE_DIAGNOSTIC_FILE', None)
        saved_text = target.read_text()
        assert json.loads(saved_text)['code'] == expected, saved_text
        assert 'private-host' not in saved_text and 'Network is unreachable' not in saved_text, saved_text

ansible_playbook = shutil.which('ansible-playbook')
assert ansible_playbook, 'ansible-playbook is required for the no_log callback regression'
with tempfile.TemporaryDirectory(prefix='ultra-ansible-redacted-args-') as directory:
    root = Path(directory)
    library = root / 'library'
    library.mkdir()
    (library / 'safe_failure_probe.py').write_text(
        'from ansible.module_utils.basic import AnsibleModule\n'
        'AnsibleModule(argument_spec={"password":{"type":"str","required":True,"no_log":True},'
        '"route":{"type":"str","required":True,"no_log":True}}).fail_json('
        'msg="safe_failure", ultra_safe_failure_code="dump_exit_identity_route_disabled")\n'
    )
    (root / 'play.yml').write_text(
        '- hosts: localhost\n'
        '  connection: local\n'
        '  gather_facts: false\n'
        '  tasks:\n'
        '    - name: probe safe failure\n'
        '      safe_failure_probe:\n'
        '        password: secret-probe-value\n'
        '        route: uuid-probe-value\n'
    )
    target = root / 'diagnostic.json'
    local_scratch, remote_scratch = root / 'local-tmp', root / 'remote-tmp'
    local_scratch.mkdir()
    remote_scratch.mkdir()
    env = os.environ.copy()
    env.update({
        'ANSIBLE_LOCAL_TEMP': str(local_scratch),
        'ANSIBLE_REMOTE_TEMP': str(remote_scratch),
        'ANSIBLE_LIBRARY': str(library),
        'ANSIBLE_CALLBACK_PLUGINS': str(ROOT / 'deploy/ansible/callback_plugins'),
        'ANSIBLE_CALLBACKS_ENABLED': 'safe_result',
        'ANSIBLE_STDOUT_CALLBACK': 'default',
        'ULTRA_ANSIBLE_DIAGNOSTIC_FILE': str(target),
    })
    result = subprocess.run([ansible_playbook, '-i', 'localhost,', str(root / 'play.yml')],
                            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    saved = read_diagnostic(target, result)
    output = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert saved == {'stage': 'probe safe failure', 'node': 'localhost', 'code': 'task_failed',
                     'detail': 'dump_exit_identity_route_disabled'}, saved
    assert 'secret-probe-value' not in output and 'uuid-probe-value' not in output, output

with tempfile.TemporaryDirectory(prefix='ultra-ansible-ingress-diagnostic-') as directory:
    root = Path(directory)
    library = root / 'library'
    library.mkdir()
    (library / 'safe_failure_probe.py').write_text(
        'from ansible.module_utils.basic import AnsibleModule\n'
        'AnsibleModule(argument_spec={"address":{"type":"str","required":True,"no_log":True},'
        '"hostname":{"type":"str","required":True,"no_log":True}}).fail_json('
        'msg="ingress_probe_failed", ultra_safe_failure_code="ingress_tls_hostname_mismatch")\n'
    )
    (root / 'play.yml').write_text(
        '- hosts: localhost\n'
        '  connection: local\n'
        '  gather_facts: false\n'
        '  tasks:\n'
        '    - name: verify ingress TLS\n'
        '      safe_failure_probe:\n'
        '        address: 192.0.2.10\n'
        '        hostname: private-name.example.com\n'
    )
    target = root / 'diagnostic.json'
    local_scratch, remote_scratch = root / 'local-tmp', root / 'remote-tmp'
    local_scratch.mkdir()
    remote_scratch.mkdir()
    env = os.environ.copy()
    env.update({
        'ANSIBLE_LOCAL_TEMP': str(local_scratch),
        'ANSIBLE_REMOTE_TEMP': str(remote_scratch),
        'ANSIBLE_LIBRARY': str(library),
        'ANSIBLE_CALLBACK_PLUGINS': str(ROOT / 'deploy/ansible/callback_plugins'),
        'ANSIBLE_CALLBACKS_ENABLED': 'safe_result',
        'ANSIBLE_STDOUT_CALLBACK': 'default',
        'ULTRA_ANSIBLE_DIAGNOSTIC_FILE': str(target),
    })
    result = subprocess.run([ansible_playbook, '-vvv', '-i', 'localhost,', str(root / 'play.yml')],
                            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    saved = read_diagnostic(target, result)
    output = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert saved == {'stage': 'verify ingress TLS', 'node': 'localhost',
                     'code': 'ingress_tls_hostname_mismatch'}, saved
    assert 'private-name.example.com' not in output and '192.0.2.10' not in output, output
    assert 'private-name.example.com' not in target.read_text() and '192.0.2.10' not in target.read_text()

print('Safe Ansible failure diagnostics preserve the first failure and redact module arguments')
subprocess.run([sys.executable, str(ROOT / 'scripts/test-ansible-event-journal.py')], check=True)
