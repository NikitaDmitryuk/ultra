#!/usr/bin/env python3
"""Ensure Ansible rescue failures do not hide the original failing task."""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'deploy/ansible/callback_plugins/safe_result.py'
spec = importlib.util.spec_from_file_location('safe_result', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
callback = module.CallbackModule()

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
    env = os.environ.copy()
    env.update({
        'ANSIBLE_LIBRARY': str(library),
        'ANSIBLE_CALLBACK_PLUGINS': str(ROOT / 'deploy/ansible/callback_plugins'),
        'ANSIBLE_CALLBACKS_ENABLED': 'safe_result',
        'ANSIBLE_STDOUT_CALLBACK': 'default',
        'ULTRA_ANSIBLE_DIAGNOSTIC_FILE': str(target),
    })
    result = subprocess.run([ansible_playbook, '-i', 'localhost,', str(root / 'play.yml')],
                            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    saved = json.loads(target.read_text())
    output = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert saved == {'stage': 'probe safe failure', 'node': 'localhost', 'code': 'task_failed',
                     'detail': 'dump_exit_identity_route_disabled'}, saved
    assert 'secret-probe-value' not in output and 'uuid-probe-value' not in output, output

print('Safe Ansible failure diagnostics preserve the first failure and redact module arguments')
