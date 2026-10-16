#!/usr/bin/env python3
"""Ensure Ansible rescue failures do not hide the original failing task."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'deploy/ansible/callback_plugins/safe_result.py'
spec = importlib.util.spec_from_file_location('safe_result', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
callback = module.CallbackModule()

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

print('First Ansible failure diagnostic is preserved across rescue')
