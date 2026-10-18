#!/usr/bin/env python3
"""Generated fixtures exercise publication/backup/cache/ownership retirement gates."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_retire_experiment.py'
spec = importlib.util.spec_from_file_location('retire', source)
retire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retire)

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    def write(name, value):
        path = root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)
        path.chmod(0o600)
        return path
    def rejected(phase):
        try:
            retire.inspect(phase, root)
        except ValueError:
            return
        raise AssertionError('unsafe retirement accepted')
    descriptor = write(retire.DESCRIPTOR, {'host': 'bridge.example.com', 'endpoint': {'port': 5543}, 'status_port': 18082})
    files = {retire.DESCRIPTOR: retire.sha(descriptor.read_bytes())}
    for name in retire.OWNED:
        files[name] = retire.sha(write(name, 'owned').read_bytes())
    receipt = write('/var/lib/ultra-ingress/managed.json', files)
    backup = write('/etc/ultra-recovery/backup.json', {'state_paths': [retire.DESCRIPTOR], 'artifact_paths': []})
    deployment = write('/etc/ultra-recovery/deployment.json', {'ingress': {'experimental_port': 5543, 'status_port': 18082}})
    rejected('prepare')
    write('/etc/ultra-recovery/backup.json', {'state_paths': ['/etc/ultra-relay/spec.json'], 'artifact_paths': []})
    write('/etc/ultra-recovery/deployment.json', {'ingress': {}})
    rejected('prepare')
    write('/etc/ultra-recovery/deployment.json', {'ingress': {'experimental_port': 5543, 'status_port': 18082}})
    state = retire.inspect('prepare', root)
    stale = root / retire.JOURNAL.lstrip('/').replace('retired-experiment.json', 'retired-experiment.next')
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('interrupted write')
    stale.chmod(0o600)
    assert retire.persist(state, root / retire.JOURNAL.lstrip('/'))
    assert not stale.exists()
    assert json.loads((root / retire.JOURNAL.lstrip('/')).read_text()) == state
    (root / retire.JOURNAL.lstrip('/')).unlink()
    write(retire.JOURNAL, state)
    rejected('verify')
    descriptor.unlink()
    files.pop(retire.DESCRIPTOR)
    write('/var/lib/ultra-ingress/managed.json', files)
    cache_path = '/var/lib/ultra-bot/subscriptions.json'
    def cache(confirmed, body='normal'):
        return write(cache_path, {'version': 1, 'entries': {'digest?format=happ': {
            'confirmed_at': confirmed, 'body': base64.b64encode(body.encode()).decode()}}})
    cache('2000-01-01T00:00:00Z')
    rejected('verify')
    now = datetime.now(timezone.utc).isoformat()
    cache(now, 'Эксперимент · XHTTP TLS')
    rejected('verify')
    cache(now)
    assert set(retire.inspect('verify', root)['files']) == set(retire.OWNED)
    write(retire.OWNED[0], 'drift')
    rejected('verify')
    write(retire.OWNED[0], 'owned')
    for name in retire.OWNED:
        (root / name.lstrip('/')).unlink()
        files.pop(name)
    write('/var/lib/ultra-ingress/managed.json', files)
    assert retire.inspect('verify', root)['files'] == state['files']
print('Experimental retirement backup, unpublication, cache, drift and retry gates passed')

import yaml
playbook = yaml.safe_load((source.parents[1] / 'playbooks/ingress.yml').read_text())
tasks = playbook[1]['tasks']
names = [task['name'] for task in tasks]
ordered = ['Validate legacy experimental ownership and recovery metadata',
           'Unpublish only receipt-owned experimental descriptor',
           'Require persisted subscription cache refreshed after unpublication',
           'Stop retired experimental service only after publication proof',
           'Remove only verified receipt-owned experimental runtime files']
assert [names.index(name) for name in ordered] == sorted(names.index(name) for name in ordered)
for name in ordered:
    assert any("retire-experiment" in condition for condition in
               ([tasks[names.index(name)]['when']] if isinstance(tasks[names.index(name)]['when'], str)
                else tasks[names.index(name)]['when']))
print('Experimental retirement is explicit and stops only after ownership, unpublication and cache proof')
