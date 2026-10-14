#!/usr/bin/env python3
"""Installed release identity is independent of the incoming adoption artifact."""
import hashlib
import importlib.util
from pathlib import Path
from copy import deepcopy

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_adopt_probe.py'
spec = importlib.util.spec_from_file_location('adopt_probe', source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
installed = b'previous compatible release'
candidate = b'incoming Ansible release'
manifest = {'version': 'v2.4.6', 'capabilities': ['service-access-v1', 'provider-pool-quota-v1'],
            'assets': [{'name': 'ultra-relay-linux-amd64', 'size': len(installed),
                        'sha256': hashlib.sha256(installed).hexdigest()}]}
probe.installed_baseline(manifest, 'amd64', installed)
for name, mutation, binary, architecture in [
    ('candidate cannot attest previous', lambda m: None, candidate, 'amd64'),
    ('wrong architecture', lambda m: None, installed, 'arm64'),
    ('unsupported architecture', lambda m: None, installed, 'x86'),
    ('missing accounting contract', lambda m: m.update(capabilities=[]), installed, 'amd64'),
    ('wrong size', lambda m: m['assets'][0].update(size=1), installed, 'amd64'),
    ('wrong checksum', lambda m: m['assets'][0].update(sha256='0'*64), installed, 'amd64'),
    ('ambiguous asset', lambda m: m['assets'].append(dict(m['assets'][0])), installed, 'amd64'),
    ('invalid version', lambda m: m.update(version='latest'), installed, 'amd64'),
]:
    modified = deepcopy(manifest)
    mutation(modified)
    try:
        probe.installed_baseline(modified, architecture, binary)
    except ValueError as failure:
        assert str(failure) == 'installed_artifact_drift'
    else:
        raise AssertionError(name)
print('Adoption installed baseline: valid previous release accepted; 8 invalid identities rejected')
