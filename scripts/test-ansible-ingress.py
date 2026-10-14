#!/usr/bin/env python3
"""Ingress state regressions use generated private state, never live infrastructure."""
import importlib.util
import json
from pathlib import Path
import tempfile

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_ingress_state.py'
specification = importlib.util.spec_from_file_location('state', source)
state = importlib.util.module_from_spec(specification)
specification.loader.exec_module(state)
plan = {'domain': 'edge.example.com', 'public_host': 'edge.example.com', 'path': '/connect',
        'backend_port': 18080, 'gateway_port': 18081, 'staging_port': 18443}
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    specification = root / 'spec.json'
    before = {'role': 'bridge', 'database': {'dsn': 'retained'}, 'public_host': 'old.example.com',
              'public_xhttp_tls': {'port': 5443, 'server_name': 'old.example.com', 'path': '/old', 'certificate_file': '/cert', 'key_file': '/key'}}
    specification.write_text(json.dumps(before))
    operation = root / 'operation'
    prepared = state.transition(specification, operation, plan, 'stage', 'prepare')
    candidate = Path(prepared['candidate']).read_bytes()
    assert json.loads(candidate)['database'] == before['database']
    assert state.transition(specification, operation, plan, 'stage', 'commit')['changed']
    assert not state.transition(specification, operation, plan, 'stage', 'commit')['changed']
    assert Path(state.transition(specification, operation, plan, 'stage', 'prepare')['candidate']).read_bytes() == candidate
    assert state.transition(specification, operation, plan, 'stage', 'rollback')['changed']
    assert json.loads(specification.read_text()) == before
    specification.write_text('{"role":"bridge","foreign":true}')
    try:
        state.transition(specification, operation, plan, 'stage', 'commit')
        raise AssertionError('drift accepted')
    except ValueError:
        pass
published = {'role': 'bridge', 'database': {'dsn': 'retained'},
             'primary_xhttp': {'host': 'old.example.com', 'server_name': 'old.example.com', 'port': 443,
                               'path': '/connect', 'backend_port': 18080, 'fingerprint': 'firefox'}}
try:
    state.candidate(published, plan, 'stage')
    raise AssertionError('published endpoint replaced by ordinary stage')
except ValueError:
    pass
try:
    state.candidate(published, plan, 'activate')
    raise AssertionError('published endpoint changed without cutover')
except ValueError:
    pass
cutover = state.candidate(published, plan, 'cutover')
assert cutover['database'] == published['database']
assert cutover['primary_xhttp']['host'] == 'edge.example.com'
assert published['primary_xhttp']['host'] == 'old.example.com'
recovered = state.recovery_candidate(cutover, published, 18080)
assert recovered['primary_xhttp'] == published['primary_xhttp']
assert recovered['database'] == cutover['database']
print('Ansible ingress stage, replay, drift, cutover and rollback regressions passed')
