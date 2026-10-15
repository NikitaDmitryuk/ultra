#!/usr/bin/env python3
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('release_ci', Path(__file__).with_name('check-release-ci.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
commit = 'a' * 40
ok = {'head_sha': commit, 'event': 'push', 'run_number': 4, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success'}
assert module.approved([ok], commit)
assert not module.approved([{**ok, 'head_sha': 'b' * 40}], commit)
assert not module.approved([{**ok, 'event': 'pull_request'}], commit)
assert not module.approved([ok, {**ok, 'run_attempt': 2, 'conclusion': 'failure'}], commit)
assert not module.approved([ok, {**ok, 'run_number': 5, 'status': 'in_progress', 'conclusion': None}], commit)
assert not module.approved([], commit)
print('release CI identity and latest-attempt regressions passed')

# The existing required check remains an aggregate over every independent group.
import json
import os
import subprocess
import yaml
workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text())
jobs = workflow['jobs']
gate = jobs['lint-test-build']
assert gate['name'] == 'Lint, test, build'
assert gate['if'] == '${{ always() }}'
assert set(gate['needs']) == set(jobs) - {'lint-test-build'}
assert all('needs' not in jobs[name] for name in gate['needs'])
assert 'postgres' in jobs['go-tests']['services']
assert 'DATABASE_URL' in jobs['go-tests']['env']
test_commands = '\n'.join(step.get('run', '') for step in jobs['go-tests']['steps'])
assert 'make test\n' in test_commands
assert 'test-load-pg-recovery.py' in test_commands
assert 'postgres' in jobs['go-race']['services']
assert 'DATABASE_URL' in jobs['go-race']['env']
race_commands = '\n'.join(step.get('run', '') for step in jobs['go-race']['steps'])
assert 'make test-race' in race_commands
command = gate['steps'][0]['run']
for state in ('success', 'failure', 'cancelled', 'skipped'):
    needs = {name: {'result': 'success'} for name in gate['needs']}
    needs[gate['needs'][0]]['result'] = state
    result = subprocess.run(['bash', '-c', command], env={**os.environ, 'CI_RESULTS': json.dumps(needs)}, capture_output=True)
    assert (result.returncode == 0) == (state == 'success'), (state, result.stderr)
print('parallel CI preserves PostgreSQL and rejects failed, cancelled or skipped groups')
