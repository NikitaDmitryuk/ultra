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
