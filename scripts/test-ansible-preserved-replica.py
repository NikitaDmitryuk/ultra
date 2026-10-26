#!/usr/bin/env python3
"""Exercise real primary-task ordering without connecting to a database or host."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
role = yaml.safe_load((ROOT / 'deploy/ansible/roles/postgres_replica/tasks/preserved_primary.yml').read_text())
projections = [task for task in role if 'ansible.builtin.set_fact' in task]
assert len(projections) == 2

with tempfile.TemporaryDirectory(prefix='ultra-replica-order-') as directory:
    directory = Path(directory)
    for name in ['bootstrap.yml', 'bootstrap-postgres.yml']:
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks' / name).read_text())
        play = next(p for p in plays if p['name'] == 'Prepare primary replication slot and identity')
        tasks = copy.deepcopy(play['tasks'])
        for task in tasks:
            if 'ansible.builtin.command' in task:
                # Any primary-provisioning command must remain skipped. A missing
                # guard fails locally rather than executing production SQL.
                task['ansible.builtin.command'] = {'argv': ['/bin/false']}
            if 'ansible.builtin.include_role' in task:
                assert task.pop('ansible.builtin.include_role') == {
                    'name': 'postgres_replica', 'tasks_from': 'preserved_primary'}
                task['block'] = copy.deepcopy(projections)
        tasks.append({'name': 'Require preserved projections after every skipped register',
                      'ansible.builtin.assert': {'that': [
                          "postgres_replica_primary_identity.stdout == '12345'",
                          '(postgres_replica_primary_parameters.stdout_lines[0] | from_json).max_connections == 100']}})
        fixture = [{'name': 'Verify canonical preserved-primary task order',
                    'hosts': 'localhost', 'gather_facts': False, 'vars': {
                        'ultra_preserve_primary': True,
                        'postgres_replica_preserved_identity': {'stdout_lines': ['BEGIN', '12345', 'ROLLBACK']},
                        'postgres_replica_preserved_parameters': {'stdout_lines': [
                            'BEGIN', '1', json.dumps({'max_connections': 100}), 'ROLLBACK']}}, 'tasks': tasks}]
        path = directory / name
        path.write_text(yaml.safe_dump(fixture, sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(path)],
                                cwd=directory, env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(directory / 'local'),
                                                       ANSIBLE_REMOTE_TEMP=str(directory / 'remote')),
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
print('Both canonical playbooks preserve primary identity and parameters after skipped registrations')
