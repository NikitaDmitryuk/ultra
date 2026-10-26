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

# Execute the actual preserved-primary-before tasks with a harmless psql fixture.
# Real psql output contains transaction status lines around the JSON row; only
# the parsed row should be persisted to the .json identity file.
with tempfile.TemporaryDirectory(prefix='ultra-preserved-primary-identity-') as directory:
    directory = Path(directory)
    saved_identity = directory / 'preserved-primary-identity.json'
    psql_output = ('BEGIN\n' + json.dumps({
        'system_identifier': '12345', 'database': 'fixturedb',
        'database_oid': 42, 'primary': True,
    }) + '\nROLLBACK\n')
    before = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/tasks/preserved-primary-before.yml').read_text())
    before = copy.deepcopy(before)
    query = next(task for task in before if 'ansible.builtin.command' in task)
    query['ansible.builtin.command'] = {'argv': ['/usr/bin/printf', psql_output]}

    # Reuse the role's own identity assertion and projection to prove that the
    # file written by the real task remains consumable by downstream bootstrap.
    role_tasks = copy.deepcopy(role[:3])
    identity_query = next(task for task in role_tasks if 'ansible.builtin.command' in task)
    identity_query['ansible.builtin.command'] = {'argv': ['/usr/bin/printf', 'BEGIN\n12345\nROLLBACK\n']}
    before.extend(role_tasks)
    before.append({'name': 'Require canonical saved identity JSON', 'ansible.builtin.assert': {'that': [
        "lookup('file', ultra_preserved_primary_identity_file) | from_json == "
        "{'system_identifier': '12345', 'database': 'fixturedb', 'database_oid': 42, 'primary': true}",
        "postgres_replica_primary_identity.stdout == '12345'",
    ]}})
    play = [{
        'name': 'Persist and consume preserved primary identity fixture',
        'hosts': 'database',
        'gather_facts': False,
        'vars': {
            'ultra_preserved_primary_host': 'database',
            'ultra_preserved_primary_database': 'fixturedb',
            'ultra_preserved_primary_identity_file': str(saved_identity),
            'ultra_preserve_primary': True,
            'ultra_database_import_dump': '',
        },
        'tasks': before,
    }]
    playbook = directory / 'preserved-primary.yml'
    playbook.write_text(yaml.safe_dump(play, sort_keys=False))
    inventory = directory / 'inventory.ini'
    inventory.write_text('[databases]\ndatabase ansible_connection=local ansible_host=database\n'
                         '[bridge]\nbridge ansible_host=bridge\n[exits]\nexit_0 ansible_host=exit-0\n')
    result = subprocess.run(
        ['ansible-playbook', '-i', str(inventory), str(playbook)],
        cwd=directory,
        env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(directory / 'local'),
                 ANSIBLE_REMOTE_TEMP=str(directory / 'remote')),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    with saved_identity.open() as source:
        identity = json.load(source)
    assert identity == {
        'system_identifier': '12345', 'database': 'fixturedb',
        'database_oid': 42, 'primary': True,
    }
print('Preserved primary identity is canonical JSON and remains consumable by the replica role')
