#!/usr/bin/env python3
"""Exercise the bootstrap replication-slot SQL twice in isolated PostgreSQL 16."""
from pathlib import Path
import subprocess
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
playbooks = [ROOT / 'deploy/ansible/playbooks/bootstrap.yml',
             ROOT / 'deploy/ansible/playbooks/bootstrap-postgres.yml']


def slot_tasks(path):
    plays = yaml.safe_load(path.read_text())
    matches = []
    for play in plays:
        for task in play.get('tasks', []):
            if task.get('name') == 'Ensure bounded persistent bridge replication slot':
                matches.append(task)
    assert len(matches) == 1, f'{path.name}: expected one slot task'
    return matches[0]


tasks = [slot_tasks(path) for path in playbooks]
sql = tasks[0]['ansible.builtin.command']['stdin']
assert all(task['ansible.builtin.command']['stdin'] == sql for task in tasks), 'bootstrap slot SQL differs'
assert 'IF NOT EXISTS' in sql and 'pg_create_physical_replication_slot' in sql
assert "ULTRA_REPLICA_SLOT_CREATED" in sql
container = 'ultra-pg-replica-slot-' + uuid.uuid4().hex[:12]


def docker(*args, stdin=None, check=True):
    result = subprocess.run(['docker', *args], input=stdin, text=True,
                            capture_output=True, check=False)
    if check and result.returncode:
        raise AssertionError(f'docker command failed ({result.returncode}): {result.stderr.strip()}')
    return result


try:
    docker('run', '--detach', '--rm', '--pull=never', '--network', 'none', '--name', container,
           '-e', 'POSTGRES_PASSWORD=fixture-superuser', 'postgres:16')
    previous_start = None
    stable_start_checks = 0
    for _ in range(80):
        result = docker('exec', container, 'psql', '-U', 'postgres', '-Atc',
                        'SELECT pg_postmaster_start_time()', check=False)
        start = result.stdout.strip() if result.returncode == 0 else None
        if start and start == previous_start:
            stable_start_checks += 1
            if stable_start_checks >= 12:
                break
        else:
            previous_start = start
            stable_start_checks = 0
        time.sleep(0.25)
    else:
        raise AssertionError('fixture PostgreSQL did not reach a stable server process')

    first = docker('exec', '-i', container, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1',
                   '-At', stdin=sql)
    assert 'ULTRA_REPLICA_SLOT_CREATED' in first.stderr, 'first run did not create the slot'
    second = docker('exec', '-i', container, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1',
                    '-At', stdin=sql)
    assert 'ULTRA_REPLICA_SLOT_CREATED' not in second.stderr, 'rerun unexpectedly recreated the slot'
    assert docker('exec', container, 'psql', '-U', 'postgres', '-Atc',
                  "SELECT count(*) FROM pg_replication_slots WHERE slot_name='ultra_bridge' AND slot_type='physical' AND NOT temporary").stdout.strip() == '1'
    print('PostgreSQL physical replication-slot bootstrap is idempotent in both playbooks')
finally:
    docker('rm', '--force', container, check=False)
