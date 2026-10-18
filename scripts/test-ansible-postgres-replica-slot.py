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
    return subprocess.run(['docker', *args], input=stdin, text=True,
                          capture_output=True, check=check)


try:
    docker('run', '--detach', '--rm', '--network', 'none', '--name', container,
           '-e', 'POSTGRES_PASSWORD=fixture-superuser', 'postgres:16')
    for _ in range(60):
        if docker('exec', container, 'psql', '-U', 'postgres', '-Atc', 'SELECT 1', check=False).returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise AssertionError('fixture PostgreSQL did not start')

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
