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
           '-e', 'POSTGRES_PASSWORD=fixture-superuser', 'postgres:16',
           '-c', 'wal_level=logical', '-c', 'max_slot_wal_keep_size=1MB')
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
    # Exercise the production SQL itself; only the validated system identifier
    # interpolation differs from the Ansible call.
    reset_tasks = yaml.safe_load((ROOT / 'deploy/ansible/roles/postgres_replica/tasks/reset_lost_slot.yml').read_text())
    reset_template = reset_tasks[0]['ansible.builtin.command']['stdin']
    binding = "{{ hostvars['database'].postgres_replica_primary_identity.stdout | trim }}"
    assert binding in reset_template and 'slot.active' in reset_template

    def psql(sql, check=True):
        return docker('exec', '-i', container, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-At',
                      stdin=sql, check=check)

    preflight = yaml.safe_load((ROOT / 'deploy/ansible/roles/postgres_replica/tasks/preserved_primary.yml').read_text())
    preflight_sql = next(t['ansible.builtin.command']['stdin'] for t in preflight
                         if t['name'] == 'Observe preserved primary recovery parameters and restricted replication identity')
    assert psql(preflight_sql, check=False).returncode != 0, 'missing replication role accepted'
    psql('CREATE ROLE ultra_replication LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT')
    assert psql(preflight_sql).returncode == 0
    psql('ALTER ROLE ultra_replication SUPERUSER')
    assert psql(preflight_sql, check=False).returncode != 0, 'privileged replication role accepted'
    psql('ALTER ROLE ultra_replication NOSUPERUSER')
    identifier = psql('SELECT system_identifier FROM pg_control_system()').stdout.strip()
    reset = reset_template.replace(binding, identifier)
    assert psql(reset_template.replace(binding, '0'), check=False).returncode != 0
    assert 'ULTRA_REPLICA_LOST_SLOT_RESET' not in psql(reset).stderr
    # A lost physical slot is recreated, while table data remains intact.
    psql("SELECT pg_drop_replication_slot('ultra_bridge'); SELECT pg_create_physical_replication_slot('ultra_bridge', true);")
    psql("CREATE TABLE fixture_wal AS SELECT g, repeat(md5(g::text), 1024) data FROM generate_series(1,2048) g; SELECT pg_switch_wal(); CHECKPOINT;")
    assert psql("SELECT wal_status FROM pg_replication_slots WHERE slot_name='ultra_bridge'").stdout.strip() == 'lost'
    assert 'ULTRA_REPLICA_LOST_SLOT_RESET' in psql(reset).stderr
    assert 'ULTRA_REPLICA_LOST_SLOT_RESET' not in psql(reset).stderr
    assert psql('SELECT count(*) FROM fixture_wal').stdout.strip() == '2048'
    # Neither missing slots nor a logical slot with the managed name is adopted.
    psql("SELECT pg_drop_replication_slot('ultra_bridge')")
    assert psql(reset, check=False).returncode != 0
    psql("SELECT pg_create_logical_replication_slot('ultra_bridge','test_decoding')")
    assert psql(reset, check=False).returncode != 0
    assert psql("SELECT slot_type FROM pg_replication_slots WHERE slot_name='ultra_bridge'").stdout.strip() == 'logical'
    psql("SELECT pg_drop_replication_slot('ultra_bridge')")
    assert psql("SELECT pg_create_physical_replication_slot('ultra_bridge', false, true);\n" + reset,
                check=False).returncode != 0, 'temporary slot accepted'
    psql("SELECT pg_create_physical_replication_slot('ultra_bridge')")
    docker('exec', container, 'mkdir', '/tmp/fixture-receiver')
    receiver = subprocess.Popen(['docker', 'exec', container, 'pg_receivewal', '-U', 'postgres',
                                 '-D', '/tmp/fixture-receiver', '--slot=ultra_bridge', '--no-loop'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if psql("SELECT active FROM pg_replication_slots WHERE slot_name='ultra_bridge'").stdout.strip() == 't':
                break
            time.sleep(0.1)
        else:
            raise AssertionError('fixture WAL receiver did not activate slot')
        assert psql(reset, check=False).returncode != 0, 'active slot accepted'
        assert psql("SELECT active FROM pg_replication_slots WHERE slot_name='ultra_bridge'").stdout.strip() == 't'
    finally:
        receiver.terminate()
        receiver.wait(timeout=10)
    print('Physical slot bootstrap and narrowly scoped lost-slot recovery passed in isolated PostgreSQL 16')
finally:
    docker('rm', '--force', container, check=False)
