#!/usr/bin/env python3
"""Exercise actual monitor SQL and physical streaming in isolated PostgreSQL 16.

Only creates a disposable Docker container; no installer or private config input.
Requires PyYAML and a locally available postgres:16 image.
"""
from pathlib import Path
import subprocess
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
task = yaml.safe_load((ROOT / 'deploy/ansible/roles/postgres/tasks/monitor.yml').read_text())[0]
sql = task['ansible.builtin.command']['stdin'].replace('{{ ultra_postgres.user }}', 'fixture_app')
assert '{{' not in sql
# Infrastructure objects must be installed after the empty-target import gate.
for filename in ['bootstrap.yml', 'bootstrap-postgres.yml']:
    plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks' / filename).read_text())
    primary = next(play for play in plays if play['name'] == 'Configure primary database')
    assert primary['roles'][-1]['role'] == 'database_import'
    monitor = primary['post_tasks'][-1]['ansible.builtin.include_role']
    assert monitor == {'name': 'postgres', 'tasks_from': 'monitor'}
assert 'monitor.yml' not in (ROOT / 'deploy/ansible/roles/postgres/tasks/main.yml').read_text()
restore = yaml.safe_load((ROOT / 'deploy/ansible/roles/restore_database/tasks/main.yml').read_text())
assert restore[-2]['name'] == 'Require verified database restore acknowledgement'
assert restore[-1]['ansible.builtin.include_role'] == {'name': 'postgres', 'tasks_from': 'monitor'}
container = 'ultra-pg-monitor-' + uuid.uuid4().hex[:12]


def docker(*args, stdin=None, check=True):
    result = subprocess.run(['docker', *args], input=stdin, text=True,
                            capture_output=True, check=False)
    if check and result.returncode:
        raise AssertionError(f'docker command failed ({result.returncode}): {result.stderr.strip()}')
    return result


def query(sql_text, role='postgres', port='5432', check=True, database='postgres'):
    return docker('exec', '-i', container, 'psql', '-U', role, '-p', port,
                  '-d', database, '-v', 'ON_ERROR_STOP=1', '-At', stdin=sql_text, check=check)


def state():
    return query('SELECT state FROM ultra_monitor.bridge_replication_status()', 'fixture_app').stdout.strip()


def wait_state(expected):
    for _ in range(80):
        actual = state()
        if actual == expected:
            return
        time.sleep(.25)
    raise AssertionError(f'expected {expected}, observed {actual}')


try:
    docker('run', '--detach', '--rm', '--pull=never', '--network', 'none', '--name', container,
           '-e', 'POSTGRES_PASSWORD=fixture-password', 'postgres:16')
    previous_start = None
    stable_start_checks = 0
    for _ in range(80):
        result = query('SELECT pg_postmaster_start_time()', check=False)
        start = result.stdout.strip() if result.returncode == 0 else None
        if start and start == previous_start:
            stable_start_checks += 1
            if stable_start_checks >= 12:
                break
        else:
            previous_start = start
            stable_start_checks = 0
        time.sleep(.25)
    else:
        raise AssertionError('fixture PostgreSQL did not reach a stable server process')
    query("CREATE ROLE fixture_app LOGIN; CREATE ROLE fixture_other LOGIN; "
          "CREATE ROLE ultra_replication LOGIN REPLICATION PASSWORD 'fixture-replication';")
    query(sql)
    query(sql)  # idempotent reconfigure
    assert state() == 'unknown', 'missing slot cannot claim a known standby state'
    query("SELECT pg_create_physical_replication_slot('ultra_bridge')")
    assert state() == 'disconnected'
    assert query('SELECT * FROM ultra_monitor.bridge_replication_status()', 'fixture_other', check=False).returncode != 0
    assert query('CREATE TABLE ultra_monitor.injected(n int)', 'fixture_app', check=False).returncode != 0
    assert query("SELECT rolsuper OR rolreplication OR pg_has_role(current_user, 'pg_monitor', 'MEMBER') "
                 "OR pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER') FROM pg_roles WHERE rolname=current_user",
                 'fixture_app').stdout.strip() == 'f'
    assert query("SELECT proconfig::text FROM pg_proc WHERE oid='ultra_monitor.bridge_replication_status()'::regprocedure").stdout.strip() == '{search_path=pg_catalog}'
    assert query("SELECT has_function_privilege('fixture_other', 'ultra_monitor.bridge_replication_status()', 'EXECUTE')").stdout.strip() == 'f'
    # Logical backups carry application data, never the privileged monitor owner
    # or SECURITY DEFINER definition. Recreate infra separately after restore.
    dump = docker('exec', container, 'pg_dump', '-U', 'fixture_app', '--schema-only',
                  '--no-owner', '--no-acl', '--exclude-schema=ultra_monitor', 'postgres').stdout
    assert 'ultra_monitor' not in dump
    query('CREATE DATABASE fixture_import OWNER fixture_app')
    docker('exec', '-i', container, 'psql', '-U', 'fixture_app', '-d', 'fixture_import',
           '-v', 'ON_ERROR_STOP=1', stdin=dump)
    assert docker('exec', container, 'psql', '-U', 'fixture_app', '-d', 'fixture_import', '-Atc',
                  "SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public') AND nspname NOT LIKE 'pg_toast%'").stdout.strip() == '0'
    query(sql, database='fixture_import')
    assert query("SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid='ultra_monitor.bridge_replication_status()'::regprocedure",
                 database='fixture_import').stdout.strip() == 'postgres'
    assert query('SELECT state FROM ultra_monitor.bridge_replication_status()', 'fixture_app',
                 database='fixture_import').stdout.strip() == 'disconnected'
    # Standby runs in the same disposable container, over its loopback only.
    docker('exec', '--user', 'postgres', '-e', 'PGPASSWORD=fixture-replication', container,
           'pg_basebackup', '-D', '/tmp/standby', '-d',
           'host=127.0.0.1 user=ultra_replication application_name=ultra_bridge connect_timeout=5',
           '--slot=ultra_bridge', '--wal-method=stream', '--write-recovery-conf', '--checkpoint=fast', '--no-password')
    docker('exec', '--user', 'postgres', '-e', 'PGPASSWORD=fixture-replication', container,
           'pg_ctl', '-D', '/tmp/standby', '-l', '/tmp/standby.log', '-o', '-p 5433', '-w', 'start')
    wait_state('streaming')
    assert query("SELECT pg_is_in_recovery() AND EXISTS(SELECT 1 FROM pg_stat_wal_receiver WHERE status='streaming')", port='5433').stdout.strip() == 't'
    query('SELECT pg_wal_replay_pause()', port='5433')
    query("CREATE TABLE wal_fixture AS SELECT repeat(md5(n::text), 8) value FROM generate_series(1,150000) n; CHECKPOINT;")
    wait_state('lagging')
    lag = query('SELECT replay_lag_bytes FROM ultra_monitor.bridge_replication_status()', 'fixture_app').stdout.strip()
    assert int(lag) > 16777216
    query('SELECT pg_wal_replay_resume()', port='5433')
    wait_state('streaming')
    marker = query('SELECT pg_current_wal_flush_lsn()').stdout.strip()
    for _ in range(80):
        if query(f"SELECT pg_last_wal_replay_lsn() >= '{marker}'::pg_lsn", port='5433').stdout.strip() == 't':
            break
        time.sleep(.25)
    else:
        raise AssertionError('standby did not replay durable primary WAL marker')
    docker('exec', '--user', 'postgres', container, 'pg_ctl', '-D', '/tmp/standby', '-w', 'stop')
    wait_state('disconnected')
    print('Restricted monitor: idempotence, privileges, streaming, replay, lag and disconnection passed')
finally:
    docker('rm', '--force', container, check=False)
