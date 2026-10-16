#!/usr/bin/env python3
"""Exercise the role's real rendered SQL against an isolated PostgreSQL 16.

Run with the pinned Ansible Python; requires the cached postgres:16 Docker image.
No production configuration is read and the container has no network interface.
"""
import importlib.util
from pathlib import Path
import subprocess
import time
import uuid

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

ROOT = Path(__file__).resolve().parents[1]
loader = DataLoader()
tasks = loader.load_from_file(str(ROOT / 'deploy/ansible/roles/postgres/tasks/main.yml'))
provision = next(t for t in tasks if t['name'].startswith('Provision missing'))
spec = importlib.util.spec_from_file_location('controller', ROOT / 'deploy/ansible/controller.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
container = 'ultra-pg-credential-' + uuid.uuid4().hex[:12]


def docker(*args, stdin=None, check=True):
    return subprocess.run(['docker', *args], input=stdin, text=True, capture_output=True, check=check)


def sql(statement):
    return docker('exec', '-i', container, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-At',
                  stdin=statement).stdout.strip()


def render(task, values):
    return Templar(loader=loader, variables=loader.load(controller.unsafe_yaml(values))).template(
        trust_as_template(task['ansible.builtin.command']['stdin']))


def login(password):
    return docker('exec', '-e', 'PGPASSWORD=' + password, container, 'psql', '--no-password',
                  '-h', '127.0.0.1', '-U', 'ultra_fixture', '-d', 'ultra_fixture', '-Atc', 'SELECT 1',
                  check=False).returncode == 0


try:
    docker('run', '--detach', '--rm', '--network', 'none', '--name', container,
           '-e', 'POSTGRES_PASSWORD=fixture-superuser',
           '-e', 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256', 'postgres:16')
    for _ in range(60):
        if docker('exec', container, 'psql', '-U', 'postgres', '-Atc', 'SELECT 1', check=False).returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise AssertionError('fixture PostgreSQL did not start')
    # Exercise creation on a cluster whose default differs from our required verifier.
    sql("SET password_encryption='scram-sha-256'; CREATE ROLE ultra_fixture LOGIN PASSWORD 'prior-attempt'; CREATE DATABASE ultra_fixture OWNER ultra_fixture;")
    sql("ALTER SYSTEM SET password_encryption='md5'; SELECT pg_reload_conf();")
    assert sql('SHOW password_encryption') == 'md5', 'fixture did not switch its default to MD5'
    password = "saved'credential\\with-special-characters"
    values = {'ultra_postgres': {'name': 'ultra_fixture', 'user': 'ultra_fixture', 'password': password}}
    old_verifier = sql("SELECT rolpassword FROM pg_authid WHERE rolname='ultra_fixture'")
    sql(render(provision, values))
    assert not login(password), 'provisioning unexpectedly changed an existing credential'
    assert login('prior-attempt'), 'existing database credential was not preserved'
    assert sql("SELECT rolpassword FROM pg_authid WHERE rolname='ultra_fixture'") == old_verifier
    # A fresh role is created as SCRAM despite the cluster-wide MD5 default.
    sql('DROP DATABASE ultra_fixture; DROP ROLE ultra_fixture;')
    sql(render(provision, values))
    assert login(password), 'new role did not use the saved credential'
    verifier = sql("SELECT rolpassword FROM pg_authid WHERE rolname='ultra_fixture'")
    assert verifier.startswith('SCRAM-SHA-256$'), 'saved credential is not SCRAM'
    # Repeated provisioning does not rotate an already-working credential.
    sql(render(provision, values))
    assert login(password)
    assert sql("SELECT rolpassword FROM pg_authid WHERE rolname='ultra_fixture'") == verifier
    print('PostgreSQL SCRAM provisioning, existing credential preservation and idempotency passed')
finally:
    docker('rm', '--force', container, check=False)
