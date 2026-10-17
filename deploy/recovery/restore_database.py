#!/usr/bin/env python3
"""Restore a verified bundle only into the configured empty dedicated DB host."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024  # Transport, including tar/gzip overhead.
MAX_STATE_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_DUMP_BYTES = 512 * 1024 * 1024
RESTORE_ROOT = Path('/var/lib/ultra-restore')


def private_file(path, maximum):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > maximum:
        raise ValueError('private_restore_file_required')
    return path


def require_root():
    if os.geteuid() != 0:
        raise ValueError('root_target_required')


def run(argv, data=None, timeout=60, stdin=None):
    result = subprocess.run(argv, input=data, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode:
        raise ValueError('dedicated_database_restore_failed')
    return result.stdout.decode().strip()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value):
        raise ValueError('unsupported_database_identifier')
    return '"' + value + '"'


def sql(statement, database='postgres'):
    return run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1',
                '-d', database], statement.encode())


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def extract_dump(archive_path, directory, expected_stage_digest, expected_dump_digest, verify_toc=True):
    archive_path = private_file(archive_path, MAX_ARCHIVE_BYTES)
    if digest(archive_path) != expected_stage_digest:
        raise ValueError('restore_stage_digest_mismatch')
    dump_path = Path(directory) / 'database.dump'
    if dump_path.exists() or dump_path.is_symlink():
        private_file(dump_path, MAX_DUMP_BYTES)
        if digest(dump_path) != expected_dump_digest:
            raise ValueError('restore_database_dump_digest_mismatch')
        if verify_toc:
            run(['pg_restore', '--list', str(dump_path)])
        return dump_path
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers()
        state_bytes = sum(member.size for member in members if not member.name.startswith('artifacts/'))
        artifact_bytes = sum(member.size for member in members if member.name.startswith('artifacts/'))
        if len(members) > 45000 or state_bytes > MAX_STATE_BYTES or artifact_bytes > MAX_ARTIFACT_BYTES:
            raise ValueError('restore_stage_exceeds_bounds')
        selected = [member for member in members if member.name == 'database.dump']
        if len(selected) != 1 or not selected[0].isfile() or selected[0].size <= 0 or selected[0].size > MAX_DUMP_BYTES:
            raise ValueError('restore_database_dump_missing')
        source = archive.extractfile(selected[0])
        if source is None:
            raise ValueError('restore_database_dump_missing')
        descriptor = os.open(dump_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
        finally:
            source.close()
    if digest(dump_path) != expected_dump_digest:
        dump_path.unlink(missing_ok=True)
        raise ValueError('restore_database_dump_digest_mismatch')
    if verify_toc:
        listing = run(['pg_restore', '--list', str(dump_path)])
        comment = b';' if isinstance(listing, bytes) else ';'
        if not any(line.strip() and not line.lstrip().startswith(comment) for line in listing.splitlines()):
            raise ValueError('restore_database_dump_invalid')
    return dump_path


def validate_plan(directory, plan):
    if (not isinstance(plan, dict) or set(plan) != {'restore_id', 'database', 'database_host', 'stage_sha256', 'dump_sha256', 'schema_min', 'schema_max'}
            or not re.fullmatch(r'[a-f0-9]{64}', str(plan['restore_id']))
            or not re.fullmatch(r'[a-f0-9]{64}', str(plan['stage_sha256']))
            or not re.fullmatch(r'[a-f0-9]{64}', str(plan['dump_sha256']))
            or type(plan['schema_min']) is not int or type(plan['schema_max']) is not int
            or plan['schema_min'] < 0 or plan['schema_max'] < plan['schema_min']):
        raise ValueError('invalid_dedicated_database_restore_plan')
    import ipaddress
    ipaddress.IPv4Address(plan['database_host'])
    database = plan['database']
    if not isinstance(database, dict) or set(database) != {'name', 'user'}:
        raise ValueError('invalid_dedicated_database_restore_plan')
    name, user = database['name'], database['user']
    quoted_name, quoted_user = identifier(name), identifier(user)
    directory = Path(directory)
    expected_dir = RESTORE_ROOT / (plan['restore_id'] + '-database')
    if directory != expected_dir or directory.is_symlink() or not directory.is_dir():
        raise ValueError('invalid_dedicated_database_restore_directory')
    directory_info = directory.stat()
    if directory_info.st_uid != os.geteuid() or stat.S_IMODE(directory_info.st_mode) & 0o077:
        raise ValueError('private_restore_directory_required')
    private_file(directory / 'plan.json', 65536)
    stage_path = private_file(directory / 'stage.tar.gz', MAX_ARCHIVE_BYTES)
    return name, user, stage_path




def database_identity(name):
    value = sql("SELECT system_identifier::text || ':' || (SELECT oid::text FROM pg_database WHERE datname=current_database()) FROM pg_control_system()", name)
    if not re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', value):
        raise ValueError('restore_database_identity_unavailable')
    cluster, oid = value.split(':')
    return {'system_identifier': cluster, 'database_oid': oid}


def completed_restore(directory, plan, name, stage_path):
    receipt = Path(directory) / 'database-result.json'
    if not receipt.exists() and not receipt.is_symlink():
        return None
    plan_hash = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    saved = json.loads(private_file(receipt, 4096).read_text())
    if (saved.get('plan_sha256') != plan_hash or saved.get('database') != name
            or saved.get('verified') is not True or type(saved.get('schema')) is not int
            or not plan['schema_min'] <= saved['schema'] <= plan['schema_max']):
        raise ValueError('restore_database_receipt_conflict')
    if saved.get('database_identity') != database_identity(name):
        raise ValueError('restored_database_identity_changed')
    if digest(stage_path) != plan['stage_sha256']:
        raise ValueError('restore_stage_digest_mismatch')
    if sql("SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')", name) == '0':
        raise ValueError('restored_database_contents_missing')
    if sql('SELECT max(version) FROM schema_migrations', name) != str(saved['schema']):
        raise ValueError('restored_database_schema_changed')
    return {'verified': True, 'database': name, 'schema': saved['schema'], 'resumed': True}


def check(directory, plan):
    """Validate the bundle before PostgreSQL provisioning can mutate the host."""
    require_root()
    name, _, stage_path = validate_plan(directory, plan)
    completed = completed_restore(directory, plan, name, stage_path)
    if completed is not None:
        return completed
    dump = extract_dump(stage_path, directory, plan['stage_sha256'], plan['dump_sha256'], verify_toc=False)
    dump.unlink()
    if shutil.which('psql') is None:
        return {'verified': True, 'empty': True}
    # An installed but unavailable PostgreSQL is ambiguous, so never treat it as
    # a fresh server. Existing servers must be reachable and provably empty.
    try:
        databases = sql("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres')")
        if databases == '0':
            return {'verified': True, 'empty': True}
        if databases != '1':
            raise ValueError('dedicated_database_host_not_empty')
        exists = sql("SELECT count(*) FROM pg_database WHERE datname='" + name.replace("'", "''") + "'")
        if exists != '1':
            raise ValueError('dedicated_database_host_not_empty')
        tables = sql("SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')", name)
        if tables != '0':
            raise ValueError('dedicated_database_not_empty')
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('dedicated_database_preflight_failed') from error
    return {'verified': True, 'empty': True}


def restore(directory, plan):
    require_root()
    name, user, stage_path = validate_plan(directory, plan)
    directory = Path(directory)
    plan_hash = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    receipt = directory / 'database-result.json'
    lock_path = directory / 'database.lock'
    with lock_path.open('a') as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        completed = completed_restore(directory, plan, name, stage_path)
        if completed is not None:
            return completed
        if sql('SELECT current_setting(\'server_version_num\')::int/10000') != '16' or sql('SELECT pg_is_in_recovery()') != 'f':
            raise ValueError('dedicated_postgres_16_primary_required')
        if sql("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres'," +
               "'" + name.replace("'", "''") + "')") != '0':
            raise ValueError('dedicated_database_host_not_empty')
        if sql("SELECT count(*) FROM pg_roles WHERE rolname='" + user.replace("'", "''") + "'") != '1':
            raise ValueError('dedicated_database_role_missing')
        if sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='" + name.replace("'", "''") + "'") != user:
            raise ValueError('dedicated_database_owner_mismatch')
        if sql("SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')", name) != '0':
            raise ValueError('dedicated_database_not_empty')
        identity = database_identity(name)
        dump = extract_dump(stage_path, directory, plan['stage_sha256'], plan['dump_sha256'])
        # Root opens the verified private dump before runuser changes identity.
        # PostgreSQL reads the inherited descriptor without traversing staging.
        with dump.open('rb') as stream:
            run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--single-transaction',
                 '--no-owner', '--no-acl', '--role=' + user, '-d', name], timeout=600, stdin=stream)
        schema = sql('SELECT max(version) FROM schema_migrations', name)
        if not schema.isdigit() or not plan['schema_min'] <= int(schema) <= plan['schema_max']:
            raise ValueError('restored_database_schema_missing')
        if database_identity(name) != identity:
            raise ValueError('restored_database_identity_changed')
        result = {'plan_sha256': plan_hash, 'database': name, 'schema': int(schema), 'database_identity': identity, 'verified': True}
        temporary = receipt.with_suffix('.pending')
        with temporary.open('x') as stream:
            os.chmod(temporary, 0o600)
            json.dump(result, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, receipt)
        return {'verified': True, 'database': name, 'schema': int(schema)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--check', action='store_true')
    arguments = parser.parse_args()
    directory = Path(arguments.directory)
    plan = json.loads(private_file(directory / 'plan.json', 65536).read_text())
    print(json.dumps(check(directory, plan) if arguments.check else restore(directory, plan), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError):
        print(json.dumps({'verified': False, 'error': 'dedicated_database_restore_failed'}))
        raise SystemExit(2)
