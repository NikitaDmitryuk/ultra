"""Atomic, database-bound evidence for one-time imports into empty databases.

The database owner can COMMENT ON DATABASE; no application schema is reserved.
The comment and restored contents commit in one transaction. Filesystem receipts
are only caches and may be reconstructed from this exact database evidence.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

IDENTITY_SQL = "SELECT system_identifier::text || ':' || (SELECT oid::text FROM pg_database WHERE datname=current_database()) FROM pg_control_system()"
MARKER_SQL = "SELECT coalesce(shobj_description(oid, 'pg_database'), '') FROM pg_database WHERE datname=current_database()"
EMPTY_SQL = "SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')=0 AND (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public') AND nspname NOT LIKE 'pg_toast%')=0 THEN 0 ELSE 1 END"


def literal(value):
    return "E'" + str(value).replace('\\', '\\\\').replace("'", "''") + "'"


def marker(evidence):
    return 'ultra-import-v1:' + json.dumps(evidence, sort_keys=True, separators=(',', ':'))


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_receipt(path, evidence):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(evidence, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def import_transaction(archive, database, evidence, psql, *, call=subprocess.run,
                       env=None, role=None, schema_bounds=None):
    """Generate SQL fully before dispatch, then commit contents and evidence once.

    pg_restore has no --create/--clean/--single-transaction here: SQL output stays
    on the selected connection and psql owns the sole transaction boundary.
    A generation failure cannot leave a partial SQL stream committed.
    """
    identity = evidence.get('database_identity') or evidence
    expected_identity = identity['system_identifier'] + ':' + identity['database_oid']
    guard = ("DO $ultra_import_guard$ BEGIN IF (" + IDENTITY_SQL + ") <> " + literal(expected_identity)
             + " OR (" + MARKER_SQL + ") <> '' OR (" + EMPTY_SQL
             + ") <> 0 THEN RAISE EXCEPTION 'import_target_changed'; END IF; END $ultra_import_guard$;\n")
    with tempfile.TemporaryFile(mode='w+b') as sql_file:
        sql_file.write(guard.encode())
        if role:
            sql_file.write(('SET ROLE "' + role + '";\n').encode())
        sql_file.flush()
        with Path(archive).open('rb') as dump:
            call(['pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '--file=-'],
                 check=True, stdin=dump, stdout=sql_file, stderr=subprocess.DEVNULL,
                 env=env, timeout=600)
        if role:
            sql_file.write(b'\nRESET ROLE;\n')
        if schema_bounds is not None:
            low, high = schema_bounds
            sql_file.write(("\nDO $ultra_import_schema$ DECLARE v bigint; BEGIN SELECT max(version) INTO v FROM public.schema_migrations; "
                            f"IF v IS NULL OR v < {low} OR v > {high} THEN RAISE EXCEPTION 'restored_database_schema_missing'; "
                            "END IF; END $ultra_import_schema$;\n").encode())
        sql_file.write(('\nCOMMENT ON DATABASE "' + database + '" IS ' + literal(marker(evidence)) + ';\n').encode())
        sql_file.flush()
        sql_file.seek(0)
        call(psql + ['--single-transaction', '--file=-'], check=True, stdin=sql_file,
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=600)
