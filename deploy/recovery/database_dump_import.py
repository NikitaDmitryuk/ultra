#!/usr/bin/env python3
"""Safely import an operator supplied custom-format PostgreSQL archive."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from import_protocol import MARKER_SQL, atomic_receipt, import_transaction, marker

MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
QUERY_TIMEOUT_SECONDS = 60
RESTORE_TIMEOUT_SECONDS = 600
IDENT = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
RECEIPT = Path("/var/lib/ultra-db-import-state/receipt.json")


def legacy_receipt_matches(expected):
    # Completed pre-protocol imports already have exact durable file evidence.
    try:
        return json.loads(RECEIPT.read_text()) == expected
    except (OSError, ValueError):
        return False


def archive_digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("archive_must_be_regular_file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive_size_out_of_bounds")
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            observed += len(chunk)
            if observed > MAX_ARCHIVE_BYTES:
                raise ValueError("archive_size_out_of_bounds")
            digest.update(chunk)
    if observed != size or Path(path).stat().st_size != size:
        raise ValueError("archive_changed_during_validation")
    return size, digest.hexdigest()


def validate_archive(plan, call, environ=None):
    if not isinstance(plan, dict) or set(plan) != {"archive", "database", "user", "sha256"}:
        raise ValueError("invalid_import_plan")
    archive = Path(plan["archive"])
    database, user = plan["database"], plan["user"]
    if not isinstance(database, str) or not isinstance(user, str) or not IDENT.fullmatch(database) or not IDENT.fullmatch(user):
        raise ValueError("invalid_database_identity")
    size, digest = archive_digest(archive)
    if not isinstance(plan["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", plan["sha256"]):
        raise ValueError("invalid_expected_sha256")
    if digest != plan["sha256"]:
        raise ValueError("archive_sha256_mismatch")
    env = dict(os.environ if environ is None else environ)
    env["PGCONNECT_TIMEOUT"] = "5"
    call(["pg_restore", "--list", str(archive)], check=True, stdout=subprocess.DEVNULL,
         stderr=subprocess.DEVNULL, env=env, timeout=QUERY_TIMEOUT_SECONDS)
    return archive, database, user, size, digest, env


def detect_cluster_state(call):
    """Return absent/online/unavailable without starting or changing PostgreSQL."""
    lsclusters = shutil.which("pg_lsclusters")
    if lsclusters:
        result = call([lsclusters, "--no-header"], check=True,
                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                      text=True, timeout=QUERY_TIMEOUT_SECONDS,
                      env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
        if any(len(row) >= 4 and row[3] == "online" for row in rows):
            return "online"
        if rows:
            return "unavailable"
    data_dirs = list(Path("/var/lib/postgresql").glob("*/*/PG_VERSION"))
    configs = list(Path("/etc/postgresql").glob("*/*/postgresql.conf"))
    if data_dirs or configs:
        return "unavailable"
    return "absent"


def preflight(plan, call=subprocess.run, cluster_state=None):
    """Validate archive and inspect an existing target read-only as local postgres."""
    archive, database, user, size, digest, env = validate_archive(plan, call)
    cluster_state = detect_cluster_state(call) if cluster_state is None else cluster_state
    if cluster_state == "absent":
        return {"size": size, "sha256": digest, "fresh_database_target": True}
    if cluster_state != "online" or not shutil.which("psql") or not shutil.which("runuser"):
        raise ValueError("postgresql_state_unavailable")
    peer_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PGCONNECT_TIMEOUT": "5"}

    def peer_psql(dbname, sql):
        return call(["runuser", "-u", "postgres", "--", "psql", "--no-psqlrc",
                     "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
                     "--dbname", dbname, "--command", sql], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    env=peer_env, timeout=QUERY_TIMEOUT_SECONDS)

    exists = peer_psql("postgres", "SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname='" + database + "') THEN 1 ELSE 0 END").stdout.strip()
    if exists == "0":
        return {"size": size, "sha256": digest, "fresh_database_target": True}
    if exists != "1":
        raise ValueError("invalid_database_presence_response")
    identity = peer_psql(database, "SELECT system_identifier::text || ':' || (SELECT oid::text FROM pg_database WHERE datname=current_database()) FROM pg_control_system()").stdout.strip()
    if not re.fullmatch(r"[0-9]+:[0-9]+", identity):
        raise ValueError("invalid_database_identity_response")
    empty = peer_psql(database, "SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')=0 AND (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public') AND nspname NOT LIKE 'pg_toast%')=0 THEN 0 ELSE 1 END").stdout.strip()
    if empty == "0":
        return {"size": size, "sha256": digest, "fresh_database_target": True}
    if empty != "1":
        raise ValueError("invalid_database_empty_response")
    receipt = {"sha256": digest, "database": database, "user": user,
               "system_identifier": identity.split(":", 1)[0],
               "database_oid": identity.split(":", 1)[1]}
    if peer_psql(database, MARKER_SQL).stdout.strip() != marker(receipt) and not legacy_receipt_matches(receipt):
        raise ValueError("target_database_not_empty")
    return {"size": size, "sha256": digest, "fresh_database_target": False}


def run(plan, environ=None, call=subprocess.run):
    env = dict(os.environ if environ is None else environ)
    archive, database, user, size, digest, env = validate_archive(plan, call, env)
    env["PGCONNECT_TIMEOUT"] = "5"
    identity = call(["psql", "--no-psqlrc", "--no-password", "--host", "127.0.0.1",
                 "--username", user, "--dbname", database, "--tuples-only", "--no-align",
                 "--set", "ON_ERROR_STOP=1", "--command",
                 "SELECT system_identifier::text || ':' || (SELECT oid::text FROM pg_database WHERE datname=current_database()) FROM pg_control_system()"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, env=env, timeout=QUERY_TIMEOUT_SECONDS)
    database_identity = identity.stdout.strip()
    if not re.fullmatch(r"[0-9]+:[0-9]+", database_identity):
        raise ValueError("invalid_database_identity_response")
    receipt = {"sha256": digest, "database": database, "user": user,
               "system_identifier": database_identity.split(":", 1)[0],
               "database_oid": database_identity.split(":", 1)[1]}
    probe = call(["psql", "--no-psqlrc", "--no-password", "--host", "127.0.0.1",
                 "--username", user, "--dbname", database, "--tuples-only", "--no-align",
                 "--set", "ON_ERROR_STOP=1", "--command",
                 "SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')=0 AND (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public') AND nspname NOT LIKE 'pg_toast%')=0 THEN 0 ELSE 1 END"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, env=env, timeout=QUERY_TIMEOUT_SECONDS)
    psql = ["psql", "--no-psqlrc", "--no-password", "--host", "127.0.0.1",
            "--username", user, "--dbname", database, "--set", "ON_ERROR_STOP=1"]
    observed_marker = call(psql + ["--tuples-only", "--no-align", "--command", MARKER_SQL],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, env=env, timeout=QUERY_TIMEOUT_SECONDS).stdout.strip()
    if probe.stdout.strip() != "0":
        if observed_marker != marker(receipt) and not legacy_receipt_matches(receipt):
            raise ValueError("target_database_not_empty")
        atomic_receipt(RECEIPT, receipt)
        return {"size": size, "sha256": digest, "already_imported": True}
    if observed_marker:
        raise ValueError("target_database_comment_conflict")
    import_transaction(archive, database, receipt, psql, call=call, env=env)
    atomic_receipt(RECEIPT, receipt)
    return {"size": size, "sha256": digest, "already_imported": False}


def main():
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--check", action="store_true")
        args = parser.parse_args()
        plan = json.load(sys.stdin)
        result = preflight(plan) if args.check else run(plan)
        # Only fixed metadata is emitted; no credentials or archive contents.
        print(json.dumps(result, sort_keys=True))
        return 0
    except subprocess.TimeoutExpired:
        print(json.dumps({"error": "database_import_timeout"}), file=sys.stderr)
        return 1
    except Exception as exc:
        # Exception text can contain paths, SQL, or tool output; emit stable code only.
        code = str(exc) if isinstance(exc, ValueError) else "database_import_failed"
        print(json.dumps({"error": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
