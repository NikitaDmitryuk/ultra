#!/usr/bin/env python3
"""Dump and restore an isolated test schema while five real VPN clients run."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import urlparse
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    args = parser.parse_args()
    dsn = urlparse(os.environ.get('DATABASE_URL', ''))
    database = dsn.path.lstrip('/')
    if dsn.hostname not in ('localhost', '127.0.0.1') or database not in ('ultra_test', 'ultra_ci'):
        raise ValueError('explicit isolated loopback test database required')
    inspection = json.loads(subprocess.check_output(['docker', 'inspect', args.container]))[0]
    ports = inspection['NetworkSettings']['Ports'].get('5432/tcp') or []
    if not any(int(p['HostPort']) == (dsn.port or 5432) for p in ports):
        raise ValueError('container does not match allocated test database port')
    user = dsn.username or 'postgres'
    base = ['docker', 'exec', args.container]
    def sql(db, query):
        return subprocess.check_output(base + ['psql', '-U', user, '-d', db, '-At', '-v', 'ON_ERROR_STOP=1', '-c', query], stderr=subprocess.DEVNULL).decode().strip()
    before = set(sql(database, "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'ultra_combined_%'").splitlines())
    restored = 'ultra_restore_' + uuid.uuid4().hex
    created = False
    with tempfile.TemporaryDirectory(prefix='ultra-load-restore-') as directory:
        log = Path(directory) / 'load.log'
        with log.open('wb') as output:
            process = subprocess.Popen(['go', 'test', './cmd/ultra-relay', '-run', '^TestFiveClientsDuringDurableShippingArtifactCopyAndFailover$', '-count=1', '-timeout=90s'], stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                schema = None
                while time.monotonic() < deadline and process.poll() is None:
                    candidates = set(sql(database, "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'ultra_combined_%'").splitlines()) - before
                    if len(candidates) == 1:
                        candidate = candidates.pop()
                        # Wait for all clients and confirmed traffic, not just schema creation.
                        try:
                            if int(sql(database, f'SELECT count(DISTINCT account_id) FROM "{candidate}".account_exit_usage')) == 5:
                                schema = candidate
                                break
                        except subprocess.CalledProcessError:
                            pass
                    time.sleep(0.1)
                if schema is None:
                    raise ValueError('five active accounting clients not observed')
                with (Path(directory) / 'dump').open('wb') as dump:
                    subprocess.run(base + ['pg_dump', '-U', user, '-d', database, '-n', schema, '-Fc', '--no-owner', '--no-acl'], stdout=dump, stderr=subprocess.DEVNULL, check=True, timeout=20)
                if process.poll() is not None:
                    raise ValueError('dump did not overlap live clients')
                subprocess.run(base + ['createdb', '-U', user, restored], check=True, stderr=subprocess.DEVNULL)
                created = True
                with (Path(directory) / 'dump').open('rb') as dump:
                    subprocess.run(['docker', 'exec', '-i', args.container, 'pg_restore', '-U', user, '-d', restored, '--exit-on-error', '--no-owner', '--no-acl'], stdin=dump, check=True, stderr=subprocess.DEVNULL, timeout=20)
                counts = sql(restored, f'SELECT count(DISTINCT account_id),sum(uplink_bytes+downlink_bytes),max(charged_bytes) FROM "{schema}".account_exit_usage').split('|')
                if counts[0] != '5' or int(counts[1]) <= 0 or int(counts[2]) <= 0:
                    raise ValueError('restored accounting incomplete')
                if sql(restored, f'SELECT max(version) FROM "{schema}".schema_migrations') != '23':
                    raise ValueError('restored schema version invalid')
                if process.wait(timeout=90) != 0:
                    raise ValueError('VPN load/failover failed')
                print('PASS: pg_dump during five TCP/UDP clients; isolated restore schema23, five owners and confirmed traffic; failover and final accounting passed')
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                if created:
                    subprocess.run(base + ['dropdb', '-U', user, restored], check=True, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
