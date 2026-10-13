#!/usr/bin/env python3
"""Validate a staged recovery bundle in a NEW disposable PostgreSQL database."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import uuid
from recovery import private, run


def smoke(stage, spec_relative):
    stage = Path(stage)
    manifest = json.loads(private(stage / 'manifest.json').read_text())
    if manifest.get('kind') != 'backup':
        raise ValueError('staged backup required')
    name = 'ultra_recovery_smoke_' + uuid.uuid4().hex
    if not re.fullmatch(r'[a-z0-9_]+', name):
        raise ValueError('invalid disposable database')
    created = False
    try:
        run(['runuser', '-u', 'postgres', '--', 'createdb', name])
        created = True
        # pg_restore runs as root so private staging never becomes world-readable;
        # connect via the postgres OS account through a private streamed dump.
        with (stage / 'database.dump').open('rb') as dump:
            run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '-d', name], stdin=dump, timeout=120)
        run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', name, '-c',
             "SELECT count(*) FROM users; SELECT count(*) FROM exit_nodes;"], stdout=subprocess.DEVNULL)
        binary = stage / 'artifacts/usr/local/bin/ultra-relay'
        relative = Path(spec_relative)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('spec path must be relative to staged state')
        spec = stage / 'state' / relative
        # Only validate configs whose asset/certificate paths are available. This
        # check does not bind listeners, start workers, or apply SQL migrations.
        run([str(binary), '-check', '-spec', str(spec)], stdout=subprocess.DEVNULL)
    finally:
        if created:
            run(['runuser', '-u', 'postgres', '--', 'dropdb', name])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True)
    parser.add_argument('--spec-relative', default='etc/ultra-relay/spec.json')
    args = parser.parse_args()
    try:
        smoke(args.stage, args.spec_relative)
        print('Recovery SQL and relay configuration verified; live services unchanged')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('recovery smoke failed; sensitive details suppressed')
