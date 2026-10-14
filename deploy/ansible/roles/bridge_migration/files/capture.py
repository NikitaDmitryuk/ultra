#!/usr/bin/python3
"""Validate and project already-created ciphertext; never carries the age identity."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys


def main():
    directory = Path(sys.argv[1])
    if not re.fullmatch(r'/var/tmp/ultra-migration-[a-f0-9]{64}', str(directory)) or directory.is_symlink():
        raise ValueError('private_export_directory_required')
    status = json.loads(Path('/var/lib/ultra-recovery/last-success.json').read_text())
    minimum = int((directory / 'freeze-start').read_text())
    if status.get('snapshot_at', 0) < minimum:
        raise ValueError('generation_predates_frozen_writers')
    result = {'snapshot_at': status['snapshot_at']}
    for kind in ('backup', 'artifact'):
        name, expected = status[kind + '_name'], status[kind + '_sha256']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.age', name) or not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('ciphertext_identity_invalid')
        source = Path('/var/lib/ultra-recovery') / name
        if source.is_symlink() or not source.is_file():
            raise ValueError('ciphertext_unavailable')
        value = hashlib.sha256()
        with source.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                value.update(chunk)
        if value.hexdigest() != expected:
            raise ValueError('ciphertext_checksum_mismatch')
        shutil.copyfile(source, directory / (kind + '.age'))
        (directory / (kind + '.age')).chmod(0o600)
        result[kind + '_name'] = name
        result[kind + '_sha256'] = expected
    (directory / 'capture.json').write_text(json.dumps(result))
    (directory / 'capture.json').chmod(0o600)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('migration_ciphertext_projection_failed', file=sys.stderr)
        raise SystemExit(1)
