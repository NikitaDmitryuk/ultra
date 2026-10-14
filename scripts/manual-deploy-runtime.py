#!/usr/bin/env python3
"""Reuse release wheels only after provenance, pins, hashes and ABI checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('runtime input must be regular')
    return path.read_bytes()


def archive_files(path):
    files = {}
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive.getmembers():
            name = member.name.removeprefix('./')
            if member.isdir():
                continue
            if not member.isfile() or name.startswith('/') or '..' in Path(name).parts or name in files or member.size > 100 * 1024 * 1024:
                raise ValueError('unsafe runtime archive')
            files[name] = archive.extractfile(member).read()
    return files


def validate_pair(directory, requirements):
    if not __debug__:
        raise ValueError('runtime validation requires assertions enabled')
    manifest = json.loads(regular(directory / 'release-manifest.json'))
    assert manifest['schema_version'] == 1 and re.fullmatch('[0-9a-f]{40}', manifest['source_commit']), 'runtime provenance invalid'
    rows = manifest['assets']
    assert len(rows) == 14 and len({row['name'] for row in rows}) == 14, 'runtime manifest incomplete'
    checksums = regular(directory / 'checksums.txt')
    checksum_rows = {}
    for line in checksums.decode().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/]+)', line)
        assert match and match[2] not in checksum_rows, 'runtime checksum row invalid'
        checksum_rows[match[2]] = match[1]
    for name in ['checksums.txt', 'ultra-ansible-runtime-linux-amd64.tar.gz', 'ultra-ansible-runtime-linux-arm64.tar.gz']:
        raw = regular(directory / name)
        row = next(row for row in rows if row['name'] == name)
        assert row['size'] == len(raw) and row['sha256'] == digest(raw), 'runtime manifest hash mismatch'
        if name != 'checksums.txt':
            assert checksum_rows[name] == digest(raw), 'runtime checksum mismatch'
    pins = requirements.read_text().splitlines()
    for architecture, wheel_arch in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
        files = archive_files(directory / ('ultra-ansible-runtime-linux-' + architecture + '.tar.gz'))
        locked = files.pop('requirements.lock').decode().splitlines()
        assert [line.split(' --hash=', 1)[0] for line in locked] == pins, 'runtime requirements pins mismatch'
        assert files and all(re.fullmatch(r'wheels/[^/]+\.whl', name) for name in files), 'runtime contents invalid'
        for name, raw in files.items():
            package, version = Path(name).name.split('-')[:2]
            pin = package.replace('_', '-').lower() + '==' + version
            matching = [line for line in locked if line.split(' --hash=', 1)[0].replace('_', '-').lower() == pin]
            assert len(matching) == 1 and ' --hash=sha256:' + digest(raw) in matching[0], 'runtime wheel hash mismatch'
            assert name.endswith('-none-any.whl') or 'manylinux' in name and wheel_arch in name, 'runtime wheel architecture mismatch'
        for line in locked:
            package, version = line.split(' --hash=', 1)[0].split('==')
            wheels = [name for name in files if Path(name).name.lower().startswith(package.replace('-', '_').lower() + '-' + version + '-')]
            assert set(re.findall(r' --hash=sha256:([0-9a-f]{64})', line)) == {digest(files[name]) for name in wheels}, 'runtime lock has missing wheels'
            for python in [312, 313, 314]:
                assert any('-none-any.whl' in name or '-cp' + str(python) + '-' in name or re.search(r'-cp(\d+)-abi3-', name) and int(re.search(r'-cp(\d+)-abi3-', name)[1]) <= python for name in wheels), 'runtime Python ABI missing'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--output', required=True)
    arguments = parser.parse_args()
    offline = os.environ.get('ULTRA_VERIFIED_RUNTIME_DIR')
    if offline:
        directory = Path(offline)
        validate_pair(directory, ROOT / 'deploy/ansible/requirements.txt')
        output = Path(arguments.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(directory / ('ultra-ansible-runtime-linux-' + arguments.architecture + '.tar.gz'), output)
    else:
        subprocess.run([sys.executable, str(ROOT / 'scripts/build-ansible-runtime.py'), '--architecture', arguments.architecture, '--output', arguments.output], check=True)


if __name__ == '__main__':
    main()
