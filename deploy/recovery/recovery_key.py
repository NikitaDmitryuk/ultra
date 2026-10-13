#!/usr/bin/env python3
"""Operator-local age key lifecycle; never installs an identity on a server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

from recovery import atomic_json, private, restore


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode:
        raise ValueError('age_operation_failed')
    return result.stdout


def recipient(identity):
    value = command(['age-keygen', '-y', str(private(identity))]).decode().strip()
    if not __import__('re').fullmatch(r'age1[a-z0-9]{50,100}', value):
        raise ValueError('invalid_age_recipient')
    return value


def initialize(identity, recipient_output):
    identity, recipient_output = Path(identity), Path(recipient_output)
    if not identity.is_absolute() or not recipient_output.is_absolute() or identity == recipient_output:
        raise ValueError('distinct_absolute_key_paths_required')
    for path in (identity, recipient_output):
        if path.is_symlink():
            raise ValueError('key_output_symlink')
        if not path.parent.is_dir() or path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise ValueError('private_existing_key_directory_required')
    # Retry-safe: reuse a valid identity and finish a missing public recipient.
    # Never rotate an existing key, including after an interrupted first run.
    if not identity.exists():
        command(['age-keygen', '-o', str(identity)])
        identity.chmod(0o600)
    public = recipient(identity)
    if recipient_output.exists():
        if private(recipient_output).read_text().strip() != public:
            raise ValueError('existing_recipient_does_not_match')
        return {'initialized': True, 'recipient': public, 'extracted_copy_verified': False}
    fd = os.open(recipient_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(public + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    return {'initialized': True, 'recipient': public, 'extracted_copy_verified': False}


def verify_copy(bundle, identity, extracted_identity, receipt):
    original, extracted = private(identity), private(extracted_identity)
    if os.path.samefile(original, extracted):
        raise ValueError('independently_extracted_identity_required')
    public = recipient(original)
    if recipient(extracted) != public:
        raise ValueError('extracted_identity_does_not_match')
    # Decrypt both archives with the extracted copy, never with the original.
    with tempfile.TemporaryDirectory(prefix='ultra-key-verification-') as directory:
        manifest = restore(SimpleNamespace(command='verify', bundle=str(bundle), identity=str(extracted),
                                           target=str(Path(directory) / 'unused'), test_stage=False))
    value = {'extracted_copy_verified': True, 'independent_storage_verified': False, 'recipient': public,
             'bundle_sha256': hashlib.sha256(Path(bundle).read_bytes()).hexdigest(),
             'snapshot_at': manifest['snapshot_at']}
    destination = Path(receipt)
    if not destination.is_absolute() or destination.is_symlink() or destination.parent.stat().st_mode & 0o077:
        raise ValueError('private_receipt_directory_required')
    atomic_json(destination, value)
    return value


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init')
    init.add_argument('--identity', required=True)
    init.add_argument('--recipient-output', required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('--bundle', required=True)
    verify.add_argument('--identity', required=True)
    verify.add_argument('--extracted-identity', required=True)
    verify.add_argument('--receipt', required=True)
    args = parser.parse_args(argv)
    if args.action == 'init':
        result = initialize(args.identity, args.recipient_output)
    else:
        result = verify_copy(args.bundle, args.identity, args.extracted_identity, args.receipt)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('recovery_key_failed; private details suppressed')
