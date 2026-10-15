#!/usr/bin/env python3
"""Bounded, encrypted recovery bundles. Commands never print configuration values."""
import argparse
import datetime
import fcntl
import grp
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 20000
NAME = re.compile(r'(?:backup-[0-9]{10}-[a-f0-9]{32}|artifact-[a-f0-9]{64})\.age$')
SOURCE = re.compile(r'[a-zA-Z0-9_-]{1,64}$')
EXCLUDED = {'runtime.db', 'runtime.db.lock'}
EXCLUDED_FILES = {
    Path('/var/lib/ultra-bot/subscriptions.json'),
    Path('/var/lib/ultra-relay/recovery-status.json'),
    Path('/var/lib/ultra-relay/recovery-reconcile-status.json'),
}
EXCLUDED_DIRECTORIES = {Path('/var/lib/ultra-relay/releases'), Path('/var/lib/ultra-relay/candidates')}
# Manual deployment keeps its subscription probe in retryable operation inputs
# until the cutover completes. Those inputs are selected state, but the URL is
# an ephemeral credential and must not be copied into recovery bundles.
EPHEMERAL_PROBE_FILE = 'subscription-probe-url'
PROBE_INPUT_FILES = {'request.json', 'variables.json', 'vars.yml', 'variables.yml'}
PROBE_VARIABLE_NAME = b'ultra_cutover_subscription_url'
PROBE_VARIABLE_FIELD = re.compile(rb'(?<![A-Za-z0-9_])' + PROBE_VARIABLE_NAME + rb'(?![A-Za-z0-9_])["\']?[ \t]{0,16}:')
# Operation-pinned code and candidate rollback code must survive recovery, but
# their bytes belong in the versioned artifact rather than every database dump.
VERSIONED_STATE_PATHS = (
    (Path('/var/lib/ultra-relay/vultr'), ('*/ultra-relay',)),
    (Path('/var/lib/ultra-bot/candidates'), ('*/ultra-bot', '*/before/ultra-bot')),
)


def run(args, **kwargs):
    result = subprocess.run(args, stderr=subprocess.DEVNULL, timeout=kwargs.pop('timeout', 60), **kwargs)
    if result.returncode:
        raise ValueError('recovery command failed')
    return result


def private(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('private regular file required')
    if path.stat().st_uid != os.geteuid():
        raise ValueError('private file owner differs from operator')
    return path


def read_config(path):
    return json.loads(private(path).read_text())


def atomic_json(path, value, group=None):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
            if group is not None:
                os.fchown(stream.fileno(), 0, group)
                os.fchmod(stream.fileno(), 0o640)
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def sync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '.' == name or str(path) != name:
        raise ValueError('unsafe archive path')
    return path


def repository(path, source, initialize=False):
    path = Path(path)
    if not SOURCE.fullmatch(source) or not path.is_absolute() or path.is_symlink():
        raise ValueError('invalid repository')
    if initialize:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        if any(path.iterdir()):
            raise ValueError('repository initialization requires empty directory')
        atomic_json(path / '.ultra-recovery-repository', {'version': 1, 'source': source})
    marker = json.loads(private(path / '.ultra-recovery-repository').read_text())
    if marker != {'version': 1, 'source': source} or path.stat().st_mode & 0o077:
        raise ValueError('repository ownership or source mismatch')
    return path


def collect(paths, excluded_paths=()):
    """Dereference only selected files; sockets/devices and active runtime DB are excluded."""
    result = {}
    excluded_paths = {Path(path) for path in excluded_paths}
    for raw in paths:
        path = Path(raw)
        if not path.is_absolute() or len(path.parts) < 3 or '..' in path.parts:
            raise ValueError('state path must be a selected application path')
        if str(path) in ('/etc/ssh', '/root/.ssh', '/var/lib', '/etc/letsencrypt'):
            raise ValueError('broad system state is not accepted')
        if not path.exists():
            raise ValueError('required state missing')
        candidates = [path] if path.is_file() else sorted(path.rglob('*'))
        for candidate in candidates:
            if contains_ephemeral_probe(candidate):
                continue
            if candidate in EXCLUDED_FILES:
                continue  # Derived cache and health receipts are recomputed after restore.
            if any(p == candidate or p in candidate.parents for p in excluded_paths):
                continue  # Explicitly versioned assets are copied only in the artifact.
            if any(p == candidate or p in candidate.parents for p in EXCLUDED_DIRECTORIES):
                continue  # Old build staging is not state; current binaries are versioned separately.
            if candidate.name in EXCLUDED or candidate.suffix == '.log' or 'cache' in candidate.parts:
                continue
            if candidate.is_dir():
                continue
            if not candidate.is_file():
                raise ValueError('special files cannot be captured')
            name = str(candidate.relative_to('/'))
            safe_name(name)
            result[name] = {'sha256': digest(candidate), 'mode': candidate.stat().st_mode & 0o777,
                            'bytes': candidate.stat().st_size}
    if len(result) > MAX_FILES or sum(row['bytes'] for row in result.values()) > MAX_BYTES:
        raise ValueError('state exceeds backup limits')
    return result


def contains_ephemeral_probe(path):
    """Exclude the staged probe URL and serialized operation inputs carrying it.

    The exact URL is never materialized or logged here; only the variable name
    is searched. Other operation files and unrelated state remain recoverable.
    """
    if path.name == EPHEMERAL_PROBE_FILE:
        return True
    if path.name not in PROBE_INPUT_FILES or not path.is_file():
        return False
    with path.open('rb') as stream:
        overlap = b''
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return False
            data = overlap + chunk
            if PROBE_VARIABLE_FIELD.search(data):
                return True
            overlap = data[-(len(PROBE_VARIABLE_NAME) + 16):]


def capture_artifact_paths(config):
    """Move only selected, exact pinned binary paths; keep metadata in state."""
    selected = [Path(path) for path in config['state_paths']]
    paths = set(config.get('artifact_paths', []))
    for path in selected:
        candidates = [path] if path.is_file() else path.rglob('*')
        for candidate in candidates:
            if not candidate.is_file() or 'cache' in candidate.parts:
                continue
            for root, patterns in VERSIONED_STATE_PATHS:
                if root not in candidate.parents:
                    continue
                relative = candidate.relative_to(root)
                if any(len(relative.parts) == len(PurePosixPath(pattern).parts)
                       and relative.match(pattern) for pattern in patterns):
                    paths.add(str(candidate))
    return sorted(paths)


def pack(destination, metadata, files):
    if len(files) > MAX_FILES or sum(Path(p).stat().st_size for p in files.values()) > MAX_BYTES:
        raise ValueError('bundle exceeds backup limits')
    manifest = dict(metadata, format=1, files={})
    with tarfile.open(destination, 'w:gz', dereference=True) as archive:
        for name, path in sorted(files.items()):
            safe_name(name)
            info = archive.gettarinfo(str(path), name)
            if not info.isfile():
                raise ValueError('only regular files allowed')
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mode &= 0o777
            manifest['files'][name] = {'sha256': digest(path), 'bytes': info.size, 'mode': info.mode}
            with open(path, 'rb') as stream:
                archive.addfile(info, stream)
        payload = json.dumps(manifest, sort_keys=True).encode()
        info = tarfile.TarInfo('manifest.json')
        info.mode, info.size = 0o600, len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return manifest


def inspect_bundle(path):
    with tarfile.open(path) as archive:
        members, total = [], 0
        for item in archive:
            total += item.size
            members.append(item)
            if len(members) > MAX_FILES + 2 or total > MAX_BYTES:
                raise ValueError('archive exceeds limits')
        seen = set()
        for item in members:
            safe_name(item.name)
            if item.name in seen or not item.isfile() or item.size < 0:
                raise ValueError('duplicate or special archive member')
            seen.add(item.name)
        if 'manifest.json' not in seen:
            raise ValueError('missing manifest')
        manifest = json.load(archive.extractfile('manifest.json'))
        if manifest.get('format') != 1 or set(manifest['files']) != seen - {'manifest.json'}:
            raise ValueError('manifest inventory mismatch')
        for name, expected in manifest['files'].items():
            info = archive.getmember(name)
            if info.size != expected['bytes'] or info.mode != expected['mode']:
                raise ValueError('manifest metadata mismatch')
            if hashlib.sha256(archive.extractfile(name).read()).hexdigest() != expected['sha256']:
                raise ValueError('manifest checksum mismatch')
        return manifest


def unpack(path, target):
    manifest = inspect_bundle(path)
    target = Path(target)
    if target.is_symlink() or (target.exists() and any(target.iterdir())):
        raise ValueError('restore requires an empty staging directory')
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tarfile.open(path) as archive:
        for name, metadata in manifest['files'].items():
            out = target / name
            out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with out.open('xb') as stream:
                shutil.copyfileobj(archive.extractfile(name), stream)
            os.chmod(out, metadata['mode'] & 0o700)  # staged secrets stay operator-only
    atomic_json(target / 'manifest.json', manifest)
    return manifest


def ssh(config, destination, command, **kwargs):
    host = destination['host']
    if not re.fullmatch(r'[A-Za-z0-9_.@:-]+', host) or host.startswith('-'):
        raise ValueError('invalid SSH destination')
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
            '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2']
    identity = destination.get('identity_file', config.get('identity_file'))
    known_hosts = destination.get('known_hosts', config.get('known_hosts'))
    if identity:
        args += ['-i', identity]
    if known_hosts:
        args += ['-o', 'UserKnownHostsFile=' + known_hosts]
    import shlex
    return run(args + [host, shlex.join(command)], **kwargs)


def deliver(config, destination, source, encrypted, snapshot):
    command = ['python3', '/opt/ultra-recovery/recovery.py', 'receive', '--repository',
               '/var/lib/ultra-recovery', '--source', source, '--name', encrypted.name,
               '--sha256', digest(encrypted), '--snapshot', str(snapshot)]
    with encrypted.open('rb') as stream:
        ssh(config, destination, command, stdin=stream, stdout=subprocess.DEVNULL)


def encrypt(bundle, output, recipient):
    if not re.fullmatch(r'age1[a-z0-9]{50,100}', recipient):
        raise ValueError('age public recipient required')
    run(['age', '-r', recipient, '-o', str(output), str(bundle)])


def verify_remote_artifact(config, destination, artifact):
    result = ssh(config, destination, ['sha256sum', '/var/lib/ultra-recovery/' + artifact.name], stdout=subprocess.PIPE)
    if result.stdout.split()[:1] != [digest(artifact).encode('ascii')]:
        raise ValueError('remote recovery artifact checksum differs')


def diagnostic_status(config, successful, snapshot, completed):
    if not config.get('diagnostic_status'):
        return
    targets = [item.get('name', item['host']) for item in config['destinations'] if item['host'] in successful]
    atomic_json('/var/lib/ultra-relay/recovery-status.json',
                {'source': config['source'], 'snapshot_at': snapshot, 'completed_at': completed,
                 'targets': targets, 'independent': bool(config.get('independent', True))},
                group=grp.getgrnam('ultra-relay').gr_gid)


def create(config):
    source = config['source']
    repo = repository(config['repository'], source)
    destinations = config['destinations']
    if not destinations or not any(item.get('required') for item in destinations):
        raise ValueError('required backup destination is missing')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', config['database']):
        raise ValueError('invalid database name')
    with open(repo / '.capture-lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix='.capture-', dir=repo) as work:
            work = Path(work)
            artifact_paths = capture_artifact_paths(config)
            before = collect(config['state_paths'], artifact_paths)
            artifacts = collect(artifact_paths)
            artifact_manifest = json.dumps(artifacts, sort_keys=True).encode()
            artifact_id = hashlib.sha256(artifact_manifest).hexdigest()
            artifact = repo / ('artifact-' + artifact_id + '.age')
            if not artifact.exists():
                bundle = work / 'artifact.tar.gz'
                packed = pack(bundle, {'kind': 'artifact', 'source': source}, {name: Path('/') / name for name in artifacts})
                if packed['files'] != artifacts or collect(artifact_paths) != artifacts:
                    raise ValueError('binary artifacts changed during capture')
                inspect_bundle(bundle)
                candidate = work / artifact.name
                encrypt(bundle, candidate, config['recipient'])
                os.replace(candidate, artifact)
                sync_directory(repo)
            snapshot = int(time.time())
            dump = work / 'database.dump'
            with dump.open('wb') as stream:
                run(['runuser', '-u', 'postgres', '--', 'pg_dump', '-Fc', '--no-owner', '--no-acl', config['database']], stdout=stream)
            if collect(config['state_paths'], artifact_paths) != before:
                raise ValueError('configuration changed during capture; retry next interval')
            bundle = work / 'backup.tar.gz'
            files = {'state/' + name: Path('/') / name for name in before}
            files['database.dump'] = dump
            pack(bundle, {'kind': 'backup', 'source': source, 'snapshot_at': snapshot,
                          'artifact': artifact.name, 'database': config['database']}, files)
            # Hash again after archive reads to avoid pairing a dump with changed keys.
            if collect(config['state_paths'], artifact_paths) != before:
                raise ValueError('configuration changed during archive')
            if capture_artifact_paths(config) != artifact_paths or collect(artifact_paths) != artifacts:
                raise ValueError('binary artifacts changed during capture')
            encrypted = work / ('backup-' + str(snapshot) + '-' + uuid.uuid4().hex + '.age')
            encrypt(bundle, encrypted, config['recipient'])
            successful, errors = [], []
            for destination in destinations:
                try:
                    verify_remote_artifact(config, destination, artifact)
                except (ValueError, subprocess.TimeoutExpired):
                    try:
                        deliver(config, destination, source, artifact, snapshot)
                    except (ValueError, subprocess.TimeoutExpired):
                        errors.append(destination)
                        continue
                try:
                    deliver(config, destination, source, encrypted, snapshot)
                    successful.append(destination['host'])
                except (ValueError, subprocess.TimeoutExpired):
                    errors.append(destination)
            if any(item.get('required') for item in errors):
                raise ValueError('required backup delivery failed')
            if time.time() - snapshot > 180:
                raise ValueError('backup exceeded freshness budget')
            completed = int(time.time())
            atomic_json(repo / 'last-success.json', {'source': source, 'snapshot_at': snapshot,
                         'completed_at': completed, 'destinations': successful,
                         'backup_name': encrypted.name, 'backup_sha256': digest(encrypted),
                         'artifact_name': artifact.name, 'artifact_sha256': digest(artifact),
                         'delivered_target_ids': [item.get('id', item.get('name', item['host'])) for item in destinations if item['host'] in successful]})
            diagnostic_status(config, successful, snapshot, completed)


def receive(args, stream):
    repo = repository(args.repository, args.source)
    if not NAME.fullmatch(args.name) or not re.fullmatch(r'[a-f0-9]{64}', args.sha256):
        raise ValueError('invalid backup identity')
    if args.snapshot > time.time() + 30 or args.snapshot < 0:
        raise ValueError('invalid snapshot timestamp')
    if shutil.disk_usage(repo).free < MAX_BYTES + 1024 * 1024 * 1024:
        raise ValueError('receiver disk reserve reached')
    fd, temp = tempfile.mkstemp(prefix='.incoming-', dir=repo)
    try:
        total, h = 0, hashlib.sha256()
        with os.fdopen(fd, 'wb') as output:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError('encrypted backup exceeds bounds')
                h.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if h.hexdigest() != args.sha256 or total == 0:
            raise ValueError('incomplete backup transfer')
        target = repo / args.name
        if target.exists():
            if digest(target) != args.sha256:
                raise ValueError('immutable backup name collision')
        else:
            os.replace(temp, target)
        sync_directory(repo)
        if args.name.startswith('backup-'):
            status = repo / 'last-success.json'
            previous = json.loads(status.read_text()) if status.exists() else {}
            if args.snapshot >= previous.get('snapshot_at', 0):
                atomic_json(status, {'snapshot_at': args.snapshot, 'received_at': int(time.time()), 'name': args.name})
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def retention(names, now):
    """Keep all last-hour snapshots, one per hour for 24h, one per day for 14d."""
    keep, hours, days = set(), set(), set()
    valid = sorted((name for name in names if NAME.fullmatch(name) and name.startswith('backup-')), reverse=True)
    for name in valid:
        stamp = int(name.split('-')[1])
        age = now - stamp
        hour, day = stamp // 3600, stamp // 86400
        if age < 3600 or (age < 86400 and hour not in hours) or (age < 14 * 86400 and day not in days):
            keep.add(name)
        hours.add(hour)
        days.add(day)
    if valid:
        keep.add(valid[0])  # Never delete the last successful generation, even when stale.
    return keep


def restore(args):
    private(args.identity)
    target = Path(args.target)
    if not target.is_absolute() or target == Path('/') or target.is_symlink() or (target.exists() and any(target.iterdir())):
        raise ValueError('restore requires a new absolute staging directory')
    with tempfile.TemporaryDirectory(prefix='ultra-verify-') as tmp:
        plain = Path(tmp) / 'bundle.tar.gz'
        run(['age', '-d', '-i', args.identity, '-o', str(plain), args.bundle])
        manifest = inspect_bundle(plain)
        if manifest.get('kind') != 'backup' or not SOURCE.fullmatch(manifest.get('source', '')):
            raise ValueError('not a bridge backup')
        artifact_name = manifest['artifact']
        if not NAME.fullmatch(artifact_name) or not artifact_name.startswith('artifact-'):
            raise ValueError('invalid artifact reference')
        artifact = Path(args.bundle).parent / artifact_name
        artifact_plain = Path(tmp) / 'artifact.tar.gz'
        run(['age', '-d', '-i', args.identity, '-o', str(artifact_plain), str(artifact)])
        artifact_manifest = inspect_bundle(artifact_plain)
        if artifact_manifest.get('kind') != 'artifact' or artifact_manifest.get('source') != manifest['source']:
            raise ValueError('wrong recovery artifact source')
        artifact_id = hashlib.sha256(json.dumps(artifact_manifest['files'], sort_keys=True).encode()).hexdigest()
        if artifact_name != 'artifact-' + artifact_id + '.age':
            raise ValueError('artifact version checksum differs')
        if args.command == 'verify':
            if getattr(args, 'test_stage', False):
                # Disposable off-host rehearsal, never an activation or promotion.
                unpack(plain, target)
                unpack(artifact_plain, target / 'artifacts')
            return manifest
        if not args.fence_file:
            raise ValueError('operator fencing attestation required')
        fence = json.loads(private(args.fence_file).read_text())
        age = time.time() - fence.get('confirmed_at', 0)
        if fence.get('source') != manifest['source'] or fence.get('confirmed_offline') is not True or not 0 <= age <= 3600:
            raise ValueError('fencing attestation missing, stale or wrong source')
        unpack(plain, target)
        unpack(artifact_plain, target / 'artifacts')
        return manifest


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--repository', required=True); init.add_argument('--source', required=True)
    capture = sub.add_parser('capture'); capture.add_argument('--config', required=True)
    recv = sub.add_parser('receive')
    recv.add_argument('--repository', required=True); recv.add_argument('--source', required=True)
    recv.add_argument('--name', required=True); recv.add_argument('--sha256', required=True); recv.add_argument('--snapshot', type=int, required=True)
    prune = sub.add_parser('prune'); prune.add_argument('--repository', required=True); prune.add_argument('--source', required=True)
    for command in ('verify', 'restore'):
        cmd = sub.add_parser(command)
        cmd.add_argument('--bundle', required=True); cmd.add_argument('--identity', required=True)
        cmd.add_argument('--target', default='/var/tmp/ultra-restore-staging'); cmd.add_argument('--fence-file')
        if command == 'verify':
            cmd.add_argument('--test-stage', action='store_true', help='write private disposable rehearsal files without activating services')
    args = parser.parse_args()
    if args.command == 'init': repository(args.repository, args.source, True)
    elif args.command == 'capture': create(read_config(args.config))
    elif args.command == 'receive': receive(args, sys.stdin.buffer)
    elif args.command == 'prune':
        repo = repository(args.repository, args.source)
        keep = retention([p.name for p in repo.iterdir()], time.time())
        for path in repo.glob('backup-*.age'):
            if NAME.fullmatch(path.name) and path.name not in keep: path.unlink()
    else:
        result = restore(args)
        print(json.dumps({'verified': True, 'snapshot_at': result['snapshot_at'], 'staged': args.command == 'restore' or getattr(args, 'test_stage', False)}))

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        print('recovery operation failed; details suppressed to protect credentials', file=sys.stderr)
        sys.exit(1)
