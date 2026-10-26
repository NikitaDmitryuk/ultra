#!/usr/bin/env python3
"""Capture a pinned DB primary dump, encrypt and authenticate it on the operator PC."""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy' / 'recovery'))
from ssh_policy import ssh_options

SSH_PROBE_OPTIONS = ssh_options('probe')
MAX_PROTECTED_FILE_BYTES = 1024 * 1024

def operator_uid():
    return os.geteuid()


class DumpError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DumpError(message)


def config_values(path):
    """Parse literal assignments without sourcing, interpolation or shell evaluation."""
    result = {}
    content = read_protected(path).decode()
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        require('=' in line, 'invalid config assignment')
        key, value = line.split('=', 1)
        key = key.strip()
        tokens = shlex.split(value, comments=True)
        require(re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in result and len(tokens) <= 1,
                'invalid or duplicate config assignment')
        result[key] = tokens[0] if tokens else ''
    return result


def local_file(path):
    """Open an effective-user-owned protected file without following a final symlink."""
    require(path.is_absolute(), 'absolute input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == operator_uid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe protected input file')
    finally:
        os.close(fd)


def protected_directory(path):
    require(path.is_absolute(), 'absolute output directory required')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == operator_uid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe protected output directory')
    finally:
        os.close(fd)


def read_protected(path):
    require(path.is_absolute(), 'absolute input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == operator_uid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe protected input file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            content = stream.read(MAX_PROTECTED_FILE_BYTES + 1)
            require(len(content) <= MAX_PROTECTED_FILE_BYTES, 'protected input file too large')
            return content
    finally:
        os.close(fd)


def run(argv, **kwargs):
    result = subprocess.run(argv, stderr=subprocess.DEVNULL, **kwargs)
    require(result.returncode == 0, 'command failed (exit %d)' % result.returncode)
    return result


@contextlib.contextmanager
def child(argv, **kwargs):
    process = subprocess.Popen(argv, stderr=subprocess.DEVNULL, **kwargs)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdout is not None:
            process.stdout.close()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def interrupted(signum, frame):
    raise InterruptedError('interrupted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path, help='absolute protected operator config')
    parser.add_argument('--identity', required=True, type=Path, help='absolute protected age identity')
    parser.add_argument('--output-dir', required=True, type=Path, help='absolute protected output directory')
    args = parser.parse_args(argv)
    stage = 'config preflight'
    published = None
    try:
        require(all(p.is_absolute() for p in (args.config, args.identity, args.output_dir)),
                'explicit absolute paths required')
        values = config_values(args.config)
        host = str(ipaddress.ip_address(values.get('DATABASE_IP', '')))
        bridge = str(ipaddress.ip_address(values.get('BRIDGE_IP', '')))
        database = values.get('DB_NAME', '').strip() or 'ultra_db'
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', database), 'DB_NAME must be a literal database name')
        key = Path(values.get('DATABASE_SSH_KEY', ''))
        require(key.is_absolute(), 'DATABASE_SSH_KEY must be an absolute operator path')
        bridge_key = Path(values.get('BRIDGE_SSH_KEY', ''))
        require(bridge_key.is_absolute(), 'BRIDGE_SSH_KEY must be an absolute operator path')
        stage = 'SSH identity preflight'
        local_file(key)  # Metadata only: SSH opens the key itself.
        local_file(bridge_key)
        identity = args.identity
        stage = 'age identity preflight'
        local_file(identity)  # Only local age opens the private identity.
        pins = args.output_dir / 'bootstrap-known_hosts'
        stage = 'host-key pins preflight'
        pins_raw = read_protected(pins)
        output_dir = args.output_dir
        protected_directory(output_dir)
        stage = 'identity'
        recipient = run(['age-keygen', '-y', str(identity)], stdout=subprocess.PIPE).stdout.decode().strip()
        require(re.fullmatch(r'age1[0-9a-z]+', recipient), 'invalid local age recipient')
        started = datetime.now(timezone.utc)
        timestamp = started.strftime('%Y-%m-%dT%H:%M:%SZ')
        destination = output_dir / ('primary-db-' + started.strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex + '.backup.tar.age')
        with tempfile.TemporaryDirectory(prefix='.operator-db-dump-', dir=output_dir) as temporary:
            scratch = Path(temporary)
            pinned = scratch / 'known_hosts'
            pinned.write_bytes(pins_raw)
            pinned.chmod(0o600)
            stage = 'host-key pin'
            matches = run(['ssh-keygen', '-F', host, '-f', str(pinned)], stdout=subprocess.PIPE).stdout
            require(matches.strip(), 'database host-key pin is missing')
            bridge_matches = run(['ssh-keygen', '-F', bridge, '-f', str(pinned)], stdout=subprocess.PIPE).stdout
            require(bridge_matches.strip(), 'bridge host-key pin is missing')
            remote = shlex.join(['runuser', '-u', 'postgres', '--', 'pg_dump', '-Fc', '--no-owner', '--no-acl', '--dbname', database])
            proxy = shlex.join([
                'ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', *SSH_PROBE_OPTIONS,
                '-o', 'UserKnownHostsFile=' + str(pinned),
                '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'VerifyHostKeyDNS=no', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-i', str(bridge_key),
                '-W', host + ':22', 'root@' + bridge,
            ])
            ssh = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', *SSH_PROBE_OPTIONS,
                   '-o', 'UserKnownHostsFile=' + str(pinned), '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'VerifyHostKeyDNS=no', '-o', 'IdentitiesOnly=yes',
                   '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
                   '-o', 'ProxyCommand=' + proxy, '-i', str(key), '--', 'root@' + host, remote]
            raw_dump = scratch / 'primary.dump'
            stage = 'pg_dump'
            with raw_dump.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                with child(ssh, stdin=subprocess.DEVNULL, stdout=stream) as dump:
                    code = dump.wait()
                    require(code == 0, 'pg_dump/SSH failed (exit %d)' % code)
                stream.flush()
                os.fsync(stream.fileno())
            dump_hash = sha256_file(raw_dump)
            source_hash = hashlib.sha256((host + '\0' + database).encode()).hexdigest()
            manifest = {
                'version': 1,
                'snapshot_started_utc': timestamp,
                'source_sha256': source_hash,
                'database': database,
                'dump_sha256': dump_hash,
            }
            archive = scratch / 'bundle.tar'
            with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as bundle:
                raw = json.dumps(manifest, separators=(',', ':')).encode()
                info = tarfile.TarInfo('manifest.json')
                info.size = len(raw)
                info.mode = 0o600
                info.mtime = int(started.timestamp())
                bundle.addfile(info, io.BytesIO(raw))
                bundle.add(str(raw_dump), arcname='primary.dump', recursive=False)
            encrypted = scratch / 'dump.age'
            stage = 'age encryption'
            with encrypted.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                with archive.open('rb') as bundle:
                    run(['age', '-r', recipient], stdin=bundle, stdout=stream)
                stream.flush()
                os.fsync(stream.fileno())
            stage = 'age decrypt/authentication'
            plaintext = scratch / 'verified.tar'
            with plaintext.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                # Consume the entire ciphertext before pg_restore: TOC listing alone
                # may stop early and cannot authenticate the complete age stream.
                run(['age', '-d', '-i', str(identity), str(encrypted)], stdout=stream)
            stage = 'bundle verification'
            with tarfile.open(plaintext, 'r:') as bundle:
                members = bundle.getmembers()
                require(len(members) == 2 and [m.name for m in members] == ['manifest.json', 'primary.dump'],
                        'invalid backup bundle members')
                require(all(m.isfile() and m.linkname == '' for m in members), 'unsafe backup bundle member')
                manifest_data = bundle.extractfile(members[0]).read(1024 * 1024 + 1)
                require(len(manifest_data) <= 1024 * 1024, 'backup manifest too large')
                parsed = json.loads(manifest_data)
                require(parsed == manifest, 'backup bundle manifest mismatch')
                dump_path = scratch / 'verified.dump'
                dump_digest = hashlib.sha256()
                with dump_path.open('xb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    extracted = bundle.extractfile(members[1])
                    for block in iter(lambda: extracted.read(1024 * 1024), b''):
                        dump_digest.update(block)
                        stream.write(block)
                require(dump_digest.hexdigest() == dump_hash, 'backup bundle digest mismatch')
            run(['pg_restore', '--file=/dev/null', str(dump_path)], stdout=subprocess.DEVNULL)
            dump_path.unlink()
            plaintext.unlink()
            stage = 'publication'
            digest = hashlib.sha256()
            with encrypted.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            size = encrypted.stat().st_size
            require(size > 0, 'empty encrypted dump')
            # Hard-link publication is atomic and refuses to replace any file.
            os.link(encrypted, destination)
            published = destination
            sync_directory(output_dir)
        print('path=' + str(destination.absolute()))
        print('snapshot_started_utc=' + timestamp)
        print('size_bytes=' + str(size))
        print('sha256=' + digest.hexdigest())
        print('exit_code=0')
        return 0
    except (OSError, ValueError, DumpError, KeyboardInterrupt) as error:
        if published is not None:
            published.unlink(missing_ok=True)
        detail = str(error) if isinstance(error, DumpError) else type(error).__name__
        print('ERROR stage=' + stage + ': ' + detail + '; exit_code=1', file=sys.stderr)
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    sys.exit(main())
