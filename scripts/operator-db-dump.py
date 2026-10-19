#!/usr/bin/env python3
"""Capture a pinned DB primary dump, encrypt and authenticate it on the operator PC."""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


class DumpError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DumpError(message)


def config_values(path):
    """Parse literal assignments without sourcing, interpolation or shell evaluation."""
    result = {}
    for line in path.read_text().splitlines():
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


def local_file(path, private=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid(), 'operator-owned regular file required')
    require(not info.st_mode & (0o077 if private else 0o022), 'unsafe input file permissions')


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


def interrupted(signum, frame):
    raise InterruptedError('interrupted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path,
                        help='Local age identity (overrides config and home default)')
    args = parser.parse_args(argv)
    stage = 'config preflight'
    published = None
    try:
        values = config_values(ROOT / 'install.config')
        host = str(ipaddress.ip_address(values.get('DATABASE_IP', '')))
        database = values.get('DB_NAME', '').strip() or 'ultra_db'
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', database), 'DB_NAME must be a literal database name')
        key = Path(values.get('DATABASE_SSH_KEY', '')).expanduser()
        require(key.is_absolute(), 'DATABASE_SSH_KEY must be an absolute operator path')
        stage = 'SSH identity preflight'
        local_file(key, private=True)  # Metadata only: SSH opens the key itself.
        identity = (args.identity or Path(values.get('ULTRA_OPERATOR_AGE_IDENTITY_FILE', '').strip()
                    or str(Path.home() / '.local/share/ultra/recovery/age-identity.txt'))).expanduser().absolute()
        stage = 'age identity preflight'
        local_file(identity, private=True)  # Only local age opens the private identity.
        pins = ROOT / 'dist/manual/bootstrap-known_hosts'
        stage = 'host-key pins preflight'
        local_file(pins)
        output_dir = pins.parent
        directory = output_dir.lstat()
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.geteuid()
                and not directory.st_mode & 0o022, 'unsafe output directory permissions')
        stage = 'identity'
        recipient = run(['age-keygen', '-y', str(identity)], stdout=subprocess.PIPE).stdout.decode().strip()
        require(re.fullmatch(r'age1[0-9a-z]+', recipient), 'invalid local age recipient')
        started = datetime.now(timezone.utc)
        timestamp = started.strftime('%Y-%m-%dT%H:%M:%SZ')
        destination = output_dir / ('primary-db-' + started.strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex + '.dump.age')
        with tempfile.TemporaryDirectory(prefix='.operator-db-dump-', dir=output_dir) as temporary:
            scratch = Path(temporary)
            pinned = scratch / 'known_hosts'
            pinned.write_bytes(pins.read_bytes())
            pinned.chmod(0o600)
            stage = 'host-key pin'
            matches = run(['ssh-keygen', '-F', host, '-f', str(pinned)], stdout=subprocess.PIPE).stdout
            require(matches.strip(), 'database host-key pin is missing')
            remote = shlex.join(['runuser', '-u', 'postgres', '--', 'pg_dump', '-Fc', '--no-owner', '--no-acl', '--dbname', database])
            ssh = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile=' + str(pinned), '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'UpdateHostKeys=no', '-o', 'VerifyHostKeyDNS=no', '-o', 'IdentitiesOnly=yes',
                   '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
                   '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
                   '-i', str(key), '--', 'root@' + host, remote]
            encrypted = scratch / 'dump.age'
            stage = 'pg_dump / encryption'
            with encrypted.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                with child(ssh, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE) as dump:
                    with child(['age', '-r', recipient], stdin=dump.stdout, stdout=stream) as encrypt:
                        dump.stdout.close()
                        encrypt_code = encrypt.wait()
                        dump_code = dump.wait()
                        require(dump_code == 0, 'pg_dump/SSH failed (exit %d)' % dump_code)
                        require(encrypt_code == 0, 'age encryption failed (exit %d)' % encrypt_code)
                stream.flush()
                os.fsync(stream.fileno())
            stage = 'age decrypt/authentication'
            plaintext = scratch / 'verified.dump'
            with plaintext.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                # Consume the entire ciphertext before pg_restore: TOC listing alone
                # may stop early and cannot authenticate the complete age stream.
                run(['age', '-d', '-i', str(identity), str(encrypted)], stdout=stream)
            stage = 'pg_restore --list'
            run(['pg_restore', '--list', str(plaintext)], stdout=subprocess.DEVNULL)
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
