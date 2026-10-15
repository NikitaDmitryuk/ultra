"""Credential-safe access to the dedicated PostgreSQL host through its tunnel."""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import tempfile
import urllib.parse
from contextlib import contextmanager


APP_ENVIRONMENT = Path('/etc/ultra-relay/environment')
APP_SPEC = Path('/etc/ultra-relay/spec.json')


def dsn_from_runtime(database):
    values = {}
    if APP_ENVIRONMENT.exists():
        for line in read_private_runtime_file(APP_ENVIRONMENT).splitlines():
            key, separator, value = line.partition('=')
            if separator and key.strip() == 'ULTRA_RELAY_DB_DSN':
                values[key.strip()] = value.strip().strip('"\'')
    dsn = values.get('ULTRA_RELAY_DB_DSN')
    if not dsn and APP_SPEC.exists():
        dsn = json.loads(read_private_runtime_file(APP_SPEC)).get('database', {}).get('dsn')
    try:
        parsed = urllib.parse.urlsplit(dsn or '')
        valid = (parsed.scheme in ('postgres', 'postgresql')
                 and parsed.hostname in ('127.0.0.1', 'localhost') and parsed.port == 25432
                 and bool(parsed.username) and bool(parsed.password))
        name = urllib.parse.unquote(parsed.path.lstrip('/'))
        valid = valid and re.fullmatch(r'[A-Za-z0-9_-]+', name) is not None
    except ValueError:
        valid = False
        name = ''
    if not valid:
        raise ValueError('dedicated_database_tunnel_dsn_required')
    if name != database:
        raise ValueError('backup_database_dsn_mismatch')
    return parsed


def read_private_runtime_file(path):
    path = Path(path)
    parent = path.parent.lstat()
    try:
        relay_uid = pwd.getpwnam('ultra-relay').pw_uid
    except KeyError:
        relay_uid = -1
    allowed_owners = {0, relay_uid}
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid not in allowed_owners or parent.st_mode & 0o022:
        raise ValueError('private_database_runtime_config_required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in allowed_owners or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('private_database_runtime_config_required')
        with os.fdopen(descriptor, 'r') as stream:
            descriptor = -1
            return stream.read(1024 * 1024 + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def pgpass(directory, parsed):
    """Provide libpq credentials via a private temporary file, never argv."""
    def escape(value):
        return value.replace('\\', '\\\\').replace(':', '\\:')
    fields = (parsed.hostname, str(parsed.port), urllib.parse.unquote(parsed.path.lstrip('/')),
              urllib.parse.unquote(parsed.username), urllib.parse.unquote(parsed.password))
    descriptor, name = tempfile.mkstemp(prefix='.pgpass-', dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(':'.join(escape(value) for value in fields) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        environment = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
        environment['PGPASSFILE'] = name
        environment['PGCONNECT_TIMEOUT'] = '10'
        environment['PGSSLMODE'] = 'disable'
        yield environment
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def connection_args(parsed, database, command):
    return [command, '-w', '-h', parsed.hostname, '-p', str(parsed.port),
            '-U', urllib.parse.unquote(parsed.username), '-d', database]
