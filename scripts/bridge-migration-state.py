#!/usr/bin/env python3
"""Server-side migration inventory/archives. Never print environment values or DSNs."""
import hashlib
import datetime
import io
import json
import os
import pathlib
import pwd
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse


BASE = ('/etc/ultra-relay', '/var/lib/ultra-relay', '/var/lib/ultra-bot',
        '/usr/local/bin/ultra-relay', '/usr/local/bin/ultra-bot', '/usr/local/bin/ultra-install',
        '/etc/systemd/system/ultra-relay.service', '/etc/systemd/system/ultra-bot.service',
        '/etc/systemd/system/ultra-relay.service.d', '/etc/systemd/system/ultra-bot.service.d')
MARKER = 'var/lib/ultra-relay/bridge-migration'
MANIFEST = '.ultra-migration-manifest.json'
PAUSE = '/etc/systemd/system/ultra-relay.service.d/zzzz-bridge-migration.conf'


def run(*args, **kwargs):
    result = subprocess.run(args, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise ValueError('server command failed; sensitive diagnostics suppressed')
    return result


def environment(unit='ultra-relay.service'):
    # systemctl show exposes configured directives, not the environment of a running process.
    values = {}
    raw = run('systemctl', 'show', unit, '-p', 'Environment', '--value',
              stdout=subprocess.PIPE, text=True).stdout
    for item in shlex.split(raw):
        if '=' in item:
            key, value = item.split('=', 1)
            values[key] = value
    files = run('systemctl', 'show', unit, '-p', 'EnvironmentFiles', '--value',
                stdout=subprocess.PIPE, text=True).stdout
    # EnvironmentFile values override Environment=, regardless of directive order.
    for filename, optional in re.findall(r'(\S+) \(ignore_errors=(yes|no)\)', files):
        path = pathlib.Path(filename)
        if not path.exists() and optional == 'yes':
            continue
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith(('#', ';')):
                continue
            if '=' not in line or line.endswith('\\'):
                raise ValueError('unsupported systemd environment file syntax')
            key, value = line.split('=', 1)
            parts = shlex.split(value, comments=False)
            if len(parts) > 1:
                raise ValueError('unsupported unquoted environment value')
            values[key.strip()] = parts[0] if parts else ''
    return values


def safe_path(value):
    path = pathlib.Path(value)
    # Never interpret a broad system directory as application state.
    if (not path.is_absolute() or '..' in path.parts or len(path.parts) < 3
            or path.parts[1] not in ('etc', 'var', 'opt', 'srv', 'usr', 'home', 'root')
            or value in ('/var/lib', '/var/log', '/var/cache', '/usr/local', '/etc/systemd', '/etc/letsencrypt', '/root/.ssh')
            or value.startswith(('/etc/ssh/', '/etc/sudoers', '/etc/passwd', '/etc/shadow', '/etc/group', '/root/.ssh/authorized_keys'))
            or '\n' in value or '\r' in value):
        raise ValueError('unsafe configured state path')
    return path


def spec():
    return json.loads(pathlib.Path('/etc/ultra-relay/spec.json').read_text())


def database():
    u = urllib.parse.urlsplit(spec().get('database', {}).get('dsn', ''))
    if (u.scheme not in ('postgres', 'postgresql') or u.hostname not in ('localhost', '127.0.0.1', '::1')
            or (u.port or 5432) != 5432):
        raise ValueError('only local PostgreSQL URI on port 5432 is supported')
    name, user = urllib.parse.unquote(u.path.lstrip('/')), urllib.parse.unquote(u.username or '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or not re.fullmatch(r'[A-Za-z0-9_.-]+', user) or not u.password:
        raise ValueError('unsupported database identity')
    return name, user


def paths():
    selected = {pathlib.Path(p) for p in BASE if pathlib.Path(p).exists()}
    for unit in ('ultra-relay.service', 'ultra-bot.service'):
        if unit == 'ultra-bot.service' and not pathlib.Path('/usr/local/bin/ultra-bot').exists():
            continue
        for prop in ('FragmentPath', 'DropInPaths'):
            output = run('systemctl', 'show', unit, '-p', prop, '--value', stdout=subprocess.PIPE, text=True).stdout
            for value in shlex.split(output):
                selected.add(safe_path(value))
        env = environment(unit)
        if unit == 'ultra-bot.service' and env.get('ULTRA_DB_DSN') and env['ULTRA_DB_DSN'] != spec().get('database', {}).get('dsn'):
            raise ValueError('bot uses a different database; single-database migration required')
        start = run('systemctl', 'show', unit, '-p', 'ExecStart', '--value', stdout=subprocess.PIPE, text=True).stdout
        for value in re.findall(r'(?:^|\s)-data-dir(?:=|\s+)([^\s;]+)', start):
            selected.add(safe_path(value))
        for key, value in env.items():
            if value and key.startswith('ULTRA_') and (key.endswith('_KEY_FILE') or key.endswith('_STATE_DIR')):
                selected.add(safe_path(value))
        files = run('systemctl', 'show', unit, '-p', 'EnvironmentFiles', '--value', stdout=subprocess.PIPE, text=True).stdout
        for value, optional in re.findall(r'(\S+) \(ignore_errors=(yes|no)\)', files):
            if pathlib.Path(value).exists() or optional == 'no':
                selected.add(safe_path(value))
    d = spec()
    for value in (d.get('public_xhttp_tls') or {}).values():
        if isinstance(value, str) and value.startswith('/'):
            selected.add(safe_path(value))
    if d.get('geo_assets_dir'):
        for name in ('geoip.dat', 'geosite.dat'):
            selected.add(safe_path(str(pathlib.Path(d['geo_assets_dir']) / name)))
    env = environment('ultra-bot.service') if pathlib.Path('/usr/local/bin/ultra-bot').exists() else {}
    domain = env.get('ULTRA_BOT_DOMAIN', '')
    if domain:
        if not re.fullmatch(r'[A-Za-z0-9.-]+', domain):
            raise ValueError('invalid bot domain')
        for suffix in ('live/' + domain, 'archive/' + domain, 'renewal/' + domain + '.conf', 'renewal-hooks/deploy/ultra-bot'):
            selected.add(pathlib.Path('/etc/letsencrypt') / suffix)
        renewal = pathlib.Path('/etc/letsencrypt/renewal') / (domain + '.conf')
        config = dict(re.findall(r'(?m)^\s*([a-z_]+)\s*=\s*(.*?)\s*$', renewal.read_text()))
        if config.get('authenticator') != 'standalone' or config.get('installer', 'None') not in ('None', 'none'):
            raise ValueError('only certbot standalone renewal is supported; custom plugins require preparation')
        account, server = config.get('account', ''), urllib.parse.urlsplit(config.get('server', ''))
        if not re.fullmatch(r'[a-f0-9]+', account) or server.scheme != 'https' or not server.hostname:
            raise ValueError('unsupported ACME account configuration')
        selected.add(safe_path('/etc/letsencrypt/accounts/' + server.netloc + server.path.rstrip('/') + '/' + account))
        for key in ('pre_hook', 'post_hook', 'renew_hook', 'deploy_hook'):
            if config.get(key) and '/etc/letsencrypt/renewal-hooks/deploy/ultra-bot' not in config[key]:
                raise ValueError('custom renewal hook requires manual preparation')
    for path in list(selected):
        if not path.exists():
            raise ValueError('required migration file is missing')
        if path.is_symlink():
            selected.add(safe_path(str(path.resolve(strict=True))))
    # Avoid duplicate recursive archive entries.
    return sorted(p for p in selected if not any(parent in selected for parent in p.parents))


def excluded(path):
    parts = pathlib.PurePosixPath(path).parts
    return (str(path) == MARKER or str(path).startswith(MARKER + '/')
            or str(path).startswith('var/lib/ultra-relay/bridge-migration-source')
            or 'logs' in parts or 'cache' in parts or str(path).endswith('.log')
            or str(path) == PAUSE.lstrip('/'))


def fingerprint(path):
    if path.is_symlink():
        return 'link:' + os.readlink(path)
    if path.is_file():
        h = hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    if path.is_dir():
        return 'directory'
    raise ValueError('unsupported special file in state')


def export(root=pathlib.Path('/')):
    manifest = {}
    def record(info):
        if excluded(info.name):
            return None
        manifest[info.name] = fingerprint(root / info.name)
        return info
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as archive:
        for path in paths():
            archive.add(path, arcname=str(path.relative_to(root)), filter=record)
        payload = json.dumps(manifest, sort_keys=True).encode()
        info = tarfile.TarInfo(MANIFEST)
        info.size, info.mode = len(payload), 0o600
        archive.addfile(info, io.BytesIO(payload))


def import_state(root=pathlib.Path('/')):
    os.umask(0o077)
    backup_root = root / 'var/backups/ultra-bridge-migration'
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = pathlib.Path(tempfile.mkdtemp(prefix='state-' + stamp + '-', dir=backup_root))
    with tempfile.TemporaryDirectory(prefix='ultra-migrate-', dir=root / 'var/tmp') as tmp:
        incoming = pathlib.Path(tmp) / 'incoming.tar.gz'
        with incoming.open('wb') as f:
            shutil.copyfileobj(sys.stdin.buffer, f)
        with tarfile.open(incoming) as archive:
            members = archive.getmembers()
            manifest = json.load(archive.extractfile(MANIFEST))
            for member in members:
                if member.name == MANIFEST:
                    continue
                safe_path('/' + member.name)
                if member.name not in manifest or excluded(member.name) or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError('invalid incoming archive member')
                if member.issym() or member.islnk():
                    resolved = os.path.normpath(os.path.join('/' + os.path.dirname(member.name), member.linkname)) if member.issym() else '/' + member.linkname
                    if resolved.lstrip('/') not in manifest:
                        raise ValueError('archive link escapes selected state')
            roots = [name for name in manifest if not any(str(p) in manifest for p in pathlib.PurePosixPath(name).parents if str(p) != '.')]
            with tarfile.open(backup / 'state.tar.gz', 'w:gz') as previous:
                for name in roots:
                    path = root / name
                    if path.exists() or path.is_symlink():
                        previous.add(path, arcname=name)
            # Retain the migration marker independently of restored service state.
            marker = root / MARKER
            saved = pathlib.Path(tmp) / 'marker'
            if marker.exists():
                shutil.copytree(marker, saved)
            for name in roots:
                path = root / name
                if path.is_dir() and not path.is_symlink():
                    if os.path.ismount(path):
                        for child in path.iterdir():
                            if child.is_dir() and not child.is_symlink():
                                shutil.rmtree(child)
                            else:
                                child.unlink()
                    else:
                        shutil.rmtree(path)
                elif path.exists() or path.is_symlink():
                    path.unlink()
            run('tar', '-C', str(root), '-xzf', str(incoming), '--exclude=' + MANIFEST, stdout=subprocess.DEVNULL)
            if saved.exists():
                shutil.copytree(saved, marker, dirs_exist_ok=True)
            for name, expected in manifest.items():
                if fingerprint(root / name) != expected:
                    raise ValueError('transferred state checksum mismatch')
            marker.mkdir(mode=0o700, parents=True, exist_ok=True)
            (marker / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
    run('chown', '-R', 'ultra-relay:ultra-relay', str(root / 'etc/ultra-relay'), str(root / 'var/lib/ultra-relay'), stdout=subprocess.DEVNULL)
    os.chmod(root / 'etc/ultra-relay', 0o700)
    for path in (root / 'etc/ultra-relay').rglob('*'):
        if path.is_file() and not path.is_symlink():
            os.chmod(path, path.stat().st_mode & 0o700)
    run('systemctl', 'daemon-reload', stdout=subprocess.DEVNULL)
    if root == pathlib.Path('/'):
        run('chown', '-R', 'root:root', str(root / MARKER), stdout=subprocess.DEVNULL)
        uid = pwd.getpwnam('ultra-relay').pw_uid
        gid = pwd.getpwnam('ultra-relay').pw_gid
        for key, value in environment().items():
            if value and key.startswith('ULTRA_') and key.endswith('_KEY_FILE'):
                p = safe_path(value).resolve(strict=True)
                os.chown(p, uid, gid)
                os.chmod(p, 0o600)
            elif value and key.startswith('ULTRA_') and key.endswith('_STATE_DIR'):
                run('chown', '-R', 'ultra-relay:ultra-relay', str(safe_path(value)), stdout=subprocess.DEVNULL)
        for value in (spec().get('public_xhttp_tls') or {}).values():
            if isinstance(value, str) and value.startswith('/'):
                p = safe_path(value).resolve(strict=True)
                os.chown(p, uid, gid)
                os.chmod(p, 0o600)


def database_fingerprint():
    name, _ = database()
    psql = ['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', name]
    tables = run(*psql, input="SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;", text=True, stdout=subprocess.PIPE).stdout.splitlines()
    digest = hashlib.sha256()
    for table in tables:
        ident = '"' + table.replace('"', '""') + '"'
        # Small logical-migration databases only; sort canonical rows, not physical order.
        rows = run(*psql, input='SELECT row_to_json(t)::text FROM public.' + ident + ' t ORDER BY row_to_json(t)::text;', text=True, stdout=subprocess.PIPE).stdout
        digest.update(table.encode() + b'\0' + rows.encode())
    return digest.hexdigest()


def main():
    command = sys.argv[1]
    if command == 'export':
        export()
    elif command == 'import':
        import_state()
    elif command == 'check':
        manifest = json.loads(pathlib.Path('/' + MARKER + '/manifest.json').read_text())
        for name, expected in manifest.items():
            if fingerprint(pathlib.Path('/') / name) != expected:
                raise ValueError('state checksum mismatch')
    elif command == 'env':
        values = environment(sys.argv[2] if len(sys.argv) > 2 else 'ultra-relay.service')
        for key, value in values.items():
            if re.fullmatch(r'[A-Z_][A-Z_0-9]*', key):
                print(key + '=' + shlex.quote(value))
        host = spec().get('admin_listen', '')
        if not re.fullmatch(r'(127\.0\.0\.1|localhost|\[::1\]):[0-9]+', host) or not 0 < int(host.rsplit(':', 1)[1]) < 65536:
            raise ValueError('Admin API is not loopback-only')
        print('ADMIN_URL=' + shlex.quote('http://' + host))
    elif command == 'validate':
        database()
        if spec().get('role') != 'bridge':
            raise ValueError('source must be a bridge')
        primary = run('runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-d', 'postgres',
                      '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT pg_is_in_recovery();', stdout=subprocess.PIPE, text=True).stdout.strip()
        if primary != 'f':
            raise ValueError('source PostgreSQL must be a primary')
        if pathlib.Path(PAUSE).exists():
            raise ValueError('source has an unfinished migration pause; resolve it before moving again')
        selected = paths()
        print('EXTRA_STATE_BYTES=' + str(sum(p.stat().st_size for root in selected for p in ([root] if root.is_file() else root.rglob('*')) if p.is_file())))
        print('LOCATIONS=' + json.dumps([str(p) for p in selected]))
        bot = environment('ultra-bot.service') if pathlib.Path('/usr/local/bin/ultra-bot').exists() else {}
        print('BOT_DOMAIN=' + bot.get('ULTRA_BOT_DOMAIN', ''))
        print('BOT_PORT=' + bot.get('ULTRA_BOT_PORT', ''))
        print('BOT_ENABLED=' + ('yes' if bot else 'no'))
    elif command == 'database-fingerprint':
        print(database_fingerprint())
    else:
        raise ValueError('invalid helper command')


if __name__ == '__main__':
    def interrupted(signum, _frame):
        # Raise through context managers so remote temporary archives are removed.
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError):
        print('bridge migration state operation failed; sensitive details suppressed', file=sys.stderr)
        sys.exit(1)
