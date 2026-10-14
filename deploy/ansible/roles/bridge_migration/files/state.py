#!/usr/bin/env python3
"""Read-only server inventory and diagnostic environment projection."""
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import urllib.parse


BASE = ('/etc/ultra-relay', '/var/lib/ultra-relay', '/var/lib/ultra-bot',
        '/usr/local/bin/ultra-relay', '/usr/local/bin/ultra-bot', '/usr/local/bin/ultra-install',
        '/etc/systemd/system/ultra-relay.service', '/etc/systemd/system/ultra-bot.service',
        '/etc/systemd/system/ultra-relay.service.d', '/etc/systemd/system/ultra-bot.service.d')


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
    if domain and (pathlib.Path('/etc/letsencrypt/renewal') / (domain + '.conf')).exists():
        if not re.fullmatch(r'[A-Za-z0-9.-]+', domain):
            raise ValueError('invalid bot domain')
        for suffix in ('live/' + domain, 'archive/' + domain, 'renewal/' + domain + '.conf'):
            selected.add(pathlib.Path('/etc/letsencrypt') / suffix)
        for hook_name in ('ultra-bot', 'ultra-vpn', 'ultra-ansible'):
            hook_path = pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy') / hook_name
            if hook_path.exists():
                selected.add(hook_path)
        renewal = pathlib.Path('/etc/letsencrypt/renewal') / (domain + '.conf')
        config = dict(re.findall(r'(?m)^\s*([a-z_]+)\s*=\s*(.*?)\s*$', renewal.read_text()))
        if config.get('authenticator') not in ('standalone', 'webroot') or config.get('installer', 'None') not in ('None', 'none'):
            raise ValueError('only standalone or Ultra webroot renewal is supported')
        if config.get('authenticator') == 'webroot':
            if config.get('webroot_path', '').rstrip(', /') != '/var/www/ultra-acme':
                raise ValueError('unsupported ACME webroot')
            selected.add(pathlib.Path('/var/www/ultra-acme'))
            # Include only Ultra-owned nginx state, never other hosted sites.
            for name in ('/etc/nginx/conf.d/ultra-vpn.conf', '/etc/nginx/conf.d/ultra-acme.conf', '/etc/nginx/conf.d/ultra-bot-acme.conf'):
                if pathlib.Path(name).exists():
                    selected.add(pathlib.Path(name))
            hook = pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/ultra-vpn')
            if hook.exists():
                selected.add(hook)
        account, server = config.get('account', ''), urllib.parse.urlsplit(config.get('server', ''))
        if not re.fullmatch(r'[a-f0-9]+', account) or server.scheme != 'https' or not server.hostname:
            raise ValueError('unsupported ACME account configuration')
        selected.add(safe_path('/etc/letsencrypt/accounts/' + server.netloc + server.path.rstrip('/') + '/' + account))
        for key in ('pre_hook', 'post_hook', 'renew_hook', 'deploy_hook'):
            if config.get(key) and config[key] not in ('/etc/letsencrypt/renewal-hooks/deploy/ultra-bot', '/etc/letsencrypt/renewal-hooks/deploy/ultra-vpn', '/etc/letsencrypt/renewal-hooks/deploy/ultra-ansible'):
                raise ValueError('custom renewal hook requires manual preparation')
    for path in list(selected):
        if not path.exists():
            raise ValueError('required migration file is missing')
        if path.is_symlink():
            selected.add(safe_path(str(path.resolve(strict=True))))
    # Avoid duplicate recursive archive entries.
    return sorted(p for p in selected if not any(parent in selected for parent in p.parents))


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
    if command == 'env':
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
    try:
        main()
    except (OSError, ValueError, KeyError):
        print('bridge migration state operation failed; sensitive details suppressed', file=sys.stderr)
        sys.exit(1)
