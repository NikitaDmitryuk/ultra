#!/usr/bin/env python3
"""Project only the remote relay Admin API credential into its verification shell."""
import json
import pathlib
import re
import shlex
import subprocess

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


if __name__ == '__main__':
    values = environment()
    host = json.loads(pathlib.Path('/etc/ultra-relay/spec.json').read_text()).get('admin_listen', '')
    if not re.fullmatch(r'(127\.0\.0\.1|localhost|\[::1\]):[0-9]+', host) or not 0 < int(host.rsplit(':', 1)[1]) < 65536:
        raise ValueError('Admin API is not loopback-only')
    print('ULTRA_RELAY_ADMIN_TOKEN=' + shlex.quote(values.get('ULTRA_RELAY_ADMIN_TOKEN', '')))
    print('ADMIN_URL=' + shlex.quote('http://' + host))
