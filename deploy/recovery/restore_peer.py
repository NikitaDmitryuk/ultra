"""Bounded recovery actions on existing pinned exits; never provisions a VM."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess


def run(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise ValueError('peer_command_failed')
    return result.stdout.decode()


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError('peer_marker_symlink')
    temporary = path.with_name('.' + path.name + '.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def stale_forward_pids(listeners, connections, old_address):
    old = str(ipaddress.IPv4Address(old_address))
    pids = set()
    for row in listeners.splitlines():
        if not re.search(r'(?:127\.0\.0\.1|\[::1\]):15432\b', row):
            continue
        for pid in re.findall(r'pid=(\d+)', row):
            matches = [item for item in connections.splitlines() if 'pid=' + pid + ',' in item]
            if any(re.search(r'\b' + re.escape(old) + r':\d+\b', item) and re.search(r'(?:\b|\]):22\b', item) for item in matches):
                pids.add(int(pid))
            else:
                raise ValueError('replica_forward_owner_unconfirmed')
    return pids


def cluster_identifier(data, runner=run):
    text = runner(['/usr/lib/postgresql/16/bin/pg_controldata', str(data)])
    value = re.search(r'(?m)^Database system identifier:\s*(\d+)\s*$', text)
    if not value:
        raise ValueError('replica_system_identifier_unavailable')
    return value[1]


def reseed(plan, root=Path('/'), runner=run):
    root = Path(root)
    if plan.get('new_bridge_address') is not None:
        address = str(ipaddress.IPv4Address(plan['new_bridge_address']))
        port = plan['tunnel_port']
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('invalid_restored_tunnel_port')
        runner(['sh', '-c', "if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then ufw allow from " + address + " to any port " + str(port) + " proto tcp >/dev/null; fi"])
    directory = root / 'var/lib/ultra-postgres-replica'
    data = directory / 'data'
    retired = directory / ('retired-' + plan['restore_id'][:16])
    marker = retired / 'restore.json'
    if data.is_symlink() or directory.is_symlink():
        raise ValueError('foreign_replica_path')
    if marker.exists():
        saved = json.loads(marker.read_text())
        if saved.get('restore_id') != plan['restore_id'] or saved.get('new_system_identifier') != plan['system_identifier']:
            raise ValueError('replica_restore_marker_conflict')
        if saved.get('reseed_prepared'):
            return {'reseed_prepared': True, 'resumed': True}
    if data.exists():
        if (not (directory / 'managed-by-ultra').is_file() or not (data / 'standby.signal').is_file()
                or (data / 'PG_VERSION').read_text().strip() != '16'):
            raise ValueError('foreign_or_incompatible_replica')
        current = cluster_identifier(data, runner)
        if current == plan['system_identifier']:
            return {'reseed_prepared': True, 'already_matches_new_primary': True}
        if (retired / 'data').exists():
            raise ValueError('different_replica_already_retired')
    else:
        current = None
    listeners = runner(['ss', '-Hlnpt', 'sport = :15432'])
    connections = runner(['ss', '-Hntp', 'sport = :22'])
    for pid in stale_forward_pids(listeners, connections, plan['old_bridge_address']):
        if not re.fullmatch(r'sshd(?:-session|-auth)?', (root / 'proc' / str(pid) / 'comm').read_text().strip()):
            raise ValueError('replica_forward_process_not_sshd')
        os.kill(pid, signal.SIGTERM)
    # Do not stop any relay, monitor, or the exit's standard PostgreSQL cluster.
    if data.exists():
        runner(['systemctl', 'stop', 'ultra-postgres-replica.service'])
    retired.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic(marker, {'restore_id': plan['restore_id'], 'old_system_identifier': current,
                    'new_system_identifier': plan['system_identifier'], 'reseed_prepared': False})
    config = root / 'etc/ultra-postgres-replica'
    if config.exists() and not (retired / 'configuration').exists():
        if config.is_symlink():
            raise ValueError('foreign_replica_configuration')
        shutil.copytree(config, retired / 'configuration', symlinks=True)
    if data.exists():
        data.rename(retired / 'data')
    atomic(marker, {'restore_id': plan['restore_id'], 'old_system_identifier': current,
                    'new_system_identifier': plan['system_identifier'], 'reseed_prepared': True})
    return {'reseed_prepared': True, 'previous_data_preserved': current is not None}


def configurations(address, domain):
    ipaddress.IPv4Address(address)
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', domain):
        raise ValueError('invalid_subscription_domain')
    stream = f'''server {{
    listen 443;
    listen [::]:443;
    listen 8444;
    listen [::]:8444;
    access_log off;
    proxy_pass {address}:8444;
    proxy_connect_timeout 10s;
    proxy_timeout 300s;
}}
'''
    acme = f'''server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    access_log off;
    location /.well-known/acme-challenge/ {{
        proxy_pass http://{address}:80;
        proxy_set_header Host $host;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }}
    location / {{ return 404; }}
}}
'''
    return {'stream.d/bot-proxy.conf': stream.encode(), 'conf.d/acme-proxy.conf': acme.encode()}


def forward(plan, root=Path('/'), runner=run):
    nginx = Path(root) / 'etc/nginx'
    marker = nginx / 'ultra-ingress.sha256.json'
    known = json.loads(marker.read_text()) if marker.exists() else {}
    expected = configurations(plan['old_bridge_address'], plan['subscription_domain'])
    desired = configurations(plan['new_bridge_address'], plan['subscription_domain'])
    previous, changes = {}, {}
    normalize = lambda data: re.sub(rb'\s+', b'', data)
    for name, content in desired.items():
        path = nginx / name
        if not path.is_file() or path.is_symlink():
            raise ValueError('prepared_owned_ingress_required')
        old = path.read_bytes()
        legacy = expected[name].replace(b'    listen 443;\n    listen [::]:443;\n', b'').replace(b'    access_log off;\n', b'').replace(b'location / { return 404; }', b'location / { return 301 https://$host:8444$request_uri; }')
        if normalize(old) not in (normalize(expected[name]), normalize(legacy), normalize(content)) and hashlib.sha256(old).hexdigest() != known.get(name):
            raise ValueError('foreign_ingress_configuration')
        previous[name] = old
        if old != content:
            changes[name] = content
    if changes:
        backup = Path(root) / 'var/lib/ultra-restore' / plan['restore_id'] / 'ingress-before'
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name, data in previous.items():
            path = backup / Path(name).name
            if not path.exists():
                path.write_bytes(data); path.chmod(0o600)
        try:
            for name, data in changes.items():
                (nginx / name).write_bytes(data)
            runner(['nginx', '-t'])
            runner(['systemctl', 'reload', 'nginx'])
        except Exception:
            for name, data in previous.items():
                (nginx / name).write_bytes(data)
            runner(['nginx', '-t'])
            runner(['systemctl', 'reload', 'nginx'])
            raise ValueError('ingress_failed_previous_restored') from None
    runner(['nginx', '-t'])
    runner(['systemctl', 'is-active', '--quiet', 'nginx'])
    atomic(marker, {name: hashlib.sha256(data).hexdigest() for name, data in desired.items()})
    return {'ingress_ready': True, 'dns_changed': False, 'config_changed': bool(changes)}


def main(value):
    os.umask(0o077)
    if os.geteuid() != 0 or not re.fullmatch(r'[a-f0-9]{64}', value.get('restore_id', '')):
        raise ValueError('invalid_peer_restore_request')
    if value['action'] == 'reseed':
        result = reseed(value)
    elif value['action'] == 'forward':
        result = forward(value)
    else:
        raise ValueError('invalid_peer_restore_action')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main(payload)  # Supplied through the pinned SSH stdin envelope.
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('restore_peer_failed; private details suppressed')
