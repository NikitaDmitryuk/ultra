"""Owned bridge subscription vhost. Leaves legacy forwarding and XHTTP configuration intact."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time


def validate(p):
    for key in ('domain', 'upstream_domain'):
        value = p[key]
        if len(value) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or '..' in value:
            raise ValueError('invalid_subscription_domain')
    if type(p['bot_port']) is not int or not 1024 <= p['bot_port'] <= 65535 or p['bot_port'] == 443:
        raise ValueError('invalid_bot_port')


def check_published(current, requested):
    active = current.get('primary_xhttp', {})
    if active and active.get('published', True):
        expected = {'server_name': requested['domain'], 'host': requested.get('public_host', requested['domain']),
                    'path': requested['path'], 'backend_port': requested['backend_port'], 'port': 443}
        if any(active.get(key) != value for key, value in expected.items()):
            raise ValueError('published_ingress_change_requires_explicit_cutover')
        return True
    return False


def nginx(p):
    validate(p)
    return f'''# Managed by ultra-install; independent subscription vhost.
server {{
    listen 80;
    server_name {p['domain']};
    access_log off;
    error_log /var/log/nginx/ultra-subscription-error.log crit;
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/ultra-acme; }}
    location / {{ return 301 https://{p['domain']}$request_uri; }}
}}
server {{
    listen 443 ssl http2;
    server_name {p['domain']};
    ssl_certificate /etc/letsencrypt/live/{p['domain']}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{p['domain']}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;
    error_log /var/log/nginx/ultra-subscription-error.log crit;
    location / {{
        proxy_pass https://127.0.0.1:{p['bot_port']};
        proxy_ssl_server_name on;
        proxy_ssl_name {p['upstream_domain']};
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 4;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_set_header Host {p['domain']};
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Forwarded "";
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 40s;
        proxy_send_timeout 40s;
    }}
}}
'''.encode()


def probe(p, timeout=20):
    context = ssl.create_default_context()
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection(('127.0.0.1', 443), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname=p['domain']) as connection:
                    connection.sendall(('GET /healthz HTTP/1.1\r\nHost: ' + p['domain'] + '\r\nConnection: close\r\n\r\n').encode())
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    if response.status == 200:
                        return
        except (OSError, http.client.HTTPException):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('subscription_https_not_ready')
        time.sleep(0.25)


def atomic(path, data, mode=0o644):
    if path.is_symlink():
        raise ValueError('managed_symlink')
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    temporary = path.with_name(path.name + '.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        if previous is not None:
            os.fchown(stream.fileno(), previous.st_uid, previous.st_gid)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(p, root=Path('/'), run=subprocess.run, check=probe):
    content = nginx(p)
    site = root/'etc/nginx/conf.d/ultra-subscription.conf'
    hook = root/'etc/letsencrypt/renewal-hooks/deploy/ultra-subscription'
    marker = root/'var/lib/ultra-ingress/managed.json'
    before_marker = marker.read_bytes() if marker.exists() else None
    manifest = json.loads(before_marker) if before_marker else {}
    hook_content = (f'#!/bin/sh\nset -eu\n[ "${{RENEWED_LINEAGE:-}}" = "/etc/letsencrypt/live/{p["domain"]}" ] || exit 0\nnginx -t\nsystemctl reload nginx\nsystemctl restart ultra-bot\n').encode()
    targets = {site: (content, 0o644), hook: (hook_content, 0o755)}
    previous = {}
    for path in targets:
        if path.is_symlink():
            raise ValueError('managed_symlink')
        previous[path] = path.read_bytes() if path.exists() else None
        key = '/' + str(path.relative_to(root))
        if previous[path] is not None and manifest.get(key) != hashlib.sha256(previous[path]).hexdigest():
            raise ValueError('foreign_subscription_configuration')
    try:
        for path, (data, mode) in targets.items():
            atomic(path, data, mode)
        run(['nginx', '-t'], check=True, capture_output=True, timeout=15)
        # A prior successful HUP exit status does not prove listeners were applied.
        run(['systemctl', 'reload', 'nginx'], check=True, capture_output=True, timeout=30)
        check(p)
        for path, (data, _) in targets.items():
            manifest['/' + str(path.relative_to(root))] = hashlib.sha256(data).hexdigest()
        atomic(marker, json.dumps(manifest, sort_keys=True).encode(), 0o600)
    except Exception:
        for path, data in previous.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, data, targets[path][1])
        try:
            run(['nginx', '-t'], check=True, capture_output=True, timeout=15)
            run(['systemctl', 'reload', 'nginx'], check=True, capture_output=True, timeout=30)
        except Exception:
            raise RuntimeError('subscription_config_restored_reload_failed') from None
        raise RuntimeError('subscription_apply_failed_previous_restored') from None
    return {'subscription_https_ready': True}
