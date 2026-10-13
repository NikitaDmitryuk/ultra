"""Run on an existing SSH-managed ingress; never calls a cloud provider."""
import hashlib
import ipaddress
import json
import pathlib
import re
import socket
import subprocess
import sys
import time


def configurations(bridge, domain):
    ipaddress.IPv4Address(bridge)
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', domain):
        raise ValueError('invalid_domain')
    stream = f'''server {{
    listen 443;
    listen [::]:443;
    listen 8444;
    listen [::]:8444;
    access_log off;
    proxy_pass {bridge}:8444;
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
        proxy_pass http://{bridge}:80;
        proxy_set_header Host $host;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }}
    location / {{ return 404; }}
}}
'''
    legacy_stream = stream.replace('    listen 443;\n    listen [::]:443;\n', '').replace('    access_log off;\n', '')
    legacy_acme = acme.replace('    access_log off;\n', '').replace('location / { return 404; }', 'location / { return 301 https://$host:8444$request_uri; }')
    return {'stream.d/bot-proxy.conf': (stream, legacy_stream), 'conf.d/acme-proxy.conf': (acme, legacy_acme)}


def forward_main(text):
    include = r'include\s+/etc/nginx/stream\.d/\*\.conf\s*;'
    active = re.sub(r'(?m)#.*$', '', text)
    if re.search(r'stream\s*\{[^{}]*' + include, active):
        return text
    # Repair only the exact bare include emitted by the initial v2 bootstrap.
    if re.search(r'\bstream\s*\{', active):
        raise ValueError('existing_stream_context_requires_owned_include')
    text = re.sub(r'(?m)^include /etc/nginx/stream\.d/\*\.conf;[ \t]*\n?', '', text)
    if re.search(include, text):
        raise ValueError('unrecognized_stream_include_context')
    return text + '\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n'


def prepare_forward(root=pathlib.Path('/'), run=subprocess.run):
    main = root/'etc/nginx/nginx.conf'
    before = main.read_text()
    after = forward_main(before)
    (root/'etc/nginx/stream.d').mkdir(exist_ok=True)
    if after == before:
        return
    main.write_text(after)
    try:
        run(['nginx','-t'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    except Exception:
        main.write_text(before)
        raise


def wait_listeners(timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        try:
            for port in (80, 443, 8444):
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    pass
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('ingress_listeners_unavailable') from None
            time.sleep(0.2)


def install(bridge, domain, root=pathlib.Path('/'), run=subprocess.run):
    configs = configurations(bridge, domain)
    nginx = root/'etc/nginx'
    main = nginx/'nginx.conf'
    if not main.is_file():
        raise ValueError('install_nginx_and_stream_module_first')
    main_text = main.read_text()
    if not re.search(r'include\s+/etc/nginx/stream\.d/\*\.conf\s*;', main_text):
        raise ValueError('nginx_stream_include_required')
    marker = nginx/'ultra-ingress.sha256.json'
    known = json.loads(marker.read_text()) if marker.exists() else {}
    changes = {}
    normalize = lambda text: re.sub(r'\s+', '', text)
    for name, (desired, legacy) in configs.items():
        path = nginx/name
        if path.is_symlink():
            raise ValueError('symlink_configuration_not_owned')
        previous = path.read_bytes() if path.exists() else None
        if previous is not None and normalize(previous.decode()) not in (normalize(desired), normalize(legacy)):
            if hashlib.sha256(previous).hexdigest() != known.get(name):
                raise ValueError('foreign_nginx_configuration')
        if previous != desired.encode():
            changes[path] = (previous, desired.encode())
    if changes:
        backup = root/'root/ultra-ingress-backups'/str(time.time_ns())
        backup.mkdir(parents=True, mode=0o700)
        for path, (previous, _) in changes.items():
            if previous is not None:
                (backup/path.name).write_bytes(previous)
    try:
        for path, (_, desired) in changes.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(desired)
        run(['nginx', '-t'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        run(['systemctl', 'reload', 'nginx'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        run(['systemctl', 'is-active', '--quiet', 'nginx'], check=True, timeout=10)
        wait_listeners()
    except Exception:
        for path, (previous, _) in changes.items():
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(previous)
        # Restore a partially applied reload too. Failure is explicit to the operator.
        try:
            run(['nginx', '-t'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            run(['systemctl', 'reload', 'nginx'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except Exception:
            raise RuntimeError('configuration_restored_but_nginx_recovery_failed') from None
        raise RuntimeError('configuration_apply_failed_previous_restored') from None
    marker.write_text(json.dumps({name: hashlib.sha256((nginx/name).read_bytes()).hexdigest() for name in configs}))
    print('nginx_ready=true config_changed='+str(bool(changes)))


if __name__ == '__main__':
    try:
        if settings.get('prepare_stream'):
            prepare_forward()
        install(settings['bridge'], settings['domain'])
    except (ValueError, RuntimeError) as error:
        print('ingress_setup_failed='+str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print('ingress_setup_failed='+type(error).__name__, file=sys.stderr)
        sys.exit(1)
