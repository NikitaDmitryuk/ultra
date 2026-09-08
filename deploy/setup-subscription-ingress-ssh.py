"""Run on an existing SSH-managed ingress; never calls a cloud provider."""
import hashlib
import ipaddress
import json
import pathlib
import re
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
    else:
        run(['nginx', '-t'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    run(['systemctl', 'is-active', '--quiet', 'nginx'], check=True, timeout=10)
    marker.write_text(json.dumps({name: hashlib.sha256((nginx/name).read_bytes()).hexdigest() for name in configs}))
    print('nginx_ready=true config_changed='+str(bool(changes)))


if __name__ == '__main__':
    try:
        install(settings['bridge'], settings['domain'])
    except (ValueError, RuntimeError) as error:
        print('ingress_setup_failed='+str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print('ingress_setup_failed='+type(error).__name__, file=sys.stderr)
        sys.exit(1)
