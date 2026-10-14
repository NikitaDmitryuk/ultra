#!/usr/bin/python
"""Known forward-ingress adoption and pure configuration generation; no service changes."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from ansible.module_utils.basic import AnsibleModule


def atomic(path, data):
    temporary = path.with_name(path.name + '.next')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def configurations(bridge, domain, port):
    ipaddress.IPv4Address(bridge)
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', domain) or not 1 <= port <= 65535 or port in (80, 443):
        raise ValueError('invalid_forward_parameters')
    stream = f'''server {{
    listen 443;
    listen [::]:443;
    listen {port};
    listen [::]:{port};
    access_log off;
    proxy_pass {bridge}:{port};
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


def main_candidate(before):
    include = r'include\s+/etc/nginx/stream\.d/\*\.conf\s*;'
    active = re.sub(r'(?m)#.*$', '', before)
    if re.search(r'stream\s*\{[^{}]*' + include, active):
        return before
    if re.search(r'\bstream\s*\{', active):
        raise ValueError('foreign_stream_context')
    after = re.sub(r'(?m)^include /etc/nginx/stream\.d/\*\.conf;[ \t]*\n?', '', before)
    if re.search(include, after):
        raise ValueError('foreign_stream_include')
    return after + '\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n'


def prepare(root, bridge, domain, port, verify_existing=False):
    nginx = Path(root) / 'etc/nginx'
    configs = configurations(bridge, domain, port)
    legacy_marker = nginx / 'ultra-ingress.sha256.json'
    if legacy_marker.is_symlink():
        raise ValueError('forward_receipt_symlink')
    legacy = json.loads(legacy_marker.read_text()) if legacy_marker.exists() else {}
    if not isinstance(legacy, dict):
        raise ValueError('invalid_forward_receipt')
    current_receipt = Path(root) / 'var/lib/ultra-ingress/forward-managed.json'
    if current_receipt.is_symlink():
        raise ValueError('forward_receipt_symlink')
    current = json.loads(current_receipt.read_text()) if current_receipt.exists() else {}
    if not isinstance(current, dict):
        raise ValueError('invalid_forward_receipt')
    pending = current_receipt.with_name(current_receipt.name + '.pending')
    if verify_existing and (pending.exists() or pending.is_symlink()):
        raise ValueError('forward_existing_transaction_pending')
    generated = []
    adopted = {}
    normalize = lambda text: re.sub(r'\s+', '', text)
    main = nginx / 'nginx.conf'
    for relative, (desired, known_old) in configs.items():
        path = nginx / relative
        if path.is_symlink():
            raise ValueError('forward_configuration_symlink')
        if verify_existing and (not path.is_file() or path.stat().st_uid != 0):
            raise ValueError('forward_existing_publication_required')
        if path.exists():
            previous = path.read_bytes()
            if verify_existing and normalize(previous.decode()) not in (normalize(desired), normalize(known_old)):
                raise ValueError('forward_existing_publication_mismatch')
            digest = hashlib.sha256(previous).hexdigest()
            if verify_existing and ((str(path) in current and current[str(path)] != digest) or
                                    (relative in legacy and legacy[relative] != digest)):
                raise ValueError('forward_existing_ownership_drift')
            if normalize(previous.decode()) not in (normalize(desired), normalize(known_old)) and digest != legacy.get(relative) and digest != current.get(str(path)):
                raise ValueError('foreign_forward_configuration')
            adopted[str(path)] = digest
        generated.append({'path': str(path), 'content': desired, 'mode': '0644'})
    if verify_existing and (main.is_symlink() or not main.is_file() or main.stat().st_uid != 0):
        raise ValueError('forward_existing_main_required')
    if main.exists():
        if main.is_symlink():
            raise ValueError('forward_main_symlink')
        before = main.read_text()
        if verify_existing and main_candidate(before) != before:
            raise ValueError('forward_existing_stream_include_required')
        generated.append({'path': str(main), 'content': main_candidate(before), 'mode': '0644'})
        adopted[str(main)] = hashlib.sha256(before.encode()).hexdigest()
    return generated, adopted


def main():
    module = AnsibleModule(argument_spec={
        'root': {'type': 'path', 'default': '/'},
        'bridge': {'type': 'str', 'required': True},
        'domain': {'type': 'str', 'required': True},
        'port': {'type': 'int', 'default': 8444},
        'adopt': {'type': 'bool', 'default': False},
        'verify_existing': {'type': 'bool', 'default': False},
    }, supports_check_mode=True)
    try:
        files, observed = prepare(module.params['root'], module.params['bridge'], module.params['domain'], module.params['port'], module.params['verify_existing'])
        if module.params['adopt'] and not module.check_mode and not module.params['verify_existing']:
            root = Path(module.params['root'])
            receipt = root / 'var/lib/ultra-ingress/forward-managed.json'
            receipt.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if receipt.is_symlink():
                raise ValueError('forward_receipt_symlink')
            existing = json.loads(receipt.read_text()) if receipt.exists() else {}
            for name, digest in observed.items():
                if name in existing and existing[name] != digest:
                    raise ValueError('owned_forward_drift')
                existing[name] = digest
            atomic(receipt, json.dumps(existing, sort_keys=True).encode())
        ports = [80, module.params['port']]
        if module.params['verify_existing']:
            stream = (Path(module.params['root']) / 'etc/nginx/stream.d/bot-proxy.conf').read_text()
            if re.search(r'listen\s+443\s*;', stream):
                ports.append(443)
        module.exit_json(changed=False, files=files, ports=ports)
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='forward_ownership_validation_failed')


if __name__ == '__main__':
    main()
