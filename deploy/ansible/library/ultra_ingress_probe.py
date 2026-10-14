#!/usr/bin/python
"""Read-only application/TLS checks, without service management or secret output."""
import json
from pathlib import Path
import socket
import ssl
import http.client
import ipaddress
import urllib.parse
import urllib.request
from ansible.module_utils.basic import AnsibleModule


def relay_endpoint():
    spec = json.loads(Path('/etc/ultra-relay/spec.json').read_text())
    address = spec.get('admin_listen') or '127.0.0.1:8443'
    parsed = urllib.parse.urlsplit('http://' + address)
    host = parsed.hostname
    if (not host or (host != 'localhost' and not ipaddress.ip_address(host).is_loopback)
            or parsed.port is None or not 1 <= parsed.port <= 65535 or parsed.path or parsed.query
            or parsed.fragment or parsed.username or parsed.password):
        raise ValueError('non_loopback_admin_endpoint')
    return 'http://' + address + '/v1/hardening'


def relay_ready():
    values = {}
    for line in Path('/etc/ultra-relay/environment').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip().strip('"').strip("'")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(relay_endpoint(),
                                     headers={'Authorization': 'Bearer ' + values['ULTRA_RELAY_ADMIN_TOKEN']})
    with opener.open(request, timeout=3) as response:
        data = json.load(response)
    reload_state = data.get('reload', {})
    return reload_state.get('count', 0) > 0 and not reload_state.get('error')


def bot_ready():
    values = {}
    for line in Path('/etc/ultra-relay/environment').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip().strip('"').strip("'")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(('127.0.0.1', int(values['ULTRA_BOT_PORT'])), timeout=3) as connection:
        with context.wrap_socket(connection, server_hostname=values['ULTRA_BOT_DOMAIN']) as secured:
            secured.sendall(('GET /healthz HTTP/1.1\r\nHost: ' + values['ULTRA_BOT_DOMAIN'] + '\r\nConnection: close\r\n\r\n').encode())
            response = http.client.HTTPResponse(secured)
            response.begin()
            response.read(4096)
            return response.status == 200


def tls_ready(address, hostname, port):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((address, port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=hostname):
            return True


def main():
    module = AnsibleModule(argument_spec={
        'kind': {'type': 'str', 'choices': ['relay', 'bot', 'tls'], 'required': True},
        'address': {'type': 'str', 'default': '127.0.0.1'},
        'hostname': {'type': 'str'},
        'port': {'type': 'int', 'default': 443},
    }, supports_check_mode=True)
    try:
        ready = (relay_ready() if module.params['kind'] == 'relay' else bot_ready() if module.params['kind'] == 'bot'
                 else tls_ready(module.params['address'], module.params['hostname'], module.params['port']))
        if not ready:
            raise ValueError('not_ready')
        module.exit_json(changed=False, ready=True)
    except (OSError, ValueError, KeyError):
        module.fail_json(msg='ingress_probe_failed', ready=False)


if __name__ == '__main__':
    main()
