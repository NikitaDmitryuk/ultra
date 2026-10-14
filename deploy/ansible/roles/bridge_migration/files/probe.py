#!/usr/bin/python3
"""Full client payload check, no service installation or direct fallback."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tempfile
import urllib.parse


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def target_profile(document, target):
    """Pin the real target IP without changing TLS/REALITY identity or credentials."""
    address = str(ipaddress.ip_address(target))
    if 'profiles' in document:
        matches = [p for p in document['profiles'] if p.get('id') == 'fast_tcp_reality']
        if len(matches) != 1:
            raise ValueError('unambiguous_monitor_profile_required')
        document = matches[0]
    if 'full_xray_config_base64' in document:
        document = json.loads(base64.b64decode(document['full_xray_config_base64'], validate=True))
    candidates = [p for p in document.get('outbounds', []) if p.get('protocol') == 'vless']
    if len(candidates) != 1:
        raise ValueError('unambiguous_bridge_outbound_required')
    proxy = candidates[0]
    destinations = proxy.get('settings', {}).get('vnext', [])
    if len(destinations) != 1 or not destinations[0].get('users'):
        raise ValueError('bridge_credentials_required')
    destinations[0]['address'] = address
    proxy['tag'] = 'migration-target'
    # Neither another bridge, a routing bypass nor an observatory may pass the check.
    document['outbounds'] = [proxy]
    document['routing'] = {'rules': [{'type': 'field', 'network': 'tcp,udp',
                                    'outboundTag': 'migration-target'}]}
    for name in ('observatory', 'burstObservatory'):
        document.pop(name, None)
    return document


def main():
    destination = urllib.parse.urlsplit(sys.argv[1])
    expected = ipaddress.ip_address(sys.argv[2])
    if destination.scheme != 'https' or not destination.hostname or destination.username or destination.password:
        raise ValueError('https_payload_endpoint_required')
    profile = Path('/etc/ultra-recovery/probe.json')
    if profile.is_symlink() or not profile.is_file() or profile.stat().st_mode & 0o077:
        raise ValueError('private_monitor_profile_required')
    socks, http = port(), port()
    if socks == http:
        raise ValueError('distinct_probe_ports_required')
    environment = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
    temporary = tempfile.TemporaryDirectory(prefix="ultra-migration-probe-")
    rendered = Path(temporary.name) / "client.json"
    rendered.write_text(json.dumps(target_profile(json.loads(profile.read_text()), sys.argv[3])))
    rendered.chmod(0o600)
    process = subprocess.Popen(['/usr/local/bin/ultra-client', '-config', str(rendered),
                                '-socks', '127.0.0.1:' + str(socks), '-http', '127.0.0.1:' + str(http)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError('client_start_failed')
            try:
                with socket.create_connection(('127.0.0.1', socks), timeout=1):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise ValueError('client_start_timeout')
        # The only fetch explicitly uses SOCKS. No direct fallback, no inherited proxy env.
        result = subprocess.run(['curl', '--silent', '--fail', '--show-error', '--max-time', '40',
                                 '--connect-timeout', '10', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:' + str(socks),
                                 urllib.parse.urlunsplit(destination)], env=environment, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45)
        if len(result.stdout) > 8192 or ipaddress.ip_address(result.stdout.decode().strip()) != expected:
            raise ValueError('unexpected_exit_egress')
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        temporary.cleanup()
    print('{"verified":true}')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('migration_client_payload_failed', file=sys.stderr)
        raise SystemExit(1)
