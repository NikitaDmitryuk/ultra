#!/usr/bin/python
"""Domain alias subscription identity checks; no host or service changes."""
import importlib.util
import json
import re
import socket
import subprocess
import time
import http.client
import os
from pathlib import Path
import urllib.parse
from ansible.module_utils.basic import AnsibleModule


def save(path, data):
    temporary = path.with_name(path.name + '.next')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def payload(contract, directory, domain, address):
    profile = json.loads(Path('/etc/ultra-recovery/probe.json').read_text())
    old = json.loads((directory / 'before.json').read_text())['primary_xhttp']
    target = {'domain': domain, 'public_host': domain}
    try:
        selected = contract.single_alias_probe(profile, old, target, address)
    except ValueError:
        current = json.loads(Path('/etc/ultra-relay/spec.json').read_text())['primary_xhttp']
        selected = contract.single_alias_probe(profile, current, target, address)
    path = directory / 'payload-probe.json'
    save(path, selected)
    sockets = [socket.socket(), socket.socket()]
    for connection in sockets:
        connection.bind(('127.0.0.1', 0))
    ports = [connection.getsockname()[1] for connection in sockets]
    for connection in sockets:
        connection.close()
    environment = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
    process = subprocess.Popen(['/usr/local/bin/ultra-client', '-config', str(path),
                                '-socks', '127.0.0.1:' + str(ports[0]), '-http', '127.0.0.1:' + str(ports[1])],
                               env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError('probe_client_failed')
            result = subprocess.run(['curl', '--silent', '--fail', '--max-time', '8', '--connect-timeout', '3',
                '--max-filesize', '16384', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:' + str(ports[0]),
                'https://www.cloudflare.com/cdn-cgi/trace'], env=environment, capture_output=True, timeout=10)
            if result.returncode == 0 and re.search(rb'(?m)^ip=[0-9a-fA-F:.]+$', result.stdout):
                return
            time.sleep(.25)
        raise ValueError('payload_unavailable')
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    module = AnsibleModule(argument_spec={
        'phase': {'type': 'str', 'choices': ['baseline', 'verify'], 'required': True},
        'directory': {'type': 'path', 'required': True},
        'subscription_url': {'type': 'str', 'required': True, 'no_log': True},
        'subscription_domain': {'type': 'str', 'required': True},
        'bridge_ipv4': {'type': 'str', 'required': True},
        'domain': {'type': 'str', 'required': True},
    }, supports_check_mode=False)
    try:
        source = Path('/opt/ultra-recovery/cutover_contract.py')
        if source.is_symlink() or source.stat().st_uid != 0 or source.stat().st_mode & 0o022:
            raise ValueError('untrusted_cutover_contract')
        specification = importlib.util.spec_from_file_location('ultra_cutover_contract', source)
        contract = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(contract)
        parsed = urllib.parse.urlsplit(module.params['subscription_url'])
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or not parsed.path.startswith('/sub/') or any(char in parsed.path for char in '\r\n '):
            raise ValueError('private_subscription_url_invalid')
        directory = Path(module.params['directory'])
        for fmt in ('happ', 'uri'):
            baseline = directory / ('subscription-' + fmt + '.json')
            path = parsed.path + '?format=' + fmt
            if module.params['phase'] == 'baseline':
                shape = contract.subscription_shape(contract.https(parsed.hostname, parsed.hostname, parsed.port or 443, path))
                if baseline.exists():
                    if baseline.is_symlink() or json.loads(baseline.read_text()) != shape:
                        raise ValueError('subscription_identity_changed')
                else:
                    save(baseline, shape)
            else:
                body = contract.https(module.params['subscription_domain'], module.params['bridge_ipv4'], 443, path)
                if json.loads(baseline.read_text()) != contract.subscription_shape(body):
                    raise ValueError('subscription_identity_changed')
                expected = (module.params['domain'], module.params['domain'])
                if expected not in contract.subscription_tls_endpoints(body):
                    raise ValueError('new_domain_not_published')
        if module.params['phase'] == 'verify':
            payload(contract, directory, module.params['domain'], module.params['bridge_ipv4'])
        module.exit_json(changed=False, verified=True)
    except (OSError, KeyError, ValueError, TypeError, subprocess.SubprocessError, http.client.HTTPException):
        module.fail_json(msg='cutover_subscription_probe_failed')


if __name__ == '__main__':
    main()
