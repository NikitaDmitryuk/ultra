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
import hashlib
import stat
from pathlib import Path
import urllib.parse
from ansible.module_utils.basic import AnsibleModule


def private_subscription_url(parameters):
    """Consume the frozen credential without putting it in module arguments."""
    path = parameters.get('subscription_url_file')
    if not path:
        return parameters.get('subscription_url')
    if parameters.get('subscription_url') or not re.fullmatch(r'[a-f0-9]{64}', parameters.get('subscription_url_sha256', '')):
        raise ValueError('private_subscription_url_invalid')
    source = Path(path)
    if not source.is_absolute() or str(source) != os.path.normpath(path) or any(parent.is_symlink() for parent in source.parents):
        raise ValueError('private_subscription_url_invalid')
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid() or info.st_nlink != 1 or not 0 < info.st_size <= 4096:
            raise ValueError('private_subscription_url_invalid')
        raw = stream.read(4097)
    if len(raw) > 4096 or hashlib.sha256(raw).hexdigest() != parameters['subscription_url_sha256']:
        raise ValueError('private_subscription_url_invalid')
    value = raw.decode('utf-8').removesuffix('\n')
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'https' or parsed.netloc != parameters.get('subscription_source_domain') or
            parsed.query or parsed.fragment or re.search(r'[\s\x00]', value) or
            not re.fullmatch(r'/sub/[A-Za-z0-9_-]{1,1024}', parsed.path)):
        raise ValueError('private_subscription_url_invalid')
    return value


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


def payload(contract, directory, domain, address, public_host=None, path=None):
    profile = json.loads(Path('/etc/ultra-recovery/probe.json').read_text())
    old = json.loads((directory / 'before.json').read_text())['primary_xhttp']
    target = {'domain': domain, 'public_host': public_host or domain, 'path': path or old['path']}
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
        'subscription_url': {'type': 'str', 'no_log': True},
        'subscription_url_file': {'type': 'path'},
        'subscription_url_sha256': {'type': 'str'},
        'subscription_source_domain': {'type': 'str'},
        'subscription_domain': {'type': 'str', 'required': True},
        'bridge_ipv4': {'type': 'str', 'required': True},
        'domain': {'type': 'str', 'required': True},
        'public_host': {'type': 'str'},
        'path': {'type': 'str'},
    }, supports_check_mode=False)
    try:
        source = Path('/opt/ultra-recovery/cutover_contract.py')
        if source.is_symlink() or source.stat().st_uid != 0 or source.stat().st_mode & 0o022:
            raise ValueError('untrusted_cutover_contract')
        specification = importlib.util.spec_from_file_location('ultra_cutover_contract', source)
        contract = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(contract)
        parsed = urllib.parse.urlsplit(private_subscription_url(module.params))
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
                expected = (module.params['public_host'] or module.params['domain'], module.params['domain'])
                if expected not in contract.subscription_tls_endpoints(body):
                    raise ValueError('new_domain_not_published')
        if module.params['phase'] == 'verify':
            payload(contract, directory, module.params['domain'], module.params['bridge_ipv4'], module.params['public_host'], module.params['path'])
        module.exit_json(changed=False, verified=True)
    except (OSError, KeyError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError, http.client.HTTPException):
        module.fail_json(msg='cutover_subscription_probe_failed')


if __name__ == '__main__':
    main()
