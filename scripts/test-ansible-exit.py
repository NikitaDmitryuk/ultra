#!/usr/bin/env python3
"""Actual SSH/Ansible exit-role test in a disposable container, without production inputs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    result = subprocess.run(arguments, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        # This driver consumes generated fixture credentials only.
        if arguments[0] == 'ssh':
            print(result.stderr.decode(), flush=True)
        result.check_returncode()
    return result.stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installer', required=True)
    parser.add_argument('--ansible-playbook', required=True)
    parser.add_argument('--runtime', help='optional offline Python 3.12 runtime archive')
    arguments = parser.parse_args()
    image = 'ultra-ansible-exit-fixture'
    run(['docker', 'build', '-q', '-t', image, str(ROOT / 'deploy/ansible/tests')])
    with tempfile.TemporaryDirectory(prefix='ultra-ansible-fixture-') as temporary:
        directory = Path(temporary)
        identity = directory / 'identity'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(identity)])
        container = run(['docker', 'run', '-d', '--network', 'bridge', '-p', '127.0.0.1::22', image])
        worker = None
        try:
            if arguments.runtime:
                run(['docker', 'cp', arguments.runtime, container + ':/tmp/runtime.tar.gz'])
                run(['docker', 'exec', container, 'mkdir', '-p', '/tmp/runtime'])
                run(['docker', 'exec', container, 'tar', '-xzf', '/tmp/runtime.tar.gz', '-C', '/tmp/runtime'])
                run(['docker', 'exec', container, 'python3', '-m', 'venv', '/tmp/runtime-venv'])
                run(['docker', 'exec', container, '/tmp/runtime-venv/bin/pip', 'install', '--no-index',
                     '--require-hashes', '--find-links=/tmp/runtime/wheels', '-r', '/tmp/runtime/requirements.lock'])
                assert 'core 2.20.0' in run(['docker', 'exec', container, '/tmp/runtime-venv/bin/ansible-playbook', '--version'])
            run(['docker', 'cp', str(ROOT / 'deploy/ansible/tests/ufw.py'), container + ':/usr/sbin/ufw'])
            run(['docker', 'exec', container, 'chmod', '755', '/usr/sbin/ufw'])
            port = int(run(['docker', 'port', container, '22/tcp']).split(':')[-1])
            run(['docker', 'cp', str(identity.with_suffix('.pub')), container + ':/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chown', 'root:root', '/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chmod', '600', '/root/.ssh/authorized_keys'])
            key = run(['docker', 'exec', container, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub']).split()
            known_hosts = directory / 'known_hosts'
            known_hosts.write_text(f'[127.0.0.1]:{port} {key[0]} {key[1]}\n')
            known_hosts.chmod(0o600)
            # Confirm the same pinned SSH endpoint before involving Ansible.
            run(['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                 '-o', 'UserKnownHostsFile=' + str(known_hosts), '-p', str(port), '-i', str(identity),
                 'root@127.0.0.1', 'true'])
            binary = directory / 'ultra-relay'
            binary.write_text('#!/bin/sh\nexit 0\n')
            request = {
                'host': '127.0.0.1', 'port': port, 'user': 'root', 'identity': str(identity),
                'known_hosts': str(known_hosts), 'bridge_ipv4': '192.0.2.1',
                'spec': {'role': 'exit', 'schema_version': 1, 'mimic_preset': 'steamlike',
                         'listen_address': '0.0.0.0', 'vless_port': 8443,
                         'splithttp_host': 'example.com', 'splithttp_path': '/fixture',
                         'exit': {'tunnel_uuid': str(uuid.uuid4())},
                         'exit_cert': {'cert_file': '/etc/ultra-relay/fullchain.pem', 'key_file': '/etc/ultra-relay/privkey.pem'}},
            }
            request_file = directory / 'request.json'
            request_file.write_text(json.dumps(request))
            request_file.chmod(0o600)
            socket = directory / 'worker.sock'
            worker = subprocess.Popen([arguments.installer, 'ansible-controller', '--state', str(directory / 'state'),
                                       '--socket', str(socket), '--python', shutil.which('python3'),
                                       '--executable', arguments.ansible_playbook, '--allowed-user', run(['id', '-un'])],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 10
            while not socket.exists() and time.monotonic() < deadline:
                if worker.poll() is not None:
                    raise ValueError('fixture controller exited')
                time.sleep(0.05)
            pins = []
            restart_counts = []
            for _ in range(2):
                operation = str(uuid.uuid4())
                try:
                    run([arguments.installer, 'ansible-exit', '--socket', str(socket), '--request', str(request_file),
                         '--binary', str(binary), '--id', operation], timeout=180)
                except subprocess.CalledProcessError:
                    receipt = directory / 'state' / operation / 'receipt.json'
                    if receipt.exists():
                        print(json.loads(receipt.read_text()).get('diagnostic', {'code': 'fixture_failed'}), flush=True)
                    raise
                result = json.loads((directory / 'state' / operation / 'receipt.json').read_text())
                pins.append(result['result']['cert_pin'])
                restart_counts.append(json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))['activations'])
            assert pins[0] == pins[1], 'certificate was rotated on repeated configuration'
            state = json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))
            assert state['active'] and state['enabled']
            assert restart_counts[0] >= 1 and restart_counts[0] == restart_counts[1], 'unchanged configuration restarted the service: ' + str(restart_counts)
            installed = json.loads(run(['docker', 'exec', container, 'cat', '/etc/ultra-relay/spec.json']))
            assert installed['exit']['tunnel_uuid'] == request['spec']['exit']['tunnel_uuid'], 'route UUID changed'
            # A configuration string must stay literal rather than evaluate a lookup on the controller.
            sentinel = directory / 'template-injection'
            request['spec']['splithttp_path'] = "/{{ lookup('ansible.builtin.pipe', 'touch " + str(sentinel) + "') }}"
            request_file.write_text(json.dumps(request))
            operation = str(uuid.uuid4())
            run([arguments.installer, 'ansible-exit', '--socket', str(socket), '--request', str(request_file),
                 '--binary', str(binary), '--id', operation], timeout=180)
            assert not sentinel.exists(), 'peer configuration evaluated a controller lookup'
            installed = json.loads(run(['docker', 'exec', container, 'cat', '/etc/ultra-relay/spec.json']))
            assert installed['splithttp_path'] == request['spec']['splithttp_path'], 'literal configuration changed'
            calls = json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-ufw.json']))
            expected = ['allow', 'from', request['bridge_ipv4'], 'to', 'any', 'port', str(request['spec']['vless_port']), 'proto', 'tcp']
            assert calls == [expected], 'firewall exposed more than the pinned bridge path'
            run(['docker', 'exec', container, 'touch', '/var/lib/fixture-ufw-inactive'])
            run([arguments.installer, 'ansible-exit', '--socket', str(socket), '--request', str(request_file), '--binary', str(binary), '--id', str(uuid.uuid4())], timeout=180)
            assert json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-ufw.json'])) == calls, 'inactive firewall was modified'
            print('SSH/Ansible exit-role fixture passed; systemd and tunnel payload are outside this fixture')
        finally:
            if worker:
                worker.terminate()
                try:
                    worker.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.communicate()
            subprocess.run(['docker', 'rm', '-f', container], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
