#!/usr/bin/env python3
"""Real SSH release-role regression; fixture systemd/probe, no production inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ansible-playbook', required=True)
    args = parser.parse_args()
    run(['docker', 'build', '-q', '-t', 'ultra-ansible-exit-fixture', str(ROOT / 'deploy/ansible/tests')])
    with tempfile.TemporaryDirectory(prefix='ultra-release-fixture-') as name:
        directory = Path(name)
        key = directory / 'identity'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
        container = run(['docker', 'run', '-d', '-p', '127.0.0.1::22', 'ultra-ansible-exit-fixture'])
        try:
            run(['docker', 'cp', str(key.with_suffix('.pub')), container + ':/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chown', 'root:root', '/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chmod', '600', '/root/.ssh/authorized_keys'])
            public = run(['docker', 'exec', container, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub']).split()
            port = run(['docker', 'port', container, '22/tcp']).split(':')[-1]
            pins = directory / 'pins'
            pins.write_text(f'[127.0.0.1]:{port} {public[0]} {public[1]}\n')
            old = b'#!/bin/sh\n# old compatible release\nexit 0\n'
            new = b'#!/bin/sh\n# new compatible release\nexit 0\n'
            old_file = directory / 'old'
            old_file.write_bytes(old)
            old_file.chmod(0o755)
            run(['docker', 'exec', container, 'mkdir', '-p', '/opt/ultra-recovery'])
            run(['docker', 'cp', str(old_file), container + ':/opt/ultra-recovery/monitor.py'])
            run(['docker', 'cp', str(old_file), container + ':/usr/local/bin/ultra-relay'])
            probe = directory / 'probe'
            probe.write_text('#!/bin/sh\ntest ! -f /tmp/probe-failure\n')
            probe.chmod(0o755)
            run(['docker', 'cp', str(probe), container + ':/usr/local/bin/ultra-install'])
            release = directory / 'release'
            release.mkdir()
            asset = 'ultra-relay-linux-amd64'
            (release / asset).write_bytes(new)
            tool_source = release / 'monitor.py'
            tool_source.write_bytes(new)
            def manifest(version, data):
                return {'version': version, 'database_schema_min': 24, 'database_schema_max': 25,
                        'capabilities': ['service-access-v1', 'provider-pool-quota-v1'],
                        'assets': [{'name': asset, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]}
            inventory = {'all': {'children': {'exits': {'hosts': {'fixture': {
                'ansible_host': '127.0.0.1', 'ansible_port': int(port), 'ansible_user': 'root',
                'ansible_ssh_private_key_file': str(key), 'ansible_ssh_args': '-F /dev/null -o ControlMaster=no',
                'ansible_ssh_common_args': '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + str(pins),
                'ultra_architecture': 'amd64', 'ultra_exit_id': 'fixture'} }}, 'bridge': {'hosts': {}}}}}
            variables = {'ultra_release_version': 'v2.4.7', 'ultra_release_source': str(release),
                         'ultra_release_manifest': manifest('v2.4.7', new),
                         'ultra_previous_manifest': manifest('v2.4.6', old),
                         'ultra_bridge_inventory_host': 'fixture', 'ultra_recovery_files': [{
                             'source': str(tool_source), 'destination': '/opt/ultra-recovery/monitor.py',
                             'mode': '0755', 'sha256': hashlib.sha256(new).hexdigest(),
                             'previous_sha256': hashlib.sha256(old).hexdigest(),
                             'backup_name': hashlib.sha256(b'/opt/ultra-recovery/monitor.py').hexdigest()}]}
            (directory / 'inventory.json').write_text(json.dumps(inventory))
            (directory / 'vars.json').write_text(json.dumps(variables))
            playbook = directory / 'test.yml'
            playbook.write_text('---\n- name: Exercise release activation\n  hosts: exits\n  gather_facts: false\n  vars:\n    release_component: ultra-relay\n  tasks:\n    - name: Activate relay\n      ansible.builtin.include_role:\n        name: release\n    - name: Activate runtime tools\n      ansible.builtin.include_role:\n        name: release\n        tasks_from: tools\n')
            env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'ANSIBLE_CONFIG': str(ROOT / 'deploy/ansible/ansible.cfg'),
                   'ANSIBLE_ROLES_PATH': str(ROOT / 'deploy/ansible/roles'),
                   'ANSIBLE_LOCAL_TEMP': str(directory / 'ansible-temp'), 'ANSIBLE_HOME': str(directory / 'ansible-home')}
            command = [args.ansible_playbook, '-i', str(directory / 'inventory.json'), '-e', '@' + str(directory / 'vars.json'), str(playbook)]
            run(command, env=env, timeout=180)
            actual = run(['docker', 'exec', container, 'sha256sum', '/usr/local/bin/ultra-relay']).split()[0]
            assert actual == hashlib.sha256(new).hexdigest()
            fallback = '/var/lib/ultra-ansible/releases/v2.4.7/ultra-relay.previous'
            assert run(['docker', 'exec', container, 'sha256sum', fallback]).split()[0] == hashlib.sha256(old).hexdigest()
            first = json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))['activations']
            run(command, env=env, timeout=180)
            second = json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))['activations']
            assert first == second, 'idempotent replay restarted the unchanged release'
            run(['docker', 'exec', container, 'touch', '/tmp/probe-failure'])
            failure = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            assert failure.returncode != 0, 'failed probe was reported as success'
            actual = run(['docker', 'exec', container, 'sha256sum', '/usr/local/bin/ultra-relay']).split()[0]
            assert actual == hashlib.sha256(old).hexdigest(), 'compatible rollback did not restore executable bytes'
            assert run(['docker', 'exec', container, 'sha256sum', fallback]).split()[0] == hashlib.sha256(old).hexdigest()
            # A failed bridge readiness probe runs after target activation. Its
            # local rescue must leave the fallback stopped while fleet rollback
            # still needs to restore the exits (and may fail doing so).
            hosts = inventory['all']['children']
            hosts['bridge']['hosts'] = hosts['exits']['hosts']
            hosts['exits']['hosts'] = {}
            variables['ultra_legacy_bridge_maintenance'] = True
            (directory / 'inventory.json').write_text(json.dumps(inventory))
            (directory / 'vars.json').write_text(json.dumps(variables))
            playbook.write_text('---\n- name: Fail legacy bridge readiness\n  hosts: bridge\n  gather_facts: false\n  vars:\n    release_component: ultra-relay\n  tasks:\n    - name: Activate bridge relay\n      ansible.builtin.include_role:\n        name: release\n')
            before = json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))['activations']
            failure = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            assert failure.returncode != 0, 'failed legacy bridge readiness was reported as success'
            restored = json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))
            assert not restored['active'], 'legacy bridge rescue reopened traffic before fleet rollback'
            assert restored['activations'] == before + 1, 'legacy bridge fallback was restarted locally'
            assert run(['docker', 'exec', container, 'sha256sum', '/usr/local/bin/ultra-relay']).split()[0] == hashlib.sha256(old).hexdigest()
            # The common rollback starts an already restored bridge only after
            # the exit play succeeds. Prove a failed exit blocks that later play.
            hosts['exits']['hosts'] = {'failed-exit': dict(hosts['bridge']['hosts']['fixture'])}
            (directory / 'inventory.json').write_text(json.dumps(inventory))
            playbook.write_text('---\n- name: Fail exit fleet rollback\n  hosts: exits\n  gather_facts: false\n  any_errors_fatal: true\n  tasks:\n    - name: Simulate exit rollback failure\n      ansible.builtin.fail:\n        msg: fixture_exit_rollback_failed\n- name: Resume restored bridge after exits\n  hosts: bridge\n  gather_facts: false\n  tasks:\n    - name: Start restored bridge\n      ansible.builtin.systemd_service:\n        name: ultra-relay.service\n        state: started\n')
            failure = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            assert failure.returncode != 0, 'exit rollback failure was reported as success'
            assert not json.loads(run(['docker', 'exec', container, 'cat', '/var/lib/fixture-systemctl.json']))['active'], 'failed exit rollback allowed the legacy bridge to start'
            playbook.write_text('---\n- name: Restore compatible tools\n  hosts: exits\n  gather_facts: false\n  tasks:\n    - name: Restore tools\n      ansible.builtin.include_role:\n        name: release\n        tasks_from: rollback-tools\n')
            run(command, env=env, timeout=180)
            assert run(['docker', 'exec', container, 'sha256sum', '/opt/ultra-recovery/monitor.py']).split()[0] == hashlib.sha256(old).hexdigest()
            print('Release SSH role: activation, replay, preserved fallback, failed-probe rollback and legacy bridge barrier passed; real systemd/payload remain separate acceptance')
        finally:
            subprocess.run(['docker', 'rm', '-f', container], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
