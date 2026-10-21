#!/usr/bin/env python3
"""Exercise strict tunnel reuse locally with synthetic keys and primary files."""
import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / 'deploy/ansible/roles/db_tunnel'


class TunnelReuseTests(unittest.TestCase):
    def test_default_generation_and_primary_writes_are_guarded(self):
        generate = yaml.safe_load((ROLE / 'tasks/generate.yml').read_text())
        generation = next(task for task in generate if task['name'] == 'Generate dedicated Ed25519 key when absent')
        self.assertEqual(generation['ansible.builtin.command']['creates'], '/etc/ultra-db-tunnel/id_ed25519')
        self.assertIn('length == 0', generation['when'])
        authorization = yaml.safe_load((ROLE / 'tasks/authorize.yml').read_text())
        mutations = [task for task in authorization if any(name in task for name in ('ansible.builtin.user', 'ansible.builtin.file', 'ansible.builtin.copy'))]
        self.assertEqual(len(mutations), 4)
        for task in mutations:
            self.assertIn('length == 0', task['when'])
        reuse = yaml.safe_load((ROLE / 'tasks/reuse.yml').read_text())
        for task in reuse:
            if 'ansible.builtin.copy' in task:
                self.assertTrue(task['no_log'])
                self.assertFalse(task['diff'])
                self.assertEqual(task['ansible.builtin.copy']['mode'], '0600')
        verify = next(task for task in reuse if task['name'] == 'Verify preserved identity is already narrowly authorized on primary')
        self.assertEqual(verify['delegate_to'], 'database')
        self.assertFalse(verify['changed_when'])
        self.assertTrue(verify['no_log'])
        self.assertNotIn('write', verify['ansible.builtin.command']['argv'][-1])
        self.assertLess(reuse.index(verify), next(i for i, task in enumerate(reuse)
                                                  if task['name'] == 'Install preserved database tunnel private key'))

    def test_restart_only_after_install_even_when_only_private_key_changed(self):
        generate = yaml.safe_load((ROLE / 'tasks/generate.yml').read_text())
        reuse = yaml.safe_load((ROLE / 'tasks/reuse.yml').read_text())
        install = yaml.safe_load((ROLE / 'tasks/install.yml').read_text())
        for task in generate + reuse + install:
            self.assertNotIn('notify', task, task['name'])
            self.assertNotEqual(task.get('ansible.builtin.meta'), 'flush_handlers')
        self.assertFalse(any('ansible.builtin.systemd_service' in task for task in generate + reuse))
        services = [(i, task) for i, task in enumerate(install) if 'ansible.builtin.systemd_service' in task]
        self.assertEqual(len(services), 1)
        restart_index, restart = services[0]
        self.assertEqual(restart['ansible.builtin.systemd_service'], {
            'name': 'ultra-db-tunnel.service', 'enabled': True,
            'state': 'restarted', 'daemon_reload': True,
        })
        self.assertNotIn('when', restart)  # Also runs if only the key changed in generate.
        for name in ('Install pinned database SSH host keys', 'Enforce private key permissions',
                     'Install database tunnel systemd unit'):
            self.assertLess(next(i for i, task in enumerate(install) if task['name'] == name), restart_index)
        self.assertGreater(next(i for i, task in enumerate(install)
                                if 'ansible.builtin.wait_for' in task), restart_index)

    def test_local_reuse_pins_source_derives_public_and_never_logs_private_material(self):
        with tempfile.TemporaryDirectory(prefix='ultra-tunnel-reuse-') as name:
            directory = Path(name)
            source = directory / 'preserved'
            unrelated = directory / 'other'
            for key in (source, unrelated):
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            private = source.read_text()
            public = source.with_suffix('.pub').read_text().strip()
            source.with_suffix('.pub').write_text(unrelated.with_suffix('.pub').read_text())
            destination = directory / 'bridge'
            destination.mkdir(mode=0o700)
            auth = directory / 'authorized_keys'
            expected_auth = f'restrict,port-forwarding,permitopen="127.0.0.1:5432" {public}\n'
            auth.write_text(expected_auth)
            auth.chmod(0o600)
            tasks = yaml.safe_load((ROLE / 'tasks/reuse.yml').read_text().replace('/etc/ultra-db-tunnel', str(destination)))
            for task in tasks:
                if 'ansible.builtin.copy' in task:
                    task['ansible.builtin.copy']['owner'] = pwd.getpwuid(os.getuid()).pw_name
                    task['ansible.builtin.copy']['group'] = grp.getgrgid(os.getgid()).gr_name
            # Synthetic primary account/path; all production checks remain active.
            verify = next(task for task in tasks if task['name'] == 'Verify preserved identity is already narrowly authorized on primary')
            script = verify['ansible.builtin.command']['argv'][-1]
            script = script.replace("pwd.getpwnam('ultra-db-tunnel')", f'pwd.getpwnam({pwd.getpwuid(os.getuid()).pw_name!r})')
            script = script.replace("'/var/lib/ultra-db-tunnel/.ssh/authorized_keys'", repr(str(auth)))
            verify['ansible.builtin.command']['argv'][-1] = script
            inventory = directory / 'inventory.json'
            inventory.write_text(json.dumps({'all': {'hosts': {'bridge': {'ansible_connection': 'local'}, 'database': {'ansible_connection': 'local', 'ansible_become': False}}}}))
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            playbook = directory / 'check.yml'
            playbook.write_text(yaml.safe_dump([{
                'hosts': 'bridge', 'gather_facts': False,
                'vars': {'ultra_db_tunnel_private_key_source': str(source), 'ultra_db_tunnel_private_key_sha256': digest},
                'tasks': tasks,
            }], sort_keys=False))
            environment = os.environ.copy()
            environment['ANSIBLE_CONFIG'] = str(ROOT / 'deploy/ansible/ansible.cfg')
            environment['ANSIBLE_LOCAL_TEMP'] = str(directory / 'ansible-local')

            def run(expected):
                result = subprocess.run(['ansible-playbook', '-i', str(inventory), '--limit', 'bridge', str(playbook)],
                                        cwd=ROOT, env=environment, capture_output=True, text=True)
                # Never print captured logs if a secret leak occurs.
                for line in private.splitlines():
                    self.assertNotIn(line, result.stdout + result.stderr, 'private material leaked into Ansible logs')
                if (result.returncode == 0) != expected:
                    self.fail(f'Unexpected Ansible exit {result.returncode}; synthetic diagnostic: {result.stdout[-2500:]} {result.stderr[-1000:]}')
                self.assertEqual(auth.read_text(), expected_auth if expected else auth_before)

            run(True)
            self.assertEqual((destination / 'id_ed25519').read_bytes(), source.read_bytes())
            self.assertEqual((destination / 'id_ed25519.pub').read_text().split()[:2], public.split()[:2])
            self.assertEqual((destination / 'id_ed25519').stat().st_mode & 0o777, 0o600)
            auth.write_text(expected_auth + f'{public}\n')
            auth_before = auth.read_text()
            run(False)
            self.assertEqual((destination / 'id_ed25519').read_bytes(), source.read_bytes())
            auth.write_text(expected_auth + f'command="/usr/bin/true extra" ssh-ed25519 {public.split()[1]}\n')
            auth_before = auth.read_text()
            run(False)
            self.assertEqual((destination / 'id_ed25519').read_bytes(), source.read_bytes())
            auth.write_text('restrict ssh-ed25519 AAAAunknown fixture\n')
            auth_before = auth.read_text()
            run(False)
            self.assertEqual((destination / 'id_ed25519').read_bytes(), source.read_bytes())
            # Frozen digest rejects replacement before it can replace bridge identity.
            source.write_text(unrelated.read_text())
            run(False)
            self.assertEqual((destination / 'id_ed25519').read_text(), private)


if __name__ == '__main__':
    unittest.main()
