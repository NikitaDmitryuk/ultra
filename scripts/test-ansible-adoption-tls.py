#!/usr/bin/env python3
"""Exercise adoption TLS guards locally with actual Ansible and synthetic facts."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = os.environ.get('ANSIBLE_PLAYBOOK', 'ansible-playbook')
PIN = 'a' * 64
OTHER = 'b' * 64


class AdoptionTLSTests(unittest.TestCase):
    def run_tasks(self, tasks, values, okay=True):
        with tempfile.TemporaryDirectory(prefix='ultra-adoption-tls-') as directory:
            path = Path(directory)
            tasks = copy.deepcopy(tasks)
            # The topology module has separate DB integration tests. Stub only its
            # action here; retain the production task and every actual TLS guard.
            for task in tasks:
                imported = task.get('ansible.builtin.import_tasks')
                if imported and not Path(imported).is_absolute():
                    task['ansible.builtin.import_tasks'] = str(ROOT / 'deploy/ansible/playbooks' / imported)
                if 'ultra_adopt_topology' in task:
                    del task['ultra_adopt_topology']
                    task['ansible.builtin.assert'] = {'that': [True]}
            tasks.append({'name': 'Save fixture facts', 'ansible.builtin.copy': {
                'content': '{{ {"entries": bootstrap_pinned | default([]), "spec": ultra_spec | default({})} | to_json }}',
                'dest': str(path / 'result.json'), 'mode': '0600'}})
            values = copy.deepcopy(values)
            hosts = values.pop('hostvars', {})
            hosts['localhost'] = {'ansible_connection': 'local'}
            (path / 'inventory.json').write_text(json.dumps({'all': {'hosts': hosts}}))
            (path / 'play.yml').write_text(yaml.safe_dump([{
                'name': 'Local synthetic TLS contract', 'hosts': 'localhost', 'gather_facts': False,
                'vars': values, 'tasks': tasks}]))
            result = subprocess.run([PLAYBOOK, '-i', str(path / 'inventory.json'), '-c', 'local', str(path / 'play.yml')],
                                    capture_output=True, text=True,
                                    env={**os.environ, 'ANSIBLE_CONFIG': str(ROOT / 'deploy/ansible/ansible.cfg'), 'ANSIBLE_LOCAL_TEMP': str(path / 'local'), 'ANSIBLE_REMOTE_TEMP': str(path / 'remote')})
            self.assertEqual(result.returncode == 0, okay, result.stdout + result.stderr)
            return json.loads((path / 'result.json').read_text()) if okay else None

    def bridge_tasks(self, name):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks' / name).read_text())
        return next(play['pre_tasks'] for play in plays if play['hosts'] == 'bridge' and 'pre_tasks' in play)

    def values(self):
        return {'ultra_preserve_runtime': True,
                'ultra_spec': {'tunnel_tls_provision': 'self_signed', 'exit': {'pinned_peer_cert_sha256': OTHER}},
                'ultra_exit_hosts': {'static': 'exit_static', 'dynamic': 'exit_dynamic'},
                'ultra_bootstrap_pins': {'exit_static': PIN, 'exit_dynamic': OTHER},
                'hostvars': {'exit_static': {'relay_fingerprint': {'stdout': 'sha256 Fingerprint=' + PIN}}, 'exit_dynamic': {'relay_fingerprint': {'stdout': 'sha256 Fingerprint=' + OTHER}}},
                'ultra_bootstrap_entries': [{'name': 'static', 'pinned_peer_cert_sha256': PIN},
                                             {'name': 'dynamic', 'pinned_peer_cert_sha256': OTHER}]}

    def test_adoption_rejects_changed_static_certificate_before_bridge(self):
        for name in ('bootstrap-bridge.yml', 'bootstrap.yml'):
            with self.subTest(playbook=name):
                values = self.values()
                values['ultra_bootstrap_entries'][0]['pinned_peer_cert_sha256'] = OTHER
                self.run_tasks(self.bridge_tasks(name), values, okay=False)

    def test_adoption_preserves_rows_and_active_pin(self):
        for name in ('bootstrap-bridge.yml', 'bootstrap.yml'):
            with self.subTest(playbook=name):
                values = self.values()
                result = self.run_tasks(self.bridge_tasks(name), values)
                self.assertEqual(result['entries'], values['ultra_bootstrap_entries'])
                self.assertEqual(result['spec'], values['ultra_spec'])

    def test_adoption_rejects_unverified_dynamic_topology(self):
        for name in ('bootstrap-bridge.yml', 'bootstrap.yml'):
            with self.subTest(playbook=name):
                values = self.values()
                del values['ultra_exit_hosts']['dynamic']
                self.run_tasks(self.bridge_tasks(name), values, okay=False)

    def test_normal_bootstrap_resolves_actual_pin(self):
        for name in ('bootstrap-bridge.yml', 'bootstrap.yml'):
            with self.subTest(playbook=name):
                values = self.values()
                values['ultra_preserve_runtime'] = False
                for row in values['ultra_bootstrap_entries']:
                    row['pinned_peer_cert_sha256'] = 'old'
                result = self.run_tasks(self.bridge_tasks(name), values)
                self.assertEqual([row['pinned_peer_cert_sha256'] for row in result['entries']], [PIN, OTHER])
                self.assertEqual(result['spec']['exit']['pinned_peer_cert_sha256'], PIN)

    def test_adoption_rejects_missing_or_malformed_receipts(self):
        for name in ('bootstrap-bridge.yml', 'bootstrap.yml'):
            for receipt in ('', 'bad'):
                with self.subTest(playbook=name, receipt=receipt):
                    values = self.values()
                    values['ultra_bootstrap_pins']['exit_static'] = receipt
                    values['hostvars']['exit_static']['relay_fingerprint']['stdout'] = receipt
                    self.run_tasks(self.bridge_tasks(name), values, okay=False)

    def test_adoption_requires_both_existing_tls_files(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/roles/relay/tasks/main.yml').read_text())
        guards = [task for task in tasks if task['name'] in (
            'Reject symlink certificates and require provided TLS when generation is disabled',
            'Require a complete exit TLS pair or a fully fresh managed pair')]
        for exists in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(exists=exists):
                self.run_tasks(guards, {'ultra_spec': {'role': 'exit'}, 'ultra_preserve_runtime': True,
                    'ultra_generate_exit_tls': True, 'relay_existing_tls': {'results': [
                        {'stat': {'exists': value, 'isreg': True, 'islnk': False}} for value in exists]}},
                    okay=all(exists))
        self.run_tasks(guards, {'ultra_spec': {'role': 'exit'}, 'ultra_preserve_runtime': False,
            'ultra_generate_exit_tls': True, 'relay_existing_tls': {'results': [
                {'stat': {'exists': False, 'isreg': False, 'islnk': False}} for _ in range(2)]}})


if __name__ == '__main__':
    unittest.main()
