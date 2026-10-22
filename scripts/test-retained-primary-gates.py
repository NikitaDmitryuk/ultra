#!/usr/bin/env python3
"""Local synthetic checks: unreachable DB cannot admit any recovery mutation play."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / 'deploy/ansible/playbooks'
GATE = PLAYBOOKS / 'tasks/retained-primary-gate.yml'


class RetainedPrimaryGateTests(unittest.TestCase):
    def mutation_plays(self):
        selected = []
        for name in ['rebuild-retained-primary.yml', 'rebuild-retained-bridge.yml', 'bootstrap-exit.yml', 'bootstrap-bridge.yml', 'ingress.yml', 'configure-bot.yml']:
            for play in yaml.safe_load((PLAYBOOKS / name).read_text()):
                host = play.get('hosts', '')
                if host in ['localhost', 'databases'] or not host or (host == 'exits' and not play.get('pre_tasks')):
                    continue
                gates = [task for task in play.get('pre_tasks', []) if task.get('ansible.builtin.import_tasks') == 'tasks/retained-primary-gate.yml']
                self.assertEqual(len(gates), 1, (name, play['name']))
                self.assertEqual(gates[0].get('when'), 'ultra_retained_recovery_binding_sha256 is defined')
                selected.append((play, gates[0]))
        self.assertGreaterEqual(len(selected), 7)
        return selected

    def test_unreachable_or_missing_db_success_never_reaches_mutation(self):
        for scenario in ['missing', 'unreachable', 'success', 'ordinary']:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(prefix='ultra-retained-gate-') as name:
                directory = Path(name)
                database = {'ansible_connection': 'local'}
                if scenario in ['unreachable', 'success']:
                    database['retained_primary_before'] = {'rc': 0, 'unreachable': scenario == 'unreachable'}
                    # Deliberately stale success marker must not mask unreachable.
                    database['retained_primary_readonly_verified'] = True
                inventory = {'all': {'children': {
                    'bridge': {'hosts': {'bridge': {'ansible_connection': 'local'}}},
                    'exits': {'hosts': {'exit_0': {'ansible_connection': 'local'}}},
                    'databases': {'hosts': {'database': database}},
                    'forward_ingress': {'hosts': {'subscription_forward': {'ansible_connection': 'local'}}},
                }}}
                if scenario == 'ordinary':
                    inventory['all']['children'].pop('databases')
                inv = directory / 'inventory.json'
                inv.write_text(json.dumps(inventory))
                plays = []
                for i, (original, gate) in enumerate(self.mutation_plays()):
                    target = original['hosts']
                    if '{{' in target:
                        target = 'exit_0'
                    local_gate = dict(gate, **{'ansible.builtin.import_tasks': str(GATE)})
                    variables = {} if scenario == 'ordinary' else {'ultra_retained_recovery_binding_sha256': 'a' * 64}
                    plays.append({'name': original['name'], 'hosts': target, 'gather_facts': False,
                                  'vars': variables, 'pre_tasks': [local_gate],
                                  'tasks': [{'name': 'Synthetic mutation sentinel', 'ansible.builtin.copy': {
                                      'content': 'mutation admitted', 'dest': str(directory / f'{i}.mutated')}}]})
                book = directory / 'check.yml'
                book.write_text(yaml.safe_dump(plays, sort_keys=False))
                env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'deploy/ansible/ansible.cfg'),
                           ANSIBLE_LOCAL_TEMP=str(directory / 'tmp'), ANSIBLE_REMOTE_TEMP=str(directory / 'remote'))
                executable = os.environ.get('ULTRA_TEST_ANSIBLE_PLAYBOOK', 'ansible-playbook')
                result = subprocess.run([executable, '-i', str(inv), str(book)], env=env,
                                        cwd=ROOT, capture_output=True, text=True, timeout=90)
                admitted = scenario in ['success', 'ordinary']
                self.assertEqual(result.returncode == 0, admitted, result.stdout[-2000:] + result.stderr[-1000:])
                self.assertEqual(len(list(directory.glob('*.mutated'))), len(plays) if admitted else 0)

    def test_subscription_copy_and_template_accept_task_diff_without_leaking_payload(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/roles/upgrade_subscription/tasks/main.yml').read_text())
        with tempfile.TemporaryDirectory(prefix='ultra-subscription-task-') as name:
            directory = Path(name)
            source = directory / 'source.json'
            source.write_text('synthetic_private_keyring_fixture')
            source.chmod(0o600)
            selected = []
            for task in tasks:
                module = next((key for key in ['ansible.builtin.copy', 'ansible.builtin.template'] if key in task), None)
                if not module:
                    continue
                self.assertNotIn('diff', task[module])
                self.assertFalse(task['diff'])
                self.assertTrue(task['no_log'])
                task = dict(task)
                args = dict(task[module])
                args.pop('owner', None)
                args.pop('group', None)
                args['dest'] = str(directory / ('staged.json' if module.endswith('copy') else 'subscription.conf'))
                args['src'] = str(source if module.endswith('copy') else ROOT / 'deploy/ansible/roles/upgrade_subscription/templates/subscription.conf.j2')
                task[module] = args
                selected.append(task)
            book = directory / 'play.yml'
            book.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'tasks': selected}], sort_keys=False))
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(directory / 'local'), ANSIBLE_REMOTE_TEMP=str(directory / 'remote'))
            executable = os.environ.get('ULTRA_TEST_ANSIBLE_PLAYBOOK', 'ansible-playbook')
            result = subprocess.run([executable, '-i', 'localhost,', '--diff', str(book)], env=env, capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stdout[-1000:] + result.stderr[-1000:])
            self.assertEqual((directory / 'staged.json').read_bytes(), source.read_bytes())
            self.assertEqual((directory / 'staged.json').stat().st_mode & 0o777, 0o600)
            self.assertNotIn(source.read_text(), result.stdout + result.stderr)

    def test_final_receipt_requires_successful_after_result(self):
        plays = yaml.safe_load((PLAYBOOKS / 'rebuild-retained-primary.yml').read_text())
        final = plays[-1]['tasks']
        self.assertIn('ansible.builtin.assert', final[0])
        assertions = '\n'.join(final[0]['ansible.builtin.assert']['that'])
        for needed in ['retained_primary_after', 'unreachable', 'failed', 'rc', 'stdout', 'retained_primary_before']:
            self.assertIn(needed, assertions)
        self.assertIn('ansible.builtin.copy', final[1])


if __name__ == '__main__':
    unittest.main()
