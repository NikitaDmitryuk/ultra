#!/usr/bin/env python3
"""Selected controller and recovery-generation identities must stay aligned."""
import base64
import json
from pathlib import Path
import unittest

import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / 'deploy/ansible/roles/release/tasks'
OLD = '/opt/ultra-ansible/releases/v2.4.6'
NEW = '/opt/ultra-ansible/releases/v2.4.7'


def encoded(value):
    return {'content': base64.b64encode(json.dumps(value).encode()).decode()}


def render(value, variables):
    return Templar(loader=DataLoader(), variables=variables).template(trust_as_template(value))


class Identity(unittest.TestCase):
    def test_upgrade_generation_contains_the_selected_controller(self):
        retired_units = ['/etc/systemd/system/ultra-auto-upgrade.service',
                         '/etc/systemd/system/ultra-auto-upgrade.timer']
        backup = {'artifact_paths': [OLD, '/usr/local/bin/ultra-relay', '/unrelated/retain'],
                  'state_paths': ['/etc/ultra-ansible', *retired_units]}
        identity = ROLE / 'backup-identity.yml'
        if identity.exists():
            tasks = yaml.safe_load(identity.read_text())
            variables = {'release_backup_controller_directory': NEW,
                         'ultra_previous_controller_directory': OLD, 'ultra_controller_directory': NEW,
                         'release_identity_backup': encoded(backup),
                         'release_identity_deployment': encoded({'controller_directory': OLD, 'other': 'retain'})}
            outputs = {task['ansible.builtin.copy']['dest']: json.loads(render(task['ansible.builtin.copy']['content'], variables))
                       for task in tasks if 'ansible.builtin.copy' in task}
            result = outputs['/etc/ultra-recovery/backup.json']
            self.assertEqual(outputs['/etc/ultra-recovery/deployment.json']['controller_directory'], NEW)
            self.assertEqual(outputs['/etc/ultra-recovery/deployment.json']['other'], 'retain')
        else:
            tasks = yaml.safe_load((ROLE / 'publish.yml').read_text())
            copy = next(task['ansible.builtin.copy'] for task in tasks
                        if task.get('ansible.builtin.copy', {}).get('dest') == '/etc/ultra-recovery/backup.json')
            result = json.loads(render(copy['content'], {'release_publish_backup_policy': encoded(backup),
                                'release_publish_backup_signatures': {'results': []},
                                'ultra_controller_directory': NEW, 'ultra_previous_controller_directory': OLD}))
        self.assertIn(NEW, result['artifact_paths'], 'new controller unit points outside the backed-up runtime')
        self.assertNotIn(OLD, result['artifact_paths'])
        self.assertIn('/unrelated/retain', result['artifact_paths'])
        self.assertFalse(set(retired_units) & set(result['state_paths']),
                         'retired upgrade units cannot remain required backup paths')

    def test_publication_preserves_ownership_catalog_without_rewriting_artifact_refs(self):
        tasks = yaml.safe_load((ROLE / 'publish.yml').read_text())
        copy = next(task['ansible.builtin.copy'] for task in tasks
                    if task.get('ansible.builtin.copy', {}).get('dest') == '/etc/ultra-recovery/backup.json')
        backup = {'artifact_paths': [NEW, '/unrelated/retain'], 'state_paths': ['/etc/ultra-ansible']}
        variables = {'release_publish_backup_policy': encoded(backup),
                     'release_publish_backup_signatures': {'results': []}}
        result = json.loads(render(copy['content'], variables))
        self.assertIn('/var/lib/ultra-ansible/retention', result['state_paths'])
        self.assertEqual(result['artifact_paths'], sorted(backup['artifact_paths']))
        variables['release_publish_backup_policy'] = encoded(result)
        self.assertEqual(json.loads(render(copy['content'], variables)), result)

    def test_rollback_generation_selects_the_compatible_controller(self):
        identity = ROLE / 'backup-identity.yml'
        self.assertTrue(identity.exists(), 'no shared controller recovery identity update')
        tasks = yaml.safe_load(identity.read_text())
        variables = {'release_backup_controller_directory': OLD, 'ultra_previous_controller_directory': OLD,
                     'ultra_controller_directory': NEW,
                     'release_identity_backup': encoded({'artifact_paths': [NEW, '/unrelated/retain']}),
                     'release_identity_deployment': encoded({'controller_directory': NEW})}
        outputs = {task['ansible.builtin.copy']['dest']: json.loads(render(task['ansible.builtin.copy']['content'], variables))
                   for task in tasks if 'ansible.builtin.copy' in task}
        self.assertEqual(outputs['/etc/ultra-recovery/deployment.json']['controller_directory'], OLD)
        self.assertIn(OLD, outputs['/etc/ultra-recovery/backup.json']['artifact_paths'])
        self.assertNotIn(NEW, outputs['/etc/ultra-recovery/backup.json']['artifact_paths'])


    def test_partial_metadata_update_resumes_idempotently(self):
        tasks = yaml.safe_load((ROLE / 'backup-identity.yml').read_text())
        variables = {'release_backup_controller_directory': NEW, 'ultra_previous_controller_directory': OLD,
                     'ultra_controller_directory': NEW,
                     'release_identity_backup': encoded({'artifact_paths': [OLD, '/unrelated/retain']}),
                     'release_identity_deployment': encoded({'controller_directory': NEW})}
        guard = next(task['ansible.builtin.assert']['that'] for task in tasks
                     if task['name'].startswith('Reject foreign'))
        for expression in guard:
            self.assertTrue(render('{{ ' + expression + ' }}', variables))
        for task in tasks:
            if 'ansible.builtin.copy' not in task:
                continue
            copy = task['ansible.builtin.copy']
            rendered = render(copy['content'], variables)
            result = json.loads(rendered)
            key = 'release_identity_backup' if copy['dest'].endswith('backup.json') else 'release_identity_deployment'
            variables[key] = encoded(result)
            self.assertEqual(json.loads(render(copy['content'], variables)), result)

    def test_foreign_deployment_controller_is_rejected(self):
        tasks = yaml.safe_load((ROLE / 'backup-identity.yml').read_text())
        guard = next(task['ansible.builtin.assert']['that'] for task in tasks
                     if task['name'].startswith('Reject foreign'))
        variables = {'release_backup_controller_directory': NEW, 'ultra_previous_controller_directory': OLD,
                     'ultra_controller_directory': NEW,
                     'release_identity_backup': encoded({'artifact_paths': [OLD]}),
                     'release_identity_deployment': encoded({'controller_directory': '/opt/foreign'})}
        self.assertFalse(render('{{ ' + guard[0] + ' }}', variables))


if __name__ == '__main__':
    unittest.main()
