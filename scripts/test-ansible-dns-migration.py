#!/usr/bin/env python3
"""Focused contract checks for the bridge-only DNS migration transport."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'deploy/ansible'
basic = types.ModuleType('ansible.module_utils.basic')
basic.AnsibleModule = object
ansible = types.ModuleType('ansible')
module_utils = types.ModuleType('ansible.module_utils')
sys.modules.setdefault('ansible', ansible)
sys.modules.setdefault('ansible.module_utils', module_utils)
sys.modules['ansible.module_utils.basic'] = basic
spec = importlib.util.spec_from_file_location('ultra_dns_migration', SOURCE / 'library/ultra_dns_migration.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class DNSMigrationTransportTests(unittest.TestCase):
    def test_action_and_input_allowlists(self):
        desired = {'subscription': {'name': 'sync-new', 'data': '192.0.2.10'},
                   'vpn': {'name': 'edge-new', 'data': '192.0.2.10'}}
        operation_id = '12345678-1234-1234-1234-123456789abc'
        for action in ('prepare', 'rollback'):
            migration.validate_request(action, operation_id, desired, None)
        for action in ('promote', 'retire'):
            migration.validate_request(action, operation_id, desired, 'a' * 64)
        migration.validate_request('prepare', operation_id,
                                  {**desired, 'backend': {'name': 'bot-new', 'data': '192.0.2.20'}}, None)
        migration.validate_request('prepare', operation_id, {**desired, 'backend': None}, None)
        for action in ('../dns', 'delete', 'Prepare'):
            with self.assertRaisesRegex(ValueError, 'invalid_action'):
                migration.validate_request(action, operation_id, desired, None)
        for bad_id in ('../candidate', '/tmp/id', operation_id.upper(), 'x' * 36):
            with self.assertRaisesRegex(ValueError, 'invalid_operation_id'):
                migration.validate_request('prepare', bad_id, desired, None)
        for bad_desired in ({**desired, 'other': desired['vpn']},
                            {'subscription': {'name': '../x', 'data': '192.0.2.10'}, 'vpn': desired['vpn']},
                            {'subscription': desired['subscription'], 'vpn': desired['subscription']},
                            {'subscription': {'name': 'sync', 'data': 'not-ip'}, 'vpn': desired['vpn']},
                            {**desired, 'backend': {'name': 'bad/name', 'data': '192.0.2.20'}},
                            {**desired, 'backend': {'name': 'sync-new', 'data': '192.0.2.20'}}):
            with self.assertRaises(ValueError):
                migration.validate_request('prepare', operation_id, bad_desired, None)
        with self.assertRaisesRegex(ValueError, 'invalid_acceptance_hash'):
            migration.validate_request('promote', operation_id, desired, 'x' * 64)

    def test_paths_are_fixed_and_embedded_assets_exist(self):
        operation_id = '12345678-1234-1234-1234-123456789abc'
        candidate, journal = migration.migration_paths(operation_id)
        self.assertEqual(candidate, Path('/var/lib/ultra-recovery/dns-migrations') / operation_id / 'candidate.json')
        self.assertEqual(journal, Path('/var/lib/ultra-recovery/dns-migrations') / operation_id / 'journal.json')
        self.assertEqual(migration.CONFIG, Path('/etc/ultra-recovery/dns.json'))
        self.assertEqual(migration.OLD_RECEIPT, Path('/etc/ultra-recovery/dns-receipt.json'))
        assets = (SOURCE / 'assets.go').read_text()
        self.assertIn('//go:embed ansible.cfg playbooks roles library callback_plugins controller.py requirements.txt', assets)
        self.assertTrue((SOURCE / 'library/ultra_dns_migration.py').is_file())
        self.assertTrue((SOURCE / 'playbooks/upgrade-dns-migration.yml').is_file())

    def test_playbook_is_bridge_only_and_call_is_no_log(self):
        playbook = yaml.safe_load((SOURCE / 'playbooks/upgrade-dns-migration.yml').read_text())
        self.assertEqual(playbook[0]['hosts'], 'bridge')
        self.assertTrue(playbook[0]['become'])
        task = playbook[0]['tasks'][0]
        self.assertIn('ultra_dns_migration', task)
        self.assertTrue(task['no_log'])
        self.assertEqual(playbook[1]['hosts'], 'localhost')
        copy = playbook[1]['tasks'][0]['ansible.builtin.copy']
        self.assertTrue(playbook[1]['tasks'][0]['no_log'])
        self.assertIn('active_receipt_sha256', copy['content'])
        self.assertNotIn('candidate_receipt', copy['content'])
        self.assertNotIn('records', copy['content'])
        self.assertIn("'no_log': True", (SOURCE / 'library/ultra_dns_migration.py').read_text())
        self.assertIn('application_source: "{{ ultra_dns_migration_application_source }}"',
                      (SOURCE / 'playbooks/upgrade-dns-migration.yml').read_text())

    def test_first_run_stages_exact_source_before_import_and_pins_retry(self):
        source = "DNS_HELPER_MARKER = 'from-current-bundle'\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operation = root / '12345678-1234-1234-1234-123456789abc'
            operation.mkdir(mode=0o700)
            expected = operation / migration.APPLICATION_NAME
            original_import = migration.importlib.util.spec_from_file_location
            observed = []

            def checking_import(name, path):
                self.assertEqual(Path(path), expected)
                self.assertTrue(expected.is_file())
                self.assertEqual(expected.read_text(), source)
                observed.append(True)
                return original_import(name, path)

            migration.importlib.util.spec_from_file_location = checking_import
            try:
                loaded = migration.load_application(operation, source, os.geteuid())
            finally:
                migration.importlib.util.spec_from_file_location = original_import
            self.assertEqual(loaded.DNS_HELPER_MARKER, 'from-current-bundle')
            self.assertEqual(observed, [True])
            self.assertEqual(expected.stat().st_mode & 0o777, 0o600)
            before = expected.read_bytes()
            self.assertEqual(migration.stage_application(operation, source, os.geteuid()), expected)
            self.assertEqual(expected.read_bytes(), before)
            with self.assertRaisesRegex(ValueError, 'dns_application_conflict'):
                migration.stage_application(operation, source + '# changed on retry\n', os.geteuid())

    def test_operation_staging_rejects_foreign_or_unsafe_files(self):
        source = 'VALUE = 1\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operation = root / 'op'
            operation.mkdir(mode=0o700)
            staged = operation / migration.APPLICATION_NAME
            staged.write_text(source)
            staged.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'dns_application_untrusted'):
                migration.stage_application(operation, source, os.geteuid())
            staged.unlink()
            staged.symlink_to(root / 'outside')
            with self.assertRaisesRegex(ValueError, 'dns_application_untrusted'):
                migration.stage_application(operation, source, os.geteuid())
            staged.unlink()
            (root / 'outside').write_text(source)
            staged.symlink_to(root / 'outside')
            with self.assertRaisesRegex(ValueError, 'dns_application_untrusted'):
                migration.stage_application(operation, source, os.geteuid())
            self.assertFalse(hasattr(migration, 'APPLICATION'))

    def test_fixed_controller_dispatch(self):
        spec = importlib.util.spec_from_file_location('controller', SOURCE / 'controller.py')
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        self.assertIn('upgrade-dns-migration', controller.LOCAL_OPERATIONS)
        self.assertEqual(controller.operation_playbook('upgrade-dns-migration'), 'upgrade-dns-migration.yml')
        with self.assertRaisesRegex(ValueError, 'unsupported_operation'):
            controller.operation_playbook('upgrade-dns-migration.yml')

    def test_retirement_finalization_recovers_after_receipt_or_policy_write_failure(self):
        for failed_name in ('dns-receipt.json', 'dns.json'):
            with self.subTest(failed_name=failed_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                operation_dir = root / 'operation'
                operation_dir.mkdir(mode=0o700)
                candidate = operation_dir / 'candidate.json'
                receipt = root / 'dns-receipt.json'
                policy_path = root / 'dns.json'
                old = {'version': 1, 'zone': 'example.net', 'records': {'subscription': {'id': 'old'}}}
                new = {'version': 1, 'zone': 'example.net', 'records': {'subscription': {'id': 'new'}, 'vpn': {'id': 'vpn'}}}
                policy = {'config': {'provider': 'vultr', 'zone': 'example.net',
                                     'subscription_name': 'sync-old', 'vpn_name': 'edge-old'},
                          'desired': {'subscription': {'name': 'sync-old', 'data': '192.0.2.1'},
                                      'vpn': {'name': 'edge-old', 'data': '192.0.2.1'},
                                      'backend': {'name': 'bot', 'data': '192.0.2.2'}}}
                for path, value in ((candidate, new), (receipt, old), (policy_path, policy)):
                    path.write_text(json.dumps(value))
                    path.chmod(0o600)
                desired = {'subscription': {'name': 'sync-new', 'data': '192.0.2.10'},
                           'vpn': {'name': 'edge-new', 'data': '192.0.2.10'}}
                acceptance_hash = 'a' * 64
                failed = False

                def fail_once(path, raw):
                    nonlocal failed
                    if path.name == failed_name and not failed:
                        failed = True
                        raise OSError('simulated interrupted write')
                    migration._atomic_private(path, raw)

                with self.assertRaisesRegex(OSError, 'simulated interrupted'):
                    migration.finalize_retirement(candidate, operation_dir, desired,
                                                  policy_path, receipt, acceptance_hash, fail_once)
                digest = migration.finalize_retirement(candidate, operation_dir, desired,
                                                       policy_path, receipt, acceptance_hash)
                self.assertEqual(digest, __import__('hashlib').sha256(candidate.read_bytes()).hexdigest())
                self.assertEqual(receipt.read_bytes(), candidate.read_bytes())
                self.assertEqual((operation_dir / 'previous-receipt.json').read_bytes(), json.dumps(old).encode())
                updated = json.loads(policy_path.read_text())
                self.assertEqual(updated['desired']['subscription'], desired['subscription'])
                self.assertEqual(updated['desired']['vpn'], desired['vpn'])
                self.assertEqual(updated['config']['subscription_name'], 'sync-new')
                self.assertEqual(updated['config']['vpn_name'], 'edge-new')
                self.assertEqual(updated['desired']['backend'], policy['desired']['backend'])
                marker = json.loads((operation_dir / 'finalization.json').read_text())
                self.assertEqual(marker['phase'], 'complete')
                self.assertEqual((operation_dir / 'previous-receipt.json').stat().st_mode & 0o777, 0o600)
                migration_journal = operation_dir / 'journal.json'
                migration_journal.write_text(json.dumps({'phase': 'retired', 'acceptance_sha256': acceptance_hash}))
                migration_journal.chmod(0o600)
                self.assertTrue(migration.retirement_finalization_started(
                    operation_dir / 'finalization.json', migration_journal, acceptance_hash))
                with self.assertRaisesRegex(ValueError, 'dns_finalization_not_accepted'):
                    migration.retirement_finalization_started(
                        operation_dir / 'finalization.json', migration_journal, 'b' * 64)

    def test_finalization_updates_or_explicitly_removes_backend_but_omission_preserves_it(self):
        for backend in ({'name': 'bot-new', 'data': '192.0.2.20'}, None):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                operation_dir = root / 'operation'
                operation_dir.mkdir(mode=0o700)
                candidate = operation_dir / 'candidate.json'
                receipt = root / 'dns-receipt.json'
                policy_path = root / 'dns.json'
                old = {'version': 1, 'zone': 'example.net', 'records': {}}
                new = {'version': 1, 'zone': 'example.net', 'records': {'backend': {'id': 'new'}}}
                policy = {'config': {'provider': 'vultr', 'zone': 'example.net',
                                     'subscription_name': 'sync-old', 'vpn_name': 'edge-old'},
                          'desired': {'subscription': {'name': 'sync-old', 'data': '192.0.2.1'},
                                      'vpn': {'name': 'edge-old', 'data': '192.0.2.1'},
                                      'backend': {'name': 'bot-old', 'data': '192.0.2.3'}}}
                for path, value in ((candidate, new), (receipt, old), (policy_path, policy)):
                    path.write_text(json.dumps(value))
                    path.chmod(0o600)
                desired = {'subscription': {'name': 'sync-new', 'data': '192.0.2.10'},
                           'vpn': {'name': 'edge-new', 'data': '192.0.2.10'}}
                desired['backend'] = backend
                digest = migration.finalize_retirement(candidate, operation_dir, desired,
                                                       policy_path, receipt, 'a' * 64)
                self.assertEqual(digest, __import__('hashlib').sha256(candidate.read_bytes()).hexdigest())
                saved = json.loads(policy_path.read_text())['desired']
                saved_config = json.loads(policy_path.read_text())['config']
                self.assertEqual(saved_config['subscription_name'], 'sync-new')
                self.assertEqual(saved_config['vpn_name'], 'edge-new')
                if backend is None:
                    self.assertNotIn('backend', saved)
                else:
                    self.assertEqual(saved['backend'], backend)


if __name__ == '__main__':
    unittest.main()
