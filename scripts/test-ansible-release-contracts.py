#!/usr/bin/env python3
"""Transferred lifecycle durability/readiness guarantees, using synthetic inputs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
import yaml
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


controller = load('controller_contract', ROOT / 'deploy/ansible/controller.py')
state = load('release_state_contract', ROOT / 'deploy/ansible/roles/release/files/state.py')
# Keep these unit checks runnable without installing the remote Ansible runner.
with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.module_utils': types.ModuleType('ansible.module_utils'), 'ansible.module_utils.basic': types.SimpleNamespace(AnsibleModule=None)}):
    maintenance = load('legacy_maintenance_contract', ROOT / 'deploy/ansible/library/ultra_upgrade_maintenance.py')


class Contracts(unittest.TestCase):
    def test_atomic_receipt_syncs_data_then_rename_then_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            events = []
            sync, replace = os.fsync, os.replace
            def observed_sync(fd):
                events.append('directory_sync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_sync')
                sync(fd)
            def observed_replace(source, target):
                replace(source, target)
                events.append('rename')
            with patch.object(controller.os, 'fsync', side_effect=observed_sync), patch.object(controller.os, 'replace', side_effect=observed_replace):
                controller.atomic(path, {'state': 'succeeded'})
            self.assertEqual(events, ['file_sync', 'rename', 'directory_sync'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            real = Path(directory) / 'real';real.write_text('keep')
            link = Path(directory) / 'link';link.symlink_to(real)
            with self.assertRaises(ValueError):
                controller.atomic(link, {'state': 'changed'})
            self.assertEqual(real.read_text(), 'keep')

    def test_activation_needs_new_backup_and_monitor_evidence(self):
        values = {'reconcile.json': {'database': 'fixture'},
                  'recovery-reconcile-status.json': {'state': 'ready', 'independent': True, 'updated_at': 100},
                  'last-success.json': {'snapshot_at': 100}, 'release-manifest.json': {'version': 'v9.0.0'}}
        digest = hashlib.sha256(b'[]').hexdigest()
        def result(argv, **kwargs):
            output = b'25:25' if 'schema_migrations' in argv[-1] else b't'
            return types.SimpleNamespace(stdout=output, returncode=0)
        fake_reconcile = types.SimpleNamespace(desired_nodes=lambda *args: ([], set()), discover=lambda *args: [])
        with patch.dict(sys.modules, {'reconcile': fake_reconcile}), patch.object(state, 'read', side_effect=lambda path: values[Path(path).name]), patch.object(state.time, 'time', return_value=110), patch.object(state.subprocess, 'run', side_effect=result), patch.object(sys, 'argv', ['state.py', '--status', '--expected', digest, '--not-before', '100']):
            with self.assertRaisesRegex(ValueError, 'post_activation_evidence_required'):
                state.main()
            values['recovery-reconcile-status.json']['updated_at'] = 101
            with self.assertRaisesRegex(ValueError, 'post_activation_evidence_required'):
                state.main()
            values['last-success.json']['snapshot_at'] = 101
            with patch('builtins.print') as output:
                state.main()
            self.assertTrue(json.loads(output.call_args.args[0])['ready'])

    def test_legacy_upgrade_preserves_barrier_and_defers_all_payload_acceptance(self):
        root = ROOT / 'deploy/ansible'
        plays = yaml.safe_load((root / 'playbooks/upgrade.yml').read_text())
        names = [task['name'] for task in plays[0]['tasks']]
        ordered = ['Preserve same-operation legacy maintenance state before stopping services',
                   'Stop legacy topology producers before freezing recovery',
                   'Stop new recovery cycles without interrupting running copies',
                   'Wait for current copies and reconcile to finish naturally',
                   'Create the independent control generation before activation',
                   'Require fresh delivery to the independently confirmed primary after capture',
                   'Stop the identified legacy bridge before changing exits',
                   'Prove all legacy producers are stopped and original configuration is unchanged',
                   'Reinspect frozen topology after the legacy process has stopped']
        self.assertEqual(sorted(names.index(name) for name in ordered), [names.index(name) for name in ordered])
        tasks = plays[2]['tasks']
        names = [task['name'] for task in tasks]
        self.assertLess(names.index('Activate the bridge relay'), names.index('Verify every frozen exit through the newly started bridge'))
        self.assertLess(names.index('Verify every frozen exit through the newly started bridge'), names.index('Activate the bot after relay readiness'))
        probe = next(task for task in tasks if task['name'] == 'Verify every frozen exit through the newly started bridge')
        self.assertEqual(probe['loop'], "{{ groups['exits'] }}")
        activation = yaml.safe_load((root / 'roles/release/tasks/main.yml').read_text())
        block = next(task['block'] for task in activation if 'block' in task)
        probe = next(task for task in block if task['name'] == 'Verify the newly activated exit with a full tunnel payload')
        self.assertIn('not (ultra_legacy_bridge_maintenance', probe['when'])

    def test_legacy_rollback_starts_unchanged_bridge_before_bot_restore(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/rollback.yml').read_text())
        self.assertTrue(plays[0].get('any_errors_fatal'))
        names = [task['name'] for task in plays[1]['tasks']]
        self.assertLess(names.index('Restore the bridge relay'), names.index('Start the unchanged restored legacy bridge before probing it'))
        self.assertLess(names.index('Start the unchanged restored legacy bridge before probing it'), names.index('Require a usable restored control plane'))
        self.assertLess(names.index('Require a usable restored control plane'), names.index('Restore the original legacy bot state after the restored bridge probe'))

    def test_mixed_baseline_roles_use_frozen_per_host_and_relay_only_emergency(self):
        root = ROOT / 'deploy/ansible/roles/release/tasks'
        for name in ('main.yml', 'rollback.yml', 'retention.yml'):
            tasks = yaml.safe_load((root / name).read_text())
            self.assertEqual(tasks[0]['ansible.builtin.set_fact']['release_previous_manifest'],
                             '{{ ultra_host_previous_manifest | default(ultra_previous_manifest) }}')
            self.assertIn('ultra_previous_relay_manifest', (root / name).read_text())
        rollback = yaml.safe_load((root / 'rollback.yml').read_text())
        verified = next(task for task in rollback if task['name'] == 'Verify exact restored bytes even when the fallback was already installed')
        self.assertNotIn('when', verified)
        self.assertFalse(verified['ansible.builtin.stat']['follow'])

    def test_maintenance_service_predicate_rejects_ambiguous_states(self):
        def runner(output, rc=0):
            return types.SimpleNamespace(run_command=lambda argv: (rc, output, ''))
        ready = 'LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\n'
        self.assertEqual(maintenance.service(runner(ready), 'ultra-relay.service')['MainPID'], '0')
        for output in [ready.replace('inactive', 'activating'), ready.replace('MainPID=0', 'MainPID=-1'),
                       ready.replace('loaded', 'not-found'), ready + 'MainPID=0\n', 'ActiveState=inactive\n']:
            with self.assertRaises(ValueError):
                maintenance.service(runner(output), 'ultra-relay.service')
        with self.assertRaises(ValueError):
            maintenance.service(runner(ready, 1), 'ultra-relay.service')

    def test_maintenance_stopped_requires_owned_checkpoint_and_all_pids_zero(self):
        class Done(Exception):
            pass
        operation = '11111111-2222-3333-4444-555555555555'
        module = types.SimpleNamespace(params={'id': operation, 'legacy_sha256': 'a'*64, 'phase': 'stopped'}, check_mode=False)
        module.exit_json = lambda **result: (_ for _ in ()).throw(Done(result))
        module.fail_json = lambda **result: (_ for _ in ()).throw(Done(dict(result, failed=True)))
        checkpoint = {'id': operation, 'legacy_sha256': 'a'*64, 'configuration': {},
                      'services': {unit: 'active' for unit in maintenance.SERVICES}}
        gate = {'id': operation, 'phase': 'applying'}
        def read(path):
            return gate if path.name == 'lifecycle.json' else checkpoint
        stopped = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'}
        def invoke():
            with self.assertRaises(Done) as result:
                maintenance.main()
            return result.exception.args[0]
        with patch.object(maintenance, 'AnsibleModule', return_value=module), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'private', side_effect=read), patch.object(maintenance, 'hashes', return_value={}), patch.object(maintenance, 'service', return_value=stopped):
            self.assertTrue(invoke()['verified'])
            for key in ('MainPID', 'ControlPID'):
                stopped[key] = '123'
                self.assertTrue(invoke()['failed'])
                stopped[key] = '0'
            gate['id'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            self.assertTrue(invoke()['failed'])
            gate['id'] = operation
            checkpoint['configuration'] = {'changed': 'hash'}
            self.assertTrue(invoke()['failed'])

    def test_legacy_cleanup_restores_all_saved_states_before_receipt(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/resume-automation.yml').read_text())[0]['tasks']
        restore = next(task for task in tasks if 'ultra_upgrade_maintenance' in task)
        self.assertEqual(restore['ultra_upgrade_maintenance']['phase'], 'restore-services')
        self.assertIn('not (ultra_legacy_bridge_maintenance', tasks[0]['when'])
        rollback = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/rollback.yml').read_text())[1]['tasks']
        restore = next(task for task in rollback if 'ultra_upgrade_maintenance' in task)
        self.assertEqual(restore['ultra_upgrade_maintenance']['phase'], 'restore-services')
        activation = yaml.safe_load((ROOT / 'deploy/ansible/roles/release/tasks/main.yml').read_text())
        block = next(task['block'] for task in activation if 'block' in task)
        start = next(task for task in block if task['name'] == 'Activate the updated service')
        self.assertEqual(start['when'], 'not (release_preserve_stopped | default(false) | bool)')

    def test_maintenance_recovery_requires_current_independent_delivery(self):
        class Done(Exception):
            pass
        operation = '11111111-2222-3333-4444-555555555555'
        module = types.SimpleNamespace(params={'id': operation, 'legacy_sha256': 'a'*64, 'phase': 'recovery-ready'}, check_mode=False)
        module.exit_json = lambda **result: (_ for _ in ()).throw(Done(result))
        module.fail_json = lambda **result: (_ for _ in ()).throw(Done(dict(result, failed=True)))
        values = {
            'lifecycle.json': {'id': operation, 'phase': 'applying'},
            'maintenance.json': {'id': operation, 'legacy_sha256': 'a'*64, 'configuration': {}, 'created_at': 100, 'capture_after': 100, 'previous_delivery': {}, 'recovery_provenance': {},
                                 'services': {unit: 'active' for unit in maintenance.SERVICES}},
            'reconcile.json': {'bridge_provider': 'bridge-cloud'},
            'backup.json': {'independent': True, 'destinations': [{'id': 'primary', 'required': True, 'host': 'root@192.0.2.1'}]},
            'state.json': {'primary': 'primary', 'node_metadata': [{'id': 'primary', 'provider': 'other-cloud', 'host': 'root@192.0.2.1'}], 'updated_at': 101},
            'recovery-reconcile-status.json': {'primary': 'primary', 'state': 'ready', 'independent': True, 'updated_at': 101},
            'last-success.json': {'source': 'bridge', 'snapshot_at': 101, 'destinations': ['root@192.0.2.1'],
                                  'delivered_target_ids': ['primary'], 'backup_sha256': 'a'*64, 'artifact_sha256': 'b'*64}}
        def invoke():
            with self.assertRaises(Done) as result:
                maintenance.main()
            return result.exception.args[0]
        stopped = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'}
        with patch.object(maintenance, 'AnsibleModule', return_value=module), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'private', side_effect=lambda path, **kwargs: values[path.name]), patch.object(maintenance, 'hashes', return_value={}), patch.object(maintenance, 'recovery_provenance', return_value={}), patch.object(maintenance.time, 'time', return_value=110), patch.object(maintenance, 'service', return_value=stopped):
            self.assertTrue(invoke()['verified'])
            values['state.json']['updated_at'] = -100
            values['recovery-reconcile-status.json']['updated_at'] = -100
            self.assertTrue(invoke()['verified'])
            for name, key, replacement in [('last-success.json', 'delivered_target_ids', ['wrong']),
                                           ('last-success.json', 'snapshot_at', 100),
                                           ('last-success.json', 'source', 'exit'),
                                           ('recovery-reconcile-status.json', 'primary', 'wrong'),
                                           ('backup.json', 'independent', False)]:
                original = values[name][key]
                values[name][key] = replacement
                self.assertTrue(invoke()['failed'], (name, key))
                values[name][key] = original
            values['state.json']['node_metadata'][0]['provider'] = 'BRIDGE-CLOUD'
            self.assertTrue(invoke()['failed'])

    def test_held_retry_captures_without_starting_or_reconciling(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/preflight-retry.yml').read_text())
        tasks = plays[0]['tasks']
        phases = [t['ultra_upgrade_maintenance']['phase'] for t in tasks if 'ultra_upgrade_maintenance' in t]
        self.assertEqual(phases, ['retry-checkpoint', 'capture-tool-check', 'recovery-ready'])
        commands = [t['ansible.builtin.command']['argv'] for t in tasks if 'ansible.builtin.command' in t]
        self.assertEqual(commands, [['python3', '/opt/ultra-recovery/recovery.py', 'capture', '--config', '/etc/ultra-recovery/backup.json']])
        self.assertFalse(any('ansible.builtin.systemd_service' in t for t in tasks))
        freshness = next(t for t in tasks if t['name'] == 'Require fresh independent recovery and unchanged topology')
        self.assertIn('not (legacy_retry_barrier.held', freshness['when'])

    def test_retry_checkpoint_requires_idle_producers_and_advances_capture_evidence(self):
        class Done(Exception):
            pass
        operation = '11111111-2222-3333-4444-555555555555'
        checkpoint = {'id': operation, 'legacy_sha256': 'a'*64, 'configuration': {}, 'created_at': 10,
                      'recovery_provenance': {}, 'services': {unit: 'active' for unit in maintenance.SERVICES}}
        values = {'lifecycle.json': {'id': operation, 'phase': 'applying'}, 'maintenance.json': checkpoint,
                  'last-success.json': {'snapshot_at': 11}}
        module = types.SimpleNamespace(params={'id': operation, 'legacy_sha256': 'a'*64, 'phase': 'retry-checkpoint'}, check_mode=False)
        module.exit_json = lambda **result: (_ for _ in ()).throw(Done(result))
        module.fail_json = lambda **result: (_ for _ in ()).throw(Done(dict(result, failed=True)))
        stopped = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'}
        def invoke():
            with self.assertRaises(Done) as result:
                maintenance.main()
            return result.exception.args[0]
        with patch.object(maintenance, 'AnsibleModule', return_value=module), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'private', side_effect=lambda path, **kwargs: values[path.name]), patch.object(maintenance, 'hashes', return_value={}), patch.object(maintenance, 'recovery_provenance', return_value={}), patch.object(maintenance.time, 'time', return_value=20), patch.object(maintenance, 'service', return_value=stopped), patch.object(maintenance, 'atomic') as save, patch.object(maintenance.time, 'sleep'), patch.object(maintenance.Path, 'exists', return_value=True):
            self.assertTrue(invoke()['held'])
            self.assertEqual(save.call_args.args[1]['capture_after'], 20)
            self.assertEqual(save.call_args.args[1]['previous_delivery'], {'snapshot_at': 11})
            with patch.object(maintenance, 'service', side_effect=lambda mod, unit: dict(stopped, MainPID='7') if unit == 'ultra-relay.service' else stopped):
                self.assertTrue(invoke()['failed'])
            with patch.object(maintenance, 'recovery_provenance', return_value={'changed': 'pin'}):
                self.assertTrue(invoke()['failed'])



    def test_managed_relay_owned_recovery_pins_are_scoped_and_checked(self):
        relay_uid = os.geteuid()
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / 'var/lib/ultra-relay'
            pins = prefix / 'vultr' / '11111111-2222-3333-4444-555555555555' / 'known_hosts'
            pins.parent.mkdir(parents=True)
            pins.write_text('fixture host key\n')
            pins.chmod(0o600)
            with patch.object(maintenance.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=relay_uid)):
                digest = maintenance.recovery_file(str(pins), {relay_uid}, managed_pin=True, relay_prefix=prefix, root_uid=relay_uid, trusted_root=Path(directory))
                self.assertEqual(digest, hashlib.sha256(pins.read_bytes()).hexdigest())
                with self.assertRaises(ValueError):
                    maintenance.recovery_file(str(pins), {relay_uid + 1}, managed_pin=True, relay_prefix=prefix, root_uid=relay_uid, trusted_root=Path(directory))
                alias = Path(directory) / 'alias'
                alias.symlink_to(prefix, target_is_directory=True)
                with self.assertRaises(ValueError):
                    maintenance.recovery_file(str(alias / pins.relative_to(prefix)), {relay_uid}, managed_pin=True, relay_prefix=alias, root_uid=relay_uid, trusted_root=Path(directory))

    def test_recovery_identity_and_managed_pin_contracts_match_bootstrap_policy(self):
        relay_uid = os.geteuid()
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / 'identity'
            identity.write_text('private key fixture\n')
            identity.chmod(0o600)
            self.assertEqual(maintenance.recovery_file(str(identity), {relay_uid}, private_file=True),
                             hashlib.sha256(identity.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):
                maintenance.recovery_file(str(identity), {relay_uid + 1}, private_file=True)
            identity.chmod(0o640)
            with self.assertRaises(ValueError):
                maintenance.recovery_file(str(identity), {relay_uid}, private_file=True)

        config = {'vultr_state_dir': '/var/lib/ultra-relay/vultr'}
        node = {'id': '11111111-2222-3333-4444-555555555555', 'address': '192.0.2.1',
                'host': 'root@192.0.2.1',
                'known_hosts': '/var/lib/ultra-relay/vultr/11111111-2222-3333-4444-555555555555/known_hosts'}
        self.assertEqual(maintenance.validate_managed_pin(node, config), node['known_hosts'])
        for bad in ({**node, 'known_hosts': '/tmp/known_hosts'}, {**node, 'id': 'not-a-uuid'}):
            with self.assertRaises(ValueError):
                maintenance.validate_managed_pin(bad, config)

        topology = {'primary': node['id'], 'node_metadata': [node]}
        identity_path = '/etc/ultra-recovery/ssh_identity'
        backup = {'destinations': [{'id': node['id'], 'required': True, 'host': node['host'],
                                    'known_hosts': node['known_hosts'], 'identity_file': identity_path}]}
        maintenance.validate_primary_destination(identity_path, topology, backup)
        backup['destinations'][0]['identity_file'] = '/tmp/other'
        with self.assertRaises(ValueError):
            maintenance.validate_primary_destination(identity_path, topology, backup)

    def test_recovery_capture_tool_must_match_a_pinned_prior_or_target_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / 'recovery.py'
            tool.write_text('trusted recovery fixture\n')
            tool.chmod(0o700)
            digest = hashlib.sha256(tool.read_bytes()).hexdigest()
            self.assertEqual(maintenance.checked_recovery_tool([digest], tool, owner_uid=os.geteuid()), digest)
            with self.assertRaises(ValueError):
                maintenance.checked_recovery_tool(['0' * 64], tool, owner_uid=os.geteuid())


if __name__ == '__main__':
    unittest.main()
