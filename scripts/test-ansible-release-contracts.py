#!/usr/bin/env python3
"""Transferred lifecycle durability/readiness guarantees, using synthetic inputs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import types
import unittest
import yaml
from jinja2 import Environment
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
    def test_forward_release_hash_does_not_read_a_fact_from_same_set_fact(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/roles/release/tasks/main.yml').read_text())
        pin = next(task for task in tasks if task.get('name') == 'Pin the target and fallback hashes')
        facts = pin['ansible.builtin.set_fact']
        self.assertIn('release_target', facts)
        self.assertNotIn('release_target', facts['release_previous'])
        self.assertIn('ultra_release_manifest.assets', facts['release_previous'])
        target = {'name': 'ultra-relay-linux-amd64', 'sha256': 'a' * 64}
        previous = {'name': 'ultra-relay-linux-amd64', 'sha256': 'b' * 64}
        context = {'release_component': 'ultra-relay', 'ultra_architecture': 'amd64',
                   'release_asset_name': 'ultra-relay-linux-amd64',
                   'ultra_release_manifest': {'assets': [target]},
                   'release_previous_manifest': {'assets': [previous]},
                   'ultra_previous_manifest': {'assets': [previous]},
                   'ultra_forward_only': True}
        environment = Environment()
        environment.filters['bool'] = lambda value: value is True
        rendered = environment.from_string(facts['release_previous']).render(context)
        self.assertEqual(yaml.safe_load(rendered), target)
        context['ultra_forward_only'] = False
        rendered = environment.from_string(facts['release_previous']).render(context)
        self.assertEqual(yaml.safe_load(rendered), previous)

    def test_forward_failure_containment_confirms_every_fixed_unit_and_host(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/contain-upgrade.yml').read_text())
        self.assertEqual([play['hosts'] for play in plays], ['all', 'bridge'])
        self.assertEqual(plays[0]['strategy'], 'linear')
        first = plays[0]['tasks']
        units = plays[0]['vars']['containment_units']
        self.assertIn('ultra-bot.service', units)
        self.assertIn('ultra-relay.service', units)
        self.assertIn('ultra-recovery-backup.timer', units)
        self.assertIn('ultra-auto-upgrade.timer', units)
        self.assertTrue(next(task for task in first if 'Stop every present producer' in task['name'])['failed_when'] is False)
        assertion = next(task for task in first if 'Require each unit' in task['name'])
        expressions = assertion['ansible.builtin.assert']['that']
        environment = Environment()
        environment.tests['match'] = lambda value, pattern: re.match(pattern, value) is not None
        verify = [environment.compile_expression(expression) for expression in expressions]

        def accepted(name, lines, rc=0):
            item = {'item': name, 'stdout_lines': lines, 'rc': rc}
            return all(bool(check(item=item)) for check in verify)

        stopped = ['LoadState=loaded', 'ActiveState=inactive', 'MainPID=0', 'ControlPID=0']
        self.assertTrue(accepted('ultra-relay.service', stopped))
        self.assertTrue(accepted('ultra-bot.service', ['LoadState=not-found'], rc=1))
        self.assertTrue(accepted('ultra-recovery-backup.timer', ['LoadState=loaded', 'ActiveState=inactive']))
        self.assertFalse(accepted('ultra-relay.service', ['LoadState=loaded', 'ActiveState=active', 'MainPID=0', 'ControlPID=0']))
        self.assertFalse(accepted('ultra-bot.service', stopped[:-2]))
        self.assertFalse(accepted('ultra-recovery-backup.timer', ['LoadState=loaded', 'ActiveState=active']))
        self.assertFalse(accepted('ultra-relay.service', stopped, rc=2))
        fleet_check = next(task for task in plays[1]['tasks'] if 'whole fleet' in task['name'])
        self.assertEqual(fleet_check['ansible.builtin.assert']['that'],
                         'hostvars[item].ultra_candidate_contained | default(false) | bool')

    def test_controller_rollback_floor_is_checked_before_every_mutation(self):
        root = ROOT / 'deploy/ansible'
        plays = yaml.safe_load((root / 'playbooks/rollback.yml').read_text())
        first = plays[0]
        self.assertEqual(first['hosts'], 'bridge')
        self.assertFalse(first['gather_facts'])
        self.assertTrue(first['any_errors_fatal'])
        self.assertFalse(first.get('pre_tasks'))
        self.assertFalse(first.get('roles'))
        guard = first['tasks'][0]
        self.assertEqual(guard['ansible.builtin.include_role'],
                         {'name': 'release', 'tasks_from': 'controller-rollback-preflight'})
        self.assertNotIn('when', guard)
        direct = yaml.safe_load((root / 'roles/release/tasks/rollback-controller.yml').read_text())
        self.assertEqual(direct[0]['ansible.builtin.import_tasks'], 'controller-rollback-preflight.yml')
        self.assertNotIn('when', direct[0])
        self.assertIn('ansible.builtin.copy', direct[2]['block'][1])
        self.assertIn('ansible.builtin.systemd_service', direct[2]['block'][3])

    def test_controller_rollback_rejects_retirement_state_and_preserves_absent_state(self):
        path = ROOT / 'deploy/ansible/roles/release/tasks/controller-rollback-preflight.yml'
        inspect, guard, proof = yaml.safe_load(path.read_text())
        self.assertEqual(inspect['ansible.builtin.stat']['path'], '/var/lib/ultra-ansible/lifecycle-retired.json')
        self.assertFalse(inspect['ansible.builtin.stat']['follow'])
        self.assertFalse(inspect['ansible.builtin.stat']['get_checksum'])
        assertion = guard['ansible.builtin.assert']
        self.assertEqual(assertion['fail_msg'], 'controller_rollback_enforcement_migration_required')
        environment = Environment()
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / 'lifecycle-retired.json'
            def allowed():
                # The stat module uses lstat with follow=false. Exercise real
                # absent, regular, directory and dangling-symlink filesystem states.
                try:
                    info = ledger.lstat()
                    observed = {'exists': True, 'islnk': stat.S_ISLNK(info.st_mode), 'isreg': stat.S_ISREG(info.st_mode)}
                except FileNotFoundError:
                    observed = {'exists': False}
                variables = {'release_controller_rollback_retirement': {'stat': observed}}
                regular = all(environment.compile_expression(condition)(variables)
                              for condition in assertion['that'])
                if regular and observed['exists']:
                    # An absent/old restore request cannot supply the new exact
                    # runtime proof. Detailed proof drift is tested separately.
                    return environment.compile_expression(proof['block'][0]['ansible.builtin.assert']['that'][0])(variables)
                return regular
            self.assertTrue(allowed(), 'supported rollback without retirement obligations must remain available')
            for contents in ('{"version":1,"ids":["retired"]}', '{"version":1,"ids":[]}', 'invalid'):
                ledger.write_text(contents)
                self.assertFalse(allowed())
            ledger.unlink()
            ledger.mkdir()
            self.assertFalse(allowed())
            ledger.rmdir()
            ledger.symlink_to(Path(directory) / 'missing')
            self.assertFalse(allowed())
            ledger.unlink()
            self.assertTrue(allowed())

    def test_ordinary_upgrade_floor_preflight_is_read_only_and_precedes_state_inspection(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/inspect-upgrade.yml').read_text())
        tasks = plays[0]['tasks']
        guard, receipt, inspect, save_inspection = tasks
        enabled = 'ultra_controller_enforcement_preflight_only | default(false) | bool'
        disabled = 'not (' + enabled + ')'
        self.assertEqual(guard['ansible.builtin.import_tasks'],
                         '../roles/release/tasks/controller-enforcement-preflight.yml')
        self.assertEqual(guard['when'], enabled)
        self.assertTrue(guard['no_log'])
        self.assertEqual(receipt['when'], enabled)
        self.assertIn('release_controller_enforcement_result', receipt['ansible.builtin.copy']['content'])
        self.assertEqual(inspect['when'], disabled)
        self.assertEqual(save_inspection['when'], disabled)

    def test_restore_checks_existing_target_floor_before_any_mutation(self):
        root = ROOT / 'deploy/ansible/roles/restore/tasks'
        for name in ('main.yml', 'services.yml'):
            tasks = yaml.safe_load((root / name).read_text())
            self.assertEqual(tasks[0]['ansible.builtin.include_role'],
                             {'name': 'release', 'tasks_from': 'controller-rollback-preflight'})
            self.assertNotIn('when', tasks[0])

    def test_controller_enforcement_switch_and_rollback_use_callsite_phase(self):
        path = ROOT / 'deploy/ansible/roles/release/tasks'
        guard_tasks = yaml.safe_load((path / 'controller-rollback-preflight.yml').read_text())
        module = guard_tasks[-1]['block'][-1]['ultra_controller_enforcement']
        self.assertEqual(module['phase'], "{{ ultra_controller_enforcement_phase | default('before') }}")
        phases = []
        for task in yaml.safe_load((path / 'controller.yml').read_text()):
            if task.get('ansible.builtin.import_tasks') == 'controller-rollback-preflight.yml':
                phases.append(task.get('vars', {}).get('ultra_controller_enforcement_phase', 'before'))
        self.assertEqual(phases, ['before', 'staged', 'candidate'])
        rollback = yaml.safe_load((path / 'rollback-controller.yml').read_text())
        self.assertEqual(rollback[-1]['block'][4]['vars']['ultra_controller_enforcement_phase'], 'rollback')

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
        with patch.dict(sys.modules, {'reconcile': fake_reconcile}), patch.object(state, 'read', side_effect=lambda path: values[Path(path).name]), patch.object(state.time, 'time', return_value=110), patch.object(state.subprocess, 'run', side_effect=result), patch.object(state, 'database_query', side_effect=lambda database, query: result(['psql', query])), patch.object(sys, 'argv', ['state.py', '--status', '--expected', digest, '--not-before', '100']):
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
                   'Stop the identified legacy bridge before changing exits',
                   'Prove all legacy producers are stopped and original configuration is unchanged',
                   'Create the independent control generation before activation',
                   'Require fresh delivery to the independently confirmed primary after capture',
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
        names = [task['name'] for task in plays[2]['tasks']]
        self.assertLess(names.index('Restore the bridge relay'), names.index('Start the unchanged restored legacy bridge before probing it'))
        self.assertLess(names.index('Start the unchanged restored legacy bridge before probing it'), names.index('Require a usable restored control plane'))
        self.assertLess(names.index('Require a usable restored control plane'), names.index('Restore the original legacy bot state after the restored bridge probe'))

    def test_activation_rescue_keeps_legacy_bridge_stopped_until_fleet_rollback(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/roles/release/tasks/main.yml').read_text())
        rescue = next(task['rescue'] for task in tasks if 'rescue' in task)
        environment = Environment()
        environment.filters['bool'] = bool

        def enabled(task, variables):
            conditions = task.get('when', [])
            if isinstance(conditions, str):
                conditions = [conditions]
            return all(environment.compile_expression(condition)(**variables) for condition in conditions)

        for host, component, legacy, preserve, forward_only, expected in [
                ('bridge', 'ultra-relay', True, False, False, ['stopped']),
                ('bridge', 'ultra-relay', False, False, False, ['restarted']),
                ('exit', 'ultra-relay', True, False, False, ['restarted']),
                ('bridge', 'ultra-bot', True, False, False, ['restarted']),
                ('bridge', 'ultra-bot', True, True, False, []),
                ('exit', 'ultra-relay', True, False, True, ['stopped'])]:
            with self.subTest(host=host, component=component, legacy=legacy, preserve=preserve):
                variables = {'inventory_hostname': host, 'groups': {'bridge': ['bridge'], 'exits': ['exit']},
                             'release_component': component, 'ultra_legacy_bridge_maintenance': legacy,
                             'release_preserve_stopped': preserve, 'ultra_forward_only': forward_only}
                service_states = [task['ansible.builtin.systemd_service']['state'] for task in rescue
                                  if 'ansible.builtin.systemd_service' in task and enabled(task, variables)]
                self.assertEqual(service_states, expected)
        stop = next(index for index, task in enumerate(rescue)
                    if task.get('ansible.builtin.systemd_service', {}).get('state') == 'stopped')
        restore = next(index for index, task in enumerate(rescue) if 'ansible.builtin.copy' in task)
        self.assertLess(stop, restore, 'stop the failed new relay before replacing its executable')
        self.assertIn('ansible.builtin.fail', rescue[-1], 'local rescue must still trigger fleet rollback')
        self.assertEqual(rescue[-1]['ansible.builtin.fail']['msg'], "{{ 'release_forward_only_activation_failed' if (ultra_forward_only | default(false) | bool) else 'release_activation_failed' }}")

    def test_mixed_baseline_roles_use_frozen_per_host_and_relay_only_emergency(self):
        root = ROOT / 'deploy/ansible/roles/release/tasks'
        for name in ('main.yml', 'rollback.yml', 'retention.yml'):
            tasks = yaml.safe_load((root / name).read_text())
            expected_previous = "{{ ultra_release_manifest if (ultra_forward_only | default(false) | bool) else (ultra_host_previous_manifest | default(ultra_previous_manifest)) }}" if name == 'main.yml' else '{{ ultra_host_previous_manifest | default(ultra_previous_manifest) }}'
            actual_previous = tasks[0]['ansible.builtin.set_fact']['release_previous_manifest']
            self.assertEqual(' '.join(actual_previous.split()), ' '.join(expected_previous.split()))
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

    def test_maintenance_timer_predicate_uses_only_timer_properties(self):
        calls = []
        def run(argv):
            calls.append(argv)
            return 0, 'LoadState=loaded\nActiveState=active\n', ''
        runner = types.SimpleNamespace(run_command=run)
        self.assertEqual(maintenance.service(runner, 'ultra-recovery-backup.timer'),
                         {'LoadState': 'loaded', 'ActiveState': 'active'})
        self.assertEqual(calls, [[
            'systemctl', 'show', '--property=LoadState', '--property=ActiveState',
            'ultra-recovery-backup.timer',
        ]])
        for output in ('LoadState=loaded\nActiveState=activating\n',
                       'LoadState=loaded\nActiveState=active\nMainPID=0\n',
                       'LoadState=not-found\nActiveState=inactive\n',
                       'LoadState=loaded\nActiveState=active\nActiveState=inactive\n'):
            with self.assertRaises(ValueError):
                maintenance.service(types.SimpleNamespace(run_command=lambda argv, output=output: (0, output, '')),
                                    'ultra-recovery-backup.timer')
        with self.assertRaises(ValueError):
            maintenance.service(runner, 'ultra-recovery-backup.socket')

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
            worker = dict(stopped, ActiveState='active', MainPID='7')
            with patch.object(maintenance, 'service', side_effect=lambda _, unit: worker if unit == 'ultra-recovery-backup.service' else stopped):
                self.assertTrue(invoke()['failed'])
            gate['id'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            self.assertTrue(invoke()['failed'])
            gate['id'] = operation
            checkpoint['configuration'] = {'changed': 'hash'}
            self.assertTrue(invoke()['failed'])

    def test_legacy_cleanup_restores_all_saved_states_before_receipt(self):
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/resume-automation.yml').read_text())[0]['tasks']
        restore = next(task for task in tasks if 'ultra_upgrade_maintenance' in task)
        self.assertIn('restore-accepted', restore['ultra_upgrade_maintenance']['phase'])
        self.assertIn('restore-services', restore['ultra_upgrade_maintenance']['phase'])
        self.assertIn('not (ultra_legacy_bridge_maintenance', tasks[0]['when'])
        rollback = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/rollback.yml').read_text())[2]['tasks']
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
        self.assertEqual(commands, [['python3', '/var/lib/ultra-ansible/upgrade/{{ ultra_lifecycle_id }}/capture/recovery.py', 'capture', '--config', '/etc/ultra-recovery/backup.json']])
        self.assertFalse(any('ansible.builtin.systemd_service' in t for t in tasks))
        freshness = next(t for t in tasks if t['name'] == 'Require fresh independent recovery and unchanged topology')
        conditions = freshness['when'] if isinstance(freshness['when'], list) else [freshness['when']]
        self.assertTrue(any('not (legacy_retry_barrier.held' in condition for condition in conditions))

    def test_no_checkpoint_compensation_and_retry_require_exact_live_legacy_owner(self):
        class Done(Exception):
            pass
        operation = '11111111-2222-3333-4444-555555555555'
        sha = hashlib.sha256(b'legacy').hexdigest()
        gate = {'id': operation, 'phase': 'applying'}
        active = {'ActiveState': 'active', 'MainPID': '7', 'ControlPID': '0'}
        stopped = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'}
        def observed_service(_, unit):
            if unit.endswith('.timer'):
                return {'LoadState': 'loaded', 'ActiveState': 'active'}
            if unit in ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'):
                return stopped
            return active
        module = types.SimpleNamespace(params={'id': operation, 'legacy_sha256': sha, 'initial_runtime_request_json': '{}'}, check_mode=False)
        module.exit_json = lambda **value: (_ for _ in ()).throw(Done(value))
        module.fail_json = lambda **value: (_ for _ in ()).throw(Done(dict(value, failed=True)))
        def invoke():
            with self.assertRaises(Done) as result:
                maintenance.main()
            return result.exception.args[0]
        with patch.object(maintenance, 'AnsibleModule', return_value=module), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'private', return_value=gate), patch.object(maintenance.Path, 'exists', return_value=False), patch.object(maintenance.Path, 'is_symlink', return_value=False), patch.object(maintenance.Path, 'read_bytes', return_value=b'legacy'), patch.object(maintenance.Path, 'is_file', return_value=True), patch.object(maintenance.Path, 'lstat', return_value=types.SimpleNamespace(st_uid=0, st_mode=0o100755)), patch.object(maintenance.Path, 'read_text', return_value='{"role":"bridge"}'), patch.object(maintenance.os, 'readlink', return_value='/usr/local/bin/ultra-relay'), patch.object(maintenance, 'service', side_effect=observed_service), patch.object(maintenance, 'hashes', return_value={}), patch.object(maintenance, 'atomic') as save, patch.object(maintenance, 'untouched_runtime', return_value='active') as initial:
            for phase in ('rollback-check', 'retry-checkpoint'):
                module.params['phase'] = phase
                self.assertEqual(invoke(), {'changed': False, 'verified': True, 'held': False, 'untouched': True})
                gate['id'] = 'foreign'
                self.assertTrue(invoke()['failed'])
                gate['id'] = operation
                gate['phase'] = 'checking'
                self.assertTrue(invoke()['failed'])
                gate['phase'] = 'applying'
                with patch.object(maintenance, 'service', return_value=dict(active, ControlPID='9')):
                    self.assertTrue(invoke()['failed'])
                with patch.object(maintenance, 'service', side_effect=lambda mod, unit: {'LoadState': 'loaded', 'ActiveState': 'inactive'} if unit in maintenance.SERVICES[1:] else observed_service(mod, unit)):
                    self.assertTrue(invoke()['failed'])
                with patch.object(maintenance.Path, 'read_bytes', return_value=b'other'):
                    self.assertTrue(invoke()['failed'])
                with patch.object(maintenance.Path, 'is_symlink', return_value=True):
                    self.assertTrue(invoke()['failed'])
            save.assert_not_called()
            self.assertTrue(initial.called)

    def test_missing_checkpoint_rejects_partially_applied_runtime_images(self):
        import base64
        operation = '11111111-2222-3333-4444-555555555555'
        transaction = operation + '-runtime-1'
        request = json.dumps({'request': {'transaction': transaction, 'role': 'bridge'}})
        binding = hashlib.sha256(request.encode()).hexdigest()
        image = {'Exists': True, 'Data': base64.b64encode(b'original').decode(), 'Mode': 0o600, 'UID': 0, 'GID': 0}
        values = {'json': {'Version': 1, 'Transaction': transaction, 'State': 'prepared', 'Before': [image, image]},
                  'transport.json': {'digest': binding, 'effects_plan': {}},
                  'effects.json': {'version': 1, 'binding_sha256': binding, 'state': 'prepared', 'plan': {}, 'bot': {'active': 'active'}}}
        def read(path):
            key = 'transport.json' if path.name.endswith('.transport.json') else 'effects.json' if path.name.endswith('.effects.json') else 'json'
            return values[key]
        metadata = types.SimpleNamespace(st_mode=0o100600, st_uid=0, st_gid=0)
        live = {name: hashlib.sha256(b'original').hexdigest() for name in maintenance.FILES}
        with patch.object(maintenance, 'private', side_effect=read), patch.object(maintenance, 'hashes', return_value=live), patch.object(maintenance.Path, 'lstat', return_value=metadata):
            self.assertEqual(maintenance.untouched_runtime(request, operation), 'active')
            for name, key in [('json', 'State'), ('effects.json', 'state')]:
                values[name][key] = 'applied'
                with self.assertRaises(ValueError):
                    maintenance.untouched_runtime(request, operation)
                values[name][key] = 'prepared'
            live[maintenance.FILES[0]] = '0'*64
            with self.assertRaises(ValueError):
                maintenance.untouched_runtime(request, operation)

    def test_no_checkpoint_rollback_skips_every_mutation_and_probe(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/rollback.yml').read_text())
        checkpoint = next(task for task in plays[0]['tasks'] if 'ultra_upgrade_maintenance' in task)
        self.assertEqual(checkpoint['ultra_upgrade_maintenance']['phase'], 'rollback-check')
        self.assertTrue(plays[0]['any_errors_fatal'])
        environment = Environment()
        environment.filters['bool'] = bool
        variables = {'ultra_legacy_bridge_maintenance': True,
                     'ultra_runtime_effect_inputs': {'bridge': {'request': 'fixture'}},
                     'release_runtime_effect_binding': {'skipped': True},
                     'hostvars': {'bridge': {'legacy_rollback_barrier': {'untouched': True}}}}
        for play in plays[1:]:
            for task in play['tasks']:
                if task['name'] == 'Save the verified operation result':
                    continue
                conditions = task['when'] if isinstance(task['when'], list) else [task['when']]
                self.assertTrue(any('legacy_rollback_barrier.untouched' in condition for condition in conditions), task['name'])
                self.assertFalse(all(environment.compile_expression(condition)(**variables) for condition in conditions), task['name'])

    def test_first_and_retry_capture_use_signed_staged_collector(self):
        for name in ('upgrade.yml', 'preflight-retry.yml'):
            tasks = yaml.safe_load((ROOT / 'deploy/ansible/playbooks' / name).read_text())[0]['tasks']
            capture = next(i for i, task in enumerate(tasks) if task.get('ansible.builtin.command', {}).get('argv', [None])[0] == 'python3')
            self.assertEqual(tasks[capture-1]['ansible.builtin.include_role']['tasks_from'], 'capture-tool')
            self.assertEqual(tasks[capture]['ansible.builtin.command']['argv'][1], '/var/lib/ultra-ansible/upgrade/{{ ultra_lifecycle_id }}/capture/recovery.py')
            self.assertTrue(tasks[capture]['no_log'])
        tasks = yaml.safe_load((ROOT / 'deploy/ansible/roles/release/tasks/capture-tool.yml').read_text())
        source = next(task['ansible.builtin.assert']['that'] for task in tasks if task['name'] == 'Require exact signed release collector bytes')
        self.assertIn('release_capture_source.stat.checksum == ultra_recovery_capture_tool.sha256', source)
        final = tasks[-1]['ansible.builtin.assert']['that']
        self.assertIn('release_capture_staged.stat.checksum == ultra_recovery_capture_tool.sha256', final)
        self.assertIn("release_capture_staged.stat.mode == '0600'", final)
        self.assertIn('release_capture_staged.stat.uid == 0', final)

    def test_isolated_capture_stages_signed_transitive_database_dependency(self):
        for name in ('upgrade.yml', 'preflight-retry.yml'):
            play = yaml.safe_load((ROOT / 'deploy/ansible/playbooks' / name).read_text())[0]
            self.assertIn('/opt/ultra-recovery/db_connection.py', play['vars']['ultra_recovery_capture_dependency'])
        collector = yaml.safe_load((ROOT / 'deploy/ansible/roles/release/tasks/capture-tool.yml').read_text())
        self.assertEqual(collector[0]['ansible.builtin.include_tasks'], 'capture-dependency.yml')
        dependency = yaml.safe_load((ROOT / 'deploy/ansible/roles/release/tasks/capture-dependency.yml').read_text())
        self.assertTrue(any('capture/db_connection.py' in json.dumps(task) for task in dependency))
        final = dependency[-1]['ansible.builtin.assert']['that']
        self.assertIn('release_capture_dependency_staged.stat.checksum == ultra_recovery_capture_dependency.sha256', final)
        self.assertIn("release_capture_dependency_staged.stat.mode == '0600'", final)

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
