#!/usr/bin/env python3
"""Offline DB preservation boundary contracts, using synthetic state only."""
import copy
import base64
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import os
import tempfile
import types
import unittest
import uuid
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.module_utils': types.ModuleType('ansible.module_utils'), 'ansible.module_utils.basic': types.SimpleNamespace(AnsibleModule=None)}):
    spec = importlib.util.spec_from_file_location('db_gate', ROOT / 'deploy/ansible/library/ultra_database_preservation.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)


def observation():
    return {'cluster': '123456789', 'database': 'fixture', 'primary': True, 'oid': 16384, 'clients': 0, 'selection': 'a' * 64,
            'migrations': [{'version': n, 'applied_at': '2026-01-01T00:00:00'} for n in range(1, 26)]}


class Preservation(unittest.TestCase):
    def allowed(self, processes, metadata, operation, phase, transaction):
        return gate.controller_allowances(processes, metadata, operation, phase, transaction, own_pid=32, verify_broker=lambda *args: True)

    def controller_fixture(self, directory):
        root = Path(directory) / 'current-upgrade'
        root.mkdir(mode=0o700)
        stage = root / 'activate'
        stage.mkdir(mode=0o700)
        operation = str(uuid.UUID(bytes=hashlib.sha256(str(root).encode()).digest()[:16], version=4))
        variables = {'ultra_lifecycle_id': operation, 'ultra_forward_only': True}
        request = json.dumps({'variables': variables}).encode()
        digest = hashlib.sha256(request).hexdigest()
        job = {'schema_version': 1, 'operation': 'upgrade', 'request_sha256': digest, 'binary_sha256': 'b' * 64}
        receipt = dict(job, state='running', started_at=100)
        for name, value in (('request.json', request), ('job.json', json.dumps(job).encode()), ('receipt.json', json.dumps(receipt).encode())):
            path = stage / name
            path.write_bytes(value)
            path.chmod(0o600)
        arguments = [b'/venv/bin/python3', b'/venv/bin/ansible-playbook', b'-i', bytes(stage / 'inventory.yml'),
                     bytes(stage / 'bundle/playbooks/upgrade.yml'), b'--extra-vars', b'@' + bytes(stage / 'variables.yml')]
        installer = [b'/opt/current/ultra-install', b'operator-upgrade', b'--forward-only', b'--job-dir', bytes(root)]
        processes = [(20, installer), (30, arguments), (31, arguments), (32, [b'python3', b'/tmp/ansible-tmp-current/AnsiballZ_ultra_database_preservation.py']), (40, [b'/opt/ultra-ansible/releases/fixture/ultra-install', b'ansible-controller', b'--executable', b'/opt/ultra-ansible/releases/fixture/venv/bin/ansible-playbook'])]
        metadata = {32: {'uid': 0, 'start': 112, 'parent': 31}, 40: {'uid': 0, 'start': 1, 'parent': 1}, 20: {'uid': 0, 'start': 80, 'parent': 1}, 30: {'uid': 0, 'start': 110, 'parent': 20},
                    31: {'uid': 0, 'start': 111, 'parent': 30}}
        return operation, stage, processes, metadata

    def test_current_controller_is_bound_to_lifecycle_and_only_its_ancestry_is_exempt(self):
        with tempfile.TemporaryDirectory() as directory:
            operation, stage, processes, metadata = self.controller_fixture(directory)
            allowed = self.allowed(processes, metadata, operation, 'stopped', '')
            self.assertEqual(allowed, {20, 30, 31, 32, 40})
            gate.validate_processes(processes, 123, allowed)
            # A stale b8 installer remains forbidden even beside a valid tree.
            stale = (99, [b'/opt/b8/ultra-install', b'upgrade', b'--job-dir', b'/old-attempt'])
            with self.assertRaisesRegex(ValueError, 'legacy_worker_unfenced'):
                gate.validate_processes(processes + [stale], 123, allowed)
            with self.assertRaisesRegex(ValueError, 'controller_binding_invalid'):
                self.allowed(processes, metadata, 'another-operation', 'stopped', '')

    def test_stale_or_independently_surviving_ansible_tree_cannot_claim_current_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            operation, stage, processes, metadata = self.controller_fixture(directory)
            old = copy.deepcopy(metadata)
            # Same-second stale root would pass an int(time.time()) comparison.
            old[30]['parent'] = 1
            old[30]['start'] = 100
            with self.assertRaisesRegex(ValueError, 'controller_binding_invalid'):
                self.allowed(processes, old, operation, 'stopped', '')
            orphan = copy.deepcopy(metadata)
            orphan[31]['parent'] = 1
            with self.assertRaisesRegex(ValueError, 'controller_ambiguous'):
                self.allowed(processes, orphan, operation, 'stopped', '')
            nonroot = copy.deepcopy(metadata)
            nonroot[30]['uid'] = 1000
            with self.assertRaisesRegex(ValueError, 'controller_process_unprivileged'):
                self.allowed(processes, nonroot, operation, 'stopped', '')

    def test_controller_binding_rejects_changed_failed_and_nonforward_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            operation, stage, processes, metadata = self.controller_fixture(directory)
            receipt_path = stage / 'receipt.json'
            receipt = json.loads(receipt_path.read_text())
            for changed in (dict(receipt, state='failed'), dict(receipt, request_sha256='c' * 64)):
                receipt_path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, 'controller_binding_invalid'):
                    self.allowed(processes, metadata, operation, 'stopped', '')
            receipt_path.write_text(json.dumps(receipt))
            request_path = stage / 'request.json'
            request = json.loads(request_path.read_text())
            request['variables']['ultra_forward_only'] = False
            raw = json.dumps(request).encode()
            request_path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            for name in ('job.json', 'receipt.json'):
                path = stage / name
                value = json.loads(path.read_text())
                value['request_sha256'] = digest
                path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'controller_binding_invalid'):
                self.allowed(processes, metadata, operation, 'stopped', '')

    def test_installer_ancestor_must_explicitly_select_current_forward_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            operation, stage, processes, metadata = self.controller_fixture(directory)
            for argv in ([b'ultra-install', b'upgrade', b'--job-dir', bytes(stage.parent)],
                         [b'ultra-install', b'operator-upgrade', b'--forward-only', b'--job-dir', b'/old-attempt'],
                         [b'ultra-install', b'operator-upgrade', b'--forward-only']):
                with self.assertRaisesRegex(ValueError, 'controller_binding_invalid'):
                    self.allowed([(20, argv)] + processes[1:], metadata, operation, 'stopped', '')

    def test_preparation_controller_must_bind_the_exact_native_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            operation, stage, processes, metadata = self.controller_fixture(directory)
            prepared = stage.with_name('runtime-prepare-generation-2')
            stage.rename(prepared)
            processes = [(pid, [argument.replace(bytes(stage), bytes(prepared)) for argument in argv]) for pid, argv in processes]
            transaction = operation + '-runtime-2'
            request_path = prepared / 'request.json'
            request = json.loads(request_path.read_text())
            request['variables'] = {'ultra_lifecycle_id': operation, 'ultra_forward_only': True, 'ultra_runtime_action': 'prepare',
                                    'ultra_runtime_probe_requests': {'bridge': {'request': {'transaction': transaction}}}}
            raw = json.dumps(request).encode()
            request_path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            for name in ('job.json', 'receipt.json'):
                path = prepared / name
                value = json.loads(path.read_text())
                value['request_sha256'] = digest
                value['operation'] = 'upgrade-runtime'
                path.write_text(json.dumps(value))
            processes = [(pid, [argument.replace(b'/playbooks/upgrade.yml', b'/playbooks/upgrade-runtime.yml') for argument in argv]) for pid, argv in processes]
            allowed = self.allowed(processes, metadata, operation, 'baseline', transaction)
            self.assertEqual(allowed, {20, 30, 31, 32, 40})
            with self.assertRaisesRegex(ValueError, 'controller_binding_invalid'):
                self.allowed(processes, metadata, operation, 'baseline', operation + '-runtime-1')

    def test_destructive_migrations_must_already_be_continuously_recorded(self):
        gate.validate_observation(observation())
        for versions in (list(range(1, 6)), [1, 2, 3, 4, 5, 7, 8, 9], [0] + list(range(2, 26)), list(range(2, 27)), [True] + list(range(2, 26))):
            current = observation()
            current['migrations'] = [{'version': n, 'applied_at': 'stamp'} for n in versions]
            with self.assertRaisesRegex(ValueError, 'schema_migration_required'):
                gate.validate_observation(current)

    def test_db_replacement_selection_and_history_edits_fail(self):
        baseline = observation()
        for field, value in (('cluster', '987654321'), ('database', 'other'), ('oid', 16385), ('selection', 'b' * 64), ('migrations', observation()['migrations'][:-1])):
            current = copy.deepcopy(baseline)
            current[field] = value
            with self.assertRaisesRegex(ValueError, 'identity_or_history_changed'):
                gate.same_database(baseline, current)
        current = copy.deepcopy(baseline)
        current['migrations'][5]['applied_at'] = 'rewritten'
        with self.assertRaises(ValueError):
            gate.same_database(baseline, current)

    def test_standby_cannot_be_anchored_as_the_writer_database(self):
        with self.assertRaisesRegex(ValueError, 'schema_migration_required'):
            gate.validate_observation(dict(observation(), primary=False))

    def test_bridge_census_rejects_old_controllers_and_remote_payload_workers(self):
        own = (123, [b'/usr/bin/python3', b'/root/.ansible/tmp/ansible-tmp-123/AnsiballZ_ultra_database_preservation.py'])
        gate.validate_processes([own, (124, [b'/usr/lib/postgresql/16/bin/postgres'])], 123)
        for argv in ([b'/usr/bin/python3', b'/usr/bin/ansible-playbook', b'upgrade.yml'],
                     [b'/usr/local/bin/ultra-install', b'upgrade'],
                     [b'python3', b'/tmp/AnsiballZ_command.py'],
                     [b'python3', b'/root/.ansible/tmp/ansible-tmp-old/payload.py']):
            with self.assertRaisesRegex(ValueError, 'legacy_worker_unfenced'):
                gate.validate_processes([own, (321, argv)], 123)
        # A new module invoking the same module name is still another worker.
        with self.assertRaises(ValueError):
            gate.validate_processes([own, (321, own[1])], 123)

    def test_bridge_census_rejects_oversize_or_unreadable_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / '321'
            process.mkdir()
            (process / 'cmdline').write_bytes(b'x' * 65537)
            with self.assertRaisesRegex(ValueError, 'process_evidence_invalid'):
                gate.workers_drained(root, 123)
            (process / 'cmdline').unlink()
            gate.workers_drained(root, 123)
            with patch.object(Path, 'open', side_effect=PermissionError('unreadable')):
                with self.assertRaises(PermissionError):
                    gate.workers_drained(root, 123)

    def test_complete_gate_requires_owned_baseline_and_zero_client_backends(self):
        class Finished(Exception):
            pass
        operation = '11111111-2222-3333-4444-555555555555'
        transaction = operation + '-runtime-1'
        native_spec = {'database': {'dsn': 'postgres://owner:fixture@127.0.0.1:25432/fixture?sslmode=disable'}}
        selection = gate.database_selection(native_spec, 'fixture')
        original = dict(observation(), selection=selection, capture_after=100, previous_delivery={})
        image = {'Exists': True, 'Data': base64.b64encode(json.dumps(native_spec).encode()).decode()}
        values = {
            'lifecycle.json': {'id': operation, 'phase': 'applying'},
            'reconcile.json': {'database': 'fixture'},
            'backup.json': {'database': 'fixture'},
            'spec.json': native_spec,
            transaction + '.json': {'Version': 1, 'Transaction': transaction, 'State': 'prepared',
                                   'Before': [image, {'Data': ''}], 'Candidate': [image, {'Data': ''}]},
            'database-preservation.json': original,
            'last-success.json': {'snapshot_at': 101},
        }
        module = types.SimpleNamespace(params={'id': operation, 'phase': 'stopped', 'transaction': transaction}, check_mode=False, run_command=lambda argv: None)
        module.exit_json = lambda **result: (_ for _ in ()).throw(Finished(result))
        module.fail_json = lambda **result: (_ for _ in ()).throw(Finished(dict(result, failed=True)))
        def invoke():
            try:
                gate.main()
            except Finished as result:
                return result.args[0]
        with patch.object(gate, 'AnsibleModule', return_value=module), \
             patch.object(gate.os, 'geteuid', return_value=0), \
             patch.object(gate, 'document', side_effect=lambda path: copy.deepcopy(values[path.name])), \
             patch.object(gate.Path, 'exists', side_effect=lambda: False), \
             patch.object(gate.Path, 'is_symlink', return_value=True), \
             patch.object(gate, 'stopped') as stopped, \
             patch.object(gate, 'workers_drained') as workers, \
             patch.object(gate, 'observe', return_value=observation()) as observe, \
             patch.object(gate, 'atomic') as atomic, \
             patch.object(gate.time, 'time', return_value=110), \
             patch.object(gate.time, 'sleep'):
            self.assertTrue(invoke()['verified'])
            workers.assert_called_once()
            stopped.assert_called_once()
            self.assertEqual(atomic.call_args.args[1]['capture_after'], 110)
            observe.return_value = dict(observation(), clients=1)
            self.assertTrue(invoke()['failed'])
            observe.return_value = observation()
            module.params['phase'] = 'baseline'
            self.assertTrue(invoke()['verified'])
            values['lifecycle.json']['id'] = 'another-operation'
            self.assertTrue(invoke()['failed'])

    def test_only_explicit_local_database_selection_is_supported(self):
        accepted = 'postgres://owner:fixture@127.0.0.1:25432/fixture?sslmode=disable'
        gate.database_selection({'database': {'dsn': accepted}}, 'fixture')
        for dsn in ('postgres://owner:fixture@192.0.2.1/fixture', accepted.replace('/fixture?', '/other?'),
                    accepted + '&host=192.0.2.1', accepted + '&options=-csearch_path=other',
                    'dbname=fixture', accepted.replace(':25432', ':5433')):
            with self.assertRaises(ValueError):
                gate.database_selection({'database': {'dsn': dsn}}, 'fixture')

    def test_writers_must_have_zero_main_and_control_pids(self):
        output = 'LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\n'
        gate.stopped(types.SimpleNamespace(run_command=lambda argv: (0, output, '')))
        for bad in (output.replace('MainPID=0', 'MainPID=12'), output.replace('ControlPID=0', 'ControlPID=3'),
                    output.replace('ActiveState=inactive', 'ActiveState=active'), output.replace('LoadState=loaded', 'LoadState=not-found')):
            with self.assertRaisesRegex(ValueError, 'writers_not_stopped'):
                gate.stopped(types.SimpleNamespace(run_command=lambda argv: (0, bad, '')))

    def test_inspection_is_read_only_and_binds_the_queried_database(self):
        from contextlib import nullcontext
        calls = []
        def run(argv, **_kwargs):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(observation()))
        module = types.SimpleNamespace(run_command=run)
        dependency = types.SimpleNamespace(
            dsn_from_runtime=lambda database: 'fixture-dsn',
            pgpass=lambda directory, parsed: nullcontext({}),
            connection_args=lambda parsed, database, executable: ['runuser', '-u', 'postgres', executable, '-d', database],
        )
        with patch.dict(sys.modules, {'db_connection': dependency}), patch.object(gate.subprocess, 'run', side_effect=run):
            gate.observe(module, 'fixture')
            with self.assertRaisesRegex(ValueError, 'identity_migration_required'):
                gate.observe(module, 'other')
        self.assertEqual(calls[0][:3], ['runuser', '-u', 'postgres'])
        self.assertEqual(calls[0][calls[0].index('-d') + 1], 'fixture')
        self.assertIn('pg_control_system()', calls[0][-1])
        self.assertIn('public.schema_migrations', calls[0][-1])
        self.assertIn("backend_type='client backend'", calls[0][-1])
    def test_fresh_verified_dump_must_be_delivered_to_the_independent_primary(self):
        baseline = {'capture_after': 100, 'previous_delivery': {}}
        config = {'bridge_provider': 'bridge-provider'}
        policy = {'independent': True, 'destinations': [{'id': 'primary', 'host': '192.0.2.2', 'required': True}]}
        topology = {'primary': 'primary', 'node_metadata': [{'id': 'primary', 'host': '192.0.2.2', 'provider': 'independent-provider'}]}
        status = {'state': 'ready', 'primary': 'primary', 'independent': True}
        receipt = {'source': 'bridge', 'dump_verified': True, 'snapshot_at': 101,
                   'destinations': ['192.0.2.2'], 'delivered_target_ids': ['primary'],
                   'backup_sha256': 'a' * 64, 'artifact_sha256': 'b' * 64}
        gate.delivered(baseline, config, policy, topology, status, receipt, 110)
        for field, value in (('dump_verified', False), ('snapshot_at', 100), ('snapshot_at', 111),
                             ('destinations', []), ('delivered_target_ids', []), ('backup_sha256', 'bad')):
            bad = dict(receipt, **{field: value})
            with self.assertRaisesRegex(ValueError, 'independent_dump_required'):
                gate.delivered(baseline, config, policy, topology, status, bad, 110)
        bad_topology = copy.deepcopy(topology)
        bad_topology['node_metadata'][0]['provider'] = config['bridge_provider']
        with self.assertRaises(ValueError):
            gate.delivered(baseline, config, policy, bad_topology, status, receipt, 110)
        with self.assertRaises(ValueError):
            gate.delivered(baseline, config, policy, topology, status, receipt, 402)

    def test_orchestration_stops_writers_and_verifies_dump_before_any_release_activation(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/upgrade.yml').read_text())
        names = [task['name'] for task in plays[0]['tasks']]
        required = ['Stop legacy topology producers before freezing recovery',
                    'Wait for current copies and reconcile to finish naturally',
                    'Stop the identified legacy bridge before changing exits',
                    'Require unchanged database identity and drained writers before the final dump',
                    'Create the independent control generation before activation',
                    'Require a validated fresh independently delivered dump before activating any binary']
        positions = [names.index(name) for name in required]
        self.assertEqual(positions, sorted(positions))
        for task in plays[0]['tasks']:
            if 'ultra_database_preservation' in task:
                self.assertEqual(task.get('when'), 'ultra_forward_only | default(false) | bool')
                self.assertTrue(task['no_log'])
        runtime = yaml.safe_load((ROOT / 'deploy/ansible/roles/runtime/tasks/phase.yml').read_text())
        baseline = next(task for task in runtime if 'ultra_database_preservation' in task)
        self.assertEqual(baseline['ultra_database_preservation']['phase'], 'baseline')
        self.assertIn("ultra_runtime_action == 'prepare'", baseline['when'])
        self.assertIn('ultra_forward_only | default(false) | bool', baseline['when'])
        self.assertLess(runtime.index(next(task for task in runtime if task['name'] == 'Require the exact completed host phase')), runtime.index(baseline))
        source = (ROOT / 'cmd/ultra-install/ansible_upgrade.go').read_text()
        prepare = source.index('"prepare", generation, retryFailed)')
        activation = source.index('deployansible.RunLocal(ctx, "upgrade",', prepare)
        apply = source.index('"apply", generation)', activation)
        self.assertLess(prepare, activation)
        self.assertLess(activation, apply)

    def test_worker_detection_uses_executable_prefix_not_broker_option_values(self):
        broker = [b'/opt/ultra-ansible/releases/fixture/ultra-install', b'ansible-controller', b'--executable',
                  b'/opt/ultra-ansible/releases/fixture/venv/bin/ansible-playbook']
        self.assertIsNone(gate.playbook_argv(broker))
        self.assertIsNone(gate.playbook_argv([b'/bin/echo', b'/venv/bin/ansible-playbook']))
        worker = [b'/venv/bin/ansible-playbook', b'-i', b'/private/inventory.yml']
        self.assertEqual(gate.playbook_argv(worker), worker)
        self.assertEqual(gate.playbook_argv([b'/venv/bin/python3'] + worker), worker)

    def test_broker_requires_exact_systemd_main_process_unit_and_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            unit = Path(directory) / 'ultra-ansible-controller.service'
            argv = [b'/opt/ultra-ansible/releases/fixture/ultra-install', b'ansible-controller', b'--executable',
                    b'/opt/ultra-ansible/releases/fixture/venv/bin/ansible-playbook']
            unit.write_text('[Service]\nUser=root\nGroup=root\nKillMode=control-group\nExecStart=' + b' '.join(argv).decode() + '\n')
            unit.chmod(0o644)
            fields = {'Id': 'ultra-ansible-controller.service', 'MainPID': '40',
                      'ControlGroup': '/system.slice/ultra-ansible-controller.service', 'User': 'root', 'Group': 'root',
                      'ActiveState': 'active', 'SubState': 'running', 'FragmentPath': str(unit), 'DropInPaths': ''}
            info = {'uid': 0, 'parent': 1, 'cgroup': b'0::/system.slice/ultra-ansible-controller.service\n'}
            stat = unit.lstat()
            # Synthetic fixture ownership only; never inspect a live service.
            synthetic_stat = types.SimpleNamespace(st_uid=0, st_mode=stat.st_mode, st_size=stat.st_size)
            def run(values):
                return lambda command: (0, ''.join(key + '=' + value + '\n' for key, value in values.items()), '')
            with patch.object(gate.Path, 'lstat', return_value=synthetic_stat):
                self.assertTrue(gate.broker_identity(40, argv, info, run(fields), unit))
                for changed in (dict(fields, MainPID='99'), dict(fields, DropInPaths='/override.conf'),
                                dict(fields, ControlGroup='/system.slice/other.service'), dict(fields, User='relay'),
                                dict(fields, ActiveState='inactive'), dict(fields, FragmentPath='/foreign.service')):
                    with self.subTest(changed=changed):
                        with self.assertRaisesRegex(ValueError, 'broker_unverified'):
                            gate.broker_identity(40, argv, info, run(changed), unit)
                for changed in (dict(info, uid=1000), dict(info, parent=20), dict(info, cgroup=b'0::/system.slice/foreign.service\n')):
                    with self.assertRaisesRegex(ValueError, 'broker_unverified'):
                        gate.broker_identity(40, argv, changed, run(fields), unit)
                for changed in (argv + [b'--state', b'/foreign'], [b'/old/ultra-install'] + argv[1:],
                                argv[:3] + [b'/foreign/ansible-playbook']):
                    with self.assertRaisesRegex(ValueError, 'broker_unverified'):
                        gate.broker_identity(40, changed, info, run(fields), unit)
                unit.write_text('[Service]\nUser=root\nGroup=root\nKillMode=control-group\nExecStart=/old/ultra-install ansible-controller\n')
                with self.assertRaisesRegex(ValueError, 'broker_unverified'):
                    gate.broker_identity(40, argv, info, run(fields), unit)


if __name__ == '__main__':
    unittest.main()
