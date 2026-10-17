#!/usr/bin/env python3
"""Synthetic process trees only; never inspect the host process table."""
import copy
import importlib.util
from pathlib import Path
import sys
import os
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.module_utils': types.ModuleType('ansible.module_utils'), 'ansible.module_utils.basic': types.SimpleNamespace(AnsibleModule=None)}):
    spec = importlib.util.spec_from_file_location('worker_gate', ROOT / 'deploy/ansible/library/ultra_upgrade_worker_drain.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)


class WorkerDrain(unittest.TestCase):
    def fixture(self):
        argv = [b'/venv/python', b'/venv/ansible-playbook']
        installer = [b'/release/ultra-install', b'operator-upgrade', b'--forward-only', b'--job-dir', b'/new']
        processes = {40: [b'/opt/ultra-ansible/releases/fixture/ultra-install', b'ansible-controller', b'--executable', b'/opt/ultra-ansible/releases/fixture/venv/bin/ansible-playbook'], 10: installer, 20: argv, 21: argv, 30: [b'python', b'/tmp/ansible-tmp-1/AnsiballZ_ultra_upgrade_worker_drain.py']}
        metadata = {40: {'parent': 1, 'uid': 0, 'start': 1}, 10: {'parent': 1, 'uid': 0, 'start': 1}, 20: {'parent': 10, 'uid': 0, 'start': 110},
                    21: {'parent': 20, 'uid': 0, 'start': 111}, 30: {'parent': 21, 'uid': 0, 'start': 112}}
        return processes, metadata

    def allowed(self, processes, metadata, local=True):
        with patch.object(gate, 'controller', return_value=(Path('/new/handoff-drain-fixture'), 100)):
            return gate.allowances(processes, metadata, 30, 'old', 'new', local, verify_broker=lambda *args: True)

    def test_exact_current_tree_and_detached_workers(self):
        processes, metadata = self.fixture()
        allowed = self.allowed(processes, metadata)
        self.assertEqual(allowed, {10, 20, 21, 30, 40})
        gate.validate_processes(processes, allowed)
        for arguments in ([b'python', b'/tmp/ansible-tmp-old/AnsiballZ_shell.py'], [b'/old/ultra-install', b'upgrade'], [b'/old/ansible-playbook'], [b'sh', b'-c', b'sleep 10; python /tmp/ansible-tmp-old/AnsiballZ_shell.py']):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(ValueError, 'legacy_worker_live'):
                    gate.validate_processes(processes | {99: arguments}, allowed)

    def test_exit_only_exempts_current_module(self):
        own = {30: [b'python', b'/tmp/AnsiballZ_ultra_upgrade_worker_drain.py']}
        allowed = self.allowed(own, {}, False)
        gate.validate_processes(own, allowed)
        with self.assertRaisesRegex(ValueError, 'legacy_worker_live'):
            gate.validate_processes(own | {99: [b'python', b'/tmp/AnsiballZ_shell.py']}, allowed)
        processes, metadata = self.fixture()
        with self.assertRaisesRegex(ValueError, 'foreign_controller|broker_unverified'):
            self.allowed(processes, metadata, False)

    def test_old_or_independent_controller_fails(self):
        for kind in ('same-second-stale', 'independent', 'unbound', 'unprivileged', 'old-installer', 'missing-job-dir'):
            with self.subTest(kind=kind):
                processes, metadata = self.fixture()
                if kind == 'same-second-stale':
                    processes[99] = processes[20]
                    metadata[99] = {'parent': 1, 'uid': 0, 'start': 110}
                if kind == 'independent': metadata[21]['parent'] = 1
                if kind == 'unbound': metadata[30]['parent'] = 1
                if kind == 'unprivileged': metadata[20]['uid'] = 1000
                if kind == 'old-installer': processes[10] = [b'/old/ultra-install', b'upgrade']
                if kind == 'missing-job-dir': processes[10] = processes[10][:-2]
                with self.assertRaises(ValueError): self.allowed(processes, metadata)

    def test_unreadable_proc_fails_closed(self):
        with patch.object(Path, 'iterdir', side_effect=PermissionError('fixture')):
            with self.assertRaises(PermissionError): gate.census('old', 'new', False, Path('/synthetic'), 30)

    def test_playbook_covers_all_hosts_and_does_not_mutate(self):
        import yaml
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/drain-upgrade-workers.yml').read_text())
        self.assertEqual(plays[0]['hosts'], 'all')
        self.assertTrue(plays[0]['any_errors_fatal'])
        self.assertEqual(set(plays[0]['tasks'][0]) - {'name', 'become'}, {'ultra_upgrade_worker_drain'})

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
