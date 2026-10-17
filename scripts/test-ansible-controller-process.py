#!/usr/bin/env python3
"""Controller cleanup must precede infrastructure lease release."""
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('controller', ROOT / 'deploy/ansible/controller.py')
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


class ProcessCleanup(unittest.TestCase):
    def test_playbook_uses_tmpfs_for_all_controller_temp_layers(self):
        environment = CONTROLLER.playbook_environment(Path('/private/job'), Path('/bundle'))
        self.assertEqual(environment['TMPDIR'], '/dev/shm')
        self.assertEqual(environment['ANSIBLE_LOCAL_TEMP'], '/dev/shm')

    def test_localhost_uses_controller_tmpfs_without_joining_remote_groups(self):
        inventory = {'all': {'children': {'bridge': {'hosts': {'bridge': {}}}}}}
        CONTROLLER.configure_localhost(inventory)
        local = inventory['all']['hosts']['localhost']
        self.assertEqual(local['ansible_connection'], 'local')
        self.assertEqual(local['ansible_remote_tmp'], '/dev/shm')
        self.assertNotIn('localhost', inventory['all']['children']['bridge']['hosts'])
        for name in ('inspect-upgrade-runtime.yml', 'inspect-release-hosts.yml',
                     'inspect-bootstrap.yml', 'upgrade-runtime.yml',
                     'drain-upgrade-workers.yml', 'contain-upgrade.yml'):
            text = (ROOT / 'deploy/ansible/playbooks' / name).read_text()
            self.assertNotRegex(text, r'^\s+hosts: all\s*$', name)
        for name in ('inspect-upgrade-runtime.yml', 'upgrade-runtime.yml', 'contain-upgrade.yml'):
            text = (ROOT / 'deploy/ansible/playbooks' / name).read_text()
            for match in re.finditer(r"groups\[['\"]all['\"]\]", text):
                self.assertIn('difference', text[match.start():match.start() + 80], name)

    def test_localhost_is_added_when_optional_all_inventory_is_omitted(self):
        inventory = {}
        CONTROLLER.configure_localhost(inventory)
        self.assertEqual(inventory['all']['hosts']['localhost'], {
            'ansible_connection': 'local',
            'ansible_remote_tmp': '/dev/shm',
        })
        for invalid in (None, {'all': None}, {'all': []}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'invalid_inventory'):
                CONTROLLER.configure_localhost(invalid)

    def test_controller_host_collision_is_rejected(self):
        inventory = {'all': {'hosts': {'localhost': {'ansible_host': '192.0.2.10'}}}}
        with self.assertRaisesRegex(ValueError, 'controller_host_conflict'):
            CONTROLLER.configure_localhost(inventory)

    def test_timeout_and_exited_leader_leave_no_worker(self):
        for leader_delay in ('time.sleep(20)', 'pass'):
            with self.subTest(leader_delay=leader_delay), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / 'late'
                grandchild = ('import time,pathlib;time.sleep(.5);pathlib.Path(' +
                              repr(str(marker)) + ').write_text("late")')
                leader = ('import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",' +
                          repr(grandchild) + ']);' + leader_delay)
                if leader_delay == 'pass':
                    self.assertEqual(CONTROLLER.run_playbook(
                        [sys.executable, '-c', leader], directory, {}, timeout=.15), 0)
                else:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        CONTROLLER.run_playbook(
                            [sys.executable, '-c', leader], directory, {}, timeout=.15)
                time.sleep(.7)
                self.assertFalse(marker.exists(), 'worker ran after executor returned')


if __name__ == '__main__':
    unittest.main()
