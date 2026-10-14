#!/usr/bin/env python3
"""Controller cleanup must precede infrastructure lease release."""
import importlib.util
from pathlib import Path
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
