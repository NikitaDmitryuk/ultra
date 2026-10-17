#!/usr/bin/env python3
"""Bounded retry for lifecycle reservations contending with background jobs."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {
        'ansible': types.ModuleType('ansible'),
        'ansible.module_utils': types.ModuleType('ansible.module_utils'),
        'ansible.module_utils.basic': types.SimpleNamespace(AnsibleModule=None)}):
    spec = importlib.util.spec_from_file_location(
        'lifecycle_retry', ROOT / 'deploy/ansible/library/ultra_lifecycle.py')
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)


class LifecycleRetryTests(unittest.TestCase):
    def test_applying_retries_exact_infrastructure_busy_then_succeeds(self):
        responses = iter([
            # service.Client.exchange formats an empty diagnostic as "(: )".
            (1, '', 'Ansible lease: infrastructure_busy (: )\n'),
            (0, '', ''),
        ])
        calls = []
        result = lifecycle.run_lifecycle_transition(
            lambda: calls.append(True) or next(responses), 'applying', sleep=lambda _: None)
        self.assertIs(result, True)
        self.assertEqual(len(calls), 2)

    def test_unadorned_busy_code_remains_compatible(self):
        responses = iter([
            (1, '', 'Ansible lease: infrastructure_busy\n'),
            (0, '', ''),
        ])
        result = lifecycle.run_lifecycle_transition(lambda: next(responses), 'applying', sleep=lambda _: None)
        self.assertIs(result, True)

    def test_other_errors_and_non_applying_phases_are_not_retried(self):
        for phase, response in (
                ('applying', (1, '', 'Ansible lease: lifecycle_busy\n')),
                ('released', (1, '', 'Ansible lease: infrastructure_busy\n'))):
            calls = []
            result = lifecycle.run_lifecycle_transition(
                lambda: calls.append(True) or response, phase, sleep=lambda _: None)
            self.assertIs(result, False)
            self.assertEqual(len(calls), 1)

    def test_busy_retry_is_bounded(self):
        now = [0.0]
        calls = []

        def run():
            calls.append(True)
            return 1, '', 'Ansible lease: infrastructure_busy\n'

        def sleep(duration):
            now[0] += duration

        result = lifecycle.run_lifecycle_transition(
            run, 'applying', sleep=sleep, monotonic=lambda: now[0], retry_seconds=2)
        self.assertIsNone(result)
        self.assertEqual(len(calls), 3)


if __name__ == '__main__':
    unittest.main()
