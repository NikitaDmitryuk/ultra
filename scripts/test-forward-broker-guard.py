#!/usr/bin/env python3
"""Focused contract tests for the read-only forward broker identity guard."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'ultra_forward_broker_guard', ROOT / 'deploy/ansible/library/ultra_forward_broker_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


OLD = '11111111-1111-4111-8111-111111111111'
NEW = '22222222-2222-4222-8222-222222222222'
PREVIOUS = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.144',
            'installer_sha256': 'a' * 64, 'runtime_sha256': 'b' * 64, 'unit_sha256': 'c' * 64}
TARGET = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.145',
          'installer_sha256': 'd' * 64, 'runtime_sha256': 'e' * 64, 'unit_sha256': 'f' * 64}
PRIOR_TARGET = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.144',
                'installer_sha256': '1' * 64, 'runtime_sha256': '2' * 64, 'unit_sha256': '3' * 64}


class ForwardBrokerGuardTests(unittest.TestCase):
    def setUp(self):
        self.params = {'action': 'before', 'old_id': OLD, 'candidate_id': NEW,
                       'expected_brokers': [PREVIOUS], 'target_broker': TARGET}

    def run_verify(self, matches):
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle') as lifecycle, \
                patch.object(guard, 'broker_matches', side_effect=lambda value: id(value) in matches):
            result = guard.verify(self.params)
        lifecycle.assert_called_once_with(OLD, NEW)
        return result

    def test_before_accepts_only_frozen_old_identity(self):
        self.assertTrue(self.run_verify({id(PREVIOUS)})['verified'])
        with self.assertRaisesRegex(ValueError, 'forward_broker_predecessor_mismatch'):
            self.run_verify(set())

    def test_after_requires_the_exact_candidate_identity(self):
        self.params['action'] = 'after'
        self.assertEqual(self.run_verify({id(TARGET)})['controller_directory'], TARGET['directory'])
        with self.assertRaisesRegex(ValueError, 'forward_broker_target_mismatch'):
            self.run_verify({id(PREVIOUS)})

    def test_before_accepts_three_frozen_previous_retry_and_signed_candidate_identities(self):
        self.params['expected_brokers'] = [PREVIOUS, PRIOR_TARGET, TARGET]
        self.assertTrue(self.run_verify({id(PRIOR_TARGET)})['verified'])

    def test_rejects_more_than_three_candidate_identities(self):
        self.params['expected_brokers'] = [PREVIOUS, PRIOR_TARGET, TARGET, PREVIOUS]
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'broker_matches'):
            with self.assertRaisesRegex(ValueError, 'forward_broker_identity_invalid'):
                guard.verify(self.params)

    def test_lifecycle_verification_precedes_identity_acceptance(self):
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle', side_effect=ValueError('gate_changed')), \
                patch.object(guard, 'broker_matches') as broker:
            with self.assertRaisesRegex(ValueError, 'gate_changed'):
                guard.verify(self.params)
        broker.assert_not_called()

    def test_rejects_malformed_identity_even_when_expected(self):
        self.params['expected_brokers'] = [{'directory': '/tmp/controller',
                                            'installer_sha256': 'x',
                                            'runtime_sha256': 'b' * 64,
                                            'unit_sha256': 'c' * 64}]
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'broker_matches', return_value=True):
            with self.assertRaisesRegex(ValueError, 'forward_broker_identity_invalid'):
                guard.verify(self.params)

    def test_rejects_unknown_or_duplicate_retirement_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'lifecycle.json').touch()
            (root / 'lifecycle-retired.json').touch()
            def read(path, limit=65536):
                if Path(path).name == 'lifecycle.json':
                    return {'id': OLD, 'phase': 'applying'}
                return {'version': 1, 'ids': [OLD, OLD]}
            with patch.object(guard, 'ROOT', root), patch.object(guard, 'private_json', side_effect=read):
                with self.assertRaisesRegex(ValueError, 'forward_broker_retirement_invalid'):
                    guard.check_lifecycle(OLD, NEW)


if __name__ == '__main__':
    unittest.main()
