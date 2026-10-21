#!/usr/bin/env python3
"""Legacy accepted resume must prove the exact journalled candidate chain."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.module_utils': types.ModuleType('ansible.module_utils'), 'ansible.module_utils.basic': types.SimpleNamespace(AnsibleModule=None)}):
    spec = importlib.util.spec_from_file_location('maintenance', ROOT / 'deploy/ansible/library/ultra_upgrade_maintenance.py')
    maintenance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(maintenance)


def digest(value):
    return hashlib.sha256(value).hexdigest()


class AcceptedResume(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.operation = '12345678-1234-1234-1234-123456789abc'
        tx = self.operation + '-runtime-2'
        self.request = {'request': {'transaction': tx, 'role': 'bridge', 'bot_enabled': False}}
        self.contract = {'generation': 2, 'runtime_request_json': json.dumps(self.request)}
        self.checkpoint = {'configuration': dict(zip(maintenance.FILES, map(digest, (b'old-spec', b'old-env', b'unit'))))}
        image = lambda raw: {'Exists': True, 'Data': base64.b64encode(raw).decode(), 'Mode': 0o600, 'UID': os.geteuid(), 'GID': os.getegid()}
        self.values = {
            tx + '.json': {'Version': 1, 'Transaction': tx, 'State': 'applied', 'Before': [image(b'old-spec'), image(b'old-env')], 'Candidate': [image(b'runtime-spec'), image(b'runtime-env')]},
            tx + '.transport.json': {'digest': digest(self.contract['runtime_request_json'].encode()), 'effects_plan': {'bot_service': True, 'bot_enabled': False}},
            tx + '.effects.json': {'version': 1, 'state': 'applied', 'binding_sha256': digest(self.contract['runtime_request_json'].encode()), 'plan': {'bot_service': True, 'bot_enabled': False}},
        }
        self.live = dict(zip(maintenance.FILES, map(digest, (b'runtime-spec', b'runtime-env', b'unit'))))
        for name in maintenance.FILES[:2]:
            path = self.root / name.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
            path.chmod(0o600)

    def verify(self, compensation=False):
        with patch.object(maintenance, 'private', side_effect=lambda path: self.values[path.name]), patch.object(maintenance, 'private_bytes', side_effect=lambda path: self.values[str(path)]), patch.object(maintenance, 'hashes', return_value=self.live):
            return maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root, compensation=compensation)

    def test_accepts_desired_disabled_bot_and_rejects_drift(self):
        self.assertFalse(self.verify())
        for name in maintenance.FILES:
            saved = self.live[name]
            self.live[name] = digest(b'foreign')
            with self.assertRaises(ValueError):
                self.verify()
            self.live[name] = saved

    def test_candidate_relay_needs_exact_frozen_release_and_compatible_fallback(self):
        current = [b'candidate']
        fallback = [b'legacy']
        contract = dict(self.contract, mode='compensation', target_sha256=digest(b'candidate'), release_version='v2.5.0')
        paths = []
        def content(path):
            paths.append(str(path))
            return fallback[0] if path.name == 'ultra-relay.previous' else current[0]
        module = types.SimpleNamespace()
        metadata = types.SimpleNamespace(st_uid=0, st_mode=0o755, st_size=6)
        relay = {'ActiveState': 'active', 'MainPID': '123', 'ControlPID': '0'}
        with patch.object(maintenance, 'service', return_value=relay), patch.object(maintenance.Path, 'read_bytes', content), patch.object(maintenance.Path, 'is_symlink', return_value=False), patch.object(maintenance.Path, 'is_file', return_value=True), patch.object(maintenance.Path, 'lstat', return_value=metadata), patch.object(maintenance.os, 'readlink', return_value='/usr/local/bin/ultra-relay'):
            maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            self.assertIn(str(self.root / 'var/lib/ultra-ansible/releases/v2.5.0/ultra-relay.previous'), paths)
            fallback[0] = b'foreign'
            with self.assertRaises(ValueError):
                maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            current[0] = b'legacy'
            maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            contract['mode'] = 'committed'
            with self.assertRaises(ValueError):
                maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            current[0] = b'foreign'
            with self.assertRaises(ValueError):
                maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            contract['mode'] = 'compensation'
            relay.update(ActiveState='inactive', MainPID='0')
            with self.assertRaises(ValueError):
                maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            current[0], fallback[0] = b'candidate', b'legacy'
            maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)
            current[0] = b'legacy'
            maintenance.retry_relay_identity(module, self.checkpoint, contract, digest(b'legacy'), self.root)


    def test_retry_checkpoint_validates_chain_before_stopping_or_capture(self):
        class Done(Exception):
            pass
        checkpoint = dict(self.checkpoint, id=self.operation, legacy_sha256='a' * 64,
                          services={unit: 'active' for unit in maintenance.SERVICES}, recovery_provenance={'bound': True})
        states = {unit: 'active' for unit in maintenance.SERVICES + ('ultra-relay.service',)}
        states.update({unit: 'inactive' for unit in ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service')})
        calls = []
        def command(argv):
            calls.append(argv)
            states[argv[2]] = 'inactive'
            return 0, '', ''
        def read(path, **kwargs):
            return {'lifecycle.json': {'id': self.operation, 'phase': 'applying'},
                    'maintenance.json': checkpoint, 'last-success.json': {'prior': True}}[path.name]
        module = types.SimpleNamespace(params={'id': self.operation, 'legacy_sha256': 'a' * 64,
                                              'phase': 'retry-checkpoint', 'retry': dict(self.contract, mode='committed')},
                                       check_mode=False, run_command=command)
        module.exit_json = lambda **value: (_ for _ in ()).throw(Done(value))
        module.fail_json = lambda **value: (_ for _ in ()).throw(Done(dict(value, failed=True)))
        def invoke():
            with self.assertRaises(Done) as result:
                maintenance.main()
            return result.exception.args[0]
        with patch.object(maintenance, 'AnsibleModule', return_value=module), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'private', side_effect=read), patch.object(maintenance.Path, 'exists', return_value=True), patch.object(maintenance, 'hashes', return_value=self.live), patch.object(maintenance, 'accepted_configuration', return_value=False) as chain, patch.object(maintenance, 'retry_relay_identity') as identity, patch.object(maintenance, 'service', side_effect=lambda mod, unit: {'ActiveState': states[unit], 'MainPID': '0', 'ControlPID': '0'}), patch.object(maintenance, 'recovery_provenance', return_value={'bound': True}), patch.object(maintenance, 'atomic') as capture, patch.object(maintenance.time, 'sleep'):
            self.assertTrue(invoke()['continuation'])
            self.assertEqual(calls, [])
            capture.assert_not_called()
            identity.assert_called_once()
            chain.assert_called_once_with(checkpoint, module.params['retry'], self.operation, compensation=False)
            module.params['retry']['mode'] = 'compensation'
            self.assertTrue(invoke()['held'])
            self.assertEqual(len(calls), 6)
            self.assertTrue(all(argv[1] == 'stop' for argv in calls))
            capture.assert_called_once()
            calls.clear()
            chain.side_effect = ValueError('maintenance_live_candidate_changed')
            self.assertTrue(invoke()['failed'])
            self.assertEqual(calls, [])

    def test_compensation_accepts_only_exact_runtime_mixed_images(self):
        for state in ('prepared', 'applied', 'rolled_back'):
            self.values[self.operation + '-runtime-2.json']['State'] = state
            for spec in (b'old-spec', b'runtime-spec'):
                for env in (b'old-env', b'runtime-env'):
                    self.live.update(dict(zip(maintenance.FILES[:2], map(digest, (spec, env)))))
                    with self.subTest(state=state, spec=spec, env=env):
                        self.assertFalse(self.verify(compensation=True))
        self.live[maintenance.FILES[0]] = digest(b'foreign')
        with self.assertRaises(ValueError):
            self.verify(compensation=True)
        self.live[maintenance.FILES[0]] = digest(b'old-spec')
        (self.root / maintenance.FILES[0].lstrip('/')).chmod(0o640)
        with self.assertRaises(ValueError):
            self.verify(compensation=True)

    def test_accepted_restores_desired_bot_and_prior_timers_rollback_checks_original(self):
        class Done(Exception):
            pass
        prior = {'ultra-bot.service': 'active', 'ultra-recovery-backup.timer': 'inactive', 'ultra-recovery-reconcile.timer': 'active'}
        checkpoint = dict(self.checkpoint, id=self.operation, legacy_sha256='a' * 64, services=prior)
        states, commands = dict(prior), []
        def command(argv):
            commands.append(argv)
            states[argv[2]] = 'active' if argv[1] == 'start' else 'inactive'
            return 0, '', ''
        module = types.SimpleNamespace(params={'id': self.operation, 'legacy_sha256': 'a' * 64, 'phase': 'restore-accepted', 'accepted': self.contract}, check_mode=False, run_command=command)
        module.exit_json = lambda **value: (_ for _ in ()).throw(Done(value))
        module.fail_json = lambda **value: (_ for _ in ()).throw(Done(dict(value, failed=True)))
        def invoke():
            with self.assertRaises(Done) as result:
                maintenance.main()
            return result.exception.args[0]
        with patch.object(maintenance, 'AnsibleModule', return_value=module), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'private', side_effect=lambda path: {'lifecycle.json': {'id': self.operation, 'phase': 'applying'}, 'maintenance.json': checkpoint}[path.name]), patch.object(maintenance, 'hashes', return_value=self.live), patch.object(maintenance, 'accepted_configuration', return_value=False), patch.object(maintenance, 'service', side_effect=lambda mod, unit: {'ActiveState': states[unit]}):
            self.assertTrue(invoke()['verified'])
            self.assertEqual(states, dict(prior, **{'ultra-bot.service': 'inactive'}))
            commands.clear()
            module.params['phase'] = 'restore-services'
            self.assertTrue(invoke()['failed'])
            self.assertEqual(commands, [])
            with patch.object(maintenance, 'hashes', return_value=checkpoint['configuration']):
                self.assertTrue(invoke()['verified'])
                self.assertEqual(states, prior)

    def test_compensation_before_domain_apply_requires_no_invented_images(self):
        self.request['domain_transaction'] = 'b' * 64
        self.contract['runtime_request_json'] = json.dumps(self.request)
        self.contract['domain'] = {'binding': 'b' * 64, 'attempt': 1, 'plan': {'domain': 'edge.example.com'}, 'backend_policy': {'new': 'bot.example.com'}}
        for name, value in self.values.items():
            if name.endswith('transport.json'):
                value['digest'] = digest(self.contract['runtime_request_json'].encode())
            if name.endswith('effects.json'):
                value['binding_sha256'] = digest(self.contract['runtime_request_json'].encode())
        def read(path):
            if path.name == 'state.json':
                raise FileNotFoundError()
            return self.values[path.name]
        with patch.object(maintenance, 'private', side_effect=read), patch.object(maintenance, 'hashes', return_value=self.live):
            self.assertFalse(maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root, compensation=True))
            with self.assertRaises(FileNotFoundError):
                maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root)
            self.live[maintenance.FILES[1]] = digest(b'backend-env')
            with self.assertRaises(ValueError):
                maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root, compensation=True)

    def test_rejects_wrong_generation_unapplied_or_unbound_candidate(self):
        for file, key, value in [('json', 'State', 'prepared'), ('json', 'Transaction', 'foreign'), ('transport.json', 'digest', '0' * 64), ('effects.json', 'binding_sha256', '0' * 64), ('effects.json', 'state', 'rolled_back'), ('effects.json', 'plan', {'bot_service': True, 'bot_enabled': True})]:
            name = next(name for name in self.values if name.endswith('-2.' + file))
            old = copy.deepcopy(self.values[name][key])
            self.values[name][key] = value
            with self.subTest(file=file, key=key), self.assertRaises(ValueError):
                self.verify()
            self.values[name][key] = old
        self.contract['generation'] = 3
        with self.assertRaises(ValueError):
            self.verify()

    def test_accepts_only_chained_ingress_and_backend_candidate(self):
        binding = 'b' * 64
        self.request['domain_transaction'] = binding
        self.contract['runtime_request_json'] = json.dumps(self.request)
        for name, value in self.values.items():
            if name.endswith('transport.json'):
                value['digest'] = digest(self.contract['runtime_request_json'].encode())
            if name.endswith('effects.json'):
                value['binding_sha256'] = digest(self.contract['runtime_request_json'].encode())
        plan, policy = {'domain': 'edge.example.com'}, {'new': 'bot.example.com'}
        self.contract['domain'] = {'binding': binding, 'attempt': 3, 'plan': plan, 'backend_policy': policy}
        suffix = digest((self.operation + '-domain-2-attempt-3').encode())
        ingress = self.root / ('var/lib/ultra-ingress/ansible-' + suffix)
        self.values[str(ingress / 'before.json')] = b'runtime-spec'
        self.values[str(ingress / 'candidate.json')] = b'ingress-spec'
        state = {'request_sha': digest(json.dumps({'plan': plan, 'action': 'cutover'}, sort_keys=True).encode()), 'before_sha': digest(b'runtime-spec'), 'candidate_sha': digest(b'ingress-spec')}
        backend = {'version': 1, 'phase': 'applied', 'policy': policy, 'files': [{'path': maintenance.FILES[1], 'mode': 0o600, 'uid': os.geteuid(), 'gid': os.getegid(), 'before': base64.b64encode(b'runtime-env').decode(), 'after': base64.b64encode(b'backend-env').decode()}]}
        def read(path):
            if str(path).endswith('ansible-' + suffix + '/state.json'):
                return state
            if str(path).endswith('backend-' + suffix + '/state.json'):
                return backend
            return self.values[path.name]
        self.live[maintenance.FILES[0]] = digest(b'ingress-spec')
        self.live[maintenance.FILES[1]] = digest(b'backend-env')
        with patch.object(maintenance, 'private', side_effect=read), patch.object(maintenance, 'private_bytes', side_effect=lambda path: self.values[str(path)]), patch.object(maintenance, 'hashes', return_value=self.live):
            self.assertFalse(maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root))
            for spec_bytes in (b'old-spec', b'runtime-spec', b'ingress-spec'):
                for env_bytes in (b'old-env', b'runtime-env', b'backend-env'):
                    self.live.update(dict(zip(maintenance.FILES[:2], map(digest, (spec_bytes, env_bytes)))))
                    self.assertFalse(maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root, compensation=True))
            self.live[maintenance.FILES[0]] = digest(b'foreign')
            with self.assertRaises(ValueError):
                maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root, compensation=True)
            self.live[maintenance.FILES[0]] = digest(b'ingress-spec')
            self.live[maintenance.FILES[1]] = digest(b'backend-env')
            state['before_sha'] = digest(b'foreign')
            with self.assertRaises(ValueError):
                maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root)
            state['before_sha'] = digest(b'runtime-spec')
            backend['policy'] = {'new': 'foreign.example.com'}
            with self.assertRaises(ValueError):
                maintenance.accepted_configuration(self.checkpoint, self.contract, self.operation, self.root)


if __name__ == '__main__':
    unittest.main()
