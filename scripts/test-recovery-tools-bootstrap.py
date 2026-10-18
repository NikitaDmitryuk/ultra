#!/usr/bin/env python3
"""Adversarial local fixtures only; no installed state, DB or systemd changes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_recovery_tools_bootstrap.py'
spec = importlib.util.spec_from_file_location('bootstrap', SOURCE)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, value in {'ROOT': self.root / 'state', 'ACTIVE': self.root / 'active',
                            'MARKER': self.root / 'state/incomplete', 'JOURNAL': self.root / 'state/journal.json',
                            'SYSTEMD': self.root / 'systemd'}.items():
            context = patch.object(bootstrap, name, value)
            context.start()
            self.addCleanup(context.stop)
        bootstrap.ACTIVE.mkdir()
        self.commands = []
        self.original = {}
        for unit in bootstrap.units(False):
            self.original[unit] = {'LoadState': 'loaded', 'ActiveState': 'active' if unit == 'ultra-monitor.timer' else 'inactive',
                                   'MainPID': '0', 'ControlPID': '0'}
        self.states = copy.deepcopy(self.original)

        def systemctl(*argv):
            self.commands.append(argv)
            if argv[0] in ('start', 'stop'):
                self.states[argv[1]]['ActiveState'] = 'active' if argv[0] == 'start' else 'inactive'
            return ''

        for name, value in {'systemctl': systemctl, 'unit_state': lambda unit: self.states[unit].copy(),
                            'consumers_idle': lambda: None}.items():
            context = patch.object(bootstrap, name, value)
            context.start()
            self.addCleanup(context.stop)
        old = self.root / 'old.py'
        old.write_bytes(b'old authenticated generation\n')
        old.chmod(0o600)
        active = bootstrap.ACTIVE / 'recovery.py'
        active.write_bytes(old.read_bytes())
        active.chmod(0o755)
        self.tool = {'destination': str(active), 'sha256': bootstrap.digest(b'fixed tool\n'),
                     'previous_sha256': bootstrap.digest(old.read_bytes()),
                     'backup_name': bootstrap.digest(str(active).encode()), 'baseline_source': str(old)}
        self.spec = {'bridge': False, 'baseline': 'a' * 64, 'topology': 'b' * 64,
                     'candidate': 'c' * 64, 'version': 'v2.3.1', 'tools': [self.tool]}

    def run_phase(self, phase):
        return bootstrap.transition(phase, self.spec)

    def apply(self):
        Path(self.tool['destination']).write_bytes(b'fixed tool\n')

    def fallback(self):
        return bootstrap.ROOT / 'releases' / self.spec['version'] / 'tools-previous' / self.tool['backup_name']

    def test_complete_restores_exact_prior_timer_states_and_retains_old_bytes(self):
        self.run_phase('fence')
        self.assertTrue(bootstrap.MARKER.exists())
        self.assertTrue(all(value['ActiveState'] == 'inactive' for value in self.states.values()))
        self.run_phase('seed')
        self.assertEqual(self.fallback().read_bytes(), b'old authenticated generation\n')
        self.apply()
        self.run_phase('verify')
        self.run_phase('resume')
        self.assertEqual(self.states, self.original)
        self.assertFalse(bootstrap.MARKER.exists())
        self.assertEqual(json.loads(bootstrap.JOURNAL.read_bytes())['stage'], 'complete')
        self.assertEqual(self.fallback().read_bytes(), b'old authenticated generation\n')
        self.run_phase('proof')

    def test_completed_replay_rechecks_actual_bytes(self):
        self.run_phase('fence')
        self.run_phase('seed')
        self.apply()
        self.run_phase('verify')
        self.run_phase('resume')
        Path(self.tool['destination']).write_bytes(b'unexpected drift')
        with self.assertRaisesRegex(ValueError, 'target_incomplete'):
            self.run_phase('proof')

    def test_partial_tool_failure_cannot_remove_fence(self):
        self.run_phase('fence')
        self.run_phase('seed')
        with self.assertRaisesRegex(ValueError, 'target_incomplete'):
            self.run_phase('resume')
        self.assertTrue(bootstrap.MARKER.exists())

    def test_new_candidate_rebinds_fallback_from_authenticated_old_generation(self):
        self.run_phase('fence')
        self.run_phase('seed')
        self.apply()
        # A subsequent unrelated release repair changes version, while already
        # installed recovery bytes remain authenticated by the first receipt.
        self.spec.update(candidate='d' * 64, version='v2.3.2')
        self.run_phase('fence')
        self.run_phase('seed')
        self.assertEqual(self.fallback().read_bytes(), b'old authenticated generation\n')
        self.assertEqual(len(json.loads(bootstrap.JOURNAL.read_bytes())['history']), 2)

    def test_busy_consumer_leaves_durable_fence(self):
        with patch.object(bootstrap, 'consumers_idle', side_effect=ValueError('bootstrap_consumer_busy')):
            with self.assertRaisesRegex(ValueError, 'consumer_busy'):
                self.run_phase('fence')
        self.assertTrue(bootstrap.MARKER.exists())
        self.assertTrue(bootstrap.JOURNAL.exists())

    def test_manifest_or_topology_change_rejected_before_mutation(self):
        self.run_phase('fence')
        self.spec['topology'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'identity_changed'):
            self.run_phase('seed')
        self.assertFalse(self.fallback().exists())

    def test_unreceipted_active_target_is_not_accepted_as_prior_history(self):
        self.apply()
        with self.assertRaisesRegex(ValueError, 'active_tool_drift'):
            self.run_phase('fence')
        self.assertTrue(bootstrap.MARKER.exists())

    def test_tampered_fallback_is_never_replaced(self):
        self.run_phase('fence')
        self.run_phase('seed')
        self.fallback().write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'fallback_changed'):
            self.run_phase('seed')
        self.assertEqual(self.fallback().read_bytes(), b'wrong')

    def test_symlink_fallback_rejected(self):
        self.run_phase('fence')
        self.run_phase('seed')
        self.fallback().unlink()
        self.fallback().symlink_to(self.tool['baseline_source'])
        with self.assertRaises(OSError):
            self.run_phase('seed')

    def test_partial_bridge_set_rejected(self):
        self.spec['bridge'] = True
        with self.assertRaisesRegex(ValueError, 'incoherent_tools'):
            self.run_phase('fence')
        self.assertFalse(bootstrap.JOURNAL.exists())

    def test_verify_must_precede_resume(self):
        self.run_phase('fence')
        self.run_phase('seed')
        self.apply()
        with self.assertRaisesRegex(ValueError, 'verification_required'):
            self.run_phase('resume')
        self.assertTrue(bootstrap.MARKER.exists())

    def test_process_census_detects_standalone_import(self):
        proc = self.root / 'proc'
        (proc / '987654').mkdir(parents=True)
        (proc / '987654/cmdline').write_bytes(b'python3\0/opt/ultra-recovery/restore_database.py\0')
        # Invoke the real function instead of the fixture replacement.
        real = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real)
        with self.assertRaisesRegex(ValueError, 'consumer_busy'):
            real.consumers_idle(proc)

    def test_replay_after_checkpoint_interruption_preserves_timer_snapshot(self):
        original_save = bootstrap.save
        calls = 0

        def fail_second_save(value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('simulated power loss')
            original_save(value)

        with patch.object(bootstrap, 'save', side_effect=fail_second_save):
            with self.assertRaises(OSError):
                self.run_phase('fence')
        self.run_phase('fence')
        self.run_phase('seed')
        self.apply()
        self.run_phase('verify')
        self.run_phase('resume')
        self.assertEqual(self.states, self.original)

    def test_different_candidate_tools_normalize_authenticated_prior_then_resume_crash(self):
        self.run_phase('fence')
        self.run_phase('seed')
        self.apply()
        self.run_phase('verify')
        self.run_phase('resume')
        original_generation = Path(self.tool['baseline_source']).read_bytes()
        candidate_b = b'different candidate B bytes\n'
        self.spec.update(candidate='d' * 64, version='v2.3.2')
        self.tool['sha256'] = bootstrap.digest(candidate_b)
        self.run_phase('fence')
        self.run_phase('seed')
        atomic = bootstrap.durable

        def crash_after_original_restore(path, data, mode=0o600):
            atomic(path, data, mode)
            if str(path) == self.tool['destination']:
                raise OSError('power loss after atomic original restore')

        with patch.object(bootstrap, 'durable', side_effect=crash_after_original_restore):
            with self.assertRaisesRegex(OSError, 'power loss'):
                self.run_phase('normalize')
        self.assertTrue(bootstrap.MARKER.exists())
        self.assertEqual(Path(self.tool['destination']).read_bytes(), original_generation)
        self.assertEqual(self.fallback().read_bytes(), original_generation)
        self.run_phase('normalize')
        # Model tools.yml's unchanged strict original-or-new-target assertion.
        active = bootstrap.digest(Path(self.tool['destination']).read_bytes())
        self.assertIn(active, (self.tool['previous_sha256'], self.tool['sha256']))
        Path(self.tool['destination']).write_bytes(candidate_b)
        self.run_phase('verify')
        self.run_phase('resume')
        self.run_phase('proof')
        self.assertEqual(self.fallback().read_bytes(), original_generation)
        self.assertEqual(Path(self.tool['baseline_source']).read_bytes(), original_generation)

    def test_unknown_active_hash_rejected_before_normalization_mutates_anything(self):
        self.run_phase('fence')
        self.run_phase('seed')
        Path(self.tool['destination']).write_bytes(b'unknown bytes')
        before = {path: path.read_bytes() for path in (bootstrap.JOURNAL, self.fallback(), Path(self.tool['destination']))}
        with self.assertRaisesRegex(ValueError, 'active_tool_drift'):
            self.run_phase('normalize')
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_installed_version_rejected_before_fence_or_generation_mutation(self):
        self.spec['bridge'] = True
        self.spec['tools'] = []
        for name in bootstrap.TOOLS:
            tool = self.tool.copy()
            tool['destination'] = str(bootstrap.ACTIVE / name)
            tool['backup_name'] = bootstrap.digest(tool['destination'].encode())
            self.spec['tools'].append(tool)
        generation = self.root / 'immutable-generation'
        generation.write_bytes(b'original immutable data')
        with patch.object(bootstrap, 'inventory', return_value={'previous_manifest': {'version': self.spec['version']}}):
            with self.assertRaisesRegex(ValueError, 'generation_is_immutable'):
                self.run_phase('fence')
        self.assertFalse(bootstrap.MARKER.exists())
        self.assertFalse(bootstrap.JOURNAL.exists())
        self.assertEqual(self.commands, [])
        self.assertEqual(generation.read_bytes(), b'original immutable data')

    def test_relay_owned_ssh_exception_is_narrow_and_checks_permissions(self):
        path = Path(self.tool['baseline_source'])
        metadata = path.stat()
        account = SimpleNamespace(pw_name='ultra-relay', pw_uid=12345)
        info = SimpleNamespace(st_mode=metadata.st_mode, st_uid=account.pw_uid, st_size=metadata.st_size)
        with patch.object(bootstrap.pwd, 'getpwnam', return_value=account), patch.object(bootstrap.os, 'fstat', return_value=info):
            self.assertEqual(bootstrap.ssh_bytes(path, identity=True), path.read_bytes())
            self.assertEqual(bootstrap.ssh_bytes(path), path.read_bytes())
            with self.assertRaisesRegex(ValueError, 'private_file_required'):
                bootstrap.private_bytes(path)
            info.st_mode |= 0o040
            with self.assertRaisesRegex(ValueError, 'private_file_required'):
                bootstrap.ssh_bytes(path, identity=True)
            info.st_mode &= ~0o040
            info.st_uid = 54321
            with self.assertRaisesRegex(ValueError, 'private_file_required'):
                bootstrap.ssh_bytes(path)

    def test_inventory_accepts_private_executable_immutable_generation(self):
        active = self.root / 'active'
        generation = active / 'releases' / 'v2.3.0'
        generation.mkdir(parents=True, mode=0o700)
        manifest = active / 'release-manifest.json'
        manifest.write_text(json.dumps({'version': 'v2.3.0'}))
        manifest.chmod(0o600)
        for name in bootstrap.TOOLS:
            path = generation / name
            path.write_bytes(('installed ' + name).encode())
            path.chmod(0o755)
        nodes = [{'id': 'fixture', 'address': '192.0.2.1',
                  'known_hosts': str(self.root / 'known_hosts')}]
        known_hosts = self.root / 'known_hosts'
        known_hosts.write_text('fixture-key\n')
        known_hosts.chmod(0o600)
        identity = self.root / 'identity'
        identity.write_text('fixture-identity\n')
        identity.chmod(0o600)
        config_path = self.root / 'reconcile.json'
        config_path.write_text(json.dumps({'database': 'ultra', 'bundle_dir': str(active),
                                           'vultr_state_dir': str(self.root),
                                           'ssh_identity_file': str(identity)}))
        config_path.chmod(0o600)
        config = config_path.read_bytes()

        reconcile = SimpleNamespace(discover=lambda value: [],
                                    desired_nodes=lambda value, rows: (nodes, set()))
        original_lstat = Path.lstat
        original_private_bytes = bootstrap.private_bytes

        def lstat(path):
            info = original_lstat(path)
            if path == generation:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            return info

        def private_bytes(path, *args, **kwargs):
            if path == '/etc/ultra-recovery/reconcile.json':
                path = config_path
            return original_private_bytes(path, *args, **kwargs)

        with patch.object(bootstrap, 'ACTIVE', active), patch.object(bootstrap, 'ROOT', self.root), \
                patch.object(bootstrap.Path, 'lstat', lstat), \
                patch.object(bootstrap.pwd, 'getpwnam', return_value=SimpleNamespace(pw_name='ultra-relay',
                                                                                     pw_uid=os.geteuid())), \
                patch.dict('sys.modules', {'reconcile': reconcile}):
            with patch.object(bootstrap, 'private_bytes', side_effect=private_bytes) as read:
                result = bootstrap.inventory()
        self.assertEqual(set(result['tool_hashes']), set(bootstrap.TOOLS))
        self.assertEqual(result['previous_manifest']['version'], 'v2.3.0')
        self.assertTrue(all(call.kwargs.get('executable') is True
                            for call in read.call_args_list if Path(call.args[0]).parent == generation))


if __name__ == '__main__':
    unittest.main()
