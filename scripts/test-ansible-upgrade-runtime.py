#!/usr/bin/env python3
"""Public proof and fixed host transaction/service choreography contracts."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrade_runtime_state', ROOT / 'deploy/ansible/roles/release/files/state.py')
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)


class RuntimeUpgradeContracts(unittest.TestCase):
    def test_bridge_returns_only_tunnel_digest_and_pin(self):
        tunnel = '11111111-1111-1111-1111-111111111111'
        node = {'id': '22222222-2222-2222-2222-222222222222', 'address': '192.0.2.2'}
        rows = [{'id': node['id'], 'address': node['address'], 'tunnel_uuid': tunnel, 'pin': 'a' * 64}]
        with patch.object(state.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(rows).encode())):
            state.runtime_node_proofs('fixture', [node])
        self.assertEqual(node['tunnel_identity_digest'], hashlib.sha256(tunnel.encode()).hexdigest())
        self.assertEqual(node['certificate_pin'], 'a' * 64)
        self.assertNotIn(tunnel, json.dumps(node))
        self.assertNotIn('tunnel_uuid', node)

    def test_proof_rejects_changed_target_duplicate_or_extra_members(self):
        node = {'id': '22222222-2222-2222-2222-222222222222', 'address': '192.0.2.2'}
        row = {'id': node['id'], 'address': '192.0.2.9', 'tunnel_uuid': '11111111-1111-1111-1111-111111111111', 'pin': ''}
        for rows in ([row], [row, row], []):
            with patch.object(state.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(rows).encode())):
                with self.assertRaises(ValueError):
                    state.runtime_node_proofs('fixture', [dict(node)])

    def test_fixed_transport_validates_hash_before_host_execution(self):
        probe = (ROOT / 'deploy/ansible/playbooks/inspect-upgrade-runtime.yml').read_text()
        phase = (ROOT / 'deploy/ansible/roles/runtime/tasks/phase.yml').read_text()
        for content in (probe, phase):
            self.assertNotIn('ansible.builtin.shell', content)
            self.assertIn('checksum_algorithm: sha256', content)
            self.assertIn('not runtime_', content)
            self.assertIn('no_log: true', content)
            self.assertIn('argv: [/var/lib/ultra-ansible/runtime-probe/ultra-install, runtime-probe]', content)
        self.assertLess(phase.index('Require exact manifested'), phase.index('Execute one fixed request-bound'))

    def test_unbound_rollback_cannot_stop_bot_or_restart_relays(self):
        phase = (ROOT / 'deploy/ansible/roles/runtime/tasks/phase.yml').read_text()
        play = (ROOT / 'deploy/ansible/playbooks/upgrade-runtime.yml').read_text()
        self.assertLess(phase.index('Inspect binding'), phase.index('Stop the bot'))
        stop = phase.split('- name: Stop the bot only', 1)[1].split('- name:', 1)[0]
        self.assertIn('runtime_transaction_binding.bound | bool', stop)
        for title in ('Restart the exit', 'Restart the bridge', 'Start a new payload', 'Require new relay', 'Restore the captured bot'):
            task = play.split('- name: ' + title, 1)[1].split('- name:', 1)[0]
            self.assertIn('runtime_transaction_evidence.bound | bool', task)
        self.assertIn('serial: 1', play)
        self.assertIn('--exit-id', play)
        self.assertIn("loop: \"{{ groups['exits'] }}\"", play)
        self.assertIn('--since-nanos', play)
        self.assertIn('accept-rollback', play)
        effects = (ROOT / 'deploy/ansible/library/ultra_runtime_effects.py').read_text()
        self.assertIn("state['bot']['active'] == 'active'", effects)

    def test_upgrade_compensates_runtime_before_release_and_gate(self):
        source = (ROOT / 'cmd/ultra-install/ansible_upgrade.go').read_text()
        rollback = source.split('if leaseErr := ansibleResumeFrozenLifecycle', 1)[1]
        domain = rollback.index('domainTransaction.phase(cleanup, inventory, directory, python, executable, "rollback", generation)')
        runtime = rollback.index('runUpgradeRuntimePhase(cleanup, p, inspection, inventory, variables, directory, python, executable, "rollback", generation)')
        release = rollback.index('runUpgradeReleaseRollback(cleanup, p, inspection, inventory, variables, directory, python, executable, generation, false)')
        gate = rollback.index('ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false)')
        self.assertLess(domain, runtime)
        self.assertLess(runtime, release)
        self.assertLess(release, gate)


if __name__ == '__main__':
    unittest.main()
