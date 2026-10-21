#!/usr/bin/env python3
"""Public proof and fixed host transaction/service choreography contracts."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrade_runtime_state', ROOT / 'deploy/ansible/roles/release/files/state.py')
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)


class RuntimeUpgradeContracts(unittest.TestCase):
    def test_bridge_returns_only_tunnel_digest_and_pin(self):
        tunnel = '11111111-1111-1111-1111-111111111111'
        node = {'id': '22222222-2222-2222-2222-222222222222', 'address': '192.0.2.2'}
        rows = [{'id': node['id'], 'address': node['address'], 'tunnel_uuid': tunnel, 'pin': 'a' * 64, 'enabled': True}]
        with patch.object(state, 'database_query', return_value=SimpleNamespace(stdout=json.dumps(rows).encode())):
            state.runtime_node_proofs('fixture', [node])
        self.assertEqual(node['tunnel_identity_digest'], hashlib.sha256(tunnel.encode()).hexdigest())
        self.assertEqual(node['certificate_pin'], 'a' * 64)
        self.assertNotIn(tunnel, json.dumps(node))
        self.assertNotIn('tunnel_uuid', node)

    def test_proof_rejects_changed_target_duplicate_or_extra_members(self):
        node = {'id': '22222222-2222-2222-2222-222222222222', 'address': '192.0.2.2'}
        row = {'id': node['id'], 'address': '192.0.2.9', 'tunnel_uuid': '11111111-1111-1111-1111-111111111111', 'pin': '', 'enabled': True}
        for rows in ([row], [row, row], []):
            with patch.object(state, 'database_query', return_value=SimpleNamespace(stdout=json.dumps(rows).encode())):
                with self.assertRaises(ValueError):
                    state.runtime_node_proofs('fixture', [dict(node)])

    def test_disabled_static_exit_remains_in_upgrade_topology(self):
        node = {'id': '22222222-2222-2222-2222-222222222222', 'address': '192.0.2.2', 'managed': False}
        row = {'id': node['id'], 'address': node['address'], 'tunnel_uuid': '11111111-1111-1111-1111-111111111111',
               'pin': '', 'enabled': False}
        with patch.object(state, 'database_query', return_value=SimpleNamespace(stdout=json.dumps([row]).encode())):
            state.runtime_node_proofs('fixture', [node])
        self.assertIn('tunnel_identity_digest', node)

    def test_disabled_managed_or_uninventoried_enabled_exit_is_rejected(self):
        node = {'id': '22222222-2222-2222-2222-222222222222', 'address': '192.0.2.2', 'managed': True}
        tunnel = '11111111-1111-1111-1111-111111111111'
        disabled_managed = {'id': node['id'], 'address': node['address'], 'tunnel_uuid': tunnel, 'pin': '', 'enabled': False}
        extra_enabled = {'id': '33333333-3333-3333-3333-333333333333', 'address': '192.0.2.3',
                         'tunnel_uuid': tunnel, 'pin': '', 'enabled': True}
        for rows in ([disabled_managed], [dict(disabled_managed, enabled=True), extra_enabled]):
            with patch.object(state, 'database_query', return_value=SimpleNamespace(stdout=json.dumps(rows).encode())):
                with self.assertRaises(ValueError):
                    state.runtime_node_proofs('fixture', [dict(node)])

    def test_modern_rollback_restores_bot_activity_from_frozen_effects(self):
        plays = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/rollback.yml').read_text())
        preflight = plays[0]['tasks']
        guard = next(task for task in preflight if task['name'] == 'Require frozen bot activity evidence before modern rollback')
        self.assertIn('ultra_runtime_effect_inputs is defined', guard['ansible.builtin.assert']['that'])
        self.assertIn('inventory_hostname in ultra_runtime_effect_inputs', guard['ansible.builtin.assert']['that'])
        bridge = next(play for play in plays if play['hosts'] == 'bridge' and
                      any('ultra_runtime_effects' in task for task in play['tasks']))
        tasks = bridge['tasks']
        self.assertFalse(any(task.get('ansible.builtin.systemd_service', {}).get('name') == 'ultra-bot.service'
                             and task.get('ansible.builtin.systemd_service', {}).get('state') in ('started', 'restarted')
                             for task in tasks))
        accept = next(index for index, task in enumerate(tasks)
                      if task.get('ultra_runtime_effects', {}).get('action') == 'accept-rollback')
        restore = next(index for index, task in enumerate(tasks)
                       if task.get('ultra_runtime_effects', {}).get('action') == 'rollback')
        self.assertLess(restore, accept)

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

    def test_managed_fence_restore_and_release_choreography(self):
        phase = (ROOT / 'deploy/ansible/roles/runtime/tasks/phase.yml').read_text()
        play = (ROOT / 'deploy/ansible/playbooks/upgrade-runtime.yml').read_text()
        self.assertLess(phase.index('Exclude managed certificate renewal'), phase.index('Freeze the private certificate'))
        self.assertLess(phase.index('Freeze the private certificate'), phase.index('Prepare exact host-only external'))
        self.assertLess(play.index('Verify the frozen managed tunnel'), play.index('Quiesce bridge traffic'))
        self.assertIn("'check-restore' if ultra_runtime_action == 'rollback'", play)
        self.assertLess(play.index('Stop the exit only after'), play.index('Restore only missing owned certificate'))
        self.assertLess(play.index('Restore only missing owned certificate'), play.index('Apply or restore the request-bound exit'))
        self.assertLess(play.index('Promote candidate firewall'), play.index('Release the exact checkpoint'))
        self.assertIn('require_checkpoint: true', play)

    def test_subscription_delivery_uses_paths_and_private_copy(self):
        role = (ROOT / 'deploy/ansible/roles/upgrade_subscription/tasks/main.yml').read_text()
        dropin = (ROOT / 'deploy/ansible/roles/upgrade_subscription/templates/subscription.conf.j2').read_text()
        copy = role.split('- name: Stage subscription keyring', 1)[1].split('- name:', 1)[0]
        self.assertIn('src: "{{ ultra_upgrade_subscription_key_source }}"', copy)
        self.assertIn('mode: "0600"', copy)
        self.assertIn('diff: false', copy)
        self.assertIn('no_log: true', copy)
        self.assertIn('ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE=/var/lib/ultra-relay/automation/subscription-keys.json', dropin)
        self.assertNotIn('lookup(', role)
        self.assertNotIn('slurp', role)

    def test_upgrade_compensates_runtime_before_release_and_gate(self):
        source = (ROOT / 'cmd/ultra-install/ansible_upgrade.go').read_text()
        start = source.index('if err != nil {\n\t\tif forwardOnly {\n\t\t\t// The operator explicitly chose forward-only recovery.')
        rollback = source[start:source.index('// Readiness checks release the fleet lock', start)]
        domain = rollback.index('domainTransaction.phase(')
        runtime = rollback.index('runUpgradeRuntimePhase(')
        release = rollback.index('runUpgradeReleaseRollback(')
        gate = rollback.index('ansibleLifecycle(')
        self.assertLess(domain, runtime)
        self.assertLess(runtime, release)
        self.assertLess(release, gate)


if __name__ == '__main__':
    unittest.main()
