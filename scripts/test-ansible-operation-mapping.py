#!/usr/bin/env python3
"""Fixed operations retain independent identities while sharing implementation."""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'deploy/ansible'
spec = importlib.util.spec_from_file_location('controller', SOURCE / 'controller.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class OperationMappingTests(unittest.TestCase):
    def test_every_operation_resolves_to_one_existing_implementation(self):
        self.assertEqual(len(controller.OPERATIONS), 45)
        self.assertEqual(set(controller.PLAYBOOKS), controller.OPERATIONS)
        selected = {controller.operation_playbook(op) for op in controller.OPERATIONS}
        self.assertEqual(len(selected), 43)
        retired = {'adopt-replica-tunnels.yml', 'replica.yml', 'stop-replica.yml', 'bridge-migrate.yml', 'bridge-migrate-inspect.yml', 'bridge-migrate-fence.yml', 'bridge-migrate-probe.yml', 'bridge-migrate-rollback-peers.yml'}
        self.assertEqual(selected, {path.name for path in (SOURCE / 'playbooks').glob('*.yml')})
        for op in retired:
            with self.assertRaisesRegex(ValueError, 'unsupported_operation'):
                controller.operation_playbook(op.removesuffix('.yml'))

    def test_shared_implementation_does_not_merge_operation_identities(self):
        aliases = {'domain-cutover': 'ingress', 'configure-exit-operator': 'configure-exit',
                   'configure-replica': 'replica'}
        for operation in controller.OPERATIONS:
            self.assertEqual(controller.operation_playbook(operation), aliases.get(operation, operation) + '.yml')
        self.assertIn('configure-exit-operator', controller.LOCAL_OPERATIONS)
        self.assertIn('reserve-rolledback-bootstrap', controller.LOCAL_OPERATIONS)
        self.assertIn('retain-artifacts', controller.LOCAL_OPERATIONS)
        self.assertIn('restore-database', controller.LOCAL_OPERATIONS)
        for operation in ('bootstrap-postgres', 'bootstrap-exit', 'bootstrap-bridge'):
            self.assertIn(operation, controller.LOCAL_OPERATIONS)
        self.assertNotIn('configure-exit', controller.LOCAL_OPERATIONS)
        self.assertNotIn('configure-replica', controller.LOCAL_OPERATIONS)
        self.assertNotIn('stop-replica', controller.LOCAL_OPERATIONS)

    def test_components_reuse_native_roles_and_durable_pins(self):
        postgres = (SOURCE / 'playbooks/bootstrap-postgres.yml').read_text()
        exit_stage = (SOURCE / 'playbooks/bootstrap-exit.yml').read_text()
        bridge = (SOURCE / 'playbooks/bootstrap-bridge.yml').read_text()
        self.assertIn('- role: postgres', postgres)
        self.assertIn('- relay', exit_stage)
        self.assertIn('- role: warp', exit_stage)
        self.assertIn("'exit_host': inventory_hostname", exit_stage)
        self.assertIn('ultra_bootstrap_pins[ultra_exit_hosts[item.name]]', bridge)
        self.assertNotIn('relay_fingerprint', bridge)
        self.assertNotIn('hostvars[ultra_exit_hosts', bridge)
        self.assertIn('ultra_dump_exit_identity:', bridge)
        for stage in (postgres, exit_stage, bridge):
            self.assertNotIn('ansible.builtin.shell', stage)
            self.assertIn('verified', stage)

    def test_bridge_installs_pg16_clients_before_planner_and_replica(self):
        import yaml
        for name in ('bootstrap-postgres.yml', 'bootstrap.yml', 'bootstrap-automation.yml'):
            plays = yaml.safe_load((SOURCE / 'playbooks' / name).read_text())
            bridge_plays = [play for play in plays if play.get('hosts') == 'bridge']
            bridge_roles = [[role.get('role') if isinstance(role, dict) else role for role in play.get('roles', [])]
                            for play in bridge_plays]
            self.assertTrue(any('postgres_client' in roles for roles in bridge_roles), name)
            if name in ('bootstrap-postgres.yml', 'bootstrap.yml'):
                dns_play = next(index for index, roles in enumerate(bridge_roles) if 'dns' in roles)
                database_play = next(index for index, roles in enumerate(bridge_roles) if 'postgres_client' in roles)
                self.assertLess(dns_play, database_play, name)
                if name == 'bootstrap.yml':
                    exit_play = next(index for index, play in enumerate(plays)
                                     if play.get('hosts') == 'exits'
                                     and any((role.get('role') if isinstance(role, dict) else role) == 'tunnel_certificate'
                                             for role in play.get('roles', [])))
                    self.assertLess(dns_play, exit_play, name)
        tasks = yaml.safe_load((SOURCE / 'roles/postgres_client/tasks/main.yml').read_text())
        packages = [task['ansible.builtin.apt']['name'] for task in tasks if 'ansible.builtin.apt' in task]
        self.assertEqual(packages, ['postgresql-client-16'])
        self.assertTrue(any(task.get('ansible.builtin.include_role') == {'name': 'postgres', 'tasks_from': 'repository'} for task in tasks))
        self.assertTrue(any(task.get('loop') == ['psql', 'pg_dump'] and 'failed_when' in task for task in tasks))
        provisioning = yaml.safe_load((SOURCE / 'roles/postgres/tasks/main.yml').read_text())
        server_packages = [task['ansible.builtin.apt']['name'] for task in provisioning if 'ansible.builtin.apt' in task]
        self.assertEqual(server_packages, ['postgresql-16'])
        auth = provisioning[-1]
        self.assertIn('--no-password', auth['ansible.builtin.command']['argv'])
        self.assertIn('PGPASSWORD', auth['environment'])
        self.assertTrue(auth['no_log'])
        self.assertEqual(provisioning[-2]['ansible.builtin.meta'], 'flush_handlers')
        provision = next(task for task in provisioning if task['name'].startswith('Provision missing'))
        self.assertIn("SET password_encryption = 'scram-sha-256'", provision['ansible.builtin.command']['stdin'])
        self.assertNotIn('ALTER ROLE', provision['ansible.builtin.command']['stdin'])
        tunnel_generate = (SOURCE / 'roles/db_tunnel/tasks/generate.yml').read_text()
        self.assertNotIn('db_tunnel_ultra_public_key', tunnel_generate)
        tunnel_auth = yaml.safe_load((SOURCE / 'roles/db_tunnel/tasks/authorize.yml').read_text())
        key_read = tunnel_auth[1]
        self.assertEqual(key_read['ansible.builtin.slurp']['src'], '/etc/ultra-db-tunnel/id_ed25519.pub')
        self.assertEqual(key_read['delegate_to'], 'bridge')
        self.assertTrue(key_read['no_log'])
        key_guard = tunnel_auth[2]['ansible.builtin.assert']
        self.assertEqual(key_guard['fail_msg'], 'Bridge database tunnel authorization requires a valid SSH public key read from bridge.')
        self.assertNotIn('no_log', tunnel_auth[2])
        self.assertIn('db_tunnel_bridge_public_key_slurp.content | b64decode | trim', tunnel_auth[-1]['ansible.builtin.copy']['content'])
        self.assertNotIn("hostvars['bridge'].db_tunnel_ultra_public_key", str(tunnel_auth))

    def test_dedicated_primary_has_owned_bridge_standby_with_live_wal_verification(self):
        import yaml
        for name in ('bootstrap-postgres.yml', 'bootstrap.yml'):
            plays = yaml.safe_load((SOURCE / 'playbooks' / name).read_text())
            tunnel = next(i for i, play in enumerate(plays) if play['name'] == 'Activate application database tunnel')
            slot = next(i for i, play in enumerate(plays) if play['name'] == 'Prepare primary replication slot and identity')
            replica = next(i for i, play in enumerate(plays) if play['name'] == 'Configure bridge physical standby')
            self.assertLess(tunnel, slot, name)
            self.assertLess(slot, replica, name)
            self.assertEqual(plays[replica]['hosts'], 'bridge')
            if name == 'bootstrap-postgres.yml':
                result = next(i for i, play in enumerate(plays) if play['name'] == 'Confirm completed database component')
                self.assertLess(replica, result)
        root = SOURCE / 'roles/postgres_replica'
        inspect = (root / 'tasks/inspect.yml').read_text()
        self.assertIn('standby.signal', inspect)
        self.assertIn('system_identifier', inspect)
        seed = (root / 'tasks/seed.yml').read_text()
        self.assertIn('--write-recovery-conf', seed)
        self.assertIn('--slot=ultra_bridge', seed)
        self.assertIn('renameat2', seed)
        self.assertIn('postgres_replica_staging.path', seed)
        self.assertNotIn('pg_resetwal', seed)
        verify = yaml.safe_load((root / 'tasks/verify.yml').read_text())
        self.assertEqual(verify[0]['retries'], 30)
        self.assertEqual(verify[-1]['retries'], 30)
        self.assertIn('pg_last_wal_replay_lsn()', str(verify[-1]))
        self.assertIn("status = 'streaming'", str(verify[-1]))
        service = (root / 'templates/ultra-postgres-replica.service.j2').read_text()
        self.assertIn('Requires=ultra-db-tunnel.service', service)
        self.assertNotIn('promote', service)
        primary = (SOURCE / 'roles/postgres/tasks/replication.yml').read_text()
        self.assertIn('host replication ultra_replication 127.0.0.1/32 scram-sha-256', primary)
        self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE', primary)

    def test_no_removed_operation_or_caller_chosen_path(self):
        for operation in ['verify', '../ingress', '/tmp/ingress', 'ingress.yml', 'arbitrary']:
            with self.assertRaisesRegex(ValueError, 'unsupported_operation'):
                controller.operation_playbook(operation)
            with self.assertRaisesRegex(ValueError, 'unsupported_operation'):
                controller.validate({'schema_version': 1, 'operation': operation})

    def test_go_local_boundary_matches_controller_local_operations(self):
        source = (ROOT / 'internal/deployansible/local.go').read_text()
        allowlist = source.split('allowed := map[string]bool{', 1)[1].split('}', 1)[0]
        self.assertEqual(set(re.findall(r'"([a-z-]+)":\s+true', allowlist)), controller.LOCAL_OPERATIONS)


if __name__ == '__main__':
    unittest.main()
