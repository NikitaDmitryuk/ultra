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

    def test_bridge_installs_only_pg16_clients_before_planner_and_backup(self):
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
        auth = provisioning[-1]
        self.assertIn('--no-password', auth['ansible.builtin.command']['argv'])
        self.assertIn('PGPASSWORD', auth['environment'])
        self.assertTrue(auth['no_log'])
        self.assertEqual(provisioning[-2]['ansible.builtin.meta'], 'flush_handlers')

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
