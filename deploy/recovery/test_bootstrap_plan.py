import hashlib
import contextlib
import io
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
import shutil
import subprocess
import sys
from unittest import mock
import bootstrap_plan
import db_connection
import recovery_status


class BootstrapPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = lambda value: self.root / str(value).lstrip('/') if str(value).startswith('/') and not str(value).startswith(str(self.root)) else Path(value)
        for name, content in [('etc/ultra-fleet/id_ed25519', 'fixture-private'),
                              ('etc/ultra-fleet/id_ed25519.pub', 'fixture-public'),
                              ('etc/ultra-relay/bot.env', 'TELEGRAM_BOT_TOKEN=fixture-bot-token\n'),
                              ('etc/ultra-relay/environment', 'ULTRA_RELAY_ADMIN_TOKEN=fixture-admin-token\n'),
                              ('var/lib/ultra-relay/automation/vultr-api-key', 'fixture-cloud')]:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)
        self.spec = self.root / 'spec.json'; self.spec.write_text(json.dumps({'database': {'dsn': 'postgres://app:fixture-pass@127.0.0.1:25432/fixture?sslmode=disable'}})); self.spec.chmod(0o600)
        self.pins = self.root / 'pins'; self.pins.write_text('fixture-pins')
        self.config = {'database': 'fixture', 'database_host': '192.0.2.3', 'known_hosts_file': str(self.pins), 'spec': str(self.spec),
                       'static_nodes': [{'address': '192.0.2.2', 'name': 'Exit', 'provider': 'fixture', 'budget': {'monthly_bytes': 1024}}],
                       'age_recipient': 'fixture-age-recipient', 'bridge_provider': 'fixture', 'bridge_ipv4': '192.0.2.1',
                       'bridge_url': 'https://access.example.org/sub', 'version': 'v1.0.0', 'recovery_tool_members': [], 'tools': []}
        self.patch = mock.patch.multiple(bootstrap_plan, Path=self.path, CONFIG=self.root/'etc/ultra-recovery',
                                        ROOT=self.root/'opt/ultra-recovery', UNITS=self.root/'etc/systemd/system')
        self.patch.start()
        self.db_spec_patch = mock.patch.object(db_connection, 'APP_SPEC', self.spec)
        self.db_spec_patch.start()
        self.discovery = mock.patch.object(bootstrap_plan, 'query_database', return_value=json.dumps([{'id':'11111111-2222-3333-4444-555555555555','address':'192.0.2.2'}]).encode())
        self.discovery.start()

    def tearDown(self):
        self.db_spec_patch.stop(); self.discovery.stop(); self.patch.stop(); self.temp.cleanup()

    def test_planner_has_no_host_mutations_and_initial_independence_is_unconfirmed(self):
        before = sorted(str(p) for p in self.root.rglob('*'))
        result = bootstrap_plan.plan(self.config)
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob('*')))
        backup = json.loads(next(item['content'] for item in result['files'] if item['destination'].endswith('/backup.json')))
        self.assertFalse(backup['independent'])
        self.assertTrue(result['verified'])
        self.assertTrue(all(item['mode']=='0600' for item in result['files']))
        self.assertEqual(result['nodes'][0]['id'],'11111111-2222-3333-4444-555555555555')

    def test_secret_plan_transport_is_never_logged_by_ansible(self):
        import yaml
        role = Path(__file__).resolve().parents[1] / 'ansible/roles/recovery_primary/tasks/main.yml'
        tasks = yaml.safe_load(role.read_text())
        consumers = [task for task in tasks if 'recovery_primary_plan' in json.dumps(task)]
        self.assertGreaterEqual(len(consumers), 5)
        for task in consumers:
            self.assertIs(task.get('no_log'), True, task['name'])
        result = bootstrap_plan.plan(self.config)
        self.assertEqual(result['environment']['ULTRA_RELAY_ADMIN_TOKEN'], 'fixture-admin-token')
        token = next(item for item in result['files'] if item['destination'].endswith('/primary-bot-token'))
        self.assertEqual(token['content'], 'fixture-bot-token')
        self.assertEqual(token['mode'], '0600')

    def test_cli_transports_secrets_only_in_private_file(self):
        output = self.root / 'recovery-plan.json'
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(bootstrap_plan.sys, 'stdin', io.StringIO(json.dumps(self.config))), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            bootstrap_plan.main(['--output', str(output)])
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        result = json.loads(output.read_text())
        self.assertEqual(result['environment']['ULTRA_RELAY_ADMIN_TOKEN'], 'fixture-admin-token')
        token = next(item for item in result['files'] if item['destination'].endswith('/primary-bot-token'))
        self.assertEqual(token['content'], 'fixture-bot-token')
        import yaml
        role = Path(__file__).resolve().parents[1] / 'ansible/roles/recovery_primary/tasks/main.yml'
        tasks = yaml.safe_load(role.read_text())
        self.assertNotIn('recovery_primary_plan.stdout', role.read_text())
        transport = next(task for task in tasks if 'block' in task and 'recovery_primary_plan' in json.dumps(task))
        reader = next(task for task in transport['block'] if 'ansible.builtin.slurp' in task)
        self.assertIs(reader['no_log'], True)
        cleanup = next(task for task in transport['always'] if task.get('ansible.builtin.file', {}).get('path', '').endswith('/recovery-plan.json'))
        self.assertEqual(cleanup['ansible.builtin.file']['state'], 'absent')
        self.assertIs(cleanup['no_log'], True)
        self.assertIs(transport['no_log'], True)
        consumers = [index for index, task in enumerate(tasks) if 'recovery_primary_plan.content' in json.dumps(task)]
        # `always` runs on either planner/slurp outcome, before any consumer.
        # A later consumer failure therefore cannot strand the transport file.
        self.assertLess(tasks.index(transport), min(consumers))

    def test_private_plan_rejects_symlink_and_public_directory(self):
        target = self.root / 'untouched'
        target.write_text('original')
        output = self.root / 'recovery-plan.json'
        output.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'private_plan_file_required'):
            bootstrap_plan.write_plan(output, {'secret': 'fixture'})
        self.assertEqual(target.read_text(), 'original')
        self.assertTrue(output.is_symlink())
        output.unlink()
        public = self.root / 'public'
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'private_plan_directory_required'):
            bootstrap_plan.write_plan(public / 'plan.json', {'secret': 'fixture'})

    def test_ansible_removes_transport_on_reader_or_consumer_failure(self):
        executable = shutil.which('ansible-playbook')
        if executable is None:
            self.skipTest('ansible-playbook required for failure lifecycle regression')
        import yaml
        role = Path(__file__).resolve().parents[1] / 'ansible/roles/recovery_primary/tasks/main.yml'
        tasks = yaml.safe_load(role.read_text())
        source = next(task for task in tasks if 'block' in task and 'recovery_primary_plan' in json.dumps(task))
        for failure in ('reader', 'consumer'):
            with self.subTest(failure=failure):
                transport = copy.deepcopy(source)
                output = self.root / ('plan-' + failure + '.json')
                # Keep the production block/always structure and real file/slurp
                # modules, replacing only remote discovery with a local fixture.
                transport['block'][0]['ansible.builtin.command'] = {
                    'argv': [sys.executable, '-c',
                             'from pathlib import Path; import sys; '
                             'p=Path(sys.argv[1]); p.write_text(sys.argv[2]); p.chmod(0o600)',
                             str(output), '{"secret":"fixture-private-payload"}']}
                reader = transport['block'][1]['ansible.builtin.slurp']
                reader['src'] = str(output) if failure == 'consumer' else str(self.root / 'missing-plan')
                transport['always'][0]['ansible.builtin.file']['path'] = str(output)
                playbook = self.root / ('failure-' + failure + '.yml')
                playbook.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
                    'tasks': [transport, {'ansible.builtin.fail': {'msg': 'fixture consumer failed'}}]}]))
                result = subprocess.run([executable, '-i', 'localhost,', '-c', 'local', str(playbook)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                self.assertEqual(result.returncode, 2, result.stdout.decode(errors='replace'))
                self.assertFalse(output.exists())
                self.assertNotIn(b'fixture-private-payload', result.stdout + result.stderr)

    def test_private_plan_publish_is_atomic_and_cleans_failed_staging(self):
        output = self.root / 'recovery-plan.json'
        bootstrap_plan.write_plan(output, {'generation': 'original'})
        with mock.patch.object(bootstrap_plan.os, 'replace', side_effect=OSError('fixture publish failure')):
            with self.assertRaises(OSError):
                bootstrap_plan.write_plan(output, {'generation': 'replacement'})
        self.assertEqual(json.loads(output.read_text()), {'generation': 'original'})
        self.assertEqual(list(self.root.glob('.recovery-plan-*')), [])
        bootstrap_plan.write_plan(output, {'generation': 'replacement'})
        self.assertEqual(json.loads(output.read_text()), {'generation': 'replacement'})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_controller_ownership_catalog_survives_recovery_generations(self):
        self.config['controller_directory'] = '/opt/ultra-ansible/releases/v1.0.0'
        result = bootstrap_plan.plan(self.config)
        backup = json.loads(next(item['content'] for item in result['files'] if item['destination'].endswith('/backup.json')))
        self.assertIn('/var/lib/ultra-ansible/retention', backup['state_paths'])
        self.assertIn('/etc/ultra-db-tunnel', backup['state_paths'])
        self.assertIn('/etc/systemd/system/ultra-db-tunnel.service', backup['state_paths'])
        self.assertEqual(backup['optional_state_paths'], ['/var/lib/ultra-ansible/lifecycle.json',
                                                         '/var/lib/ultra-ansible/lifecycle-retired.json'])
        self.assertIn(self.config['controller_directory'], backup['artifact_paths'])

    def test_pin_and_age_rotation_refused(self):
        configdir=self.root/'etc/ultra-recovery';configdir.mkdir(parents=True)
        (configdir/'known_hosts').write_text('different')
        with self.assertRaisesRegex(ValueError,'pin_rotation'):
            bootstrap_plan.plan(self.config)
        (configdir/'known_hosts').unlink()
        (configdir/'backup.json').write_text(json.dumps({'recipient':'another-age-key'}))
        with self.assertRaisesRegex(ValueError,'key_rotation'):
            bootstrap_plan.plan(self.config)

    def test_unknown_tool_drift_blocks_before_desired_state(self):
        source=self.root/'opt/ultra-recovery/monitor.py';source.parent.mkdir(parents=True);source.write_text('unknown')
        self.config['tools']=[{'destination':str(source),'sha256':hashlib.sha256(b'expected').hexdigest()}]
        with self.assertRaisesRegex(ValueError,'unverified_existing'):
            bootstrap_plan.plan(self.config)

    def test_independent_proof_requires_current_generation_delivery(self):
        config={'bridge_provider':'source'}
        state={'primary':'independent','node_metadata':[{'id':'independent','provider':'other'}]}
        status={'primary':'independent','independent':True,'state':'ready'}
        backup={'source':'bridge','backup_name':'generation.age','backup_sha256':'a'*64,
                'artifact_sha256':'b'*64,'delivered_target_ids':['local']}
        self.assertFalse(recovery_status.independent_generation(config,state,status,backup))
        backup['delivered_target_ids'].append('independent')
        self.assertTrue(recovery_status.independent_generation(config,state,status,backup))
        state['primary']='replacement'
        self.assertFalse(recovery_status.independent_generation(config,state,status,backup))
        state['primary']='independent';state['node_metadata'][0]['provider']='source'
        self.assertFalse(recovery_status.independent_generation(config,state,status,backup))

    def test_status_does_not_turn_missing_evidence_into_success(self):
        with mock.patch.object(recovery_status.Path,'read_text',side_effect=FileNotFoundError):
            value=recovery_status.status(int(time.time()))
        self.assertFalse(value['verified'])
        self.assertFalse(value['ready'])
        self.assertIn('readiness_evidence_unavailable',value['reasons'])


if __name__=='__main__':unittest.main()
