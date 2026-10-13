from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock

import vm_guest
import vm_generation


class IsolatedRestoreUnitTests(unittest.TestCase):
    def test_multiple_enabled_exits_keep_identities_on_distinct_fixture_ports(self):
        nodes = [{'id': 'NL', 'priority': 0, 'tunnel_uuid': 'fixture-nl'},
                 {'id': 'US', 'priority': 1, 'tunnel_uuid': 'fixture-us'}]
        plan = vm_guest.exit_fixture_plan(nodes)
        self.assertEqual([node['id'] for node in plan], ['NL', 'US'])
        self.assertEqual([node['tunnel_uuid'] for node in plan], ['fixture-nl', 'fixture-us'])
        self.assertEqual([node['port'] for node in plan], [16443, 16444])
        self.assertEqual(len({node['unit'] for node in plan}), 2)
        self.assertNotIn('port', nodes[0])

    def test_new_generation_uses_staged_automation_without_unmasking(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            name = 'state/etc/systemd/system/ultra-recovery-reconcile.service'
            source = stage / name
            source.parent.mkdir(parents=True)
            source.write_text('[Service]\nExecStart=/fixture\n')
            (stage / 'manifest.json').write_text(json.dumps({'files': {name: {}}}))
            config = {'state_paths': ['/etc/systemd/system/ultra-recovery-reconcile.service',
                                      '/etc/ultra-recovery/reconcile.json'], 'artifact_paths': ['/opt/ultra-recovery']}
            with mock.patch.object(vm_generation, 'collect', return_value={'etc/ultra-recovery/reconcile.json': {}}) as collect:
                files = vm_generation.state_files(config, stage)
            selected, excluded = collect.call_args.args
            self.assertNotIn(config['state_paths'][0], selected)
            self.assertIn(config['state_paths'][0], excluded)
            self.assertEqual(files[name], source)
            self.assertEqual(files['state/etc/ultra-recovery/reconcile.json'], Path('/etc/ultra-recovery/reconcile.json'))

    def test_existing_automation_stopped_and_masked_before_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in vm_guest.INERT_UNITS:
                (root / name).write_text('[Service]\nExecStart=/unused/fixture\n')
            unrelated = root / 'ultra-relay.service'
            unrelated.write_text('core fixture')
            with mock.patch.object(vm_guest, 'run') as run:
                vm_guest.mask_external_automation(root)
            args = run.call_args.args[0]
            self.assertEqual(args[:3], ['systemctl', 'mask', '--now'])
            for name in ('ultra-recovery-reconcile.service', 'ultra-recovery-reconcile.timer',
                         'ultra-recovery-backup.service', 'ultra-recovery-backup.timer',
                         'ultra-monitor.service', 'ultra-monitor.timer',
                         'ultra-monitor-probe.service', 'certbot.service', 'certbot.timer'):
                self.assertIn(name, args)
                self.assertFalse((root / name).exists())
            self.assertEqual(unrelated.read_text(), 'core fixture')

    def test_restored_units_wants_and_dropins_cannot_replace_masks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'stage'
            guest = root / 'guest'
            manifest, artifacts = {'files': {}}, {'files': {}}
            fake_null = root / 'fake-null'
            fake_null.write_text('untouched mask destination')
            unit_dir = guest / 'etc/systemd/system'
            unit_dir.mkdir(parents=True)
            for name in vm_guest.INERT_UNITS:
                (unit_dir / name).symlink_to(fake_null)
            paths = [
                'etc/systemd/system/ultra-recovery-reconcile.service',
                'etc/systemd/system/timers.target.wants/ultra-recovery-reconcile.timer',
                'etc/systemd/system/ultra-monitor.service.d/credentials.conf',
                'etc/systemd/system/certbot.timer',
                'etc/systemd/system/ultra-relay.service',
                'etc/ultra-recovery/fixture-master-credentials',
            ]
            for name in paths:
                path = stage / 'state' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic fixture')
                manifest['files']['state/' + name] = {'mode': 0o600}
            binary = stage / 'artifacts/usr/local/bin/ultra-client'
            binary.parent.mkdir(parents=True)
            binary.write_text('synthetic binary')
            artifacts['files']['usr/local/bin/ultra-client'] = {'mode': 0o755}
            template = stage / 'artifacts/opt/ultra-recovery/ultra-monitor.service'
            template.parent.mkdir(parents=True)
            template.write_text('inert controller template')
            artifacts['files']['opt/ultra-recovery/ultra-monitor.service'] = {'mode': 0o644}
            vm_guest.install_stage_files(stage, manifest, artifacts, guest)
            self.assertEqual(fake_null.read_text(), 'untouched mask destination')
            self.assertTrue((unit_dir / 'ultra-recovery-reconcile.service').is_symlink())
            self.assertFalse((unit_dir / 'timers.target.wants/ultra-recovery-reconcile.timer').exists())
            self.assertFalse((unit_dir / 'ultra-monitor.service.d').exists())
            self.assertTrue((guest / 'etc/ultra-recovery/fixture-master-credentials').is_file())
            self.assertTrue((unit_dir / 'ultra-relay.service').is_file())
            self.assertEqual((guest / 'usr/local/bin/ultra-client').stat().st_mode & 0o777, 0o755)
            self.assertEqual((guest / 'opt/ultra-recovery/ultra-monitor.service').read_text(), 'inert controller template')
            self.assertFalse(vm_guest.inert_unit_path('/opt/ultra-recovery/ultra-monitor.service'))


if __name__ == '__main__':
    unittest.main()
