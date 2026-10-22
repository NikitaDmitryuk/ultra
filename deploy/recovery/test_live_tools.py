#!/usr/bin/env python3
"""Synthetic current tools identity, rollback and subsequent release contracts."""
import io
import json
import tarfile
import tempfile
import os
import stat
import types
import unittest
from pathlib import Path
from unittest.mock import patch
import live_tools

NAMES = ['recovery.py', 'db_connection.py', 'reconcile.py', 'monitor.py', 'heartbeat.py', 'live_tools.py',
         'ultra-recovery-backup.service', 'ultra-recovery-backup.timer',
         'ultra-recovery-prune.service', 'ultra-recovery-prune.timer',
         'ultra-monitor.service', 'ultra-monitor.timer', 'ultra-monitor-probe.service', 'ssh_policy.json']


class CurrentToolsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.bundle = self.root / 'bundle'; self.system = self.root / 'system'
        self.bundle.mkdir(); self.system.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(live_tools, 'ROOT', self.bundle).start(); patch.object(live_tools, 'SYSTEM', self.system).start()

    def generation(self, version, extra=None):
        stream = io.BytesIO(); files = {name: (version + ':' + name).encode() for name in NAMES}
        files['ssh_policy.json'] = Path(__file__).with_name('ssh_policy.json').read_bytes()
        files.update(extra or {})
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(name); member.size = len(data); archive.addfile(member, io.BytesIO(data))
        zipped = stream.getvalue()
        raw = json.dumps({'version': version, 'assets': [{'name': 'ultra-recovery.tar.gz', 'size': len(zipped), 'sha256': live_tools.digest(zipped)}]}).encode()
        inventory = live_tools.archive_inventory(raw, zipped)
        return files, raw, zipped, json.dumps(inventory).encode()

    def select(self, generation):
        files, manifest, archive, inventory = generation
        for name, data in files.items():
            (self.bundle / name).write_bytes(data); (self.bundle / name).chmod(0o755 if name.endswith('.py') else 0o644)
            if live_tools.recovery_member_is_systemd_unit(name):
                (self.system / name).write_bytes(data)
        for name, data in zip(live_tools.NAMES, (manifest, archive, inventory)):
            (self.bundle / name).write_bytes(data); (self.bundle / name).chmod(0o600)

    def test_prepared_app_rollback_then_two_ordinary_generations_and_prune(self):
        app = self.bundle / 'release-manifest.json'; original = b'original-application-0210'; app.write_bytes(original)
        prepared = self.generation('prepared'); self.select(prepared)
        self.assertEqual(live_tools.verify(False)['manifest_sha256'], live_tools.digest(prepared[1]))
        # Prepared app rollback retains the actual candidate tools predecessor.
        self.assertEqual(app.read_bytes(), original)
        self.select(prepared); self.assertEqual(live_tools.verify(False)['members']['reconcile.py'], live_tools.digest(prepared[0]['reconcile.py']))
        second = self.generation('ordinary-2'); self.select(second)
        self.assertEqual(live_tools.verify(False)['members']['ultra-monitor.service'], live_tools.digest(second[0]['ultra-monitor.service']))
        # Ordinary app rollback restores the exact tool fallback, not 0210 tools.
        self.select(prepared); self.assertEqual(live_tools.verify(False)['members']['reconcile.py'], live_tools.digest(prepared[0]['reconcile.py']))
        self.select(second); third = self.generation('ordinary-3'); self.select(third)
        # No historical source directory is needed by the current source bundle.
        for path in [self.root / 'old-first-snapshot', self.root / 'old-controller']:
            path.mkdir(); path.rmdir()
        self.assertEqual(live_tools.verify(False)['manifest_sha256'], live_tools.digest(third[1]))
        self.assertEqual(app.read_bytes(), original)

    def test_reconcile_projects_actual_new_scripts_and_unit_sources_after_prune(self):
        import reconcile
        generation=self.generation('ordinary-3');self.select(generation)
        captured=[];factory=Path
        def mapped(value):
            return self.bundle if str(value)=='/opt/ultra-recovery' else factory(value)
        config={'bundle_dir':'/opt/ultra-recovery','state_dir':str(self.root/'state')}
        with patch.object(live_tools,'verify_dispatcher') as dispatcher,patch.object(reconcile,'Path',side_effect=mapped), \
             patch.object(reconcile,'ansible_apply',side_effect=lambda config,node,variables:captured.append(variables)):
            reconcile.install(config,{'id':'receiver'})
        dispatcher.assert_called_once()
        files=captured[0]['ultra_recovery_files']
        self.assertTrue(any(row['destination']=='/etc/systemd/system/ultra-monitor.service' for row in files))
        for row in files:
            name=Path(row['source']).name
            self.assertEqual(Path(row['source']).read_bytes(),generation[0][name])
            self.assertTrue(str(row['source']).startswith(str(self.bundle)))

    def test_every_source_member_and_unit_copy_rejects_drift(self):
        generation = self.generation('candidate'); self.select(generation)
        for name in NAMES:
            path = self.bundle / name; original = path.read_bytes(); path.write_bytes(b'foreign')
            with self.subTest(member=name), self.assertRaises(ValueError): live_tools.verify(False)
            path.write_bytes(original)
        path = self.system / 'ultra-monitor.service'; path.write_bytes(b'old-unit')
        with self.assertRaises(ValueError): live_tools.verify(False)

    def test_policy_json_is_only_verified_under_opt_and_arbitrary_json_is_rejected(self):
        generation = self.generation('policy-json')
        self.select(generation)
        inventory = live_tools.verify(False)
        self.assertEqual(inventory['members']['ssh_policy.json'], live_tools.digest(generation[0]['ssh_policy.json']))
        self.assertEqual((self.bundle / 'ssh_policy.json').read_bytes(), generation[0]['ssh_policy.json'])
        self.assertFalse((self.system / 'ssh_policy.json').exists())
        (self.bundle / 'ssh_policy.json').write_bytes(b'changed policy')
        with self.assertRaises(ValueError):
            live_tools.verify(False)
        with self.assertRaises(ValueError):
            self.generation('arbitrary-json', {'untrusted.json': b'not allowlisted'})

    def test_manifest_archive_inventory_and_dispatcher_are_not_claimed_booleans(self):
        generation = self.generation('candidate'); self.select(generation)
        inventory = json.loads((self.bundle / 'tools-inventory.json').read_bytes()); del inventory['members']['monitor.py']
        (self.bundle / 'tools-inventory.json').write_text(json.dumps(inventory))
        with self.assertRaises(ValueError): live_tools.verify(False)
        self.select(generation); (self.bundle / 'tools.tar.gz').write_bytes(b'foreign')
        with self.assertRaises(ValueError): live_tools.verify(False)
        with patch.object(live_tools, 'CURRENT', self.root / 'absent'):
            with self.assertRaises(ValueError): live_tools.verify_dispatcher({})

    def test_dispatcher_is_exact_selected_installer_runtime_seal_and_running_instance(self):
        directory=Path('/opt/ultra-ansible/releases/managed-v0.0.2')
        current=types.SimpleNamespace(is_symlink=lambda:True)
        installer=b'candidate-installer'; runtime='a'*64
        arch={'x86_64':'amd64','aarch64':'arm64'}[live_tools.platform.machine()]
        manifest={'assets':[{'name':'ultra-install-linux-'+arch,'sha256':live_tools.digest(installer)},
                            {'name':'ultra-ansible-runtime-linux-'+arch+'.tar.gz','sha256':runtime}]}
        expected=[str(directory/'ultra-install'),'ansible-controller','--executable',str(directory/'venv/bin/ansible-playbook')]
        unit=self.system/'ultra-ansible-controller.service'
        files={str(directory/'ultra-install'):installer,str(directory/'runtime.sha256'):(runtime+'\n').encode(),
               str(unit):('[Service]\nExecStart='+' '.join(expected)+'\nUser=root\nGroup=root\nKillMode=control-group\n').encode(),
               '/proc/42/exe':installer,'/proc/42/cmdline':b'\0'.join(value.encode() for value in expected)+b'\0',
               '/proc/42/cgroup':b'0::/system.slice/ultra-ansible-controller.service\n'}
        seal={'schema':1,'path':str(directory),'identity':{'ultra-install':live_tools.digest(installer),'runtime.sha256':live_tools.digest((runtime+'\n').encode())},
              'inventory':{'ultra-install':['file',live_tools.digest(installer),0o755],'runtime.sha256':['file',live_tools.digest((runtime+'\n').encode()),0o600]}}
        files[str(live_tools.RETENTION/(live_tools.digest(str(directory).encode())+'.json'))]=json.dumps(seal).encode()
        fields={'ActiveState':'active','MainPID':'42','ControlGroup':'/system.slice/ultra-ansible-controller.service',
                'FragmentPath':str(unit),'KillMode':'control-group','Delegate':'no','User':'root','Group':'root'}
        def show(*a,**k):return types.SimpleNamespace(stdout=''.join(key+'='+value+'\n' for key,value in fields.items()).encode())
        def readlink(path):return str(directory) if path is current else str(directory/'ultra-install')
        def metadata(path):return types.SimpleNamespace(st_uid=os.geteuid(),st_mode=stat.S_IFREG|(0o755 if path.name=='ultra-install' else 0o600))
        with patch.object(live_tools,'CURRENT',current),patch.object(live_tools,'regular',side_effect=lambda path,*a,**k:files[str(path)]), \
             patch.object(live_tools.os,'readlink',side_effect=readlink),patch.object(live_tools.os,'walk',return_value=[(str(directory),[],['ultra-install','runtime.sha256'])]), \
             patch.object(live_tools.Path,'lstat',metadata),patch.object(live_tools.Path,'read_bytes',lambda path:files[str(path)]), \
             patch.object(live_tools.subprocess,'run',side_effect=show):
            live_tools.verify_dispatcher(manifest)
            files[str(directory/'runtime.sha256')]=('b'*64+'\n').encode()
            with self.assertRaises(ValueError):live_tools.verify_dispatcher(manifest)
            files[str(directory/'runtime.sha256')]=(runtime+'\n').encode()
            fields['MainPID']='99'
            with self.assertRaises((ValueError,KeyError)):live_tools.verify_dispatcher(manifest)
            fields['MainPID']='42';files['/proc/42/exe']=b'old-installer'
            with self.assertRaises(ValueError):live_tools.verify_dispatcher(manifest)



if __name__ == '__main__': unittest.main()
