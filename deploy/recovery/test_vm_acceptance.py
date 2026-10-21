import hashlib
import base64
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock
import vm_acceptance


class SerialUpgrade(unittest.TestCase):
    def fixture(self, root):
        # Preflight/command-contract fixture only. The ordinary isolated VMs use
        # forward ingress and deliberately have no managed DNS provider.
        plan=json.loads((Path(vm_acceptance.__file__).parent.parent/'install-plan-v2.example.json').read_text())
        plan['ssh']={'user':'root','identity':str(root/'fixture identity'),'strict_host_key':True}
        plan['bridge'].update(address='198.18.0.11',ssh_host='198.18.0.11',public_host='198.18.0.11',ssh_identity=plan['ssh']['identity'])
        plan['database'].update(primary_host='198.18.0.16',ssh_identity=plan['ssh']['identity'])
        plan['bot'].update(domain='vpn.fixture.test',subscription_domain='sync.fixture.test')
        plan['secrets']['env_file']=str(root/'synthetic-bot.env')
        plan['exits']=[{'name':'NL','ssh_host':'198.18.0.13','priority':100},{'name':'US','ssh_host':'198.18.0.12','priority':200}]
        plan['automation'].update(bridge_ipv4='198.18.0.11',bridge_url='https://vpn.fixture.test/happ',known_hosts_file=str(root/'known hosts'))
        plan['automation']['static_nodes']=[{'name':e['name'],'address':e['ssh_host'],'provider':'fixture-'+e['name'],'budget':{'monthly_bytes':1000+i,'is_fallback':i==0}} for i,e in enumerate(plan['exits'])]
        plan['automation']['ingress'].update(domain='vpn.fixture.test',forward_host='',public_host='198.18.0.11')
        plan['automation']['dns']={'provider':'vultr','zone':'fixture.test','ttl':300,'subscription_name':'sync','vpn_name':'vpn'}
        (root/'install-plan.json').write_text(json.dumps(plan))
        release=root/'candidate release';release.mkdir()
        (release/'release-manifest.json').write_text(json.dumps({'version':'v2.3.2'}))
        key=base64.b64encode(b'Ed'+bytes(range(40))).decode()
        public=root/'fixture.pub';public.write_text('untrusted comment: synthetic test key\n'+key+'\n')
        return plan,release,public,key

    def test_forward_vm_fixture_cannot_claim_managed_dns_upgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);plan,release,public,_=self.fixture(root)
            for dns,forward in ((None,'198.18.0.13'),(plan['automation']['dns'],'198.18.0.13'),(None,'')):
                with self.subTest(dns=dns,forward=forward):
                    plan['automation']['dns']=dns
                    plan['automation']['ingress']['forward_host']=forward
                    (root/'install-plan.json').write_text(json.dumps(plan))
                    with mock.patch.object(vm_acceptance,'run') as run:
                        with self.assertRaisesRegex(ValueError,'^synthetic_upgrade_managed_dns_fixture_required$'):
                            vm_acceptance.serial_upgrade(root,'/fixture/ultra-install',str(release),public)
                    run.assert_not_called()
                    self.assertFalse((root/'upgrade-install.config').exists())

    def test_signed_upgrade_binds_config_key_and_exact_local_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);plan,release,public,key=self.fixture(root)
            before=(root/'install-plan.json').read_bytes()
            with mock.patch.object(vm_acceptance,'run') as run:
                self.assertEqual(vm_acceptance.serial_upgrade(root,'/fixture/ultra-install',str(release),public),'v2.3.2')
            config=root/'upgrade-install.config'
            run.assert_called_once_with(['/fixture/ultra-install','upgrade','--config',str(config),'--release-dir',str(release.resolve())],root/'upgrade.log')
            values={k:json.loads(v) for k,v in (line.split('=',1) for line in config.read_text().splitlines())}
            self.assertEqual(values['ULTRA_RELEASE_MINISIGN_PUBLIC_KEY'],key)
            self.assertEqual(values['ULTRA_AUTOMATION_RELEASE_DIR'],str(release.resolve()))
            self.assertEqual(values['ULTRA_AUTOMATION_VERSION'],'v2.3.2')
            self.assertEqual(values['SUBSCRIPTION_DOMAIN'],'sync.fixture.test')
            for key,field in {'DNS_PROVIDER':'provider','DNS_ZONE':'zone','DNS_TTL':'ttl','DNS_SUBSCRIPTION_NAME':'subscription_name','DNS_VPN_NAME':'vpn_name'}.items():
                self.assertEqual(values[key],str(plan['automation']['dns'][field]))
            self.assertEqual(json.loads(values['ULTRA_AUTOMATION_STATIC_NODES']),plan['automation']['static_nodes'])
            for name,expected in {'BRIDGE_IP':plan['bridge']['address'],'DATABASE_IP':plan['database']['primary_host'],'MAIN_EXIT_IP':plan['exits'][0]['ssh_host'],'BOT_INGRESS_IP':plan['automation']['ingress']['forward_host'],'VPN_DOMAIN':plan['automation']['ingress']['domain'],'SECRETS_ENV_FILE':plan['secrets']['env_file'],'BRIDGE_SSH_KEY':plan['ssh']['identity'],'MAIN_EXIT_SSH_KEY':plan['ssh']['identity'],'DATABASE_SSH_KEY':plan['ssh']['identity'],'ULTRA_AUTOMATION_BRIDGE_URL':plan['automation']['bridge_url'],'ULTRA_AUTOMATION_KNOWN_HOSTS_FILE':plan['automation']['known_hosts_file'],'REUSE_BRIDGE_SPEC':'false'}.items():
                self.assertEqual(values[name],expected,name)
            self.assertEqual(config.stat().st_mode & 0o777,0o600)
            self.assertEqual((root/'install-plan.json').read_bytes(),before)
            self.assertFalse((root/'upgrade-plan.json').exists())

    def test_no_latest_or_unbound_release_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_,release,public,_=self.fixture(root)
            with mock.patch.object(vm_acceptance,'run') as run:
                for unbound in (None,'','latest',str(root/'missing')):
                    with self.subTest(release=unbound), self.assertRaises((ValueError,FileNotFoundError)):
                        vm_acceptance.serial_upgrade(root,'/fixture/ultra-install',unbound,public)
                (release/'release-manifest.json').write_text(json.dumps({'version':'latest'}))
                with self.assertRaisesRegex(ValueError,'explicit_synthetic_upgrade_version'):
                    vm_acceptance.serial_upgrade(root,'/fixture/ultra-install',str(release),public)
                run.assert_not_called()

    def test_trust_is_required_independently_of_release_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_,release,public,key=self.fixture(root)
            (release/'minisign.pub').write_text(key)
            with mock.patch.object(vm_acceptance,'run') as run:
                with self.assertRaisesRegex(ValueError,'trusted_public_key_file_required'):
                    vm_acceptance.serial_upgrade(root,'/fixture/ultra-install',str(release),None)
                public.write_text('not-a-Minisign-key')
                with self.assertRaisesRegex(ValueError,'invalid_synthetic_upgrade_public_key'):
                    vm_acceptance.serial_upgrade(root,'/fixture/ultra-install',str(release),public)
                run.assert_not_called()


class GenerationReceipt(unittest.TestCase):
    def test_fixture_replaces_role_specific_bridge_identity(self):
        source=Path(vm_acceptance.__file__).read_text()
        self.assertIn("ssh_identity=topology['identity']", source)
        self.assertIn("address=topology['nodes']['bridge']", source)

    def test_payload_helpers_import_without_restore_modules_installed_in_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            helpers=vm_acceptance.fixture_helper_sources()
            self.assertIn('db_connection.py',helpers)
            for name,data in helpers.items():
                (root/name).write_bytes(data)
            # The product installs recovery.py, but not operator-only restore modules.
            (root/'recovery.py').write_bytes(Path(vm_acceptance.__file__).with_name('recovery.py').read_bytes())
            code='import runpy,sys;sys.path.insert(0,sys.argv[1]);v=runpy.run_path(sys.argv[1]+"/acceptance.py");assert callable(v["seed"]);import db_connection;assert db_connection.__file__==sys.argv[1]+"/db_connection.py"'
            subprocess.run([sys.executable,'-I','-c',code,str(root)],check=True,capture_output=True)

    def test_fetches_confirmed_receiver_pair_and_verifies_before_writing(self):
        topology={'synthetic_only':True,'nodes':{'us':'198.18.0.12'}}
        data={'backup':b'encrypted-state','artifact':b'encrypted-artifacts'}
        receipt={'destinations':['root@198.18.0.12'],'backup_name':'backup-123-'+('a'*32)+'.age','artifact_name':'artifact-'+('b'*64)+'.age'}
        for kind,value in data.items():receipt[kind+'_sha256']=hashlib.sha256(value).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/'generation'
            with mock.patch.object(vm_acceptance,'ssh',side_effect=[data['backup'],data['artifact']]) as ssh:
                result=vm_acceptance.fetch_generation(topology,receipt,destination)
            self.assertEqual(result.read_bytes(),data['backup'])
            self.assertTrue(all(call.args[1]=='198.18.0.12' for call in ssh.call_args_list))
            self.assertEqual((destination/receipt['artifact_name']).read_bytes(),data['artifact'])
            with mock.patch.object(vm_acceptance,'ssh',side_effect=[data['backup'],b'tampered']):
                with self.assertRaisesRegex(ValueError,'ciphertext_mismatch'):
                    vm_acceptance.fetch_generation(topology,receipt,Path(temporary)/'invalid')
            self.assertFalse((Path(temporary)/'invalid').exists())
            with mock.patch.object(vm_acceptance,'ssh') as ssh:
                with self.assertRaisesRegex(ValueError,'confirmed_independent'):
                    vm_acceptance.fetch_generation(topology,{**receipt,'destinations':['root@198.18.0.11']},destination)
                ssh.assert_not_called()

class SyntheticFencing(unittest.TestCase):
    def test_stale_recorded_pid_does_not_hide_running_owned_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); disk=root/'topology/bridge/disk.qcow2'; proc=root/'proc'
            for pid,name in ((3454,'bridge'),(3480,'nl')):
                directory=proc/str(pid);directory.mkdir(parents=True)
                (directory/'stat').write_text(str(pid)+' (qemu-system-x86) S 0')
                (directory/'cmdline').write_bytes(b'qemu-system-x86_64\0-drive\0file='+str(root/'topology'/name/'disk.qcow2').encode()+b',if=virtio,format=qcow2\0')
            self.assertEqual(vm_acceptance.owned_vm_pids(disk,proc),[3454])
            # A similar prefix must never match the owned disk.
            self.assertEqual(vm_acceptance.owned_vm_pids(Path(str(disk)+'.other'),proc),[])

    def test_pidfd_identity_rechecked_before_signal(self):
        with mock.patch.object(vm_acceptance,'owned_vm_pids',side_effect=[[3454],[]]), mock.patch.object(vm_acceptance.os,'pidfd_open',return_value=99), mock.patch.object(vm_acceptance.os,'close') as close, mock.patch.object(vm_acceptance.signal,'pidfd_send_signal') as send:
            with self.assertRaisesRegex(ValueError,'ownership_changed'):
                vm_acceptance.fence_owned_vm(Path('/fixture/bridge/disk.qcow2'))
            send.assert_not_called();close.assert_called_once_with(99)
