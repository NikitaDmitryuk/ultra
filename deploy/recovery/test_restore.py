import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import recovery_key
import recovery
import restore
import restore_common as common
import restore_host as host
import restore_peer as peer


class RestoreContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def test_original_artifact_ciphertext_is_preserved_for_receiver_and_resume(self):
        import io
        repo=recovery.repository(self.root/'repo','bridge',initialize=True)
        name='artifact-'+('a'*64)+'.age'; original=b'original-encrypted-generation'; regenerated=b'different-age-randomness'
        target=repo/name; target.write_bytes(regenerated)
        expected=hashlib.sha256(original).hexdigest()
        # Existing immutable receiver correctly rejects a re-encrypted artifact.
        args=__import__('types').SimpleNamespace(repository=str(repo),source='bridge',name=name,sha256=expected,snapshot=int(time.time()))
        with mock.patch.object(recovery.shutil,'disk_usage',return_value=__import__('types').SimpleNamespace(free=10**12)):
            with self.assertRaisesRegex(ValueError,'immutable backup name collision'):
                recovery.receive(args,io.BytesIO(original))
            host.seed_artifact_cache(repo,name,expected,io.BytesIO(original))
            recovery.receive(args,io.BytesIO(original))
        self.assertEqual(target.read_bytes(),original)
        self.assertEqual(next(repo.glob('*.pre-restore-*')).read_bytes(),regenerated)
        host.seed_artifact_cache(repo,name,expected,io.BytesIO(original))
        self.assertEqual(target.read_bytes(),original)
        with self.assertRaisesRegex(ValueError,'staged_manifest_mismatch'):
            host.seed_artifact_cache(repo,name,expected,io.BytesIO(b'tampered'))
        self.assertEqual(target.read_bytes(),original)

    def test_artifact_cache_requires_operator_verification_before_remote_write(self):
        name='artifact-'+('b'*64)+'.age'; cipher=self.root/name;cipher.write_bytes(b'ciphertext');cipher.chmod(0o600)
        state={'artifact':name};config={'identity':'/operator/private-identity','bundle':str(self.root/'backup.age'),'state_dir':str(self.root),'target':{'host':'fixture'}}
        with mock.patch.object(restore,'restore',return_value=state) as verify, mock.patch.object(restore,'remote') as remote:
            restore.seed_original_artifact(config,state,'/var/lib/ultra-restore/owned')
            self.assertEqual(verify.call_args.args[0].command,'verify')
            self.assertEqual(remote.call_args.args[2],b'ciphertext')
            self.assertNotIn(config['identity'],str(remote.call_args))
        with mock.patch.object(restore,'restore',return_value={'artifact':'different'}), mock.patch.object(restore,'remote') as remote:
            with self.assertRaisesRegex(ValueError,'staged_manifest_mismatch'):
                restore.seed_original_artifact(config,state,'/var/lib/ultra-restore/owned')
            remote.assert_not_called()

    def certbot_fixture(self):
        stage=self.root/'stage';root=self.root/'target';state={'files':{}}
        files={'etc/letsencrypt/renewal/vpn.example.conf':
            'version = 2.9.0\narchive_dir = /etc/letsencrypt/archive/vpn.example\n'+
            ''.join(kind+' = /etc/letsencrypt/live/vpn.example/'+kind+'.pem\n' for kind in ('cert','privkey','chain','fullchain'))+'[renewalparams]\nauthenticator = webroot\n'}
        for kind in ('cert','privkey','chain','fullchain'):
            files['etc/letsencrypt/live/vpn.example/'+kind+'.pem']='synthetic-'+kind
        for name,data in files.items():
            source=stage/'state'/name;source.parent.mkdir(parents=True,exist_ok=True);source.write_text(data)
            state['files']['state/'+name]={'sha256':hashlib.sha256(data.encode()).hexdigest(),'mode':0o600,'bytes':len(data)}
        host.install_files(stage,state,{'files':{}},root)
        return stage,state,root

    def test_flattened_certbot_bundle_restores_renewable_lineage_and_resumes(self):
        stage,state,root=self.certbot_fixture()
        host.restore_certbot_lineages(stage,state,root)
        links=[]
        for kind in ('cert','privkey','chain','fullchain'):
            path=root/'etc/letsencrypt/live/vpn.example'/(kind+'.pem')
            # Certbot RenewableCert._check_symlinks requires all four to be
            # existing links, not merely readable PEM files.
            self.assertTrue(path.is_symlink())
            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(),'synthetic-'+kind)
            links.append(path.readlink())
        host.restore_certbot_lineages(stage,state,root)
        self.assertEqual(links,[(root/'etc/letsencrypt/live/vpn.example'/(k+'.pem')).readlink() for k in ('cert','privkey','chain','fullchain')])
        self.assertEqual(len(list((root/'etc/letsencrypt/archive/vpn.example').iterdir())),4)

    def test_certbot_lineage_recovers_interrupted_link_write(self):
        stage,state,root=self.certbot_fixture()
        original=os.replace
        def interrupt(source,target):
            if str(source).endswith('.chain.pem.restore-link'):
                raise OSError('synthetic interruption')
            return original(source,target)
        with mock.patch.object(host.os,'replace',side_effect=interrupt):
            with self.assertRaises(OSError):host.restore_certbot_lineages(stage,state,root)
        host.restore_certbot_lineages(stage,state,root)
        live=root/'etc/letsencrypt/live/vpn.example'
        self.assertTrue(all((live/(k+'.pem')).is_symlink() for k in ('cert','privkey','chain','fullchain')))
        self.assertFalse(list(live.glob('.*.restore-link')))

    def test_certbot_lineage_preserves_archive_history(self):
        stage,state,root=self.certbot_fixture()
        old=root/'etc/letsencrypt/archive/vpn.example/cert1.pem';old.parent.mkdir(parents=True);old.write_text('older-certificate')
        host.restore_certbot_lineages(stage,state,root)
        self.assertEqual(old.read_text(),'older-certificate')
        self.assertEqual((root/'etc/letsencrypt/live/vpn.example/cert.pem').readlink().name,'cert2.pem')

    def test_certbot_lineage_rejects_foreign_links_and_missing_state(self):
        stage,state,root=self.certbot_fixture()
        live=root/'etc/letsencrypt/live/vpn.example/cert.pem'
        external=self.root/'foreign.pem';external.write_text(live.read_text());live.unlink();live.symlink_to(external)
        with self.assertRaisesRegex(ValueError,'certbot_lineage_invalid'):
            host.restore_certbot_lineages(stage,state,root)
        self.assertFalse((root/'etc/letsencrypt/archive').exists())
        live.unlink();live.write_text(external.read_text())
        del state['files']['state/etc/letsencrypt/live/vpn.example/chain.pem']
        with self.assertRaisesRegex(ValueError,'certbot_lineage_state_incomplete'):
            host.restore_certbot_lineages(stage,state,root)
        self.assertFalse((root/'etc/letsencrypt/archive').exists())

    def test_failure_diagnostics_are_safe_and_successful_resume_clears(self):
        secret = 'secret-password --token private-argv'
        def failed(config, diagnostic):
            diagnostic.directory = self.root
            diagnostic.stage = 'database'
            raise subprocess.CalledProcessError(1, ['private-argv'], stderr=secret)
        with mock.patch.object(restore, '_execute', side_effect=failed):
            with self.assertRaises(restore.RestoreFailure) as caught:
                restore.execute({})
        value = json.loads((self.root/'last-error.json').read_text())
        self.assertEqual(value['stage'], 'database')
        self.assertEqual(value['code'], 'subprocess_failed')
        self.assertNotIn('private', json.dumps(value))
        self.assertNotIn(secret, str(caught.exception))
        def success(config, diagnostic):
            diagnostic.directory = self.root
            return {'ready': True}
        with mock.patch.object(restore, '_execute', side_effect=success):
            self.assertEqual(restore.execute({}), {'ready': True})
        self.assertFalse((self.root/'last-error.json').exists())
        with mock.patch.object(restore, '_execute', side_effect=ValueError(secret)), mock.patch.object(restore, 'atomic_json') as write:
            with self.assertRaises(restore.RestoreFailure) as caught:
                restore.execute({'state_dir': '/untrusted'})
            write.assert_not_called()
            self.assertEqual(caught.exception.diagnostic['code'], 'invalid_input')

    def test_remote_errors_accept_only_literal_codes_never_stderr(self):
        for stderr, expected in (
                (b'{"restore_error_code":"target_disk_insufficient"}', 'target_disk_insufficient'),
                (b'{"restore_error_code":"dns_propagation_timeout"}', 'dns_propagation_timeout'),
                (b'{"restore_error_code":"secret-password"}', 'pinned_remote_action_failed'),
                (b'{"restore_error_code":"target_disk_insufficient","argv":"secret"}', 'pinned_remote_action_failed'),
                (b'private traceback password token', 'pinned_remote_action_failed')):
            with mock.patch.object(restore, 'ssh_arguments', return_value=['ssh']), mock.patch.object(restore.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', stderr)):
                with self.assertRaisesRegex(ValueError, '^'+expected+'$'):
                    restore.remote({}, ['secret-argv'], b'secret-stdin')
    def test_fence_requires_exact_target_source_and_freshness(self):
        value = dict(source='bridge', source_address='192.0.2.1', target_host='root@target', confirmed_offline=True, confirmed_at=100)
        common.fence(value, 'bridge', 'root@target', '192.0.2.1', now=150)
        for update in ({'confirmed_at': 151}, {'confirmed_at': -3601}, {'target_host': 'other'}, {'source_address': '192.0.2.2'}, {'confirmed_offline': False}):
            with self.assertRaises(ValueError):
                common.fence(dict(value, **update), 'bridge', 'root@target', '192.0.2.1', now=150)
    def test_plan_default_source_and_stable_resume_identity(self):
        value = json.loads(Path(__file__).with_name('restore.example.json').read_text())
        value.pop('source')
        config = common.configuration(value)
        expected = common.plan_id(config, 'a'*64)
        original_provider=config['new_bridge_provider']
        config['new_bridge_provider']='different-provider'
        self.assertNotEqual(common.plan_id(config, 'a'*64), expected)
        config['new_bridge_provider']=original_provider
        config['fence_file'] = '/other/fence.json'
        self.assertEqual(common.plan_id(config, 'a'*64), expected)
        config['target']['host'] = 'root@different'
        self.assertNotEqual(common.plan_id(config, 'a'*64), expected)
    def test_direct_mode_needs_no_forward_host_and_binds_resume(self):
        value = json.loads(Path(__file__).with_name('restore.example.json').read_text())
        legacy = common.configuration(value)
        direct = dict(value, ingress_mode='direct')
        direct.pop('ingress')
        direct = common.configuration(direct)
        self.assertNotEqual(common.plan_id(legacy, 'a'*64), common.plan_id(direct, 'a'*64))
        with self.assertRaises(KeyError):
            common.configuration(dict(direct, ingress_mode='forward'))

    def test_direct_dns_preflight_failure_and_resume(self):
        import dns
        plan = {'restore_id':'r', 'ingress_mode':'direct', 'target_host':'target',
                'old_bridge_address':'192.0.2.1', 'new_bridge_address':'192.0.2.2',
                'public_host':'edge.example.test', 'subscription_domain':'sync.example.test',
                'fence':{'source':'bridge','source_address':'192.0.2.1','target_host':'target',
                         'confirmed_offline':True,'confirmed_at':int(time.time())}}
        policy = {'config':{'zone':'example.test'}, 'desired':{
            'subscription':{'name':'sync','data':'192.0.2.1'}, 'vpn':{'name':'edge','data':'192.0.2.1'}}}
        policy_path=self.root/'dns.json';policy_path.write_text(json.dumps(policy))
        instance=host.Host(self.root, plan)
        with mock.patch.object(dns, 'private', return_value=policy_path), mock.patch.object(host.socket, 'create_connection') as connection, mock.patch.object(host.ssl, 'create_default_context'), mock.patch.object(host, 'run'), mock.patch.object(dns, 'execute') as execute, mock.patch.object(dns, 'wait_ready') as ready, mock.patch.object(dns, 'save') as save:
            connection.side_effect=OSError('private TLS detail')
            with self.assertRaises(OSError): instance.ingress()
            execute.assert_not_called()
            connection.side_effect=None
            ready.side_effect=ValueError('dns_convergence_timeout')
            with self.assertRaises(ValueError): instance.ingress()
            self.assertEqual(execute.call_count, 1)
            save.assert_not_called()
            # Resume reconciles the same desired records through dns's durable
            # receipt; failure never asks for the fenced source IP again.
            ready.side_effect=None
            instance.ingress()
            self.assertEqual(execute.call_count, 2)
            for call in execute.call_args_list:
                self.assertEqual({v['data'] for v in call.args[1].values()}, {'192.0.2.2'})
            save.assert_called_once()
            plan['fence']['confirmed_at']=0
            with self.assertRaises(ValueError): instance.ingress()
            self.assertEqual(execute.call_count, 2)
        plan['fence']['confirmed_at']=int(time.time())
        instance.status['completed']=list(common.PHASES[:common.PHASES.index('ingress')+1])
        with mock.patch.object(instance, 'verify_resume') as verify, mock.patch.object(instance, 'direct_ingress') as recheck:
            instance.phase('ingress')
            verify.assert_called_once()
            recheck.assert_called_once()
        legacy=host.Host(self.root, dict(plan, ingress_mode='forward'))
        with self.assertRaisesRegex(ValueError, 'verified_public_ingress_required'): legacy.ingress()

    def test_state_rejects_symlink_and_host_identity_overwrites(self):
        (self.root/'etc').symlink_to('/tmp')
        with self.assertRaises(ValueError): common.safe_target(self.root, 'etc/ultra-relay/spec.json')
        for path in ('etc/ssh/sshd_config', 'root/.ssh/authorized_keys', 'var/lib/postgresql/16/data', 'etc/passwd', '../etc/shadow'):
            with self.assertRaises(ValueError): common.destination(path)
    def test_relocation_preserves_credentials_sni_and_other_bridges(self):
        spec={'public_host':'old.example','primary_xhttp':{'host':'old.example','server_name':'stable.example'},
              'subscription_bridges':[{'host':'192.0.2.1','transport':'xhttp','server_name':'stable.example'},{'host':'old.example','transport':'tcp','public_key':'unchanged'},{'host':'other.example'}],
              'public_entries':[{'host':'192.0.2.1'},{'host':'nl.example'}], 'users':[{'uuid':'stable-user'}], 'exits':[{'address':'192.0.2.1'}]}
        changed=host.relocate_spec(spec,'192.0.2.1','192.0.2.2')
        self.assertEqual([x['host'] for x in changed['subscription_bridges']],['192.0.2.2','192.0.2.2','other.example'])
        self.assertEqual(changed['primary_xhttp']['server_name'],'stable.example')
        self.assertEqual(changed['users'],[{'uuid':'stable-user'}]);self.assertEqual(changed['exits'],[{'address':'192.0.2.1'}])
        self.assertEqual(changed['public_entries'][1]['host'],'nl.example')
    def test_managed_firewall_admission_precedes_peer_ssh(self):
        target=host.Host(self.root,{'restore_id':'a'*64,'old_bridge_address':'192.0.2.1','new_bridge_address':'192.0.2.2'})
        target.status['system_identifier']='123';target.status['database_name']='fixture'
        module=mock.Mock();calls=[]
        module.ensure_provider_peer_rule.side_effect=lambda *args,**kwargs:calls.append('firewall')
        module.execute.side_effect=lambda *args,**kwargs:calls.append('ssh')
        with mock.patch.object(target,'nodes',return_value=(module,{},[{'id':'node','address':'192.0.2.3'}])),mock.patch.object(host,'sql',return_value='[8443]'):target.peer_reseed()
        self.assertEqual(calls,['firewall','firewall','ssh'])
    def test_certificate_inventory_uses_only_explicit_file_fields(self):
        value={'public_xhttp_tls':{'cert_file':'/etc/letsencrypt/live/vpn/fullchain.pem','key_file':'/etc/letsencrypt/live/vpn/privkey.pem'},'reality':{'private_key':'opaque-secret'},'other':{'key_file':'not-a-path'}}
        self.assertEqual(host.certificate_files(value),['/etc/letsencrypt/live/vpn/fullchain.pem','/etc/letsencrypt/live/vpn/privkey.pem'])
    def test_dsn_requires_local_pg16_default_endpoint(self):
        self.assertEqual(host.database_spec({'database':{'dsn':'postgres://app:p%40ss@localhost:5432/app?sslmode=disable'}}), ('app','app','p@ss'))
        for value in ('postgres://app:pw@remote/app', 'postgres://app:pw@localhost:5433/app','postgres://app@localhost/app','postgres://app:pw@localhost/app;DROP'):
            with self.assertRaises(ValueError): host.database_spec({'database':{'dsn':value}})
    def test_saved_environment_reset_and_file_override(self):
        directory=self.root/'etc/systemd/system';directory.mkdir(parents=True)
        (directory/'ultra-relay.service').write_text('[Service]\nUser=ultra-relay\nEnvironment="A=one" "B=two"\nEnvironmentFile=/etc/ultra-relay/env\n')
        env=self.root/'etc/ultra-relay/env';env.parent.mkdir();env.write_text('A="file override"\n')
        user,values=host.unit_environment('ultra-relay.service',self.root)
        self.assertEqual(user,'ultra-relay');self.assertEqual(values,{'A':'file override','B':'two'})
    def test_ingress_failure_rolls_back_both_owned_files(self):
        nginx=self.root/'etc/nginx';nginx.mkdir(parents=True)
        original=peer.configurations('192.0.2.1','vpn.example.org')
        for name,data in original.items():
            path=nginx/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
        calls=[]
        def runner(args):
            calls.append(args)
            if len(calls)==1:raise ValueError('bad nginx')
            return ''
        plan={'restore_id':'a'*64,'old_bridge_address':'192.0.2.1','new_bridge_address':'192.0.2.2','subscription_domain':'vpn.example.org'}
        with self.assertRaisesRegex(ValueError,'previous_restored'):peer.forward(plan,self.root,runner)
        for name,data in original.items():self.assertEqual((nginx/name).read_bytes(),data)
        self.assertEqual(calls[-1],['systemctl','reload','nginx'])
    def test_forward_pid_must_be_old_primary_owned_ssh(self):
        listeners='LISTEN 0 128 127.0.0.1:15432 0.0.0.0:* users:(("sshd",pid=456,fd=5))'
        connections='ESTAB 0 0 198.51.100.1:22 192.0.2.1:40100 users:(("sshd",pid=456,fd=4))'
        self.assertEqual(peer.stale_forward_pids(listeners,connections,'192.0.2.1'),{456})
        with self.assertRaises(ValueError):peer.stale_forward_pids(listeners,connections,'192.0.2.2')
    def test_reseed_preserves_managed_pg16_data_and_is_idempotent(self):
        directory=self.root/'var/lib/ultra-postgres-replica';data=directory/'data';data.mkdir(parents=True)
        (directory/'managed-by-ultra').write_text('managed');(data/'standby.signal').touch();(data/'PG_VERSION').write_text('16');(data/'original').write_text('sentinel')
        plan={'restore_id':'a'*64,'system_identifier':'456','old_bridge_address':'192.0.2.1'}
        calls=[]
        def runner(args):
            calls.append(args)
            return 'Database system identifier: 123\n' if 'pg_controldata' in args[0] else ''
        self.assertTrue(peer.reseed(plan,self.root,runner)['previous_data_preserved'])
        self.assertFalse(data.exists());self.assertEqual((directory/('retired-'+'a'*16)/'data/original').read_text(),'sentinel')
        count=len(calls);self.assertTrue(peer.reseed(plan,self.root,runner)['resumed']);self.assertEqual(count,len(calls))
    def test_fresh_ingress_ack_required_before_automation(self):
        plan={'restore_id':'a'*64,'target_host':'target','old_bridge_address':'192.0.2.1', 'fence':{'source':'bridge','confirmed_offline':True,'confirmed_at':time.time(),'target_host':'target','source_address':'192.0.2.1'}}
        target=host.Host(self.root,plan)
        target.status['completed']=list(common.PHASES[:5])
        with self.assertRaisesRegex(ValueError,'phase_order'):target.phase('automation')
        with self.assertRaisesRegex(ValueError,'verified_public'):target.phase('ingress')
        plan['ingress_confirmed']=True;target.phase('ingress')
        self.assertIn('ingress',target.status['completed'])
    def test_readiness_waits_for_first_receipts(self):
        target=host.Host(self.root,{'restore_id':'a'*64,'readiness_timeout':30})
        target.status['database_name']='fixture'
        backup={'snapshot_at':time.time()};controller={'state':'ready','independent':True,'updated_at':time.time()}
        with mock.patch.object(target,'wait_runtime'),mock.patch.object(host.time,'sleep') as sleep,mock.patch.object(Path,'read_text',side_effect=[FileNotFoundError(),json.dumps(backup),json.dumps(controller)]),mock.patch.object(host,'sql',return_value='[{"state":"streaming","age":1}]'):
            target.ready()
        sleep.assert_called_once();self.assertEqual(target.status['replicas_ready'],1)


@unittest.skipUnless(shutil.which('age-keygen'), 'age tools required')
class KeyLifecycle(unittest.TestCase):
    def test_init_reuses_key_repairs_missing_recipient_and_rejects_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identity=root/'identity';recipient=root/'recipient'
            first=recovery_key.initialize(identity,recipient);fingerprint=hashlib.sha256(identity.read_bytes()).digest()
            self.assertEqual(recovery_key.initialize(identity,recipient),first)
            recipient.unlink();self.assertEqual(recovery_key.initialize(identity,recipient),first)
            self.assertEqual(hashlib.sha256(identity.read_bytes()).digest(),fingerprint)
            recipient.write_text('different')
            with self.assertRaises(ValueError):recovery_key.initialize(identity,recipient)
            self.assertEqual(hashlib.sha256(identity.read_bytes()).digest(),fingerprint)
    def test_extracted_copy_decrypts_both_archives_and_records_limited_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identity=root/'identity';public=root/'recipient';copy=root/'extracted'
            value=recovery_key.initialize(identity,public)
            shutil.copyfile(identity,copy);copy.chmod(0o600)
            item=root/'item';item.write_bytes(b'synthetic recovery fixture')
            artifact_plain=root/'artifact.tar.gz'
            manifest=recovery.pack(artifact_plain,{'kind':'artifact','source':'bridge'}, {'usr/local/bin/fixture':item})
            artifact_id=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True).encode()).hexdigest()
            artifact=root/('artifact-'+artifact_id+'.age')
            recovery.encrypt(artifact_plain,artifact,value['recipient'])
            plain=root/'backup.tar.gz';bundle=root/'backup.age'
            recovery.pack(plain,{'kind':'backup','source':'bridge','snapshot_at':123,'artifact':artifact.name},{'database.dump':item})
            recovery.encrypt(plain,bundle,value['recipient'])
            proof=recovery_key.verify_copy(bundle,identity,copy,root/'receipt.json')
            self.assertTrue(proof['extracted_copy_verified']);self.assertFalse(proof['independent_storage_verified'])
            self.assertEqual(proof['snapshot_at'],123)
            self.assertEqual(json.loads((root/'receipt.json').read_text()),proof)
            artifact.write_bytes(b'corrupt')
            with self.assertRaises(Exception):recovery_key.verify_copy(bundle,identity,copy,root/'failed-receipt.json')
            self.assertFalse((root/'failed-receipt.json').exists())
    def test_verify_rejects_same_inode_before_decryption(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identity=root/'identity';recipient=root/'recipient'
            recovery_key.initialize(identity,recipient)
            alias=root/'hardlink';os.link(identity,alias)
            with self.assertRaisesRegex(ValueError,'independently_extracted'):recovery_key.verify_copy(root/'missing',identity,alias,root/'receipt')

if __name__=='__main__':unittest.main()
