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
    def test_retirement_floor_requires_enforcing_recovery_migration(self):
        ledger='state/var/lib/ultra-ansible/lifecycle-retired.json'
        common.restore_controller_floor({'files':{}})
        common.restore_controller_floor({'controller_enforcement_floor':0,'files':{}})
        for value in (1, 2, -1, True, None, '0'):
            with self.subTest(floor=value),self.assertRaisesRegex(ValueError,'^controller_enforcement_migration_required$'):
                common.restore_controller_floor({'controller_enforcement_floor':value,'files':{}})
        with self.assertRaisesRegex(ValueError,'^controller_enforcement_migration_required$'):
            common.restore_controller_floor({'controller_enforcement_floor':0,'files':{ledger:{}}})
        self.assertEqual(common.safe_error_code(ValueError('controller_enforcement_migration_required')),
                         'controller_enforcement_migration_required')

    def test_stage_rejects_declared_enforcement_floor_before_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory);(stage/'artifacts').mkdir()
            (stage/'manifest.json').write_text(json.dumps({'kind':'backup','source':'bridge','files':{},
                                                         'controller_enforcement_floor':1}))
            (stage/'artifacts/manifest.json').write_text(json.dumps({'kind':'artifact','source':'bridge','files':{}}))
            with self.assertRaisesRegex(ValueError,'^controller_enforcement_migration_required$'):
                common.stage_manifests(stage)
            (stage/'manifest.json').write_text(json.dumps({'kind':'backup','source':'bridge','files':{}}))
            (stage/'artifacts/manifest.json').write_text(json.dumps({'kind':'artifact','source':'bridge','files':{},
                                                                   'controller_enforcement_floor':1}))
            with self.assertRaisesRegex(ValueError,'^controller_enforcement_migration_required$'):
                common.stage_manifests(stage)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def test_seed_retirement_resumes_after_crash_and_rejects_foreign_marker(self):
        directory=self.root/'replica';retired=self.root/'retired';directory.mkdir();retired.mkdir()
        seed=directory/'seed';seed.mkdir();(seed/'payload').write_text('owned old seed')
        for name in ('seed-owned-by-ultra','seed-complete'):
            path=directory/name;path.write_text('ultra_'+'b'*32+'\n');path.chmod(0o600)
        rename=Path.rename;count=0
        def crash(path,target):
            nonlocal count
            count+=1
            if count==2:raise OSError('simulated interrupted marker retirement')
            return rename(path,target)
        with mock.patch.object(Path,'rename',crash):
            with self.assertRaises(OSError):peer.retire_seed_state(directory,retired)
        peer.retire_seed_state(directory,retired)
        self.assertEqual((retired/'seed/payload').read_text(),'owned old seed')
        self.assertFalse((directory/'seed-complete').exists())
        (directory/'seed-complete').write_text('foreign')
        with self.assertRaisesRegex(ValueError,'foreign_replica_seed_marker'):
            peer.retire_seed_state(directory,retired)
        self.assertEqual((directory/'seed-complete').read_text(),'foreign')

    def test_clean_operator_runtime_uses_authenticated_wheels_and_explicit_executor(self):
        import restore_ansible as adapter
        import tarfile
        stage=self.root/'stage';deployment=stage/'state/etc/ultra-recovery/deployment.json'
        deployment.parent.mkdir(parents=True);deployment.write_text(json.dumps({'controller_directory':'/opt/ultra-ansible/releases/v1.0.0'}))
        prefix='opt/ultra-ansible/releases/v1.0.0/runtime/'
        files={}
        for name,payload in [('requirements.lock',b'locked requirements'),('wheels/pip-25.3-py3-none-any.whl',b'synthetic wheel')]:
            path=stage/'artifacts'/prefix/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(payload)
            files[prefix+name]={'sha256':common.sha(path),'bytes':len(payload)}
        config={}
        with mock.patch.object(common,'stage_manifests',return_value=({}, {'files':files})), mock.patch.object(adapter.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'{"executable":"/private/runtime/venv/bin/ansible-playbook"}')) as execute:
            executable=adapter.prepare_runtime(config,self.root)
            command=execute.call_args.args[0]
            self.assertIn('prepare-recovery-runtime',command)
            self.assertIn('--runtime-archive',command)
            archive=self.root/'operator-runtime.tar.gz';first=archive.read_bytes()
            with tarfile.open(archive) as content:self.assertEqual(content.getnames(),['requirements.lock','wheels/pip-25.3-py3-none-any.whl'])
            adapter.prepare_runtime(config,self.root);self.assertEqual(archive.read_bytes(),first)
            self.assertEqual(adapter.runtime_arguments(config),['--executable',executable])
            (stage/'artifacts'/prefix/'requirements.lock').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'authenticated_offline_runtime_changed'):
                adapter.prepare_runtime({},self.root)
        with self.assertRaisesRegex(ValueError,'offline_recovery_runtime_not_prepared'):adapter.runtime_arguments({})

    def test_preserved_address_requires_distinct_machine_and_bound_fence(self):
        config=json.loads(Path(__file__).with_name('restore.example.json').read_text())
        config['new_bridge_address']=config['old_bridge_address']
        with self.assertRaisesRegex(ValueError,'new_bridge_address_must_differ'):
            common.configuration(config)
        identity={'source_machine_id':'a'*32,'target_machine_id':'b'*32,
                  'source_ssh_endpoint':'root@192.0.2.10','target_ssh_endpoint':config['target']['host']}
        config['migration_identity']=identity
        checked=common.configuration(config)
        proof={'source':'bridge','confirmed_offline':True,'confirmed_at':100,
               'source_address':config['old_bridge_address'],'target_host':config['target']['host'],
               'migration_identity':identity}
        common.fence(proof,'bridge',config['target']['host'],config['old_bridge_address'],now=120,migration=identity)
        with self.assertRaisesRegex(ValueError,'migration_identity_fence_mismatch'):
            common.fence(dict(proof,migration_identity={}), 'bridge',config['target']['host'],config['old_bridge_address'],now=120,migration=identity)
        with self.assertRaisesRegex(ValueError,'distinct_migration_machines_required'):
            common.migration_identity(dict(identity,target_machine_id=identity['source_machine_id']))
        before=common.plan_id(checked,'c'*64)
        checked['migration_identity']=dict(identity,target_machine_id='d'*32)
        self.assertNotEqual(before,common.plan_id(checked,'c'*64))

    def test_peer_projection_is_pure_and_checks_authenticated_credentials(self):
        import restore_ansible as adapter
        identity=self.root/'stage/state/etc/ultra-recovery/key'
        identity.parent.mkdir(parents=True);identity.write_bytes(b'synthetic key')
        pins=identity.with_name('pins');pins.write_bytes(b'synthetic pins')
        manifest={'files':{'state/etc/ultra-recovery/key':{'sha256':common.sha(identity)},
                           'state/etc/ultra-recovery/pins':{'sha256':common.sha(pins)}}}
        nodes=[{'identity':'/etc/ultra-recovery/key','known_hosts':'/etc/ultra-recovery/pins',
                'address':'198.18.0.12','plan':{'action':'reseed'}}]
        with mock.patch.object(common,'stage_manifests',return_value=(manifest,{})), mock.patch.object(adapter.subprocess,'run') as execute:
            values=adapter.project_peer_inputs({'isolated_peer_addresses':['198.18.0.12']},self.root,nodes)
            self.assertEqual(values[0]['variables']['ultra_peer_plan']['action'],'reseed')
            execute.assert_not_called()
            with self.assertRaisesRegex(ValueError,'isolated_restore_production_peer_forbidden'):
                adapter.project_peer_inputs({'isolated_peer_addresses':[]},self.root,nodes)
            identity.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'restored_peer_credential_changed'):
                adapter.project_peer_inputs({},self.root,nodes)

    def test_activate_reloads_nginx_after_start_and_on_completed_resume(self):
        target=host.Host(self.root, {'restore_id':'a'*64, 'fence':{}, 'target_host':'fixture', 'old_bridge_address':'192.0.2.1'})
        with mock.patch.object(host, 'stage_manifests', return_value=({}, {})), mock.patch.object(host, 'restore_certbot_lineages'), mock.patch.object(host, 'restore_units'), mock.patch.object(target, 'override'), mock.patch.object(target, 'wait_runtime'), mock.patch.object(host, 'AUTOMATION_UNITS', ()), mock.patch.object(host, 'run') as run:
            target.activate()
            calls=[x.args[0] for x in run.call_args_list]
            self.assertIn(['nginx','-t'],calls)
            self.assertFalse(any(call[0]=='systemctl' for call in calls))
            services=(Path(__file__).parents[1]/'ansible/roles/restore/tasks/services.yml').read_text()
            self.assertLess(services.index('Start restored relay first'),services.index('Start restored bot and HTTPS'))
            self.assertLess(services.index('Start restored bot and HTTPS'),services.index('Reload restored HTTPS configuration'))
        target.status['completed']=list(common.PHASES[:common.PHASES.index('activate')+1])
        with mock.patch.object(host, 'fence'), mock.patch.object(target, 'verify_resume') as verify, mock.patch.object(target, 'activate') as activate, mock.patch.object(host, 'run') as run:
            target.phase('activate'); target.phase('activate')
            self.assertEqual(verify.call_count, 2)
            activate.assert_not_called()
            self.assertEqual([x.args[0] for x in run.call_args_list], [['nginx','-t']]*2)

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
        target=host.Host(self.root,{'restore_id':'a'*64,'old_bridge_address':'192.0.2.1','new_bridge_address':'192.0.2.2','fence':{},'target_host':'root@192.0.2.2'})
        target.status['system_identifier']='123';target.status['database_name']='fixture'
        module=mock.Mock();calls=[]
        module.ensure_provider_peer_rule.side_effect=lambda *args,**kwargs:calls.append('firewall')
        module.execute.side_effect=lambda *args,**kwargs:calls.append('ssh')
        with mock.patch.object(target,'nodes',return_value=(module,{'ssh_identity_file':'/etc/ultra-recovery/identity'},[{'id':'node','address':'192.0.2.3','known_hosts':'/etc/ultra-recovery/pins'}])),mock.patch.object(host,'sql',return_value='[8443]'):target.peer_reseed()
        self.assertEqual(calls,['firewall','firewall'])
        module.execute.assert_not_called()
        self.assertEqual(target.status['reseed_nodes'][0]['plan']['tunnel_port'],8443)
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
    def test_forward_preparation_preserves_owned_files_until_role_activation(self):
        nginx=self.root/'etc/nginx';nginx.mkdir(parents=True)
        original=peer.configurations('192.0.2.1','access.example.org')
        for name,data in original.items():
            path=nginx/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
        plan={'restore_id':'a'*64,'old_bridge_address':'192.0.2.1','new_bridge_address':'192.0.2.2','subscription_domain':'access.example.org'}
        peer.prepare_forward(plan,self.root)
        for name,data in original.items():self.assertEqual((nginx/name).read_bytes(),data)
        with self.assertRaisesRegex(ValueError,'activation_not_confirmed'):peer.commit_forward(plan,self.root)
        desired=peer.configurations('192.0.2.2','access.example.org')
        for name,data in desired.items():(nginx/name).write_bytes(data)
        self.assertTrue(peer.commit_forward(plan,self.root)['ingress_ready'])
        self.assertTrue(peer.commit_forward(plan,self.root)['ingress_ready'])
        role=(Path(__file__).parents[1]/'ansible/roles/restore_peer/tasks/forward.yml').read_text()
        self.assertIn('rescue:',role)
        self.assertIn('Reactivate previous HTTPS forward configuration',role)
        (nginx/'conf.d/acme-proxy.conf').write_text('foreign')
        with self.assertRaisesRegex(ValueError,'foreign_ingress'):peer.prepare_forward(plan,self.root)

    def test_forward_pid_must_be_old_primary_owned_ssh(self):
        listeners='LISTEN 0 128 127.0.0.1:15432 0.0.0.0:* users:(("sshd",pid=456,fd=5))'
        connections='ESTAB 0 0 198.51.100.1:22 192.0.2.1:40100 users:(("sshd",pid=456,fd=4))'
        self.assertEqual(peer.stale_forward_pids(listeners,connections,'192.0.2.1'),{456})
        with self.assertRaises(ValueError):peer.stale_forward_pids(listeners,connections,'192.0.2.2')
    def test_reseed_preserves_managed_pg16_data_and_is_idempotent(self):
        directory=self.root/'var/lib/ultra-postgres-replica';data=directory/'data';data.mkdir(parents=True)
        (directory/'managed-by-ultra').write_text('managed');(data/'standby.signal').touch();(data/'PG_VERSION').write_text('16');(data/'original').write_text('sentinel')
        for name in ('seed-owned-by-ultra','seed-complete'):
            (directory/name).write_text('ultra_'+'b'*32+'\n');(directory/name).chmod(0o600)
        plan={'restore_id':'a'*64,'system_identifier':'456','old_bridge_address':'192.0.2.1'}
        calls=[]
        def runner(args):
            calls.append(args)
            return 'Database system identifier: 123\n' if 'pg_controldata' in args[0] else ''
        self.assertTrue(peer.reseed(plan,self.root,runner)['previous_data_preserved'])
        self.assertFalse(data.exists());self.assertEqual((directory/('retired-'+'a'*16)/'data/original').read_text(),'sentinel')
        self.assertFalse((directory/'seed-complete').exists())
        self.assertTrue((directory/('retired-'+'a'*16)/'seed-complete').is_file())
        count=len(calls);self.assertTrue(peer.reseed(plan,self.root,runner)['resumed']);self.assertEqual(count,len(calls))
    def test_isolated_restore_rejects_production_peer_before_launch(self):
        import restore_ansible
        config={'isolated_peer_addresses':['198.18.0.21']}
        endpoint={'host':'root@203.0.113.21','identity':'/private/key','known_hosts':'/private/pins'}
        with mock.patch.object(restore_ansible.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'production_peer_forbidden'):
                restore_ansible.peer(config,self.root,endpoint,{'action':'reseed'})
            run.assert_not_called()

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
        backup={'snapshot_at':time.time(),'source':'bridge','backup_name':'synthetic.age','backup_sha256':'a'*64,'artifact_sha256':'b'*64,'delivered_target_ids':['independent']};controller={'state':'ready','independent':True,'updated_at':time.time(),'primary':'independent'}
        config={'bridge_provider':'source','state_dir':'/fixture'};state={'primary':'independent','updated_at':time.time(),'node_metadata':[{'id':'independent','provider':'other'}]}
        with mock.patch.object(target,'wait_runtime'),mock.patch.object(host.time,'sleep') as sleep,mock.patch.object(Path,'read_text',side_effect=[FileNotFoundError(),json.dumps(backup),json.dumps(controller),json.dumps(config),json.dumps(state)]),mock.patch.object(host,'sql',return_value='[{"state":"streaming","age":1}]'):
            with self.assertRaisesRegex(ValueError,'readiness_timeout'):
                target.ready()
            target.ready()
        sleep.assert_not_called();self.assertEqual(target.status['replicas_ready'],1)


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


class BackendDNSRestoreContracts(unittest.TestCase):
    def setUp(self):
        import dns
        self.dns = dns
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = {'config': {'zone': 'example.com', 'ttl': 300}, 'desired': {
            'subscription': {'name': 'sync', 'data': '192.0.2.1'},
            'vpn': {'name': 'edge', 'data': '192.0.2.1'},
            'backend': {'name': 'core', 'data': '192.0.2.1'}}}
        self.receipt = {'version': 1, 'zone': 'example.com', 'records': {
            role: dict(value, type='A', ttl=300, id=role) for role, value in self.policy['desired'].items()}}
        self.policy_path = self.root / 'dns.json'
        self.receipt_path = self.root / 'dns-receipt.json'
        self.policy_path.write_text(json.dumps(self.policy))
        self.receipt_path.write_text(json.dumps(self.receipt))
        self.plan = {'restore_id': 'r', 'ingress_mode': 'direct', 'target_host': 'replacement',
            'old_bridge_address': '192.0.2.1', 'new_bridge_address': '192.0.2.2',
            'public_host': 'edge.example.com', 'subscription_domain': 'sync.example.com',
            'fence': {'source': 'bridge', 'source_address': '192.0.2.1', 'target_host': 'replacement',
                'confirmed_offline': True, 'confirmed_at': int(time.time())}}
        self.target = host.Host(self.root, self.plan)
        self.patches = [
            mock.patch.object(dns, 'private', side_effect=lambda path: self.receipt_path if str(path).endswith('dns-receipt.json') else self.policy_path),
            mock.patch.object(host, 'unit_environment', return_value=('root', {'ULTRA_BOT_DOMAIN': 'core.example.com', 'ULTRA_BOT_PORT': '8444'})),
            mock.patch.object(host.socket, 'create_connection'),
            mock.patch.object(host.ssl, 'create_default_context'),
            mock.patch.object(host, 'run'), mock.patch.object(dns, 'execute'),
            mock.patch.object(dns, 'wait_ready'), mock.patch.object(dns, 'save')]
        self.private, self.environment, self.connection, self.context, self.command, self.execute, self.wait, self.save = [patcher.start() for patcher in self.patches]
        for patcher in self.patches: self.addCleanup(patcher.stop)

    def test_backend_owned_record_moves_with_public_pair_without_public_backend_listener(self):
        self.target.direct_ingress()
        desired = self.execute.call_args.args[1]
        self.assertEqual(set(desired), {'subscription', 'vpn', 'backend'})
        self.assertEqual({row['data'] for row in desired.values()}, {'192.0.2.2'})
        self.assertEqual(desired['backend']['name'], 'core')
        addresses = [call.args[0] for call in self.connection.call_args_list]
        self.assertNotIn(('core.example.com', 443), addresses)
        self.assertEqual(addresses.count(('127.0.0.1', 8444)), 2)
        self.save.assert_called_once()

    def test_backend_missing_from_legacy_policy_is_recovered_from_owned_receipt(self):
        del self.policy['desired']['backend']
        self.policy_path.write_text(json.dumps(self.policy))
        self.target.direct_ingress()
        self.assertEqual(self.execute.call_args.args[1]['backend'], {'name': 'core', 'data': '192.0.2.2'})

    def test_backend_cutover_resume_reuses_replacement_intent_after_dns_wait_failure(self):
        self.wait.side_effect = ValueError('dns_convergence_timeout')
        with self.assertRaises(ValueError): self.target.direct_ingress()
        self.save.assert_not_called()
        self.wait.side_effect = None
        self.target.direct_ingress()
        self.assertEqual(self.execute.call_count, 2)
        for call in self.execute.call_args_list:
            self.assertEqual(call.args[1]['backend'], {'name': 'core', 'data': '192.0.2.2'})
        self.save.assert_called_once()

    def test_backend_tls_failure_blocks_all_dns_publication(self):
        def connection(address, **kwargs):
            if address == ('127.0.0.1', 8444):
                raise OSError('synthetic backend TLS failure')
            return mock.MagicMock()
        self.connection.side_effect = connection
        with self.assertRaises(OSError): self.target.direct_ingress()
        self.execute.assert_not_called()
        self.save.assert_not_called()

    def test_backend_environment_and_owned_receipt_are_validated_independently(self):
        self.environment.return_value = ('root', {'ULTRA_BOT_DOMAIN': 'invalid/name', 'ULTRA_BOT_PORT': '8444'})
        with self.assertRaisesRegex(ValueError, 'backend'): self.target.direct_ingress()
        self.execute.assert_not_called()
        self.environment.return_value = ('root', {'ULTRA_BOT_DOMAIN': 'core.example.com', 'ULTRA_BOT_PORT': '8444'})
        self.receipt['records']['backend']['name'] = 'foreign'
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(ValueError, 'backend'): self.target.direct_ingress()
        self.execute.assert_not_called()

    def test_rolled_back_backend_record_moves_while_active_bot_uses_old_certificate(self):
        self.environment.return_value = ('root', {'ULTRA_BOT_DOMAIN': 'old.example.com', 'ULTRA_BOT_PORT': '8445'})
        self.target.direct_ingress()
        self.assertEqual(self.execute.call_args.args[1]['backend'], {'name': 'core', 'data': '192.0.2.2'})
        addresses = [call.args[0] for call in self.connection.call_args_list]
        self.assertEqual(addresses.count(('127.0.0.1', 8445)), 2)
        self.assertNotIn(('core.example.com', 443), addresses)
        names = [call.kwargs['server_hostname'] for call in self.context.return_value.wrap_socket.call_args_list]
        self.assertEqual(names.count('old.example.com'), 2)
        self.assertNotIn('core.example.com', names)
