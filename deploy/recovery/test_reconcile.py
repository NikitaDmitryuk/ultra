import io
import contextlib
import json
import os
import pwd
import shutil
import socket
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import urllib.error
import reconcile


ID = '11111111-1111-4111-8111-111111111111'


class ReconcileTests(unittest.TestCase):
    def test_timer_late_activation_has_independent_start_anchor(self):
        import configparser
        timer=configparser.ConfigParser()
        timer.read(Path(__file__).parent/'ultra-recovery-reconcile.timer')
        self.assertEqual(timer['Timer']['OnActiveSec'],'30s')
        self.assertEqual(timer['Timer']['OnUnitInactiveSec'],'60s')
        self.assertIn('OnBootSec',timer['Timer'])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.pin = self.root / 'known_hosts'
        self.pin.write_text('fixture pinned key')
        self.identity = self.root / 'identity'
        self.identity.write_text('fixture identity'); self.identity.chmod(0o600)
        self.chat = self.root / 'chat'
        self.chat.write_text('123'); self.chat.chmod(0o600)
        self.config = {'database':'ultra_test','bridge_provider':'vdsina','vultr_state_dir':str(self.root / 'vultr'),
                       'ssh_identity_file':str(self.identity),'backup_config':str(self.root / 'backup.json'),
                       'state_dir':str(self.root / 'state'),'status_file':str(self.root / 'status.json'),
                       'chat_id_file':str(self.chat),'bundle_dir':str(Path(__file__).parent),'client_binary':str(self.root / 'client'),
                       'bot_token_file':str(self.root / 'token'),'probe_profile_file':str(self.root / 'probe'),
                       'bridge_url':'https://bridge.example/happ','payload_url':'https://payload.example/',
                       'static_nodes':[{'id':'NL','name':'NL','provider':'vdsina','address':'192.0.2.2','known_hosts':str(self.pin)}]}
        self.nodes, _ = reconcile.desired_nodes(self.config, [])
        self.primary = {'id':ID,'name':'US','managed':True,'provider':'vultr','address':'192.0.2.3','host':'root@192.0.2.3',
                        'known_hosts':str(self.pin),'instance_id':'instance-owned','firewall_id':'firewall-owned'}
        self.backup = {'repository':str(self.root),'source':'bridge','independent':False,
                       'destinations':[{'host':'root@192.0.2.2','name':'NL','required':True}]}
        reconcile.atomic_json(self.config['backup_config'], self.backup)

    def tearDown(self):
        self.tmp.cleanup()

    def test_trusted_cloud_owner_scope_and_permissions(self):
        valid=mock.Mock(st_mode=0o100600,st_uid=123)
        with mock.patch.object(reconcile.os,'geteuid',return_value=0), mock.patch.object(reconcile.pwd,'getpwnam',return_value=mock.Mock(pw_uid=123)):
            reconcile.validate_cloud_owner(valid,'ultra-relay')
            reconcile.validate_cloud_owner(mock.Mock(st_mode=0o100600,st_uid=0),'root')
            with self.assertRaises(ValueError):reconcile.validate_cloud_owner(mock.Mock(st_mode=0o100600,st_uid=456),'ultra-relay')
            with self.assertRaises(ValueError):reconcile.validate_cloud_owner(mock.Mock(st_mode=0o100640,st_uid=123),'ultra-relay')
            with self.assertRaises(ValueError):reconcile.validate_cloud_owner(mock.Mock(st_mode=0o120600,st_uid=123),'ultra-relay')
            with self.assertRaises(ValueError):reconcile.validate_cloud_owner(valid,'arbitrary-owner')
        link=self.root/'api-link';link.symlink_to(self.identity)
        with self.assertRaises(OSError):reconcile.read_api_key({'vultr_api_key_file':str(link)})

    def test_query_readonly_does_not_include_credentials(self):
        self.assertIn('BEGIN READ ONLY', reconcile.QUERY)
        self.assertNotIn('tunnel_uuid', reconcile.QUERY)
        self.assertNotIn('users', reconcile.QUERY)
        with mock.patch.object(reconcile.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'private')):
            with self.assertRaisesRegex(ValueError,'discovery unavailable'):
                reconcile.discover(self.config)

    def test_discovery_failure_preserves_lastgood_and_sets_error(self):
        old = Path(self.config['backup_config']).read_bytes()
        with mock.patch.object(reconcile,'discover',side_effect=ValueError('offline')), mock.patch.object(reconcile,'install')as install:
            with self.assertRaises(ValueError):reconcile.reconcile(self.config)
            install.assert_not_called()
        self.assertEqual(Path(self.config['backup_config']).read_bytes(),old)
        self.assertEqual(json.loads(Path(self.config['status_file']).read_text())['state'],'error')

    def test_preserve_only_previous_required_not_optional(self):
        backup = {**self.backup,'independent':True,'destinations':[
            {'id':'NL','host':'root@192.0.2.2','required':False}, {'id':ID,'host':'root@192.0.2.3','required':True}]}
        candidate = reconcile.candidate_backup(self.config,backup,[*self.nodes,self.primary],set())
        flags = {node['id']:node['required']for node in candidate['destinations']}
        self.assertFalse(flags['NL']);self.assertTrue(flags[ID]);self.assertTrue(candidate['independent'])
        initial = reconcile.candidate_backup(self.config,self.backup,[*self.nodes,self.primary],set())
        self.assertFalse(next(node for node in initial['destinations']if node['id']==ID)['required'])
        self.assertFalse(initial['independent'])

    def test_unobserved_not_deleted_and_retired_is_removed(self):
        extra={'id':ID,'host':'root@192.0.2.3','required':True}
        backup={**self.backup,'destinations':[extra]}
        unobserved=reconcile.candidate_backup(self.config,backup,self.nodes,set())
        self.assertIn(extra,unobserved['destinations'])
        retired=reconcile.candidate_backup(self.config,backup,self.nodes,{ID})
        self.assertEqual(len(retired['destinations']),1)
        self.assertTrue(retired['destinations'][0]['required'])
        self.assertFalse(retired['independent'])

    def test_delivery_requires_both_hashes_and_freshness(self):
        receipt={'source':'bridge','destinations':[self.primary['host']],'snapshot_at':time.time(),
                 'backup_name':'backup-'+str(int(time.time()))+'-'+'a'*32+'.age','backup_sha256':'1'*64,
                 'artifact_name':'artifact-'+'a'*64+'.age','artifact_sha256':'2'*64}
        output=('1'*64+' file1\n'+'2'*64+' file2\n').encode()
        with mock.patch.object(reconcile,'execute',return_value=subprocess.CompletedProcess([],0,output)):
            reconcile.validate_delivery(self.config,self.primary,receipt)
            with self.assertRaises(ValueError):reconcile.validate_delivery(self.config,self.primary,{**receipt,'snapshot_at':time.time()-301})
        with mock.patch.object(reconcile,'execute',return_value=subprocess.CompletedProcess([],0,b'bad file1\n')):
            with self.assertRaises(ValueError):reconcile.validate_delivery(self.config,self.primary,receipt)

    def firewall_api(self,config,method,path,data=None):
        if path.startswith('/v2/instances/'):
            return {'instance':{'id':'instance-owned','main_ip':'192.0.2.3','firewall_group_id':'firewall-owned'}}
        if path.endswith('/rules'):return {'firewall_rules':[]}
        return {'firewall_group':{'id':'firewall-owned','description':'ultra-operation-'+ID}}

    def test_peer_rule_is_narrow_and_idempotent(self):
        with mock.patch.object(reconcile,'api',side_effect=self.firewall_api)as api,mock.patch.object(reconcile,'execute'):
            reconcile.allow_peer(self.config,self.primary,self.nodes[0])
            posted=[call for call in api.call_args_list if call.args[1]=='POST']
            self.assertEqual(len(posted),1)
            self.assertEqual(posted[0].args[3],{'ip_type':'v4','protocol':'tcp','subnet':'192.0.2.2','subnet_size':32,'port':'22'})
        def existing(config,method,path,data=None):
            result=self.firewall_api(config,method,path,data)
            if path.endswith('/rules'):result={'firewall_rules':[{'ip_type':'v4','protocol':'tcp','subnet':'192.0.2.2','subnet_size':32,'port':'22'}]}
            return result
        with mock.patch.object(reconcile,'api',side_effect=existing)as api,mock.patch.object(reconcile,'execute'):
            reconcile.allow_peer(self.config,self.primary,self.nodes[0])
            self.assertFalse(any(call.args[1]=='POST'for call in api.call_args_list))

    def test_foreign_instance_or_firewall_never_mutated(self):
        for bad_kind in ['instance','firewall']:
            def foreign(config,method,path,data=None):
                value=self.firewall_api(config,method,path,data)
                if bad_kind=='instance'and 'instance'in value:value['instance']['main_ip']='192.0.2.9'
                if bad_kind=='firewall'and 'firewall_group'in value:value['firewall_group']['description']='foreign'
                return value
            with mock.patch.object(reconcile,'api',side_effect=foreign)as api,mock.patch.object(reconcile,'execute')as remote:
                with self.assertRaises(ValueError):reconcile.allow_peer(self.config,self.primary,self.nodes[0])
                remote.assert_not_called()
                self.assertFalse(any(call.args[1]=='POST'for call in api.call_args_list))

    def test_redirect_rejected(self):
        request=reconcile.urllib.request.Request('https://api.vultr.com/v2/instances/owned',headers={'Authorization':'Bearer fixture'})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            reconcile.NoRedirect().redirect_request(request,io.BytesIO(),302,'redirect',{},'https://foreign.example/')
        caught.exception.close()

    def test_api_retry_bounded_and_post_not_repeated(self):
        key=self.root/'api';key.write_text('fixture-only');key.chmod(0o600)
        config={'vultr_api_key_file':str(key)}
        error=urllib.error.HTTPError('https://api.vultr.com',429,'rate limited',{'Retry-After':'999'},None)
        opener=mock.Mock();opener.open.side_effect=error
        with mock.patch.object(reconcile.urllib.request,'build_opener',return_value=opener),mock.patch.object(reconcile.time,'sleep')as sleep:
            with self.assertRaises(ValueError):reconcile.api(config,'GET','/v2/instances/owned')
            self.assertEqual(opener.open.call_count,3);self.assertEqual([call.args[0]for call in sleep.call_args_list],[4,4])
            opener.open.reset_mock()
            with self.assertRaises(ValueError):reconcile.api(config,'POST','/v2/firewalls/owned/rules',{})
            self.assertEqual(opener.open.call_count,1)

    def test_monitor_requires_two_confirmed_observations(self):
        checks={'bridge_https':True,'vpn_payload':True,'probe_execution':True,'independent_backup':True}
        second=json.dumps({'updated_at':time.time(),'checks':checks,'current_checks':checks}).encode()
        returns=[subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,second)]*2
        with mock.patch.object(reconcile,'execute',side_effect=returns)as remote:
            reconcile.monitor_ready(self.config,self.primary,'primary',True)
            self.assertEqual(remote.call_count,4)

    def test_bad_first_observation_cannot_be_hidden_by_healthy_second(self):
        checks={'bridge_https':True,'vpn_payload':True,'probe_execution':True,'independent_backup':True}
        for bad in ({}, {**checks,'vpn_payload':False}):
            with self.subTest(current=bad):
                first=json.dumps({'updated_at':time.time(),'checks':checks,'current_checks':bad}).encode()
                second=json.dumps({'updated_at':time.time(),'checks':checks,'current_checks':checks}).encode()
                returns=[subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,first),subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,second)]
                with mock.patch.object(reconcile,'execute',side_effect=returns):
                    with self.assertRaises(ValueError):reconcile.monitor_ready(self.config,self.primary,'primary',True)

    def test_fresh_monitor_can_establish_debounce_with_two_healthy_samples(self):
        checks={'bridge_https':True,'vpn_payload':True,'probe_execution':True,'independent_backup':True}
        first=json.dumps({'updated_at':time.time(),'checks':{},'current_checks':checks}).encode()
        second=json.dumps({'updated_at':time.time(),'checks':checks,'current_checks':checks}).encode()
        returns=[subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,first),subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,second)]
        with mock.patch.object(reconcile,'execute',side_effect=returns) as remote:
            reconcile.monitor_ready(self.config,self.primary,'primary',True)
            self.assertEqual(remote.call_count,4)

    def test_stale_debounced_health_cannot_promote(self):
        checks={'bridge_https':True,'vpn_payload':True,'probe_execution':True,'independent_backup':True}
        current={**checks,'vpn_payload':False}
        body=json.dumps({'updated_at':time.time(),'checks':checks,'current_checks':current}).encode()
        with mock.patch.object(reconcile,'execute',side_effect=[subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,body)]*2):
            with self.assertRaises(ValueError):reconcile.monitor_ready(self.config,self.primary,'primary',True)

    def test_production_size_client_fits_bounded_payload(self):
        client=Path(self.config['client_binary'])
        with client.open('wb')as stream:stream.truncate(52_167_976)
        Path(self.config['bot_token_file']).write_text('fixture');Path(self.config['bot_token_file']).chmod(0o600)
        Path(self.config['probe_profile_file']).write_text('{}');Path(self.config['probe_profile_file']).chmod(0o600)
        calls=[]
        def remote(config,node,command,**kwargs):
            calls.append(kwargs.get('input',b''))
            if len(calls)==1:return subprocess.CompletedProcess([],0,json.dumps(['/usr/local/bin/ultra-client']).encode())
            return subprocess.CompletedProcess([],0,b'{}')
        with mock.patch.object(reconcile,'execute',side_effect=remote):
            reconcile.install(self.config,self.primary,{'mode':'primary'})
        self.assertGreater(len(calls[1]),64<<20)
        self.assertLess(len(calls[1]),128<<20)
        self.assertEqual(list(json.loads(calls[1])['files']),['/usr/local/bin/ultra-client'])

    def run_transition(self, nl_down=False, bad_us=False, final_capture_fail=False, fresh_peer=False):
        events=[]
        nodes=[*self.nodes,self.primary]
        def install(config,node,monitor=None,extra=None):
            events.append(('install',node['id'],None if monitor is None else monitor['mode']))
            if nl_down and node['id']=='NL':raise ValueError('offline')
        def capture(config):
            events.append(('capture',config['independent']))
            if final_capture_fail and config['independent']:raise ValueError('final interrupted')
            if nl_down and any(item.get('required') and item['host']=='root@192.0.2.2' for item in config['destinations']):raise ValueError('required NL unavailable')
            receipt={'source':'bridge','destinations':[item['host']for item in config['destinations']if not nl_down or item.get('id')!='NL'],
                     'snapshot_at':time.time(),'backup_name':'backup-'+str(int(time.time()))+'-'+'a'*32+'.age','backup_sha256':'1'*64,
                     'artifact_name':'artifact-'+'a'*64+'.age','artifact_sha256':'2'*64}
            reconcile.atomic_json(self.root/'last-success.json',receipt)
        def remote(config,node,command,**kwargs):
            if command[0]=='sha256sum':
                out=('1'*64+' backup\n'+('bad'if bad_us and node['id']==ID else'2'*64)+' artifact\n').encode()
            elif command[0]=='cat':out=b'{"mode":"primary"}'
            elif kwargs.get('input')==reconcile.READ_MONITOR.encode():out=b'null' if fresh_peer else b'{"mode":"primary"}'
            else:out=json.dumps({'updated_at':time.time()}).encode()
            return subprocess.CompletedProcess([],0,out)
        stack=contextlib.ExitStack()
        stack.enter_context(mock.patch.object(reconcile,'discover',return_value=[]))
        stack.enter_context(mock.patch.object(reconcile,'desired_nodes',return_value=(nodes,set())))
        stack.enter_context(mock.patch.object(reconcile,'install',side_effect=install))
        stack.enter_context(mock.patch.object(reconcile,'create',side_effect=capture))
        stack.enter_context(mock.patch.object(reconcile,'execute',side_effect=remote))
        stack.enter_context(mock.patch.object(reconcile,'monitor_ready'))
        stack.enter_context(mock.patch.object(reconcile,'ensure_heartbeat_key',return_value=(b'fixture',b'ssh-ed25519 fixture\n')))
        stack.enter_context(mock.patch.object(reconcile,'allow_peer',side_effect=None if fresh_peer else ValueError('API unavailable')))
        return stack,events

    def test_fresh_receiver_without_monitor_becomes_ready_peer(self):
        stack,events=self.run_transition(fresh_peer=True)
        with stack:state=reconcile.reconcile(self.config)
        self.assertEqual(state['peer_pending'],[])
        self.assertIn(('install','NL','peer'),events)

    def test_optional_previous_monitor_read_only_tolerates_absence(self):
        path=self.root/'previous-monitor.json'
        script=reconcile.READ_MONITOR.replace('/etc/ultra-recovery/monitor.json',str(path))
        def remote(*args,**kwargs):
            return subprocess.run(['python3','-'],input=script.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        with mock.patch.object(reconcile,'execute',side_effect=remote):
            self.assertIsNone(reconcile.previous_monitor(self.config,self.primary))
            path.write_text('{"mode":"primary"}')
            self.assertEqual(reconcile.previous_monitor(self.config,self.primary),{'mode':'primary'})
            path.write_text('broken json')
            with self.assertRaises(ValueError):reconcile.previous_monitor(self.config,self.primary)
            path.write_bytes(b'x'*65537)
            with self.assertRaises(subprocess.CalledProcessError):reconcile.previous_monitor(self.config,self.primary)
            path.unlink();path.mkdir()
            with self.assertRaises(subprocess.CalledProcessError):reconcile.previous_monitor(self.config,self.primary)

    def test_new_independent_receiver_recovers_while_old_nl_down(self):
        stack,events=self.run_transition(nl_down=True)
        with stack:state=reconcile.reconcile(self.config)
        saved=json.loads(Path(self.config['backup_config']).read_text())
        self.assertTrue(saved['independent'])
        self.assertEqual(state['primary'],ID)
        self.assertEqual([item['host'] for item in saved['destinations'] if item.get('required')],['root@192.0.2.3'])
        self.assertIn('NL',state['peer_pending'])
        self.assertEqual([event[1]for event in events if event[0]=='capture'],[False,True])
        self.assertFalse(any(event==('install','NL','peer')for event in events))

    def test_bad_independent_cipher_never_promotes_or_demotes_old_monitor(self):
        stack,events=self.run_transition(bad_us=True)
        old=Path(self.config['backup_config']).read_bytes()
        with stack:state=reconcile.reconcile(self.config)
        self.assertFalse(json.loads(Path(self.config['backup_config']).read_text())['independent'])
        self.assertEqual(state['primary'],'NL')
        self.assertIn(ID,state['peer_pending'])
        self.assertFalse(any(event[0]=='install'and event[2]=='peer'for event in events))
        self.assertFalse(any(event==('capture',True)for event in events))

    def test_final_capture_failure_keeps_lastgood_config(self):
        stack,events=self.run_transition(final_capture_fail=True)
        old=Path(self.config['backup_config']).read_bytes()
        with stack:
            with self.assertRaises(ValueError):reconcile.reconcile(self.config)
        self.assertEqual(Path(self.config['backup_config']).read_bytes(),old)
        self.assertFalse(any(event==('install','NL','peer')for event in events))

    def generate_key(self,name):
        path=self.root/name
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','fixture-only','-f',str(path)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return path

    def test_stale_source_public_is_ignored_and_pair_is_versioned(self):
        old=self.generate_key('old')
        new=self.generate_key('new')
        state=Path(self.config['state_dir']);state.mkdir(mode=0o700)
        master=state/'heartbeat_ed25519'
        master.write_bytes(new.read_bytes());master.chmod(0o600)
        Path(str(master)+'.pub').write_bytes(Path(str(old)+'.pub').read_bytes())
        with mock.patch.object(reconcile,'execute')as remote:
            material,public=reconcile.ensure_heartbeat_key(self.config,self.primary)
        derived=(' '.join(subprocess.run(['ssh-keygen','-y','-f',str(new)],check=True,capture_output=True).stdout.decode().split()[:2])+'\n').encode()
        self.assertEqual(public,derived)
        entry=json.loads(remote.call_args.kwargs['input'])
        self.assertIn(derived.decode().strip(),entry)
        path,files=reconcile.peer_key_pair(material,public)
        self.assertNotEqual(path,'/etc/ultra-recovery/peer_ed25519')
        self.assertEqual([item[0]for item in files],[path,path+'.pub'])
        self.assertEqual([item[2]for item in files],[0o600,0o644])
        self.assertEqual(reconcile.peer_key_pair(material,public),(path,files))

    def test_real_openssh_stale_sibling_then_versioned_reauthentication(self):
        daemon='/usr/sbin/sshd'
        if not Path(daemon).is_file():self.skipTest('OpenSSH sshd unavailable')
        old=self.generate_key('old-auth')
        new=self.generate_key('new-auth')
        host=self.generate_key('host')
        supplied=self.root/'peer_ed25519'
        supplied.write_bytes(new.read_bytes());supplied.chmod(0o600)
        Path(str(supplied)+'.pub').write_bytes(Path(str(old)+'.pub').read_bytes())
        derived=(' '.join(subprocess.run(['ssh-keygen','-y','-f',str(new)],check=True,capture_output=True).stdout.decode().split()[:2])+'\n').encode()
        allowed=self.root/'authorized_keys';allowed.write_bytes(derived);allowed.chmod(0o600)
        with socket.socket()as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        username=pwd.getpwuid(os.getuid()).pw_name
        config=self.root/'sshd_config'
        config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nPidFile {self.root/'sshd.pid'}\nAuthorizedKeysFile {allowed}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin prohibit-password\nAllowUsers {username}\nForceCommand /bin/echo verified\nLogLevel ERROR\n")
        known=self.root/'server-pin'
        known.write_bytes(f'[127.0.0.1]:{port} '.encode()+Path(str(host)+'.pub').read_bytes())
        process=subprocess.Popen([daemon,'-D','-e','-f',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if process.poll()is not None:self.fail('local sshd fixture failed to start')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.01)
            def authenticate(path):
                return subprocess.run(['ssh','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=2','-o','UserKnownHostsFile='+str(known),'-p',str(port),'-i',str(path),username+'@127.0.0.1','heartbeat'],capture_output=True,timeout=5)
            stale=authenticate(supplied)
            self.assertNotEqual(stale.returncode,0)
            version,files=reconcile.peer_key_pair(new.read_bytes(),derived)
            staged=self.root/Path(version).name
            # Crash before publishing the new config: the old path/public remains untouched.
            staged.write_bytes(files[0][1]);staged.chmod(files[0][2])
            self.assertEqual(Path(str(supplied)+'.pub').read_bytes(),Path(str(old)+'.pub').read_bytes())
            # Idempotent retry completes only the inactive versioned pair.
            for _ in range(2):
                staged.write_bytes(files[0][1]);staged.chmod(files[0][2])
                Path(str(staged)+'.pub').write_bytes(files[1][1]);Path(str(staged)+'.pub').chmod(files[1][2])
                restored=authenticate(staged)
                self.assertEqual(restored.returncode,0,'versioned scoped pair did not authenticate')
                self.assertEqual(restored.stdout,b'verified\n')
        finally:
            process.terminate()
            process.communicate(timeout=5)

    def test_repository_marker_contract(self):
        self.assertIn('.ultra-recovery-repository',reconcile.INSTALL)
        self.assertIn('unmarked nonempty repository',reconcile.INSTALL)
        self.assertNotIn('marker.json',reconcile.INSTALL)


if __name__=='__main__':unittest.main()
