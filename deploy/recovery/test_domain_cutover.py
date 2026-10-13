import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location('domain_cutover',Path(__file__).with_name('domain_cutover.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class CutoverTests(unittest.TestCase):
    def old(self):
        return {'reality':{'private_key':'unchanged-fixture'},'primary_xhttp':{'host':'192.0.2.1','server_name':'old.example.com','port':443,'path':'/connect','backend_port':18080,'fingerprint':'firefox'},'subscription_bridges':[{'id':'tls','security':'tls','host':'192.0.2.1','server_name':'old.example.com','port':443,'path':'/connect','fingerprint':'firefox'},{'id':'reserve','security':'reality','host':'192.0.2.1','public_key':'unchanged'}]}
    def target(self):return {'domain':'edge.example.com','public_host':'edge.example.com','path':'/connect','backend_port':18080}

    def test_candidate_changes_only_owned_publication(self):
        old=self.old();before=copy.deepcopy(old);new=m.candidate_spec(old,self.target())
        self.assertEqual(old,before)
        self.assertEqual(new['reality'],old['reality'])
        self.assertEqual(new['subscription_bridges'][1],old['subscription_bridges'][1])
        self.assertEqual(new['primary_xhttp']['fingerprint'],'firefox')
        self.assertEqual(new['subscription_bridges'][0]['server_name'],'edge.example.com')
        new['subscription_bridges'][0]['host']='foreign.example.com'
        with self.assertRaisesRegex(ValueError,'unknown_tls'):m.candidate_spec(new,self.target())

    def test_probe_is_only_new_edge_preserves_user_and_fingerprint(self):
        profile={'outbounds':[{'protocol':'vless','tag':'old','settings':{'vnext':[{'address':'192.0.2.1','port':443,'users':[{'id':'monitor-fixture'}]}]},'streamSettings':{'network':'xhttp','security':'tls','tlsSettings':{'serverName':'old.example.com','fingerprint':'firefox'},'xhttpSettings':{'path':'/connect'}}},{'protocol':'freedom'}]}
        result=m.single_alias_probe(profile,self.old()['primary_xhttp'],self.target(),'192.0.2.1')
        self.assertEqual(len(result['outbounds']),1)
        outbound=result['outbounds'][0]
        self.assertEqual(outbound['settings']['vnext'][0]['users'][0]['id'],'monitor-fixture')
        self.assertEqual(outbound['streamSettings']['tlsSettings'],{'serverName':'edge.example.com','fingerprint':'firefox'})
        self.assertEqual(profile['outbounds'][0]['streamSettings']['tlsSettings']['serverName'],'old.example.com')

    def test_alias_first_publication_failure_rolls_back_then_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            events=[];fail=[True]
            class Host:
                def __init__(self,*args):pass
                def prepare(self):events.append('prepare')
                def aliases(self):events.append('aliases')
                def validate(self,published):
                    events.append('validate-new' if published else 'validate-old')
                    if published and fail[0]:raise ValueError('fixture failure')
                def publish(self):
                    self_state=json.loads((Path(tmp)/'journal.json').read_text())
                    assert self_state['phase']=='publishing'
                    events.append('publish')
                def finalize(self):pass
                def rollback(self):events.append('rollback')
            plan={'bridge_ipv4':'192.0.2.1','subscription_domain':'sync.example.com','ingress':self.target(),'desired':{}}
            with self.assertRaisesRegex(ValueError,'rolled_back'):m.execute(plan,tmp,Host)
            self.assertEqual(events,['prepare','aliases','validate-old','publish','validate-new','rollback'])
            self.assertEqual(json.loads((Path(tmp)/'journal.json').read_text())['phase'],'rolled_back')
            failure=json.loads((Path(tmp)/'last-error.json').read_text())
            self.assertEqual(failure['stage'],'operation')
            self.assertNotIn('fixture failure',json.dumps(failure))
            fail[0]=False;events.clear();self.assertEqual(m.execute(plan,tmp,Host)['cutover'],'complete')
            self.assertEqual(events,['aliases','validate-old','publish','validate-new'])
            self.assertFalse((Path(tmp)/'last-error.json').exists())
            events.clear();m.execute(plan,tmp,Host);self.assertEqual(events,['validate-new'])

    def test_failure_receipt_contains_only_safe_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Host:
                stage='subscription_happ'
                def __init__(self,*args):pass
                def prepare(self):pass
                def aliases(self):pass
                def validate(self,published):raise ValueError('private fixture detail')
                def publish(self):pass
                def finalize(self):pass
                def rollback(self):pass
            plan={'bridge_ipv4':'192.0.2.1','subscription_domain':'sync.example.com','ingress':self.target(),'desired':{}}
            with self.assertRaises(ValueError):m.execute(plan,tmp,Host)
            failure=json.loads((Path(tmp)/'last-error.json').read_text())
            self.assertEqual(set(failure),{'version','stage','code','timestamp'})
            self.assertEqual(failure['stage'],'subscription_happ')
            self.assertNotIn('private fixture detail',json.dumps(failure))

    def test_final_capture_failure_keeps_publication_and_resumes_finalize(self):
        with tempfile.TemporaryDirectory() as tmp:
            events=[];fail=[True]
            class Host:
                def __init__(self,*args):pass
                def prepare(self):pass
                def aliases(self):pass
                def validate(self,published):events.append('validate')
                def publish(self):events.append('publish')
                def rollback(self):events.append('rollback')
                def finalize(self):
                    events.append('finalize')
                    if fail[0]:raise ValueError('capture-failed')
            plan={'bridge_ipv4':'192.0.2.1','subscription_domain':'sync.example.com','ingress':self.target(),'desired':{}}
            with self.assertRaises(ValueError):m.execute(plan,tmp,Host)
            self.assertNotIn('rollback',events)
            self.assertEqual(json.loads((Path(tmp)/'journal.json').read_text())['phase'],'finalizing')
            fail[0]=False;events.clear();m.execute(plan,tmp,Host)
            self.assertEqual(events,['validate','finalize'])
            self.assertEqual(json.loads((Path(tmp)/'journal.json').read_text())['phase'],'complete')

    def test_crash_after_publication_resumes_durable_publishing_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            events=[];crash=[True]
            class Host:
                def __init__(self,*args):pass
                def prepare(self):events.append('prepare')
                def aliases(self):events.append('aliases')
                def validate(self,published):events.append('validate')
                def publish(self):
                    events.append('publish')
                    if crash[0]:raise SystemExit(17)
                def finalize(self):pass
                def rollback(self):events.append('rollback')
            plan={'bridge_ipv4':'192.0.2.1','subscription_domain':'sync.example.com','ingress':self.target(),'desired':{}}
            with self.assertRaises(SystemExit):m.execute(plan,tmp,Host)
            self.assertEqual(json.loads((Path(tmp)/'journal.json').read_text())['phase'],'publishing')
            crash[0]=False;events.clear();m.execute(plan,tmp,Host)
            self.assertEqual(events,['publish','validate'])
            changed=copy.deepcopy(plan);changed['subscription_domain']='changed.example.com'
            with self.assertRaisesRegex(ValueError,'plan_changed'):m.execute(changed,tmp,Host)

    def test_public_origin_uses_later_environmentfile_not_environment(self):
        host=object.__new__(m.Host)
        host.plan={'subscription_domain':'sync.example.com'}
        host.public_dropin=Path('/etc/systemd/system/ultra-bot.service.d/zz-domain-public-origin.conf')
        host.public_env=Path('/etc/ultra-relay/domain-public.env')
        files=host.public_files()
        self.assertEqual(files[host.public_dropin],b'[Service]\nEnvironmentFile=/etc/ultra-relay/domain-public.env\n')
        self.assertEqual(files[host.public_env],b'ULTRA_BOT_PUBLIC_URL=https://sync.example.com\n')
        self.assertNotIn(b'Environment=',files[host.public_dropin])

    def test_subscription_shape_ignores_endpoint_but_detects_identity_change(self):
        import base64
        old=base64.b64encode(b'vless://fixture@old.example.com:443?security=tls').rstrip(b'=')
        new=base64.b64encode(b'vless://fixture@edge.example.com:443?security=tls').rstrip(b'=')
        self.assertEqual(m.subscription_shape(old),m.subscription_shape(new))
        changed=base64.b64encode(b'vless://different@edge.example.com:443?security=tls')
        self.assertNotEqual(m.subscription_shape(old),m.subscription_shape(changed))

    def test_subscription_shape_accepts_happ_profile_array(self):
        profile={'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'old.example.com','users':[{'id':'fixture-id'}]}]},'streamSettings':{'security':'tls','tlsSettings':{'serverName':'old.example.com'}}}]}
        raw=json.dumps([profile,copy.deepcopy(profile)]).encode()
        self.assertEqual(m.subscription_shape(raw)['routes'],2)
        self.assertEqual(m.subscription_tls_endpoints(raw),{('old.example.com','old.example.com')})

    def test_published_check_rejects_stale_endpoint_with_same_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            url=Path(tmp)/'url';url.write_text('https://old.example.com/sub/fixture')
            host=object.__new__(m.Host)
            host.plan={'subscription_url_file':str(url),'subscription_domain':'sync.example.com','bridge_ipv4':'192.0.2.1','ingress':self.target()}
            host.directory=Path(tmp)
            old=b'vless://fixture@old.example.com:443?security=tls&sni=old.example.com'
            with patch.object(host,'check_spec'),patch.object(m,'private',side_effect=Path),patch.object(m,'https',return_value=old):
                with self.assertRaisesRegex(ValueError,'publication_not_visible'):host.validate(True)
            new=b'vless://fixture@edge.example.com:443?security=tls&sni=edge.example.com'
            self.assertEqual(m.subscription_shape(old),m.subscription_shape(new))
            self.assertEqual(m.subscription_tls_endpoints(new),{('edge.example.com','edge.example.com')})

    def test_alias_retry_preserves_old_site_and_standard_future_apply_path(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def mapped(value):
                path=Path(value)
                return root/str(path).lstrip('/') if path.is_absolute() and not str(path).startswith(tmp) else path
            site=mapped('/etc/nginx/conf.d/ultra-vpn.conf');site.parent.mkdir(parents=True);site.write_bytes(b'old-vhost')
            manifest=root/'manifest.json';manifest.write_text(json.dumps({str(site):m.digest(b'old-vhost')}))
            directory=root/'work';directory.mkdir();(directory/'metadata.json').write_text(json.dumps({'bot_domain':'old.example.com','bot_port':8444}))
            def atomic(path,data,*args):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            def owned(path,data,record,*args):
                if path.exists() and record.get(str(path))!=m.digest(path.read_bytes()):raise ValueError('foreign')
                atomic(path,data);record[str(path)]=m.digest(data);atomic(manifest,json.dumps(record).encode())
            host=object.__new__(m.Host);host.directory=directory
            host.plan={'dns':{},'desired':{},'ingress':self.target(),'subscription_domain':'sync.example.com'}
            host.ingress=SimpleNamespace(MANIFEST=manifest,prepare_certificate=lambda *a:None,nginx=lambda *a:b'new-vhost',owned=owned)
            failure=[True]
            def install(*args):
                if failure[0]:raise ValueError('frontend-failed')
            host.subscription=SimpleNamespace(atomic=atomic,install=install)
            with patch.object(m,'Path',side_effect=mapped),patch.object(host,'check_spec'),patch.object(m,'dns_execute'),patch.object(m,'wait_ready'),patch.object(m,'save'),patch.object(m,'run'):
                with self.assertRaisesRegex(ValueError,'frontend-failed'):host.aliases()
                self.assertEqual(site.read_bytes(),b'old-vhost')
                legacy=mapped('/etc/nginx/conf.d/ultra-vpn-legacy.conf')
                self.assertFalse(legacy.exists())
                failure[0]=False;host.aliases();host.aliases()
                self.assertEqual(site.read_bytes(),b'new-vhost')
                self.assertEqual(legacy.read_bytes(),b'old-vhost')

    def test_finalize_retains_old_inventory_and_captures_new_direct_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def mapped(value):
                path=Path(value)
                return root/str(path).lstrip('/') if path.is_absolute() and not str(path).startswith(tmp) else path
            def put(name,value):
                target=mapped(name);target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(value));return target
            put('/etc/ultra-recovery/backup.json',{'state_paths':['/old/certificate'],'recipient':'unchanged','destinations':[{'id':'unchanged'}]})
            put('/etc/ultra-recovery/reconcile.json',{'bridge_url':'https://old.example.com/healthz','database':'unchanged'})
            put('/etc/ultra-recovery/deployment.json',{'bridge_url':'https://old.example.com/healthz','bridge_provider':'unchanged','ingress':{'forward_host':'old'}})
            manifest=put('/var/lib/ultra-ingress/managed.json',{})
            for domain in ('sync.example.com','edge.example.com'):
                renewal=mapped('/etc/letsencrypt/renewal/'+domain+'.conf');renewal.parent.mkdir(parents=True,exist_ok=True);renewal.write_text('authenticator = webroot')
                mapped('/etc/letsencrypt/live/'+domain).mkdir(parents=True)
            host=object.__new__(m.Host);host.plan={'subscription_domain':'sync.example.com','ingress':self.target()}
            from types import SimpleNamespace
            host.ingress=SimpleNamespace(MANIFEST=manifest)
            with patch.object(m,'Path',side_effect=mapped),patch.object(m,'private',side_effect=mapped),patch.object(m,'run') as run:
                host.finalize()
            backup=json.loads(mapped('/etc/ultra-recovery/backup.json').read_text())
            self.assertIn('/old/certificate',backup['state_paths'])
            self.assertIn(str(mapped('/etc/letsencrypt/live/edge.example.com')),backup['state_paths'])
            self.assertEqual(backup['recipient'],'unchanged')
            deployment=json.loads(mapped('/etc/ultra-recovery/deployment.json').read_text())
            self.assertEqual(deployment['ingress_mode'],'direct')
            self.assertEqual(deployment['bridge_url'],'https://sync.example.com/healthz')
            self.assertNotIn('forward_host',deployment['ingress'])
            self.assertEqual(run.call_args.args[0][2],'capture')

if __name__=='__main__':unittest.main()
