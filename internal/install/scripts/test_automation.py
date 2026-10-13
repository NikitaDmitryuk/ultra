import importlib.util
import io
import json
from pathlib import Path
import sys
import subprocess
import hashlib
import os
import stat
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('automation', Path(__file__).with_name('automation.py'))
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

class AutomationTests(unittest.TestCase):
    def test_activation_rejects_preexisting_ready_receipts(self):
        values={'recovery-reconcile-status.json':{'state':'ready','independent':True,'updated_at':100},
                'last-success.json':{'snapshot_at':100},'reconcile.json':{'database':'fixture'}}
        def read(path):
            if path.name not in values:raise FileNotFoundError()
            return json.dumps(values[path.name])
        with patch.object(Path,'read_text',read),patch.object(a.time,'time',return_value=110),patch.object(a,'replicas_ready',return_value=True),patch.object(a,'run',return_value=b'active'):
            self.assertTrue(a.status()['ready'])
            self.assertFalse(a.status(not_before=100)['ready'])
            values['recovery-reconcile-status.json']['updated_at']=101
            self.assertFalse(a.status(not_before=100)['ready'])
            values['last-success.json']['snapshot_at']=101
            self.assertTrue(a.status(not_before=100)['ready'])

    def test_stop_existing_unit_skips_only_missing_and_preserves_errors(self):
        unit = 'ultra-recovery-backup.service'
        show = ['systemctl', 'show', '--property=LoadState', '--value', unit]
        with patch.object(a, 'run', return_value=b'not-found\n') as run:
            a.stop_existing_unit(unit)
            run.assert_called_once_with(show)
        with patch.object(a, 'run', side_effect=[b'loaded\n', b'']) as run:
            a.stop_existing_unit(unit)
            self.assertEqual(run.call_args_list[-1].args[0], ['systemctl', 'stop', unit])
        for results in ([ValueError('query failed')], [b'loaded\n', ValueError('stop failed')]):
            with self.subTest(results=results), patch.object(a, 'run', side_effect=results):
                with self.assertRaises(ValueError):
                    a.stop_existing_unit(unit)

    def test_backup_repository_repeated_bootstrap_validates_existing_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = Path(__file__).resolve().parents[3] / 'deploy/recovery'
            repo = root / 'repository'
            with patch.object(a, 'ROOT', bundle):
                a.ensure_backup_repository(repo)
                (repo / 'preserved.age').write_bytes(b'fixture')
                a.ensure_backup_repository(repo)
                self.assertEqual((repo / 'preserved.age').read_bytes(), b'fixture')
                marker = repo / '.ultra-recovery-repository'
                for content in ('{"version":1,"source":"foreign"}', 'invalid json'):
                    marker.write_text(content)
                    with self.assertRaises(ValueError):
                        a.ensure_backup_repository(repo)
                marker.write_text('{"version":1,"source":"bridge"}')
                for target in (repo, marker):
                    previous = target.stat().st_mode & 0o777
                    target.chmod(0o755)
                    with self.assertRaises(ValueError):
                        a.ensure_backup_repository(repo)
                    target.chmod(previous)

    def test_bundle_integrity_and_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with tarfile.open(root/'ultra-recovery.tar.gz','w:gz') as tar:
                for name in a.REQUIRED:
                    data=b'fixture'; member=tarfile.TarInfo(name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
            for name in ['ultra-client-linux-amd64','ultra-relay-linux-amd64','ultra-relay-linux-arm64','ultra-bot-linux-amd64']:
                (root/name).write_bytes(b'binary')
            manifest={'version':'v2','capabilities':['service-access-v1'],'assets':[{'name':p.name,'size':p.stat().st_size,'sha256':a.sha(p)} for p in root.iterdir()]}
            (root/'release-manifest.json').write_text(json.dumps(manifest))
            self.assertEqual(set(a.verify_release(root,'v2','amd64')),a.REQUIRED)
            (root/'ultra-client-linux-amd64').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):a.verify_release(root,'v2','amd64')
            self.assertFalse(a.compatible_fallback({'capabilities':[]},manifest))

    def test_compatibility_rejects_old_service_and_schema(self):
        good={'capabilities':['service-access-v1'],'database_schema_min':24,'database_schema_max':24}
        self.assertTrue(a.compatible_fallback(good,good))
        self.assertFalse(a.compatible_fallback(dict(good,capabilities=[]),good))
        self.assertFalse(a.compatible_fallback(good,dict(good,database_schema_min=25)))

    def test_serial_exit_upgrade_stops_and_rolls_back_on_payload_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'release-manifest.json').write_text(json.dumps({'capabilities':['service-access-v1','provider-pool-quota-v1'],'database_schema_min':24,'database_schema_max':24,'assets':[{'name':'ultra-relay-linux-amd64','sha256':'old'}]}))
            (root/'reconcile.json').write_text('{}');(root/'ultra-relay-linux-amd64').write_bytes(b'new')
            nodes=[{'id':'a','address':'192.0.2.1'},{'id':'b','address':'192.0.2.2'}]
            controller=types.SimpleNamespace(discover=lambda c:[],desired_nodes=lambda c,r:(nodes,set()))
            events=[]
            def remote(config,node,script,data=None):
                events.append((node['id'],script))
                if script=='dpkg --print-architecture':return b'amd64'
                if script.startswith('sha256sum'):return b'old binary'
                return b''
            def health(config,node,since):
                events.append((node['id'],'health'))
                if node['id']=='b':raise ValueError('payload failed')
            readiness=[{'ready':False},{'ready':True}]
            with patch.object(a,'STATE',root),patch.object(a,'ROOT',root),patch.object(a,'CONFIG',root),patch.object(a,'run',return_value=b''),patch.object(a,'status',side_effect=readiness),patch.object(a,'remote',side_effect=remote),patch.object(a,'wait_exit',side_effect=health),patch.object(a.time,'sleep',return_value=None),patch.dict(sys.modules,{'reconcile':controller}):
                with self.assertRaises(ValueError):a.upgrade_fleet({'spec':'unused','version':'v2'},root,'amd64',json.loads((root/'release-manifest.json').read_text()))
            self.assertLess(events.index(('a','health')),events.index(('b','dpkg --print-architecture')))
            rollback=[node for node,script in events if script.startswith('set -eu; if test')]
            self.assertEqual(rollback,['b','a'])

    def test_upgrade_preflight_rejects_controller_that_never_converges(self):
        with patch.object(a,'status',return_value={'ready':False}),patch.object(a,'run',return_value=b''),patch.object(a.time,'monotonic',side_effect=[10,10,10,11]),patch.object(a.time,'sleep',return_value=None):
            with self.assertRaisesRegex(ValueError,'fresh independent backup'):
                a.wait_upgrade_preflight_ready(timeout=1)

    def test_upgrade_resumes_after_process_death_without_overwriting_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'bin').mkdir();release=root/'release';release.mkdir()
            old=hashlib.sha256(b'old').hexdigest();new=hashlib.sha256(b'new').hexdigest()
            base={'version':'v1','capabilities':['service-access-v1'],'database_schema_min':24,'database_schema_max':24}
            previous=dict(base,assets=[{'name':n+'-linux-amd64','sha256':old} for n in ('ultra-relay','ultra-bot')])
            target=dict(base,version='v2',assets=[{'name':n+'-linux-amd64','sha256':new} for n in ('ultra-relay','ultra-bot')])
            (root/'release-manifest.json').write_text(json.dumps(previous));(root/'target.json').write_text(json.dumps(target));(root/'reconcile.json').write_text('{}')
            (root/'machines.json').write_text(json.dumps({'a':{'active':old},'b':{'active':old}}))
            for name in ('ultra-relay','ultra-bot'):
                (root/'bin'/name).write_bytes(b'old');(release/(name+'-linux-amd64')).write_bytes(b'new')
            child = r'''
import importlib.util,json,sys,types
from pathlib import Path
spec=importlib.util.spec_from_file_location('automation',sys.argv[1]);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
root=Path(sys.argv[2]);a.STATE=a.ROOT=a.CONFIG=root;a.BIN=root/'bin'
nodes=[{'id':'a','address':'192.0.2.1'},{'id':'b','address':'192.0.2.2'}]
sys.modules['reconcile']=types.SimpleNamespace(discover=lambda c:[],desired_nodes=lambda c,r:(nodes,set()))
a.run=lambda *args,**kwargs:b'';a.status=lambda:{'ready':True};a.restart_bridge=lambda spec:None
old=a.asset_hash(json.loads((root/'release-manifest.json').read_text()),'ultra-relay-linux-amd64')
new=a.asset_hash(json.loads((root/'target.json').read_text()),'ultra-relay-linux-amd64')
def remote(config,node,script,data=None):
 machines=json.loads((root/'machines.json').read_text());m=machines[node['id']]
 if script=='dpkg --print-architecture':return b'amd64'
 if script.startswith('sha256sum'):return (m['active']+' binary').encode()
 if script.startswith('set -eu; old='):
  if m['active']==old:m['fallback']=old
  else:assert m['fallback']==old
  m['active']=new;(root/'machines.json').write_text(json.dumps(machines))
 return b''
def health(config,node,since):
 if sys.argv[3]=='first' and node['id']=='a':raise SystemExit(17)
a.remote=remote;a.wait_exit=health
a.upgrade_fleet({'spec':'fixture','version':'v2'},root/'release','amd64',json.loads((root/'target.json').read_text()))
'''
            source=str(Path(__file__).with_name('automation.py'))
            first=subprocess.run([sys.executable,'-c',child,source,tmp,'first'],capture_output=True)
            self.assertEqual(first.returncode,17,first.stderr.decode())
            self.assertEqual(json.loads((root/'upgrade.json').read_text())['steps']['a']['state'],'applied')
            second=subprocess.run([sys.executable,'-c',child,source,tmp,'second'],capture_output=True)
            self.assertEqual(second.returncode,0,second.stderr.decode())
            machines=json.loads((root/'machines.json').read_text())
            self.assertTrue(all(m['active']==new and m['fallback']==old for m in machines.values()))
            self.assertTrue(json.loads((root/'upgrade.json').read_text())['fleet_verified'])
            self.assertEqual((root/'bin'/'ultra-relay.automation-previous').read_bytes(),b'old')

    def test_bootstrap_keeps_compatible_emergency_after_monitor_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); release=root/'release';release.mkdir()
            manifest={'version':'v2','capabilities':['service-access-v1'],'assets':[]}
            for name in ('ultra-relay','ultra-bot','ultra-client'):
                dest=root/'usr/local/bin'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b'compatible')
                asset=name+'-linux-amd64';(release/asset).write_bytes(b'compatible')
                manifest['assets'].append({'name':asset,'sha256':a.sha(dest)})
            (release/'release-manifest.json').write_text(json.dumps(manifest))
            real_path=Path
            def path(value):
                value=real_path(value)
                return root/str(value).lstrip('/') if str(value).startswith('/usr/local/') else value
            def fresh_run(argv, **kwargs):
                if argv[:2] == ['systemctl', 'show']:
                    return b'not-found\n'
                if argv[:2] == ['systemctl', 'stop']:
                    raise ValueError('unit not found on fresh host')
                return b'amd64'
            def configure(config):
                (root/'service-identity-created').touch()
                raise ValueError('later static pin validation failed')
            with patch.object(a,'STATE',root/'state'),patch.object(a,'BIN',root/'usr/local/bin'),patch.object(a,'ROOT',root/'active'),patch.object(a,'UNITS',root/'units'),patch.object(a,'Path',side_effect=path),patch.object(a,'verify_release',return_value={'recovery.py':b'compatible tools'}),patch.object(a,'run',side_effect=fresh_run),patch.object(a.subprocess,'run'),patch.object(a,'configure',side_effect=configure):
                with self.assertRaisesRegex(ValueError,'static pin'):
                    a.apply({'version':'v2'},release,'bootstrap')
            self.assertTrue((root/'service-identity-created').exists())
            self.assertEqual((root/'usr/local/libexec/ultra-relay-emergency').read_bytes(),b'compatible')
            self.assertEqual(json.loads((root/'usr/local/libexec/ultra-emergency-manifest.json').read_text())['capabilities'],['service-access-v1'])
            self.assertEqual((root/'active/recovery.py').read_bytes(),b'compatible tools')
            self.assertFalse(json.loads((root/'state/release.json').read_text())['ready'])

    def test_failure_receipt_contains_only_stage_codes_and_clears_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def fail(config, release, action, progress):
                progress[0]='configure'
                raise ValueError('private-token-that-must-not-be-output')
            with patch.object(a,'STATE',root),patch.object(a,'_apply',side_effect=fail):
                with self.assertRaises(ValueError):a.apply({},root,'bootstrap')
                receipt=(root/'last-error.json').read_text()
                self.assertNotIn('private-token',receipt)
                self.assertEqual(set(json.loads(receipt)),{'action','stage','code','timestamp'})
                self.assertEqual(a.status()['last_error']['code'],'configure_failed')
            with patch.object(a,'STATE',root),patch.object(a,'_apply'):
                a.apply({},root,'bootstrap')
                self.assertFalse((root/'last-error.json').exists())

    def test_main_replaces_durable_completion_receipt_only_after_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'config.json';config.write_text(json.dumps({'version':'v2.4.4'}))
            receipt=root/'receipts/upgrade-v2.4.4.json'
            receipt.parent.mkdir();receipt.write_text(json.dumps({'action':'upgrade','version':'v2.4.4','completed_at':1}))
            with patch.object(a,'STATE',root),patch.object(sys,'argv',['automation.py','--action','upgrade','--config',str(config),'--release',str(root)]),patch.object(a,'apply'):
                self.assertEqual(a.main(),0)
            value=json.loads(receipt.read_text())
            self.assertEqual((value['action'],value['version']),('upgrade','v2.4.4'))
            self.assertGreater(value['completed_at'],1)
            receipt.unlink()
            with patch.object(a,'STATE',root),patch.object(sys,'argv',['automation.py','--action','upgrade','--config',str(config),'--release',str(root)]),patch.object(a,'apply',side_effect=ValueError('failed')):
                with self.assertRaisesRegex(ValueError,'failed'):
                    a.main()
            self.assertFalse(receipt.exists())

    def test_interrupted_upgrade_emergency_matches_previous_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            old=hashlib.sha256(b'old-compatible').hexdigest()
            previous={'version':'v1','capabilities':['service-access-v1'],'assets':[{'name':'ultra-relay-linux-amd64','sha256':old}]}
            (root/'release-manifest.json').write_text(json.dumps(previous))
            (root/'ultra-relay').write_bytes(b'new-compatible')
            (root/'ultra-relay.automation-previous').write_bytes(b'old-compatible')
            (root/'upgrade.json').write_text(json.dumps({'previous':previous}))
            with patch.object(a,'BIN',root),patch.object(a,'ROOT',root),patch.object(a,'STATE',root):
                binary,raw=a.emergency_pair('upgrade',root,'amd64')
            self.assertEqual(hashlib.sha256(binary).hexdigest(),a.asset_hash(json.loads(raw),'ultra-relay-linux-amd64'))
            self.assertEqual(binary,b'old-compatible')
            # A crash before backup creation must use the still-active old binary.
            (root/'ultra-relay').write_bytes(b'old-compatible')
            (root/'ultra-relay.automation-previous').unlink()
            with patch.object(a,'BIN',root),patch.object(a,'ROOT',root),patch.object(a,'STATE',root):
                self.assertEqual(a.emergency_pair('upgrade',root,'amd64')[0],b'old-compatible')
                (root/'ultra-relay').write_bytes(b'new-compatible')
                (root/'ultra-relay.automation-previous').write_bytes(b'wrong')
                with self.assertRaisesRegex(ValueError,'does not match'):
                    a.emergency_pair('upgrade',root,'amd64')

    def test_atomic_syncs_renamed_journal_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'upgrade.json';events=[]
            original_sync=os.fsync;original_replace=os.replace
            def sync(fd):
                events.append('directory_sync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_sync')
                original_sync(fd)
            def replace(source,target):
                original_replace(source,target);events.append('rename')
            with patch.object(a.os,'fsync',side_effect=sync),patch.object(a.os,'replace',side_effect=replace):
                a.write_json(path,{'state':'prepared'})
            self.assertEqual(events,['file_sync','rename','directory_sync'])
            self.assertEqual(json.loads(path.read_text()),{'state':'prepared'})

    def test_atomic_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'real').write_bytes(b'keep');(root/'link').symlink_to(root/'real')
            with self.assertRaises(ValueError):a.atomic(root/'link',b'new')
            self.assertEqual((root/'real').read_bytes(),b'keep')

    def test_pool_transition_emergency_and_schema_contract(self):
        old={'capabilities':['service-access-v1'],'database_schema_min':24,'database_schema_max':24}
        new={'capabilities':['service-access-v1','provider-pool-quota-v1'],'database_schema_min':24,'database_schema_max':25}
        self.assertTrue(a.pool_transition(old,new))
        self.assertFalse(a.compatible_fallback(old,new))
        self.assertTrue(a.compatible_fallback(new,new))
        self.assertFalse(a.compatible_fallback(dict(new,database_schema_max=24),new))
        self.assertFalse(a.pool_transition(old,dict(new,database_schema_min=25)))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);release=root/'release';release.mkdir()
            previous=dict(old,assets=[{'name':'ultra-relay-linux-amd64','sha256':hashlib.sha256(b'old').hexdigest()}])
            target=dict(new,assets=[{'name':'ultra-relay-linux-amd64','sha256':hashlib.sha256(b'new').hexdigest()}])
            (root/'release-manifest.json').write_text(json.dumps(previous))
            (root/'ultra-relay').write_bytes(b'old')
            (release/'release-manifest.json').write_text(json.dumps(target))
            binary=release/'ultra-relay-linux-amd64';binary.write_bytes(b'new')
            with patch.object(a,'BIN',root),patch.object(a,'ROOT',root),patch.object(a,'STATE',root):
                body,manifest=a.emergency_pair('upgrade',release,'amd64')
                self.assertEqual(body,b'new')
                self.assertEqual(json.loads(manifest),target)
                binary.write_bytes(b'wrong')
                with self.assertRaisesRegex(ValueError,'does not match'):
                    a.emergency_pair('upgrade',release,'amd64')

    def test_pool_upgrade_failure_keeps_target_cache_only_and_retry_resumes(self):
        for failure in ('exit','bridge','readiness','process-death'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);release=root/'release';release.mkdir()
                active=root/'active';active.mkdir();state=root/'state';state.mkdir()
                config_dir=root/'config';config_dir.mkdir();(config_dir/'reconcile.json').write_text('{}')
                units=root/'units';units.mkdir()
                (units/'ultra-relay.service').write_text('[Service]\nExecStart=/usr/local/bin/ultra-relay -spec /etc/ultra-relay/spec.json\n')
                bins=root/'usr/local/bin';bins.mkdir(parents=True)
                previous={'version':'v1','capabilities':['service-access-v1'],'database_schema_min':24,'database_schema_max':24,'assets':[]}
                target={'version':'v2','capabilities':['service-access-v1','provider-pool-quota-v1'],'database_schema_min':24,'database_schema_max':25,'assets':[]}
                for name in ('ultra-relay','ultra-bot','ultra-client'):
                    (bins/name).write_bytes(b'old')
                    (release/(name+'-linux-amd64')).write_bytes(b'new')
                    previous['assets'].append({'name':name+'-linux-amd64','sha256':hashlib.sha256(b'old').hexdigest()})
                    target['assets'].append({'name':name+'-linux-amd64','sha256':hashlib.sha256(b'new').hexdigest()})
                (active/'release-manifest.json').write_text(json.dumps(previous))
                (active/'recovery.py').write_bytes(b'old controller')
                (release/'release-manifest.json').write_text(json.dumps(target))
                old=previous['assets'][0]['sha256'];new=target['assets'][0]['sha256']
                machines={'exit':old};events=[];fail=[failure]
                bridge_mode=['normal'];health_modes=[]
                real_wait_exit=a.wait_exit
                spec_path=root/'spec.json';spec_path.write_text(json.dumps({'admin_listen':'127.0.0.1:8443'}))
                node={'id':'exit','address':'192.0.2.1'}
                controller=types.SimpleNamespace(discover=lambda c:[],desired_nodes=lambda c,r:([node],set()))
                real_path=Path
                def path(value):
                    value=real_path(value)
                    return root/str(value).lstrip('/') if str(value).startswith('/usr/local/') else value
                def run(argv,**kwargs):
                    if argv==['dpkg','--print-architecture']:return b'amd64'
                    if '-capabilities' in argv:return json.dumps(target['capabilities']).encode()
                    if argv[:2]==['systemctl','show']:return b'loaded'
                    return b''
                def remote(config,node,script,data=None):
                    events.append(script)
                    if script=='dpkg --print-architecture':return b'amd64'
                    if script.startswith('sha256sum'):return (machines['exit']+' binary').encode()
                    if script.startswith('set -eu; old='):
                        machines['exit']=new
                        if fail[0]=='process-death':
                            self.assertIn('-cache-only',a.pool_override().read_text())
                            self.assertEqual(json.loads((state/'pool-emergency.json').read_text())['stage'],'armed')
                            raise SystemExit(17)
                    if script.startswith('set -eu; if test'):self.fail('pre-pool rollback attempted')
                    return b''
                def health(*args):
                    if fail[0]=='exit':raise ValueError('exit payload failed')
                    return real_wait_exit(*args)
                def health_response(request,**kwargs):
                    self.assertTrue(request.full_url.endswith('/v1/health'))
                    health_modes.append(bridge_mode[0])
                    # The real cache-only API contract contains no exits. It
                    # cannot satisfy wait_exit until a normal controller runs.
                    result={'control_ready':False,'runtime':{},'reload':{'count':1,'error':''}}
                    if bridge_mode[0]=='normal':
                        checked=a.datetime.datetime.fromtimestamp(a.time.time()+1,a.datetime.timezone.utc).isoformat()
                        result={'exits':[{'id':'exit','internet_ok':True,'eligible':True,'checked_at':checked}]}
                    return io.BytesIO(json.dumps(result).encode())
                def restart(spec):
                    if fail[0]=='bridge' and not a.pool_override().exists():raise ValueError('bridge startup failed')
                    bridge_mode[0]='cache-only' if a.pool_override().exists() else 'normal'
                config={'version':'v2','spec':str(spec_path),'readiness_timeout_sec':0 if failure=='readiness' else 10}
                with patch.object(a,'STATE',state),patch.object(a,'ROOT',active),patch.object(a,'CONFIG',config_dir),patch.object(a,'UNITS',units),patch.object(a,'BIN',bins),patch.object(a,'Path',side_effect=path),patch.object(a,'run',side_effect=run),patch.object(a,'verify_release',return_value={'recovery.py':b'pool controller'}),patch.object(a,'remote',side_effect=remote),patch.object(a,'wait_exit',side_effect=health),patch.object(a,'restart_bridge',side_effect=restart),patch.object(a,'status',return_value={'ready':True}),patch.object(a,'read_env',return_value={'ULTRA_RELAY_ADMIN_TOKEN':'fixture'}),patch.object(a.urllib.request,'urlopen',side_effect=health_response),patch.object(a.time,'sleep',side_effect=AssertionError('exit health polled without a normal controller')),patch.dict(sys.modules,{'reconcile':controller}):
                    if failure=='process-death':
                        with self.assertRaises(SystemExit):a.apply(config,release,'upgrade')
                        self.assertTrue(json.loads((state/'upgrade.json').read_text())['pool_activation_started'])
                        self.assertIn('-require-provider-pool-quota',(units/'ultra-relay.service').read_text())
                        self.assertEqual((root/'usr/local/libexec/ultra-relay-emergency').read_bytes(),b'new')
                        fail[0]=''
                        bridge_mode[0]='cache-only'  # host reboot uses the armed override
                        a.apply(config,release,'upgrade')
                        self.assertNotIn('cache-only',health_modes)
                        self.assertEqual((bins/'ultra-relay').read_bytes(),b'new')
                        self.assertFalse((state/'upgrade.json').exists())
                        continue
                    with self.assertRaises(ValueError):a.apply(config,release,'upgrade')
                    self.assertEqual((active/'recovery.py').read_bytes(),b'pool controller')
                    self.assertEqual((bins/'ultra-relay').read_bytes(),b'new')
                    self.assertEqual(machines['exit'],new)
                    self.assertIn('-cache-only',a.pool_override().read_text())
                    self.assertIn('-require-provider-pool-quota',(units/'ultra-relay.service').read_text())
                    self.assertEqual(json.loads((state/'pool-emergency.json').read_text())['stage'],'cache-only')
                    journal=json.loads((state/'upgrade.json').read_text())
                    self.assertEqual(journal['previous'],previous)
                    self.assertTrue(journal['pool_activation_started'])
                    self.assertEqual(json.loads((root/'usr/local/libexec/ultra-emergency-manifest.json').read_text()),target)
                    self.assertEqual((root/'usr/local/libexec/ultra-relay-emergency').read_bytes(),b'new')
                    self.assertEqual(bridge_mode[0],'cache-only')
                    # Expose the cache-only response itself, not an always-ready
                    # wait_exit mock, before resuming the interrupted upgrade.
                    request=a.urllib.request.Request('http://127.0.0.1:8443/v1/health')
                    self.assertNotIn('exits',json.load(health_response(request)))
                    health_modes.clear()
                    fail[0]='';config['readiness_timeout_sec']=10
                    a.apply(config,release,'upgrade')
                    self.assertEqual(bridge_mode[0],'normal')
                    self.assertEqual(health_modes,['normal'])
                    self.assertFalse(a.pool_override().exists())
                    self.assertFalse((state/'upgrade.json').exists())
                    self.assertEqual(json.loads((state/'pool-emergency.json').read_text())['stage'],'complete')
                    self.assertEqual((bins/'ultra-relay').read_bytes(),b'new')

    def test_pool_emergency_rejects_false_capability_before_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);real_path=Path
            def path(value):
                value=real_path(value)
                return root/str(value).lstrip('/') if str(value).startswith('/usr/local/') else value
            manifest={'capabilities':['service-access-v1','provider-pool-quota-v1'],'assets':[{'name':'ultra-relay-linux-amd64','sha256':hashlib.sha256(b'new').hexdigest()}]}
            with patch.object(a,'Path',side_effect=path),patch.object(a,'STATE',root/'state'),patch.object(a,'run',return_value=b'["service-access-v1"]'):
                with self.assertRaisesRegex(ValueError,'probe failed'):
                    a.prepare_pool_emergency(b'new',json.dumps(manifest).encode(),'amd64','digest')
                self.assertFalse((root/'state/pool-emergency.json').exists())

    def test_pool_bootstrap_configuration_failure_enters_cache_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);release=root/'release';release.mkdir();bins=root/'usr/local/bin';bins.mkdir(parents=True)
            units=root/'units';units.mkdir();(units/'ultra-relay.service').write_text('[Service]\nExecStart=/usr/local/bin/ultra-relay -spec /etc/ultra-relay/spec.json\n')
            manifest={'version':'v2','capabilities':['service-access-v1','provider-pool-quota-v1'],'database_schema_min':24,'database_schema_max':25,'assets':[]}
            for name in ('ultra-relay','ultra-bot','ultra-client'):
                (bins/name).write_bytes(b'new');asset=name+'-linux-amd64';(release/asset).write_bytes(b'new')
                manifest['assets'].append({'name':asset,'sha256':a.sha(bins/name)})
            (release/'release-manifest.json').write_text(json.dumps(manifest))
            real_path=Path
            def path(value):
                value=real_path(value)
                return root/str(value).lstrip('/') if str(value).startswith('/usr/local/') else value
            def run(argv,**kwargs):
                if '-capabilities' in argv:return json.dumps(manifest['capabilities']).encode()
                if argv[:2]==['systemctl','show']:return b'not-found'
                return b'amd64'
            with patch.object(a,'STATE',root/'state'),patch.object(a,'ROOT',root/'active'),patch.object(a,'UNITS',units),patch.object(a,'BIN',bins),patch.object(a,'Path',side_effect=path),patch.object(a,'run',side_effect=run),patch.object(a,'verify_release',return_value={'recovery.py':b'pool controller'}),patch.object(a,'configure',side_effect=ValueError('configuration failed')),patch.object(a,'restart_bridge') as restart:
                with self.assertRaisesRegex(ValueError,'configuration failed'):
                    a.apply({'version':'v2','spec':'fixture'},release,'bootstrap')
                self.assertEqual(restart.call_count,1)
                self.assertIn('-cache-only',a.pool_override().read_text())
                self.assertEqual((root/'active/recovery.py').read_bytes(),b'pool controller')
                self.assertEqual(json.loads((root/'state/pool-emergency.json').read_text())['stage'],'cache-only')
                self.assertFalse(json.loads((root/'state/release.json').read_text())['ready'])


if __name__=='__main__':unittest.main()
