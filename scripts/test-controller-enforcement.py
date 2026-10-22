#!/usr/bin/env python3
"""Isolated broker protocol and proof drift checks; no host/production access."""
import copy
import io
import tarfile
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('enforcement', ROOT / 'deploy/ansible/library/ultra_controller_enforcement.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

# A real subprocess/socket/SCM_RIGHTS transport fixture. Negative variants model
# immutable brokers which ignore the ledger or cannot retain the applying OFD.
BROKER = r'''#!/usr/bin/python3
import array,json,os,socket,sys
from pathlib import Path
args=sys.argv
state=Path(args[args.index('--state')+1]);path=args[args.index('--socket')+1]
ledger=json.loads((state/'lifecycle-retired.json').read_text());life=json.loads((state/'lifecycle.json').read_text())
sock=socket.socket(socket.AF_UNIX);sock.bind(path);sock.listen()
lock=os.open(state/'infrastructure.lock',os.O_RDWR|os.O_CREAT,0o600)
while True:
 c,_=sock.accept()
 with c:
  raw,control,flags,_=c.recvmsg(65536,socket.CMSG_SPACE(12));m=json.loads(raw);action=m['action'];oid=m['id'];fds=[]
  for level,kind,data in control:
   if kind==socket.SCM_RIGHTS:
    received=array.array('i');received.frombytes(data[:len(data)-len(data)%received.itemsize]);fds.extend(received)
  result={};sent=[]
  if action.startswith('lease-') and oid in ledger['ids'] and MODE!='ignores-ledger':result={'code':'lifecycle_retired'}
  elif action in ['ready','submit']:result={'code':'lifecycle_busy'} if life['phase']=='applying' else {'state':'ready'}
  elif action=='lease-applying':
   life={'id':oid,'phase':'applying'};(state/'lifecycle.json').write_text(json.dumps(life));result={'state':'applying'}
  elif action=='lease-attach':
   result={'state':'applying'}
   if MODE!='no-descriptor':sent=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[lock]))]
  elif action=='lease-resume':result={'state':'applying'} if fds else {'code':'missing-descriptor'}
  else:result={'code':'unsupported'}
  c.sendmsg([json.dumps(result).encode()+b'\n'],sent)
  for fd in fds:os.close(fd)
'''


class EnforcementTests(unittest.TestCase):
    def broker(self, directory, mode):
        path = Path(directory) / ('broker-' + mode)
        path.write_text(BROKER.replace('import array,json,os,socket,sys',
                                      'import array,json,os,socket,sys\nMODE=' + repr(mode)))
        path.chmod(0o700)
        return path

    def test_behavioral_probe_accepts_enforcing_broker_and_rejects_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = {'version': 1, 'ids': ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']}
            original = copy.deepcopy(ledger)
            guard.probe(self.broker(directory, 'enforces'), ledger)
            self.assertEqual(ledger, original)
            for mode in ('ignores-ledger', 'no-descriptor'):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    guard.probe(self.broker(directory, mode), ledger)

    def fixture(self, directory):
        root = Path(directory)
        ledger = {'version': 1, 'ids': ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']}
        life = {'id': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'phase': 'released'}
        for name, value in [('lifecycle-retired.json', ledger), ('lifecycle.json', life)]:
            (root / name).write_text(json.dumps(value))
            (root / name).chmod(0o600)
        candidate = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.1', 'architecture': 'amd64',
                     'installer_sha256': 'a' * 64, 'runtime_sha256': 'b' * 64, 'unit_sha256': guard.digest(b'target')}
        rollback = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.0', 'unit': 'fixture',
                    'unit_sha256': guard.digest(b'fixture'), 'installer_sha256': 'd' * 64,
                    'runtime_sha256': 'e' * 64, 'tree_sha256': 'f' * 64}
        operation = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
        proof = {'schema': 1, 'operation_id': operation, 'scope_sha256': 'd' * 64,
                 'manifest_sha256': 'e' * 64, 'machine_sha256': 'f' * 64,
                 'ledger_sha256': guard.digest((root / 'lifecycle-retired.json').read_bytes()),
                 'source_lifecycle': life, 'candidate': candidate, 'rollback': rollback}
        return root, operation, proof, candidate, rollback

    def params(self, operation, proof, candidate, phase='before'):
        return {'action': 'verify', 'operation_id': operation, 'scope_sha256': 'd' * 64,
                'manifest_sha256': 'e' * 64, 'candidate': candidate, 'proof': proof, 'phase': phase}

    def test_first_probe_failure_does_not_write_production_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, operation, _, candidate, rollback = self.fixture(temporary)
            executable = root / 'candidate'
            executable.write_bytes(b'candidate')
            candidate['installer_sha256'] = guard.digest(b'candidate')
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            params = self.params(operation, {}, candidate, 'preflight')
            params.update(action='probe', candidate_executable=str(executable))
            with patch.object(guard, 'ROOT', root), patch.object(guard, 'machine_sha', return_value='f' * 64), \
                    patch.object(guard, 'live_identity', return_value=rollback), patch.object(guard, 'probe') as probe:
                proof = guard.execute(params)
                self.assertEqual(probe.call_count, 2)
                self.assertEqual(proof['rollback'], rollback)
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                probe.side_effect = ValueError('legacy')
                with self.assertRaises(ValueError):
                    guard.execute(params)
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)

    def test_write_ahead_intent_allows_only_exact_partial_switch_and_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, operation, proof, candidate, rollback = self.fixture(temporary)
            (root / 'lifecycle.json').write_text(json.dumps({'id': operation, 'phase': 'applying'}))
            current, unit = root / 'current', root / 'controller.service'
            current.symlink_to(rollback['directory'])
            unit.write_text('fixture')
            new = dict(candidate, tree_sha256='1' * 64, unit='target')
            new.pop('architecture')
            ledger_before = (root / 'lifecycle-retired.json').read_bytes()
            def identity(directory, unit_raw):
                return rollback if directory == rollback['directory'] else new
            with patch.object(guard, 'ROOT', root), patch.object(guard, 'CURRENT', current), \
                    patch.object(guard, 'UNIT', unit), patch.object(guard, 'machine_sha', return_value='f' * 64), \
                    patch.object(guard, 'identity', side_effect=identity), patch.object(guard, 'live_identity', return_value=rollback) as live, \
                    patch.object(guard, 'running_identity', return_value=(rollback['directory'], rollback['installer_sha256'])) as running, \
                    patch.object(guard, 'sealed_candidate'):
                params = self.params(operation, proof, candidate)
                guard.execute(params)
                self.assertTrue(guard.intent_present(proof))
                fallback = root / 'releases/v0.0.1/controller.service.previous'
                fallback.parent.mkdir(parents=True, mode=0o700)
                fallback.write_text('fixture')
                current.unlink()
                current.symlink_to(candidate['directory'])
                unit.write_text('target')
                live.side_effect = ValueError('restart not completed')
                guard.execute(params)  # Retry between disk selection and restart.
                guard.execute(dict(params, phase='staged'))
                running.return_value = ('/opt/ultra-ansible/releases/foreign', '0' * 64)
                with self.assertRaises(ValueError):
                    guard.execute(params)
                running.return_value = (candidate['directory'], candidate['installer_sha256'])
                live.side_effect = None
                live.return_value = new
                guard.execute(dict(params, phase='candidate'))
                # Exact remote release before local completion is authenticated
                # only by the separate completion phase, never normal preflight.
                (root / 'lifecycle.json').write_text(json.dumps({'id': operation, 'phase': 'released'}))
                with self.assertRaises(ValueError):
                    guard.execute(dict(params, phase='preflight'))
                guard.execute(dict(params, phase='completion'))
                (root / 'lifecycle.json').write_text(json.dumps({'id': proof['source_lifecycle']['id'], 'phase': 'released'}))
                with self.assertRaises(ValueError):
                    guard.execute(dict(params, phase='completion'))
                (root / 'lifecycle.json').write_text(json.dumps({'id': operation, 'phase': 'applying'}))
                fallback.write_text('changed fallback')
                with self.assertRaises(ValueError):
                    guard.execute(dict(params, phase='candidate'))
                fallback.write_text('fixture')
                live.return_value = rollback
                current.unlink()
                current.symlink_to(rollback['directory'])
                unit.write_text('fixture')
                guard.execute(dict(params, phase='rollback'))
                self.assertEqual((root / 'lifecycle-retired.json').read_bytes(), ledger_before)

    def test_intent_publication_interruption_recovers_only_authenticated_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, operation, proof, _, _ = self.fixture(temporary)
            with patch.object(guard, 'ROOT', root):
                real_link = os.link
                def interrupted(source, destination):
                    real_link(source, destination)
                    raise InterruptedError('process interrupted after publication')
                with patch.object(guard.os, 'link', side_effect=interrupted):
                    with self.assertRaises(InterruptedError):
                        guard.save_intent(proof)
                final, pending = guard.intent_paths(proof)
                self.assertEqual(final.stat().st_nlink, 2)
                guard.save_intent(proof)
                self.assertFalse(pending.exists())
                self.assertEqual(final.stat().st_nlink, 1)
                self.assertTrue(guard.intent_present(proof))
                # An unrelated hardlink is never accepted or removed.
                foreign = root / '.foreign'
                real_link(final, foreign)
                with self.assertRaises(ValueError):
                    guard.save_intent(proof)
                self.assertTrue(foreign.exists())
                foreign.unlink()
                # Foreign and incomplete named leftovers are retained fail-closed.
                for raw in (b'{', b'{}', guard.intent_raw(proof)):
                    pending.write_bytes(raw)
                    pending.chmod(0o600)
                    with self.assertRaises(ValueError):
                        guard.save_intent(proof)
                    self.assertTrue(pending.exists())
                    pending.unlink()
                final.unlink()
                pending.write_bytes(b'{')
                pending.chmod(0o600)
                with self.assertRaises(ValueError):
                    guard.save_intent(proof)
                self.assertFalse(final.exists())

    def test_partial_switch_without_matching_intent_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, operation, proof, candidate, rollback = self.fixture(temporary)
            current, unit = root / 'current', root / 'controller.service'
            current.symlink_to(candidate['directory'])
            unit.write_text('target')
            with patch.object(guard, 'ROOT', root), patch.object(guard, 'CURRENT', current), patch.object(guard, 'UNIT', unit):
                with self.assertRaises(ValueError):
                    guard.transition_identity(proof)
                guard.save_intent(proof)
                changed = copy.deepcopy(proof)
                changed['scope_sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    guard.intent_present(changed)

    def test_proof_rejects_runtime_ledger_machine_lifecycle_and_release_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, operation, proof, candidate, rollback = self.fixture(temporary)
            def verify(value=proof, phase='preflight', target=candidate, manifest='e' * 64):
                return guard.verify(value, operation, 'd' * 64, manifest, target, phase, root)
            with patch.object(guard, 'machine_sha', return_value='f' * 64), patch.object(guard, 'identity', return_value=rollback):
                verify()
                for field in ['operation_id', 'scope_sha256', 'manifest_sha256', 'machine_sha256', 'ledger_sha256']:
                    changed = copy.deepcopy(proof)
                    changed[field] = '0' * 64
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        verify(changed)
                with self.assertRaises(ValueError):
                    verify(manifest='0' * 64)
                changed = dict(candidate, installer_sha256='0' * 64)
                with self.assertRaises(ValueError):
                    verify(target=changed)
                with patch.object(guard, 'identity', return_value=dict(rollback, runtime_sha256='changed')):
                    with self.assertRaises(ValueError):
                        verify()
                (root / 'lifecycle.json').write_text(json.dumps({'id': operation, 'phase': 'applying'}))
                verify(phase='reserved')
                (root / 'lifecycle.json').write_text(json.dumps({'id': 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'phase': 'applying'}))
                with self.assertRaises(ValueError):
                    verify(phase='reserved')
                (root / 'lifecycle-retired.json').write_text(json.dumps({'version': 1, 'ids': []}))
                with self.assertRaises(ValueError):
                    verify()

    def test_snapshot_rejects_pending_handoff_unknown_schema_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, *_ = self.fixture(temporary)
            guard.snapshot(root)
            for ledger in [{'version': 2, 'ids': []}, {'version': 1, 'ids': [], 'handoff': {}},
                           {'version': 1, 'ids': ['bad']}, {'version': True, 'ids': []}]:
                (root / 'lifecycle-retired.json').write_text(json.dumps(ledger))
                with self.assertRaises((ValueError, AttributeError)):
                    guard.snapshot(root)
            (root / 'lifecycle-retired.json').unlink()
            (root / 'lifecycle-retired.json').symlink_to(root / 'lifecycle.json')
            with self.assertRaises(ValueError):
                guard.snapshot(root)

    def test_runtime_tree_and_sealed_candidate_detect_unmarked_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / 'runtime'
            runtime.mkdir(mode=0o700)
            (runtime / 'ultra-install').write_bytes(b'installer')
            before = guard.tree_digest(runtime)
            (runtime / 'unowned').write_bytes(b'added')
            self.assertNotEqual(guard.tree_digest(runtime), before)
            candidate = {'directory': str(runtime), 'installer_sha256': 'a' * 64, 'runtime_sha256': 'b' * 64}
            receipt = root / 'retention' / (guard.digest(str(runtime).encode()) + '.json')
            receipt.parent.mkdir(mode=0o700)
            sealed = {'schema': 1, 'path': str(runtime), 'identity': {'ultra-install': 'a' * 64,
                      'runtime.sha256': guard.digest(('b' * 64 + '\n').encode())}, 'inventory': guard.tree_contents(runtime)}
            receipt.write_text(json.dumps(sealed))
            receipt.chmod(0o600)
            with patch.object(guard, 'ROOT', root):
                guard.sealed_candidate(candidate)
                (runtime / 'ultra-install').write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    guard.sealed_candidate(candidate)

    def prepared_fixture(self):
        root = guard.ROOT; state_dir = root / 'prep'; planned = root / 'upgrade-v0.0.1'
        enc = lambda value: json.dumps(value,separators=(',',':')).encode()
        candidate = {'directory':'/opt/ultra-ansible/releases/managed-v0.0.1','architecture':'amd64',
                     'installer_sha256':'a'*64,'runtime_sha256':'b'*64,'unit_sha256':guard.digest(b'unit')}
        source = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'; operation = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
        proof = {'source_lifecycle':{'id':source,'phase':'released'}}
        files = {str(root/'config'):b'original',str(root/'upgrade-config'):b'new',str(root/'manifest'):enc({'assets':[]}),
                 str(root/'known-hosts'):b'pins',str(root/'release/release-manifest.json'):b'tools',
                 str(planned/'operator-plan.json'):b'plan',str(planned/'recovery-upgrade-inventory.json'):b'inventory',
                 str(planned/'controller-enforcement.json'):enc(proof),str(guard.UNIT):b'unit'}
        request = {'protocol':'ultra-recovery-preparation-request-v1','state_directory':str(state_dir),
                   'tools_release_directory':str(root/'release'),'tools_manifest_sha256':guard.digest(b'tools'),
                   'retained_fence_sha256':'f'*64}
        for field,key,name in [('config_path','config_sha256','config'),('upgrade_config_path','upgrade_config_sha256','upgrade-config'),
                               ('baseline_manifest_path','baseline_manifest_sha256','manifest'),('known_hosts_path','known_hosts_sha256','known-hosts')]:
            request[field]=str(root/name);request[key]=guard.digest(files[request[field]])
        if getattr(self,'reimage',False):request['bridge_reimage']={'acknowledgement':'bridge-reimaged-retained-primary-and-exit-preserved'}
        files[str(state_dir/'request.json')]=enc(request); prep_sha=guard.digest(enc(request))
        envelope={'schema':2,'preparation':request};raw=enc(envelope);envelope_sha=guard.digest(raw)
        files[str(root/'deploy-operations/current.json')]=enc({'schema':1,'request_sha256':envelope_sha})
        files[str(root/'deploy-operations'/envelope_sha/'request.json')]=raw
        state_path=str(root/'deploy-operations'/envelope_sha/'state.json')
        files[state_path]=enc({'request_sha256':envelope_sha,'state':'running','stage':'upgrade'})
        files[str(root/'recovery-preparation-admission.json')]=enc({'protocol':'ultra-recovery-preparation-admission-v1',
            'phase':'sealed','fence_sha256':'f'*64,'config_sha256':request['config_sha256'],'baseline_manifest_sha256':request['baseline_manifest_sha256']})
        if getattr(self,'reimage',False):
            admission=json.loads(files[str(root/'recovery-preparation-admission.json')])
            admission.update(exit_fence_sha256='e'*64,bridge_genesis='a'*64)
            files[str(root/'recovery-preparation-admission.json')]=enc(admission)
            files[str(root/'bridge-reimage-genesis.json')]=enc({'protocol':'ultra-bridge-reimage-genesis-v1','binding_sha256':'a'*64})
            files[str(state_dir/'origins_sealed.json')]=enc({'protocol':'ultra-recovery-preparation-phase-v1',
                'phase':'origins_sealed','request_sha256':prep_sha,'verified':True,'evidence':{'admission':admission}})
        files[str(root/'retained-primary-admission.json')]=enc({'protocol':'retained-primary-admission-v1','binding_sha256':'f'*64})
        for name in ['ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
            files[str(guard.UNIT.parent/(name+'.d')/'90-retained-primary.conf')]=guard.recovery_blocked().encode()
        descriptor={'protocol':'ultra-recovery-broker-preflight-v1','request_sha256':prep_sha,'directory':str(planned),
                    'operation_id':operation,'source_id':source,'scope_sha256':'d'*64,
                    'plan_sha256':guard.digest(b'plan'),'inventory_sha256':guard.digest(b'inventory'),
                    'enforcement_sha256':guard.digest(enc(proof))}
        files[str(state_dir/'broker-preflight.json')]=enc(descriptor)
        terminal={'protocol':'ultra-recovery-broker-handoff-v1','request_sha256':prep_sha,'preflight':descriptor,
                  'verified':True,'acknowledgement':'broker-handoff-ack-23-99.json'}
        files[str(state_dir/'broker-handoff.json')]=enc(terminal)
        ack={'protocol':'ultra-recovery-broker-ack-v1','request_sha256':prep_sha,'operation_id':operation,'scope_sha256':'d'*64,
             'instance':{'pid':'23','start_time':'99','installer_sha256':guard.digest(b'exe'),'unit_sha256':guard.digest(b'unit')}}
        files[str(state_dir/terminal['acknowledgement'])]=enc(ack)
        job=state_dir/'ansible-broker-handoff';request_raw=b'job-request';request_sha=guard.digest(request_raw)
        metadata={'operation':'handoff-recovery-controller','request_sha256':request_sha,'binary_sha256':'e'*64}
        receipt={'state':'succeeded','request_sha256':request_sha,'binary_sha256':'e'*64,'result':{'verified':True,'request_sha256':prep_sha}}
        files[str(job/'request.json')]=request_raw;files[str(job/'job.json')]=enc(metadata);files[str(job/'receipt.json')]=enc(receipt)
        files[str(job/'execution-completion.json')]=enc({'outcome':'succeeded','local_cleanup':True,'receipt_sha256':guard.digest(enc(receipt)),
            'fence':{'job_directory':str(job),'operation':'handoff-recovery-controller','job_sha256':guard.digest(enc(metadata)),'request_sha256':request_sha}})
        policy={key:descriptor[key] for key in ['operation_id','source_id','scope_sha256','plan_sha256','inventory_sha256','enforcement_sha256']}
        policy.update(policy='retain-prepared-candidate',envelope_sha256=envelope_sha,preparation_sha256=prep_sha,
                      handoff_sha256=guard.digest(enc(terminal)),manifest_sha256=request['tools_manifest_sha256'],
                      baseline_manifest_sha256=request['baseline_manifest_sha256'],candidate=candidate)
        params={'prepared_policy':policy,'proof':proof,'candidate':candidate,'operation_id':operation,'scope_sha256':'d'*64,'manifest_sha256':request['tools_manifest_sha256']}
        return files,params,state_path

    def test_prepared_policy_requires_every_protected_binding_and_exact_supervisor(self):
        files,p,state_path=self.prepared_fixture()
        cgroup='0::/system.slice/ultra-deploy-'+p['prepared_policy']['envelope_sha256']+'.service\n'
        def read_text(path,*args,**kwargs):
            if str(path)=='/proc/self/cgroup':return cgroup
            if str(path)=='/proc/23/stat':return '23 (broker) '+ ' '.join(['0']*19+['99'])
            raise AssertionError(str(path))
        with patch.object(guard,'regular',side_effect=lambda path,*a,**k: files[str(path)]), \
             patch.object(guard.Path,'read_text',read_text), \
             patch.object(guard.Path,'read_bytes',return_value=b'exe'), \
             patch.object(guard.subprocess,'run',return_value=type('Result',(),{'stdout':b'MainPID=23\n'})()), \
             patch.object(guard.os.path,'lexists',return_value=False), \
             patch.object(guard,'live_identity',return_value=p['candidate']), \
             patch.object(guard,'sealed_candidate'), \
             patch.object(guard,'prepared_tools_inventory',return_value={'reconcile.py':'verified'}):
            self.assertTrue(guard.prepared_policy(p))
            with patch.object(guard,'recovery_dropin'):
                self.assertIsNotNone(guard.recovery_context(p['prepared_policy']['preparation_sha256'],p['operation_id'],
                    p['candidate'],p['manifest_sha256'],read_only=True))
            if getattr(self,'reimage',False):
                for path in [guard.ROOT/'recovery-preparation-admission.json',guard.ROOT/'bridge-reimage-genesis.json',guard.ROOT/'prep/origins_sealed.json']:
                    saved=files[str(path)];files[str(path)]=b'{}'
                    with self.subTest(path=str(path)),self.assertRaises((ValueError,KeyError)):
                        guard.prepared_policy(p)
                    with patch.object(guard,'recovery_dropin'),self.assertRaises((ValueError,KeyError)):
                        guard.recovery_context(p['prepared_policy']['preparation_sha256'],p['operation_id'],p['candidate'],p['manifest_sha256'],read_only=True)
                    files[str(path)]=saved

            for key in p['prepared_policy']:
                broken=copy.deepcopy(p);broken['prepared_policy'][key]='foreign'
                with self.subTest(field=key),self.assertRaises((ValueError,TypeError,KeyError)):
                    guard.prepared_policy(broken)
            broken=copy.deepcopy(p);broken['prepared_policy']['force']=True
            with self.assertRaises(ValueError):guard.prepared_policy(broken)
            cgroup='0::/foreign\n'
            with self.assertRaises(ValueError):guard.prepared_policy(p)
            cgroup='0::/system.slice/ultra-deploy-'+p['prepared_policy']['envelope_sha256']+'.service\n'
            original=files[state_path]
            for state,stage in [('blocked','upgrade'),('running','tools_staged'),('completed','status')]:
                files[state_path]=json.dumps({'request_sha256':p['prepared_policy']['envelope_sha256'],'state':state,'stage':stage}).encode()
                with self.subTest(state=state,stage=stage),self.assertRaises(ValueError):guard.prepared_policy(p)
            files[state_path]=original
            p['recovery_request_sha256']=p['prepared_policy']['preparation_sha256']
            with self.assertRaises(ValueError):guard.prepared_policy(p)


    def test_bridge_reimage_admission_reaches_both_enforcement_paths(self):
        self.reimage=True
        self.test_prepared_policy_requires_every_protected_binding_and_exact_supervisor()

    def test_prepared_tools_inventory_authenticates_complete_candidate_not_app_manifest(self):
        names=['recovery.py','db_connection.py','reconcile.py','monitor.py','heartbeat.py',
               'ultra-recovery-backup.service','ultra-recovery-backup.timer','ssh_policy.json']
        contents={name:('candidate-'+name).encode() for name in names}
        contents['ssh_policy.json']=(ROOT/'deploy/recovery/ssh_policy.json').read_bytes()
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w:gz') as stream:
            for name in names:
                raw=contents[name];info=tarfile.TarInfo(name);info.size=len(raw);stream.addfile(info,io.BytesIO(raw))
        zipped=archive.getvalue()
        manifest=json.dumps({'assets':[{'name':'ultra-recovery.tar.gz','size':len(zipped),'sha256':guard.digest(zipped)}]}).encode()
        request={'tools_release_directory':'/release','tools_manifest_sha256':guard.digest(manifest)}
        files={'/release/release-manifest.json':manifest,'/release/ultra-recovery.tar.gz':zipped}
        inventory={}
        for name in names:
            raw=contents[name];files['/opt/ultra-recovery/'+name]=raw;inventory['/opt/ultra-recovery/'+name]=guard.digest(raw)
            if name.endswith(('.service','.timer')):
                files['/etc/systemd/system/'+name]=raw;inventory['/etc/systemd/system/'+name]=guard.digest(raw)
        suspension={'protocol':'ultra-recovery-preparation-suspension-v1','request_sha256':'a'*64,
                    'tools_manifest_sha256':request['tools_manifest_sha256'],'active_inventory':inventory}
        files['/etc/ultra-recovery/preparation-suspension.json']=json.dumps(suspension).encode()
        with patch.object(guard,'regular',side_effect=lambda path,*a,**k:files[str(path)]):
            self.assertEqual(set(guard.prepared_tools_inventory(request,'a'*64)),set(names))
            self.assertNotIn('/etc/systemd/system/ssh_policy.json',inventory)
            self.assertIn('/opt/ultra-recovery/ssh_policy.json',inventory)
            files['/opt/ultra-recovery/ssh_policy.json']=b'changed policy'
            with self.assertRaises(ValueError):guard.prepared_tools_inventory(request,'a'*64)
            files['/opt/ultra-recovery/ssh_policy.json']=contents['ssh_policy.json']
            files['/opt/ultra-recovery/reconcile.py']=b'original-app-generation'
            with self.assertRaises(ValueError):guard.prepared_tools_inventory(request,'a'*64)
            files['/opt/ultra-recovery/reconcile.py']=b'candidate-reconcile.py'
            del suspension['active_inventory']['/opt/ultra-recovery/reconcile.py']
            files['/etc/ultra-recovery/preparation-suspension.json']=json.dumps(suspension).encode()
            with self.assertRaises(ValueError):guard.prepared_tools_inventory(request,'a'*64)

        malicious=io.BytesIO()
        with tarfile.open(fileobj=malicious,mode='w:gz') as stream:
            for name in names+['untrusted.json']:
                raw=('candidate-'+name).encode();info=tarfile.TarInfo(name);info.size=len(raw);stream.addfile(info,io.BytesIO(raw))
        zipped=malicious.getvalue()
        manifest=json.dumps({'assets':[{'name':'ultra-recovery.tar.gz','size':len(zipped),'sha256':guard.digest(zipped)}]}).encode()
        files['/release/release-manifest.json']=manifest
        files['/release/ultra-recovery.tar.gz']=zipped
        request['tools_manifest_sha256']=guard.digest(manifest)
        with patch.object(guard,'regular',side_effect=lambda path,*a,**k:files[str(path)]):
            with self.assertRaises(ValueError):guard.prepared_tools_inventory(request,'a'*64)

    def test_prepared_schedule_restoration_requires_exact_bound_checkpoint(self):
        request={'tools_manifest_sha256':'a'*64}
        sha='b'*64
        suspension={'protocol':'ultra-recovery-preparation-suspension-v1','request_sha256':sha,
                    'tools_manifest_sha256':request['tools_manifest_sha256'],
                    'active_inventory':{'/opt/ultra-recovery/reconcile.py':guard.digest(b'runtime')},
                    'background_gate_sha256':guard.digest(b'gate')}
        raw=json.dumps(suspension).encode()
        restored={'protocol':'ultra-recovery-preparation-schedules-restored-v1','request_sha256':sha,'suspension_sha256':guard.digest(raw)}
        files={'/etc/ultra-recovery/preparation-suspension.json':raw,
               '/etc/ultra-recovery/preparation-schedules-restored.json':json.dumps(restored).encode(),
               '/opt/ultra-recovery/reconcile.py':b'runtime'}
        for name in ['ultra-recovery-backup.service','ultra-recovery-reconcile.service']:
            files[str(guard.UNIT.parent/(name+'.d')/'95-deployment-background.conf')]=b'gate'
        def exists(path):return str(path) in files
        with patch.object(guard.os.path,'lexists',side_effect=exists), \
             patch.object(guard,'regular',side_effect=lambda path,*a,**k:files[str(path)]):
            self.assertTrue(guard.prepared_schedules_restored(request,sha))
            with self.assertRaises(ValueError):guard.prepared_schedules_restored(request,'c'*64)
            files['/opt/ultra-recovery/reconcile.py']=b'changed'
            with self.assertRaises(ValueError):guard.prepared_schedules_restored(request,sha)
            files['/opt/ultra-recovery/reconcile.py']=b'runtime'
            files[str(guard.UNIT.parent/'ultra-recovery-reconcile.service.d/90-retained-primary.conf')]=guard.recovery_blocked().encode()
            with self.assertRaises(ValueError):guard.prepared_schedules_restored(request,sha)

    def test_prepared_rollback_keeps_same_candidate_and_active_lifecycle_for_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, operation, proof, candidate, rollback = self.fixture(temporary)
            new = dict(candidate,tree_sha256='1'*64,unit='target');new.pop('architecture')
            fallback=root/'releases/v0.0.1/controller.service.previous'
            fallback.parent.mkdir(parents=True);fallback.write_text('fixture')
            before_ledger=(root/'lifecycle-retired.json').read_bytes()
            with patch.object(guard,'ROOT',root),patch.object(guard,'machine_sha',return_value='f'*64), \
                 patch.object(guard,'identity',return_value=rollback),patch.object(guard,'live_identity',return_value=new), \
                 patch.object(guard,'intent_present',return_value=True),patch.object(guard,'sealed_candidate'), \
                 patch.object(guard,'prepared_policy',return_value=True):
                for phase in ['applying','checking']:
                    life=json.dumps({'id':operation,'phase':phase}).encode()
                    (root/'lifecycle.json').write_bytes(life)
                    guard.execute(self.params(operation,proof,candidate,'rollback'))
                    guard.execute(self.params(operation,proof,candidate,'preflight'))
                    self.assertEqual((root/'lifecycle.json').read_bytes(),life)
                    self.assertEqual((root/'lifecycle-retired.json').read_bytes(),before_ledger)
                (root/'lifecycle.json').write_text(json.dumps({'id':operation,'phase':'released'}))
                with self.assertRaises(ValueError):guard.execute(self.params(operation,proof,candidate,'completion'))


    def test_subsequent_normal_probe_uses_prepared_candidate_as_actual_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,operation,_,candidate,_=self.fixture(temporary)
            predecessor=dict(candidate,tree_sha256='1'*64,unit='target');predecessor.pop('architecture')
            executable=root/'next-installer';executable.write_bytes(b'next')
            next_candidate=dict(candidate,directory='/opt/ultra-ansible/releases/managed-v0.0.2',installer_sha256=guard.digest(b'next'))
            params=self.params(operation,{},next_candidate,'preflight')
            params.update(action='probe',candidate_executable=str(executable))
            with patch.object(guard,'ROOT',root),patch.object(guard,'machine_sha',return_value='f'*64), \
                 patch.object(guard,'live_identity',return_value=predecessor),patch.object(guard,'probe'):
                proof=guard.execute(params)
                self.assertEqual(proof['rollback'],predecessor)
                self.assertEqual(proof['candidate'],next_candidate)


if __name__ == '__main__':
    unittest.main()
