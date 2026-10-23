#!/usr/bin/env python3
"""Isolated broker protocol and proof drift checks; no host/production access."""
import copy
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

    def test_subsequent_probe_uses_actual_predecessor(self):
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
