#!/usr/bin/env python3
"""Fixture and mocked tests only; never contact a deployment host."""
import contextlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import hashlib
import shutil
import signal
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('manual_deploy', Path(__file__).with_name('manual-deploy.py'))
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)
SUBSCRIPTION_PROBE_INPUT = D.subscription_probe_input



class RecoveryStateAttestation(unittest.TestCase):
    """Local fixtures only; no production SSH, installer or Ansible."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.h = D.recovery_attestation_helpers()
        self.sentinel = '-----BEGIN OPENSSH PRIVATE KEY-----secret-sentinel'
        self.original = '00000000-0000-4000-8000-000000000001'

    def write(self, name, value):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def stage(self, name='activate'):
        envelope = {'schema_version':1, 'operation':'upgrade', 'request_sha256':'a'*64,
                    'state':'succeeded', 'code':'', 'result':{'verified':True, 'identity':self.sentinel}}
        for filename in ('job.json', 'receipt.json'):
            self.write(name+'/'+filename, envelope)
        self.write(name+'/request.json', {'identity':self.sentinel,
            'inventory':{'identity':self.sentinel},
            'variables':{'ultra_lifecycle_id':self.original,
                         'ultra_recovery_bootstrap_candidate':'b'*64, 'identity':self.sentinel}})
        return self.root/name

    def test_projection_never_buffers_decodes_hashes_or_emits_identity_values(self):
        stage = self.stage()
        original_loads = json.loads
        def decode(raw, *args, **kwargs):
            self.assertNotIn('secret-sentinel', str(raw))
            self.assertNotIn('PRIVATE KEY', str(raw))
            return original_loads(raw, *args, **kwargs)
        real_read = os.read
        def read(fd, count):
            self.assertEqual(count, 1)
            return real_read(fd, count)
        with patch.object(json, 'loads', side_effect=decode), patch.object(os, 'read', side_effect=read), \
             patch.object(hashlib, 'sha256', side_effect=AssertionError('mixed JSON must not be hashed')):
            result = self.h['attest_stage'](stage)
        encoded = json.dumps(result)
        self.assertNotIn('identity', encoded)
        self.assertNotIn('PRIVATE KEY', encoded)
        self.assertNotIn('secret-sentinel', encoded)
        self.assertIs(result['receipt']['result.verified'], True)
        self.assertEqual(result['request_metadata']['variables.ultra_lifecycle_id'], self.original)
        self.assertFalse(result['request_digest_recomputed'])

    def test_reconcile_status_accepts_group_readable_mode(self):
        path = self.write('recovery-reconcile-status.json',
                          {'state':'ready','independent':True,'updated_at':1792315565})
        path.chmod(0o640)
        result = self.h['attest_optional'](path,
            {('state',),('independent',),('updated_at',)}, modes=(0o640,))
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(result['updated_at'], 1792315565)

    def test_recovery_health_projects_backup_and_reconcile_contracts(self):
        now = int(time.time())
        backup = self.write('recovery/last-success.json', {
            'source':'bridge','snapshot_at':now,'completed_at':now,'dump_verified':True,
            'backup_sha256':'a'*64,'artifact_sha256':'b'*64,'delivered_target_ids':['private-target']})
        independent = self.write('relay/recovery-status.json',
                                 {'snapshot_at':now,'independent':True,'targets':['private-target']})
        reconcile = self.write('relay/recovery-reconcile-status.json',
                               {'state':'ready','updated_at':now,'independent':True,'primary':'private-primary'})
        independent.chmod(0o640)
        reconcile.chmod(0o640)
        result = self.h['attest_recovery_health'](backup.parent, independent.parent, now)
        self.assertEqual(result['backup'], {'state':'succeeded','independent':True,
                                           'snapshot_at':now,'fresh':True})
        self.assertEqual(result['reconcile'], {'state':'ready','updated_at':now,
                                             'independent':True,'fresh':True})
        self.assertNotIn('private-target', json.dumps(result))
        self.assertNotIn('private-primary', json.dumps(result))

    def test_recovery_health_does_not_treat_backup_receipt_as_independent_or_fresh(self):
        now = int(time.time())
        backup = self.write('recovery/last-success.json', {
            'source':'bridge','snapshot_at':now-600,'completed_at':now-590,'dump_verified':True,
            'backup_sha256':'a'*64,'artifact_sha256':'b'*64})
        independent = self.write('relay/recovery-status.json',
                                 {'snapshot_at':now,'independent':True})
        independent.chmod(0o640)
        result = self.h['attest_recovery_health'](backup.parent, independent.parent, now)
        self.assertFalse(result['backup']['fresh'])
        self.assertFalse(result['backup']['independent'])

    def test_recovery_health_preserves_allowlisted_reconcile_failure_cause(self):
        now = int(time.time())
        reconcile = self.write('relay/recovery-reconcile-status.json', {
            'state':'error','code':'reconcile_unavailable','stage':'backup','updated_at':now-300})
        reconcile.chmod(0o640)
        result = self.h['attest_recovery_health'](self.root/'recovery', reconcile.parent, now)
        self.assertEqual(result['reconcile'], {'state':'error','code':'reconcile_unavailable',
                                               'stage':'backup','updated_at':now-300,'fresh':False})

    def test_rejects_symlink_file_and_parent(self):
        path = self.write('source.json', {'phase':'applying'})
        (self.root/'link.json').symlink_to(path)
        (self.root/'parent').symlink_to(self.root, target_is_directory=True)
        for candidate in (self.root/'link.json', self.root/'parent/source.json'):
            with self.subTest(path=candidate), self.assertRaises((OSError, ValueError)):
                self.h['attest_project'](candidate, {('phase',)})

    def test_rejects_oversized_wrong_owner_hardlinks_modes_and_types(self):
        path = self.write('file.json', {'phase':'applying'})
        with patch.object(os, 'geteuid', return_value=os.geteuid()+1000), self.assertRaises(ValueError):
            self.h['attest_project'](path, {('phase',)})
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.h['attest_project'](path, {('phase',)})
        path.chmod(0o600)
        os.link(path, self.root/'hardlink.json')
        with self.assertRaises(ValueError):
            self.h['attest_project'](path, {('phase',)})
        (self.root/'hardlink.json').unlink()
        with path.open('wb') as stream:
            stream.truncate(4194305)
        with self.assertRaises(ValueError):
            self.h['attest_project'](path, {('phase',)})
        fifo = self.root/'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            self.h['attest_project'](fifo, {('phase',)})

    def test_changed_file_during_read_is_rejected(self):
        path = self.write('change.json', {'phase':'applying'})
        with self.assertRaises(ValueError):
            with self.h['attest_open'](path):
                path.write_text('{}')

    def test_bad_json_duplicate_keys_and_depth_rejected(self):
        path = self.write('invalid.json', {})
        for raw in ('{"phase":"applying","phase":"released"}', '{"identity":"bad\\q"}',
                    '{"identity":['*60+'0'+']}'*60, '{"identity":true} trailing'):
            path.write_text(raw)
            with self.subTest(raw=raw[:40]), self.assertRaises((ValueError, RecursionError)):
                self.h['attest_project'](path, {('phase',)})

    def test_lifecycle_reports_owner_and_retirement_without_replacing_it(self):
        path = self.write('state/lifecycle.json', {'id':self.original,'phase':'applying','identity':self.sentinel})
        self.write('state/lifecycle-retired.json', {'version':1,'ids':[self.original]})
        before = path.read_bytes()
        result = self.h['attest_lifecycle'](path.parent, self.original)
        self.assertEqual(result, {'phase':'applying','original_owner_matches':True,'original_retired':True})
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(self.h['attest_lifecycle'](path.parent, '00000000-0000-4000-8000-000000000002')['original_owner_matches'])

    def test_completion_directory_does_not_imply_verified(self):
        stage = self.root/'completion-proof-123'
        stage.mkdir(mode=0o700)
        result = self.h['attest_stage'](stage)
        self.assertEqual(result['receipt'], {'evidence':'absent'})
        self.assertNotIn('verified', json.dumps(result))

    def test_selected_key_like_value_rejected_before_output(self):
        stage = self.stage()
        self.write('activate/receipt.json', {'state':self.sentinel})
        with self.assertRaises(ValueError):
            self.h['attest_stage'](stage)

    def test_remote_program_only_reads_and_locks_no_census_or_mutator(self):
        self.assertNotIn('subprocess', D.REMOTE_RECOVERY_ATTEST)
        self.assertNotIn('/proc', D.REMOTE_RECOVERY_ATTEST)
        self.assertNotIn('O_CREAT', D.REMOTE_RECOVERY_ATTEST)
        self.assertNotIn('os.write', D.REMOTE_RECOVERY_ATTEST)
        self.assertIn("state/'operator/infrastructure.lock'", D.REMOTE_RECOVERY_ATTEST)
        self.assertIn("state/'infrastructure.lock'", D.REMOTE_RECOVERY_ATTEST)
        self.assertIn("state/'operator-inputs/manual-deploy.lock'", D.REMOTE_RECOVERY_ATTEST)

    def test_cli_dispatches_before_build_checks_and_rejects_mutating_options(self):
        argv = ['manual-deploy.py','--attest-recovery-state','--attestation-bootstrap',
                'recovery-tools-bootstrap-operation-fixture','--attestation-candidate','a'*64]
        with patch.object(os.environ, 'get', side_effect=lambda key, default=None: default), \
             patch.object(D, 'collect_recovery_attestation', return_value={'schema':1}) as collect, \
             patch.object(D, 'run', side_effect=AssertionError('no build/git checks')), \
             patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()) as out:
            D.main()
        self.assertEqual(json.loads(out.getvalue()), {'schema':1})
        collect.assert_called_once()
        for extra in ('--forward-only','--retry-failed','--build-only','--continue-forward-only'):
            with self.subTest(extra=extra), patch.object(sys, 'argv', argv+[extra]), \
                 self.assertRaisesRegex(D.DeployError,'recovery_attestation_arguments_invalid'):
                D.main()

    def collector_fixture(self):
        config = self.write('install.config', {})
        raw = config.read_bytes()
        commit = 'a'*40
        version = 'v0.0.'+str(int(commit,16))
        manifest = self.write('manual/'+version+'/release-manifest.json', {})
        manifest.chmod(0o400)
        self.write('manual/operation.json', {'schema':1,'commit':commit,'version':version,
            'manifest_sha256':D.sha(manifest.read_bytes()),'config_sha256':D.sha(raw),
            'stage':'upgrade','mutator_dispatched':True})
        self.write('state/upgrade-'+version+'/operator-plan.json', {})
        self.write('state/upgrade-'+version+'/activate/request.json',
                   {'variables':{'ultra_lifecycle_id':self.original},'identity':self.sentinel})
        for lock in ('manual/deploy.lock','.install.config.manual-deploy.lock',
                     'state/operator/infrastructure.lock','state/infrastructure.lock'):
            self.write(lock, {})
        stage = self.h['attest_stage'](self.root/'absent')
        result = {'schema':1,'lifecycle':{'evidence':'absent'},'upgrade_activate':stage,
                  'bootstrap_inventory':stage,'bootstrap_phases':{},'worker_census':'not_performed',
                  'predecessor_causality_proven':False,'backup':{'evidence':'absent'},
                  'reconcile':{'evidence':'absent'}}
        return config, version, result

    def collect(self, config):
        return D.collect_recovery_attestation(self.root,self.root/'manual',config,self.root/'state',
                   'recovery-tools-bootstrap-operation-fixture','b'*64)

    def test_collector_uses_exact_pinned_transport_and_leaves_inputs_unchanged(self):
        config, version, remote = self.collector_fixture()
        before = {str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        transport = ['ssh','-F','/dev/null','-o','StrictHostKeyChecking=yes','root@192.0.2.1']
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY':''}), \
             patch.object(D,'operator_transport',return_value=(transport,'binding')), \
             patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(remote).encode())) as run:
            output = self.collect(config)
        self.assertEqual(run.call_args.args[0][:-1],transport)
        self.assertIn('python3 -I -c',run.call_args.args[0][-1])
        self.assertEqual(run.call_args.kwargs['stderr'],subprocess.DEVNULL)
        self.assertEqual(output['local']['original_lifecycle_id'],self.original)
        self.assertNotIn('secret-sentinel',json.dumps(output))
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_missing_original_id_is_a_blocker_before_ssh(self):
        config, version, remote = self.collector_fixture()
        (self.root/'state'/('upgrade-'+version)/'activate/request.json').unlink()
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY':''}), \
             patch.object(D,'operator_transport',return_value=(['ssh'],'binding')), \
             patch.object(subprocess,'run',side_effect=AssertionError('no SSH without original evidence')), \
             self.assertRaisesRegex(D.DeployError,'recovery_attestation_original_id_missing'):
            self.collect(config)

    def forward_fixture(self):
        config, version, remote = self.collector_fixture()
        journal = self.root/'manual/operation.json'
        current = json.loads(journal.read_bytes())
        commit = 'c'*40
        old_version = 'v0.0.'+str(int(commit,16))
        manifest = self.write('remote-manifest.json', {})
        staged = self.write('remote-config.json', {})
        proof = {'schema':1,'commit':commit,'version':old_version,'stage':'upgrade',
                 'mutator_dispatched':True,'remote_attempt':'d'*64,
                 'manifest_sha256':D.sha(manifest.read_bytes()),
                 'staged_config_sha256':D.sha(staged.read_bytes())}
        archive = self.write('manual/operation.forward-only-abandoned-1.json', proof)
        proof_sha = D.sha(archive.read_bytes())
        current.update({'forward_only':True,'forward_journal_sha256':proof_sha,
                        'remote_attempt':'e'*64,'staged_config_sha256':'f'*64})
        self.write('manual/operation.json', current)
        inputs = 'state/operator-inputs/manual-'+current['commit']+'-'+current['remote_attempt']
        remote_proof = self.write(inputs+'/forward-operation.json', proof)
        old_inputs = 'state/operator-inputs/manual-'+commit+'-'+proof['remote_attempt']
        self.write(old_inputs+'/release/release-manifest.json', {})
        self.write(old_inputs+'/install.config', {})
        remote_path = '/var/lib/ultra-ansible/upgrade-'+old_version
        original = str(D.uuid.UUID(bytes=hashlib.sha256(remote_path.encode()).digest()[:16],version=4))
        request = self.write('state/upgrade-'+old_version+'/activate/request.json', {
            'variables':{'ultra_lifecycle_id':original,
                         'ultra_release_manifest_sha256':proof['manifest_sha256']},
            'identity':self.sentinel})
        # The candidate never activated and has no local operator cache.
        shutil.rmtree(self.root/'state'/('upgrade-'+version))
        return config, current, remote, remote_proof, request, original

    def test_forward_collector_uses_exact_proof_without_local_activation_or_plan(self):
        config, current, remote, proof, request, original = self.forward_fixture()
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY':''}), \
             patch.object(D,'operator_transport',return_value=(['ssh'],'binding')), \
             patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(remote).encode())) as run:
            output = self.collect(config)
        self.assertEqual(output['local']['operator_plan'], {'evidence':'absent'})
        self.assertEqual(output['local']['original_lifecycle_id_source'],'remote_predecessor_request')
        self.assertNotIn('original_lifecycle_id',output['local'])
        self.assertIn(current['remote_attempt'],run.call_args.args[0][-1])
        self.assertIn(current['forward_journal_sha256'],run.call_args.args[0][-1])
        self.assertFalse(output['remote']['predecessor_causality_proven'])

    def test_forward_remote_attestation_failure_reports_only_stable_phase(self):
        config, current, remote, proof, request, original = self.forward_fixture()
        secret_output = b'host-secret /private/path 00000000-0000-4000-8000-000000000001 ' + b'a'*64
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY':''}), \
             patch.object(D,'operator_transport',return_value=(['ssh'],'binding')), \
             patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=255,stdout=secret_output,
                 stderr=secret_output)) as run:
            with self.assertRaisesRegex(D.DeployError,
                    '^recovery_attestation_remote_failed_phase_forward_predecessor$') as raised:
                self.collect(config)
        self.assertEqual(run.call_args.kwargs['stderr'],subprocess.DEVNULL)
        for value in (secret_output.decode(), 'host-secret', '/private/path', original,
                      current['forward_journal_sha256'], current['remote_attempt']):
            self.assertNotIn(value, str(raised.exception))

    def test_forward_collector_rejects_missing_or_changed_local_proof_before_ssh(self):
        config, current, remote, proof, request, original = self.forward_fixture()
        archive = self.root/'manual/operation.forward-only-abandoned-1.json'
        for missing in (False, True):
            if missing:
                archive.unlink()
            else:
                archive.write_text('{}')
            with self.subTest(missing=missing), \
                 patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY':''}), \
                 patch.object(D,'operator_transport',return_value=(['ssh'],'binding')), \
                 patch.object(subprocess,'run',side_effect=AssertionError('no SSH')), \
                 self.assertRaisesRegex(D.DeployError,'manual_forward_continuation_proof_changed'):
                self.collect(config)

    def test_remote_forward_original_projects_exact_predecessor_without_hashing_request(self):
        config, current, remote, proof, request, original = self.forward_fixture()
        digest = self.h['attest_digest']
        def safe_digest(path, **kwargs):
            self.assertNotEqual(Path(path),request)
            return digest(path, **kwargs)
        with patch.dict(self.h, {'attest_digest':safe_digest}):
            operation, observed = self.h['attest_forward_original'](self.root/'state',
                current['commit'],current['version'],current['remote_attempt'],current['forward_journal_sha256'])
        self.assertEqual(operation,request.parent.parent)
        self.assertEqual(observed,original)

    def test_remote_forward_original_rejects_missing_and_mismatched_evidence(self):
        config, current, remote, proof, request, original = self.forward_fixture()
        paths = (proof, request)
        for path in paths:
            raw = path.read_bytes()
            for missing in (False, True):
                if missing:
                    path.unlink()
                else:
                    path.write_text('{}')
                with self.subTest(path=path.name,missing=missing), self.assertRaises((ValueError,FileNotFoundError)):
                    self.h['attest_forward_original'](self.root/'state',current['commit'],current['version'],
                        current['remote_attempt'],current['forward_journal_sha256'])
                path.write_bytes(raw)

    def test_remote_forward_original_rejects_changed_uuid_or_manifest(self):
        config, current, remote, proof, request, original = self.forward_fixture()
        raw = json.loads(request.read_bytes())
        for key, value in (('ultra_lifecycle_id',self.original),('ultra_release_manifest_sha256','0'*64)):
            modified = json.loads(json.dumps(raw))
            modified['variables'][key] = value
            request.write_text(json.dumps(modified))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.h['attest_forward_original'](self.root/'state',current['commit'],current['version'],
                    current['remote_attempt'],current['forward_journal_sha256'])

    def test_unexpected_remote_identity_is_rejected(self):
        config, version, remote = self.collector_fixture()
        remote['identity'] = self.sentinel
        with self.assertRaises(ValueError):
            D.validate_recovery_attestation_remote(remote,self.h)

    def test_shared_operator_lock_excludes_collector(self):
        config, version, remote = self.collector_fixture()
        with D.existing_recovery_lock(self.root/'state/operator/infrastructure.lock'), \
             self.assertRaises(BlockingIOError):
            self.collect(config)


class LocalPreflightRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.root = self.repo / 'manual'; self.root.mkdir(mode=0o700)
        self.state = self.repo / 'state'; self.state.mkdir(mode=0o700)
        (self.state/'operator').mkdir(mode=0o700)
        self.config = self.repo/'install.config'
        self.version = 'v0.0.'+str(int(D.LOCAL_PREFLIGHT_COMMIT,16))
        self.release = self.root/self.version; self.release.mkdir(mode=0o700)
        self.operation = self.state/('upgrade-'+self.version); self.operation.mkdir(mode=0o700)
        for name in ('execution-mode.json','operator-plan.json','runtime-use.json','readiness-diagnostic-123.json'):
            D.atomic_write(self.operation/name,b'{}')
        D.atomic_write(self.release/'release-manifest.json',b'{}')
        self.previous = b'INSTALL_SCHEMA_VERSION=2\n'
        self.current = D.config_candidate(self.previous,self.version,self.release)
        D.atomic_write(self.config,self.current)
        self.backup = self.root/('install.config.before-'+self.version+'-123')
        D.atomic_write(self.backup,self.previous)
        self.record = {'schema':1,'commit':D.LOCAL_PREFLIGHT_COMMIT,'version':self.version,'adopt':False,
                       'backup':self.backup.name,'previous_sha256':D.sha(self.previous),'config_sha256':D.sha(self.current),
                       'stage':'upgrade','mutator_dispatched':True,'transport_binding':None,'manifest_sha256':None,
                       'remote_attempt':None,'probe_sha256':'','forward_only':False,'forward_journal_sha256':''}
        self.journal=self.root/'operation.json'; self.save()
        for path in (self.root/'deploy.lock', D.canonical_config_lock(self.config),
                     self.state/'operator/infrastructure.lock',self.state/'infrastructure.lock'):
            D.atomic_write(path,b'')
        self.helper=self.repo/'proof-helper'
        self.helper.write_text('''#!/usr/bin/python3
import json,sys
a=dict(zip(sys.argv[2::2],sys.argv[3::2]))
n=a['--nonce']
print(json.dumps({'schema':1,'nonce':n,'config_sha256':a['--config-sha256'],
 'manifest_sha256':a['--manifest-sha256'],'pre_mutation':True}),flush=True)
if sys.stdin.readline().strip()!='ack '+n: sys.exit(1)
print('acknowledged '+n,flush=True)
''')
        self.helper.chmod(0o700)

    def save(self):
        self.raw=json.dumps(self.record).encode(); D.atomic_write(self.journal,self.raw)

    def bridge(self, command, *args, **kwargs):
        import shlex
        argv=shlex.split(command[-1])
        return json.dumps({'schema':1,'nonce':argv[-2],'version':argv[-1],'contradictions':False,
                           'boot_sha256':'a'*64,'process_count':20})

    def recover(self, **changes):
        args=dict(repo=self.repo,root=self.root,config=self.config,installer=self.helper,
                  journal_sha=D.sha(self.raw),backup_sha=D.sha(self.previous),config_sha=D.sha(self.current),state_root=self.state)
        args.update(changes)
        with D.existing_recovery_lock(self.root/'deploy.lock'), D.existing_recovery_lock(D.canonical_config_lock(self.config)), \
                patch.object(D,'local_recovery_census',return_value=20), \
                patch.object(D,'operator_transport',return_value=(['ssh','fixture'],'c'*64)), \
                patch.object(D,'collect_local_preflight_bridge',side_effect=self.bridge):
            return D.recover_local_preflight(**args)

    def test_archive_preserves_exact_inputs_and_is_idempotent(self):
        archive=self.recover()
        self.assertFalse(self.journal.exists())
        self.assertEqual((archive/'operation.json').read_bytes(),self.raw)
        self.assertEqual(self.config.read_bytes(),self.current)
        self.assertEqual(self.backup.read_bytes(),self.previous)
        receipt=json.loads((archive/'receipt.json').read_bytes())
        self.assertEqual(receipt['kind'],'local-preflight-no-mutator-dispatch')
        self.assertEqual(receipt['collection_transport_binding'],'c'*64)
        self.assertIsNone(json.loads((archive/'operation.json').read_bytes())['remote_attempt'])
        self.assertEqual(self.recover(),archive)

    def test_original_locks_refuse_recovery(self):
        for path in (self.root/'deploy.lock',D.canonical_config_lock(self.config),
                     self.state/'operator/infrastructure.lock',self.state/'infrastructure.lock'):
            with self.subTest(path=path),D.existing_recovery_lock(path),self.assertRaises(BlockingIOError):
                self.recover()
        self.assertEqual(self.journal.read_bytes(),self.raw)

    def test_extra_mutating_incomplete_or_unknown_stage_rejected(self):
        for name in ('activate','inspect','lifecycle-applying-123','enforce','resume','completed.json','unknown','.prepare'):
            with self.subTest(stage=name):
                path=self.operation/name;path.mkdir(mode=0o700)
                with self.assertRaisesRegex(D.DeployError,'local_preflight_stage_inventory_invalid'):
                    self.recover()
                path.rmdir()
        self.assertTrue(self.journal.exists())

    def test_surviving_mutating_child_keeps_its_durable_stage(self):
        # command.Run can outlive its controller, but preparation preceded it.
        (self.operation/'activate').mkdir(mode=0o700)
        child=subprocess.Popen(['/usr/bin/sleep','30'])
        try:
            with self.assertRaisesRegex(D.DeployError,'local_preflight_stage_inventory_invalid'):
                self.recover()
            self.assertIsNone(child.poll())
        finally:
            child.terminate();child.wait()

    def test_replaced_inode_with_identical_bytes_rejected(self):
        original=self.bridge
        def replaced(*args,**kwargs):
            path=self.operation/'operator-plan.json'
            D.atomic_write(path,path.read_bytes())
            return original(*args,**kwargs)
        self.bridge=replaced
        with self.assertRaisesRegex(D.DeployError,'local_preflight_input_changed'):
            self.recover()
        self.assertEqual(self.journal.read_bytes(),self.raw)

    def test_dead_helper_before_ack_refuses_archive(self):
        self.helper.write_text(self.helper.read_text().split('if sys.stdin')[0])
        original=self.bridge
        def delay(*args,**kwargs):
            time.sleep(.1)
            return original(*args,**kwargs)
        self.bridge=delay
        with self.assertRaisesRegex(D.DeployError,'local_preflight_helper_unavailable'):
            self.recover()
        self.assertTrue(self.journal.exists())

    def test_archive_crash_before_rename_can_retry(self):
        with patch.object(D,'recovery_rename_exclusive',side_effect=OSError('simulated crash')):
            with self.assertRaises(OSError):self.recover()
        self.assertTrue(self.journal.exists())
        archive=self.recover()
        self.assertEqual((archive/'operation.json').read_bytes(),self.raw)

    def test_archive_crash_after_rename_is_idempotent(self):
        rename=D.recovery_rename_exclusive
        def crash(*args):
            rename(*args)
            raise OSError('simulated death after atomic rename')
        with patch.object(D,'recovery_rename_exclusive',side_effect=crash):
            with self.assertRaises(OSError):self.recover()
        self.assertFalse(self.journal.exists())
        archive=self.recover()
        self.assertEqual((archive/'operation.json').read_bytes(),self.raw)

    def test_bridge_contradiction_and_changed_config_refuse(self):
        original=self.bridge
        def contradiction(*args,**kwargs):
            proof=json.loads(original(*args,**kwargs));proof['contradictions']=True
            return json.dumps(proof)
        self.bridge=contradiction
        with self.assertRaisesRegex(D.DeployError,'local_preflight_bridge_proof_invalid'):self.recover()
        self.bridge=original
        D.atomic_write(self.config,self.current+b'# changed\n')
        with self.assertRaisesRegex(D.DeployError,'local_preflight_exact_inputs_required'):self.recover()

    def test_input_snapshot_rejects_symlink_and_census_permission_errors(self):
        pins=D.RecoveryInputs()
        try:
            pins.retain(self.config)
            replacement=self.repo/'replacement';replacement.write_bytes(self.current)
            os.replace(replacement,self.config)
            with self.assertRaisesRegex(D.DeployError,'local_preflight_input_changed'):pins.unchanged()
        finally:pins.close()
        with patch.object(Path,'read_text',side_effect=PermissionError('opaque proc')):
            with self.assertRaisesRegex(D.DeployError,'local_preflight_process_uncertain'):D.local_recovery_census()

    def census_fixture(self):
        proc=self.repo/'proc'
        for name in ('1','999','self'):(proc/name).mkdir(parents=True)
        (proc/'1/comm').write_text('systemd\n')
        (proc/'1/status').write_text('NSpid:\t1\n')
        (proc/'self/status').write_text('NSpid:\t999\n')
        (proc/'self/mountinfo').write_text('1 0 0:1 / /proc rw - proc proc rw\n')
        for pid in ('1','999'):
            (proc/pid/'stat').write_text(pid+' (fixture) '+' '.join(['S']+['0']*18+['123']))
            (proc/pid/'cmdline').write_bytes(b'/usr/bin/python3\0')
        scope={'os':os,'need':lambda value:D.require(value,'namespace_rejected')}
        exec(D.RECOVERY_PROCESS_CENSUS,scope)
        return proc,scope['census']

    def test_census_accepts_exact_namespace_without_privileged_readlink(self):
        proc,census=self.census_fixture()
        with patch.object(os,'readlink',side_effect=PermissionError('ptrace denied')) as readlink:
            self.assertEqual(census(proc,999),2)
            readlink.assert_not_called()

    def test_census_rejects_unknown_namespace(self):
        proc,census=self.census_fixture()
        for status in ('NSpid:\t999\t1000\n','NSpid:\t998\n','NSpid:\tinvalid\n','Name:\tpython3\n'):
            with self.subTest(self_status=status):
                (proc/'self/status').write_text(status)
                with self.assertRaises((D.DeployError,StopIteration)):
                    census(proc,999)
        (proc/'self/status').write_text('NSpid:\t999\n')
        for status in ('NSpid:\t2\n','NSpid:\t1\t2\n','NSpid:\tinvalid\n','Name:\tsystemd\n'):
            with self.subTest(pid1_status=status):
                (proc/'1/status').write_text(status)
                with self.assertRaises((D.DeployError,StopIteration)):
                    census(proc,999)

    def test_census_rejects_unreadable_process_records(self):
        proc,census=self.census_fixture()
        read_bytes=Path.read_bytes
        for name in ('stat','cmdline'):
            target=proc/'1'/name
            def guarded(path):
                if path==target:raise PermissionError('opaque process')
                return read_bytes(path)
            with self.subTest(record=name),patch.object(Path,'read_bytes',guarded):
                with self.assertRaises(PermissionError):census(proc,999)

    def test_census_rejects_conflicting_installer_and_ansible(self):
        proc,census=self.census_fixture()
        for command in (b'/usr/bin/ultra-install\0',b'/usr/bin/ansible-playbook\0'):
            with self.subTest(command=command):
                (proc/'1/cmdline').write_bytes(command)
                with self.assertRaisesRegex(D.DeployError,'namespace_rejected'):
                    census(proc,999)

    def test_helper_timeout_is_fail_closed(self):
        process=SimpleNamespace(stdout=io.BytesIO())
        with patch.object(D.select,'select',return_value=([],[],[])):
            with self.assertRaisesRegex(D.DeployError,'local_preflight_helper_unavailable'):
                D.recovery_helper_line(process)

    def test_archive_directory_entry_is_durable_before_journal_rename(self):
        events=[]
        write=D.atomic_write;sync=os.fsync;rename=D.recovery_rename_exclusive
        def writing(path,*args,**kwargs):
            result=write(path,*args,**kwargs)
            if path.name in ('receipt.json','metadata.json'):events.append(path.name+' durable')
            return result
        def syncing(fd):
            target=Path(os.readlink('/proc/self/fd/'+str(fd)))
            if target==self.root:events.append('root fsync')
            elif target.name.startswith('operation.local-preflight-'):events.append('archive fsync')
            return sync(fd)
        def renaming(*args):
            events.append('rename')
            return rename(*args)
        with patch.object(D,'atomic_write',side_effect=writing),patch.object(os,'fsync',side_effect=syncing), \
                patch.object(D,'recovery_rename_exclusive',side_effect=renaming):
            self.recover()
        receipt=events.index('receipt.json durable');metadata=events.index('metadata.json durable')
        first_root=events.index('root fsync');move=events.index('rename')
        self.assertLess(receipt,metadata);self.assertLess(metadata,first_root);self.assertLess(first_root,move)
        self.assertEqual(events[move+1:],['archive fsync','root fsync'])

    def test_hanging_remote_proof_is_killed_and_cannot_archive(self):
        collector=D.collect_local_preflight_bridge
        pidfile=self.repo/'hung-probe-pid'
        program='import os,pathlib,time;pathlib.Path('+repr(str(pidfile))+').write_text(str(os.getpid()));time.sleep(30)'
        def hanging(*args,**kwargs):
            return collector([D.sys.executable,'-c',program],self.repo,timeout=.2)
        self.bridge=hanging
        with self.assertRaisesRegex(D.DeployError,'local_preflight_bridge_timeout'):
            self.recover()
        self.assertTrue(self.journal.exists())
        self.assertFalse(list(self.root.glob('operation.local-preflight-*')))
        self.assertEqual(self.config.read_bytes(),self.current)
        pid=int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
        # Both old local execution locks were released on the error path.
        with D.existing_recovery_lock(self.state/'operator/infrastructure.lock'), \
                D.existing_recovery_lock(self.state/'infrastructure.lock'):
            pass



class ReimagedAdoptionArchive(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.root = self.repo / 'dist/manual'
        self.root.mkdir(parents=True, mode=0o700)
        self.config = self.repo / 'install.config'
        self.current = b'# new fleet: preserve byte for byte\nINSTALL_SCHEMA_VERSION=2\n'
        D.atomic_write(self.config, self.current)
        self.previous = b'INSTALL_SCHEMA_VERSION=2\nBRIDGE=192.0.2.10\nBRIDGE_SSH_HOST=192.0.2.10\nULTRA_AUTOMATION_VERSION=v2.4.2\n'
        commit = 'a' * 40
        version = 'v0.0.' + str(int(commit, 16))
        attempt = D.remote_attempt(self.previous, version, allow_legacy_keys=True)
        release = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + commit + '-' + attempt) / 'release'
        self.backup = self.root / ('install.config.before-' + version + '-123')
        D.atomic_write(self.backup, self.previous)
        self.record = {'schema': 1, 'adopt': True, 'stage': 'adoption_apply', 'mutator_dispatched': True,
                       'commit': commit, 'version': version, 'remote_attempt': attempt, 'manifest_sha256': 'd' * 64,
                       'transport_binding': 'c' * 64,
                       'previous_sha256': D.sha(self.previous), 'backup': self.backup.name,
                       'config_sha256': D.sha(D.config_candidate(self.previous, version, release))}
        self.journal = self.root / 'operation.json'
        self.save_record()
        self.reason = 'All former fleet targets wiped and reimaged by operator'

    def save_record(self):
        self.raw = json.dumps(self.record, sort_keys=True).encode()
        D.atomic_write(self.journal, self.raw)

    def archive(self, **changes):
        arguments = dict(root=self.root, config=self.config, journal_sha=D.sha(self.raw),
                         backup_sha=D.sha(self.previous), config_sha=D.sha(self.current),
                         reason=self.reason, acknowledged=True)
        arguments.update(changes)
        with patch.object(D, 'run', side_effect=AssertionError('remote/build command forbidden')), patch.object(
                D, 'rollout', side_effect=AssertionError('deployment forbidden')):
            return D.archive_reimaged_adoption(**arguments)

    def test_archive_preserves_current_config_backup_and_original_journal_and_is_idempotent(self):
        identity = self.config.stat()
        archive = self.archive()
        self.assertFalse(self.journal.exists())
        self.assertEqual((archive / 'operation.json').read_bytes(), self.raw)
        self.assertEqual(self.backup.read_bytes(), self.previous)
        self.assertEqual(self.config.read_bytes(), self.current)
        self.assertEqual(self.config.stat(), identity)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o700)
        for path in archive.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        metadata = json.loads((archive / 'metadata.json').read_bytes())
        self.assertEqual(metadata['journal_sha256'], D.sha(self.raw))
        self.assertEqual(metadata['backup_sha256'], D.sha(self.previous))
        self.assertEqual(metadata['config_sha256'], D.sha(self.current))
        self.assertEqual(metadata['reason'], self.reason)
        before = (archive / 'metadata.json').read_bytes()
        self.assertEqual(self.archive(), archive)
        self.assertEqual((archive / 'metadata.json').read_bytes(), before)

    def test_legacy_fields_are_allowed_only_for_historical_attempt_validation(self):
        with self.assertRaisesRegex(D.DeployError, '^operator_legacy_config_key_forbidden$'):
            D.remote_attempt(self.previous, self.record['version'])
        self.assertEqual(D.remote_attempt(self.previous, self.record['version'], allow_legacy_keys=True),
                         self.record['remote_attempt'])
        self.assertTrue(self.journal.exists())

    def test_requires_exact_adoption_class_and_metadata(self):
        original = dict(self.record)
        for key, value in [('schema', True), ('schema', 2), ('adopt', False), ('stage', 'upgrade'),
                           ('mutator_dispatched', False), ('remote_attempt', 'f' * 64),
                           ('manifest_sha256', None), ('transport_binding', None), ('transport_binding', 'C' * 64),
                           ('previous_sha256', 'f' * 64),
                           ('config_sha256', 'f' * 64), ('backup', '../install.config'), ('forward_only', True),
                           ('forward_only', False), ('forward_only', None), ('unknown_marker', True),
                           ('staged_config_sha256', 'e' * 64), ('forward_journal_sha256', 'e' * 64),
                           ('forward_prior_journal_sha256', 'e' * 64)]:
            with self.subTest(key=key, value=value):
                self.record = dict(original, **{key: value})
                self.save_record()
                with self.assertRaises(D.DeployError):
                    self.archive()
                self.assertEqual(self.journal.read_bytes(), self.raw)
                self.assertEqual(self.config.read_bytes(), self.current)
        self.assertFalse(list(self.root.glob('operation.reimaged-adoption-*')))

    def test_explicit_acknowledgment_digests_and_reason_required(self):
        for change in [{'acknowledged': False}, {'reason': ''}, {'reason': 'line\nbreak'},
                       {'journal_sha': 'f' * 64}, {'backup_sha': 'f' * 64}, {'config_sha': 'f' * 64}]:
            with self.subTest(change=change), self.assertRaises(D.DeployError):
                self.archive(**change)
        self.assertEqual(self.journal.read_bytes(), self.raw)
        self.assertFalse(list(self.root.glob('operation.reimaged-adoption-*')))

    def test_symlinks_and_nonprivate_or_hardlinked_inputs_rejected(self):
        for path in [self.config, self.backup, self.journal]:
            with self.subTest(path=path.name):
                path.chmod(0o644)
                with self.assertRaises(D.DeployError):
                    self.archive()
                path.chmod(0o600)
                moved = path.with_name(path.name + '.saved')
                path.rename(moved)
                path.symlink_to(moved)
                with self.assertRaises((D.DeployError, OSError)):
                    self.archive()
                path.unlink()
                os.link(moved, path)
                with self.assertRaises(D.DeployError):
                    self.archive()
                path.unlink()
                moved.rename(path)
        self.assertEqual(self.journal.read_bytes(), self.raw)

    def test_existing_archive_collision_never_overwritten(self):
        archive = self.root / ('operation.reimaged-adoption-' + D.sha(self.raw))
        archive.mkdir(mode=0o700)
        D.atomic_write(archive / 'unrelated-proof', b'retain')
        with self.assertRaises(D.DeployError):
            self.archive()
        self.assertEqual((archive / 'unrelated-proof').read_bytes(), b'retain')
        self.assertEqual(self.journal.read_bytes(), self.raw)

    def test_interrupted_before_and_after_journal_rename_can_resume(self):
        real_cdll = D.ctypes.CDLL
        for after in (False, True):
            with self.subTest(after=after):
                def interrupted(*args, **kwargs):
                    libc = real_cdll(*args, **kwargs)
                    real_rename = libc.renameat2
                    def rename(source_fd, source, target_fd, target, flag):
                        if source == b'operation.json':
                            if after:
                                self.assertEqual(real_rename(source_fd, source, target_fd, target, flag), 0)
                            raise OSError('simulated_crash')
                        return real_rename(source_fd, source, target_fd, target, flag)
                    libc.renameat2 = rename
                    return libc
                with patch.object(D.ctypes, 'CDLL', side_effect=interrupted), self.assertRaisesRegex(OSError, 'simulated_crash'):
                    self.archive()
                archive = self.archive()
                self.assertEqual((archive / 'operation.json').read_bytes(), self.raw)
                self.assertEqual(self.config.read_bytes(), self.current)
                if not after:
                    # Reset only this fixture for the second crash boundary.
                    (archive / 'operation.json').rename(self.journal)
                    (archive / 'metadata.json').unlink()
                    archive.rmdir()

    def test_atomic_publication_collision_keeps_original_journal_and_foreign_proof(self):
        real_cdll = D.ctypes.CDLL
        archive = self.root / ('operation.reimaged-adoption-' + D.sha(self.raw))
        def collide(*args, **kwargs):
            archive.mkdir(mode=0o700)
            D.atomic_write(archive / 'foreign-proof', b'retain')
            return real_cdll(*args, **kwargs)
        with patch.object(D.ctypes, 'CDLL', side_effect=collide), self.assertRaises(OSError):
            self.archive()
        self.assertEqual(self.journal.read_bytes(), self.raw)
        self.assertEqual((archive / 'foreign-proof').read_bytes(), b'retain')

    def test_fsync_failure_after_move_retains_evidence_and_retry_succeeds(self):
        real_fsync = D.os.fsync
        def fail_after_move(descriptor):
            if not self.journal.exists():
                raise OSError('fsync_interrupted')
            real_fsync(descriptor)
        with patch.object(D.os, 'fsync', side_effect=fail_after_move), self.assertRaisesRegex(OSError, 'fsync_interrupted'):
            self.archive()
        archive = self.archive()
        self.assertEqual((archive / 'operation.json').read_bytes(), self.raw)
        self.assertEqual(self.config.read_bytes(), self.current)

    def test_config_mutation_before_rename_keeps_active_journal(self):
        original_write = D.atomic_write
        def mutate(path, raw, **kwargs):
            original_write(path, raw, **kwargs)
            if path.name == 'metadata.json':
                self.config.write_bytes(self.current + b'changed')
        with patch.object(D, 'atomic_write', side_effect=mutate), self.assertRaises(D.DeployError):
            self.archive()
        self.assertEqual(self.journal.read_bytes(), self.raw)
        self.assertFalse(list(self.root.glob('operation.reimaged-adoption-*')))
        self.assertTrue(list(self.root.glob('.reimaged-adoption-*')))

    def test_retry_rejects_changed_evidence_config_backup_or_acknowledgment(self):
        archive = self.archive()
        for change in [{'reason': 'different'}, {'acknowledged': False}]:
            with self.subTest(change=change), self.assertRaises(D.DeployError):
                self.archive(**change)
        for path in [self.config, self.backup, archive / 'operation.json', archive / 'metadata.json']:
            raw = path.read_bytes()
            path.write_bytes(raw + b' ')
            with self.subTest(path=path.name), self.assertRaises(D.DeployError):
                self.archive()
            path.write_bytes(raw)
        self.assertEqual((archive / 'operation.json').read_bytes(), self.raw)

    def test_cli_is_local_even_with_dirty_checkout_and_has_no_prerequisites(self):
        argv = ['manual-deploy.py', '--archive-reimaged-adoption', '--acknowledge-former-hosts-reimaged',
                '--archive-reason', self.reason, '--journal-sha256', D.sha(self.raw),
                '--backup-sha256', D.sha(self.previous), '--config-sha256', D.sha(self.current)]
        with patch.object(D, '__file__', str(self.repo / 'scripts/manual-deploy.py')), patch.object(
                D.sys, 'argv', argv), patch.dict(D.os.environ, {'ADOPT': '0'}), patch.object(
                D.shutil, 'which', side_effect=AssertionError('no tools')), patch.object(
                D, 'run', side_effect=AssertionError('no subprocess')), patch.object(
                D, 'build_candidate', side_effect=AssertionError('no build')), contextlib.redirect_stdout(io.StringIO()):
            D.main()
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.config.read_bytes(), self.current)


class ForwardContinuationAttestationDiagnostics(unittest.TestCase):
    def failure(self, returncode, stderr):
        sentinel = b'private-host.example 192.0.2.23 /private/path candidate-secret DB-secret KEY-secret'
        def process(command, **kwargs):
            kwargs['stderr'].write(stderr + b'\n' + sentinel)
            return subprocess.CompletedProcess(command, returncode, stdout=sentinel)
        output = io.StringIO()
        with patch.object(D.subprocess, 'run', side_effect=process), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaises(D.DeployError) as raised:
                D.run(['fixture'], Path('.'), 'forward_continuation_attestation', capture=True)
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn('private', str(raised.exception))
        self.assertNotIn('secret', str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        return str(raised.exception)

    def test_timeout_is_classified_without_exposing_transport_output(self):
        self.assertEqual(self.failure(255, b'ssh: connect to host private-host.example port 22: Connection timed out'),
                         'forward_continuation_attestation_failed_exit_255_phase_transport_ssh_timeout')

    def test_other_transport_failures_have_fixed_codes(self):
        for stderr, reason in [(b'Connection refused', 'ssh_refused'),
                               (b'No route to host', 'ssh_unreachable'),
                               (b'Could not resolve hostname secret', 'ssh_dns_failed'),
                               (b'Host key verification failed', 'ssh_host_key_failed'),
                               (b'Permission denied (publickey)', 'ssh_auth_failed'),
                               (b'arbitrary failure data', 'ssh_failed')]:
            with self.subTest(reason=reason):
                self.assertEqual(self.failure(255, stderr),
                                 'forward_continuation_attestation_failed_exit_255_phase_transport_' + reason)

    def test_remote_marker_is_allowlisted_and_arbitrary_output_is_suppressed(self):
        self.assertEqual(self.failure(1, b'ultra_forward_attestation:remote_verification:lifecycle_changed'),
                         'forward_continuation_attestation_failed_exit_1_phase_remote_verification_lifecycle_changed')
        for stderr in [b'Traceback arbitrary private data',
                       b'ultra_forward_attestation:remote_verification:secret',
                       b'ultra_forward_attestation:private:missing_evidence',
                       b'ultra_forward_attestation:remote_verification:lifecycle_changed secret']:
            with self.subTest(stderr=stderr):
                self.assertEqual(self.failure(1, stderr),
                                 'forward_continuation_attestation_failed_exit_1_phase_remote_unknown')

    def test_remote_exception_hook_never_emits_exception_text(self):
        start = D.REMOTE_PROGRAM.index("if mode=='continue':\n    attestation_phase=")
        hook = D.REMOTE_PROGRAM[start:D.REMOTE_PROGRAM.index('forward_journal_sha=', start)]
        for error, reason in [(ValueError('manual_forward_continuation_lifecycle_changed'), 'lifecycle_changed'),
                              (FileNotFoundError('/private/path secret'), 'missing_evidence'),
                              (FileNotFoundError(2, 'missing', '/private/upgrade-v0.0.123/activate/request.json'),
                               'predecessor_activation_evidence_missing'),
                              (FileNotFoundError(2, 'missing', '/private/upgrade-v0.0.123/lifecycle.json'),
                               'lifecycle_evidence_missing'),
                              (FileNotFoundError(2, 'missing', '/private/path/forward-operation.json'),
                               'forward_proof_missing'),
                              (PermissionError('/private/path secret'), 'permission_denied'),
                              (BlockingIOError('secret'), 'lock_busy'),
                              (ValueError('arbitrary secret'), 'invalid_evidence'),
                              (RuntimeError('arbitrary secret'), 'unexpected_failure')]:
            scope = {'mode': 'continue', 'sys': D.sys, 'Path': D.Path, 're': D.re}
            output = io.StringIO()
            with self.subTest(reason=reason), patch.object(D.sys, 'excepthook'), \
                 contextlib.redirect_stderr(output):
                exec(hook, scope)
                D.sys.excepthook(type(error), error, None)
            self.assertEqual(output.getvalue(), 'ultra_forward_attestation:remote_setup:' + reason + '\n')
            self.assertNotIn('/private', output.getvalue())

    def test_classified_timeout_keeps_three_attempt_retry_limit(self):
        code = 'forward_continuation_attestation_failed_exit_255_phase_transport_ssh_timeout'
        with patch.object(D, 'run', side_effect=D.DeployError(code)) as runner, \
             patch.object(D.time, 'sleep') as sleep:
            with self.assertRaisesRegex(D.DeployError, '^' + code + '$'):
                D.run_forward_continuation_attestation(['ssh', '-o', 'ConnectTimeout=15', 'fixture'], Path('.'))
        self.assertEqual(runner.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4])



class ForwardContinuationAttestationRetry(unittest.TestCase):
    def test_retries_exit_255_then_returns_success(self):
        responses = [D.DeployError('forward_continuation_attestation_failed_exit_255'), 'receipt']
        command = ['ssh', '-o', 'ConnectTimeout=15', 'python3 -c read-only-probe']
        with patch.object(D, 'run', side_effect=responses) as runner, \
             patch.object(D.time, 'sleep') as sleep:
            self.assertEqual(D.run_forward_continuation_attestation(command, Path('.')), 'receipt')
        self.assertEqual(runner.call_count, 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2])
        self.assertEqual(command[2], 'ConnectTimeout=15')
        self.assertTrue(all(call.args[0][2] == 'ConnectTimeout=30' for call in runner.call_args_list))

    def test_exhausts_three_exit_255_attempts(self):
        failure = D.DeployError('forward_continuation_attestation_failed_exit_255')
        command = ['ssh', '-o', 'ConnectTimeout=15', 'python3 -c read-only-probe']
        with patch.object(D, 'run', side_effect=[failure, failure, failure]) as runner, \
             patch.object(D.time, 'sleep') as sleep:
            with self.assertRaisesRegex(D.DeployError, 'failed_exit_255'):
                D.run_forward_continuation_attestation(command, Path('.'))
        self.assertEqual(runner.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4])

    def test_does_not_retry_other_exit_codes(self):
        command = ['ssh', '-o', 'ConnectTimeout=15', 'python3 -c read-only-probe']
        with patch.object(D, 'run', side_effect=D.DeployError(
                'forward_continuation_attestation_failed_exit_1')) as runner, \
             patch.object(D.time, 'sleep') as sleep:
            with self.assertRaisesRegex(D.DeployError, 'failed_exit_1'):
                D.run_forward_continuation_attestation(command, Path('.'))
        runner.assert_called_once()
        sleep.assert_not_called()


class ManualDeploy(unittest.TestCase):
    def test_legacy_source_remains_canonical_and_fresh_upgrade_selects_runtime(self):
        legacy = {'commit': 'a' * 40, 'version': 'v0.0.1'}
        self.assertEqual(D.deployment_secrets_source(legacy, ['ssh'], False, legacy['commit'], legacy['version']), 'canonical')
        self.assertEqual(D.deployment_secrets_source(legacy, ['ssh'], False, 'b' * 40, 'v0.0.2'), 'installed-runtime')
        self.assertEqual(D.deployment_secrets_source({}, ['ssh'], True, legacy['commit'], legacy['version']), 'canonical')
        runtime = dict(legacy, secrets_source='installed-runtime')
        self.assertEqual(D.deployment_secrets_source(runtime, ['ssh'], False, legacy['commit'], legacy['version']), 'installed-runtime')
        with self.assertRaisesRegex(D.DeployError, 'manual_secrets_source_invalid'):
            D.deployment_secrets_source(runtime, None, False, legacy['commit'], legacy['version'])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.root = self.repo / 'state'
        self.root.mkdir(mode=0o700)
        self.config = self.repo / 'install.config'
        self.original = b'# keep\nINSTALL_SCHEMA_VERSION=2\nOTHER="literal $() ${HOME}"\nULTRA_AUTOMATION_VERSION=v1.2.3\nULTRA_AUTOMATION_RELEASE_DIR=/old\n'
        self.config.write_bytes(self.original)
        self.config.chmod(0o600)
        self.commit = 'a' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.bundle = self.root / self.version
        self.bundle.mkdir()
        (self.bundle / 'release-manifest.json').write_bytes(b'fixture-manifest')
        self.calls = []
        self.probe_inputs = {}

    def run_fixture(self, command, cwd, stage, capture=False, env=None):
        self.calls.append((stage, command))

    def read_probe_input(self, path, limit=4096):
        path = Path(path)
        if path in self.probe_inputs and path.exists():
            return self.probe_inputs[path][:limit + 1]
        return SUBSCRIPTION_PROBE_INPUT(path, limit)

    def rollout(self, adopt=False, runner=None, config_path=None, retry_failed=False, probe_env_file=None, forward_only=False, continue_forward_only=False):
        probe_input = self.read_probe_input if hasattr(self, 'probe_inputs') else SUBSCRIPTION_PROBE_INPUT
        with patch.object(D, 'subscription_probe_input', side_effect=probe_input), patch.object(D, 'run', runner or self.run_fixture), patch.object(D.platform, 'system', return_value='Linux'), patch.object(D.platform, 'machine', return_value='x86_64'), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            D.rollout(self.repo, self.root, self.bundle, self.commit, self.version, adopt, config_path, retry_failed, probe_env_file, forward_only, continue_forward_only)

    def probe_env(self, value=b'https://old.example.com/sub/probe-value'):
        path = self.repo / '.env'
        self.probe_inputs[path] = b'IGNORED_SETTING="$(must-not-execute)\xff\nULTRA_SUBSCRIPTION_PROBE_URL=' + value + b'\n'
        path.write_bytes(b'private fixture input\n')
        path.chmod(0o600)
        return path

    def test_probe_env_allowlist_literals_and_invalid_inputs(self):
        path = self.probe_env(b'"https://old.example.com/sub/probe-value" # comment')
        with patch.object(D, 'subscription_probe_input', side_effect=self.read_probe_input):
            self.assertEqual(D.subscription_probe_from_env(path), b'https://old.example.com/sub/probe-value')
        for value in (b'', b'http://old.example.com/sub/token', b'https://old.example.com/sub/token?secret=1',
                      b'https://old.example.com/sub/token#fragment', b'https://user@old.example.com/sub/token',
                      b'https://old.example.com:443/sub/token', b'"$(secret)"', b'"unterminated', b'\xff',
                      b'https://old.example.com/sub/token\nULTRA_SUBSCRIPTION_PROBE_URL=https://old.example.com/sub/other'):
            with self.subTest(value=value):
                self.probe_env(value)
                with patch.object(D, 'subscription_probe_input', side_effect=self.read_probe_input):
                    with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_invalid$'):
                        D.subscription_probe_from_env(path)
        self.probe_inputs.pop(path)
        path.write_bytes(b'OTHER=private-value\n')
        self.assertIsNone(D.subscription_probe_from_env(path, optional=True))
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_key_missing$'):
            D.subscription_probe_from_env(path)
        path.unlink()
        self.assertIsNone(D.subscription_probe_from_env(path, optional=True))
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_file_missing$'):
            D.subscription_probe_from_env(path)

    def test_local_probe_snapshot_argv_secrecy_cleanup_and_replay_binding(self):
        secret = b'https://old.example.com/sub/fixture-token'
        self.probe_env(secret)
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            self.assertNotIn(secret.decode(), repr(command))
            if stage == 'upgrade':
                snapshot = Path(command[command.index('--subscription-probe-url-file') + 1])
                self.assertEqual(D.subscription_probe_input(snapshot), secret)
        self.rollout(runner=runner)
        self.assertFalse((self.root / 'subscription-probe-url').exists())
        self.assertNotIn(secret, self.config.read_bytes())
        self.assertEqual(next(self.root.glob('probe-binding-*')).read_bytes(), D.sha(secret).encode())
        self.probe_env(b'https://old.example.com/sub/replacement')
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_probe_changed$'):
            self.rollout()

    def test_local_dispatched_probe_retry_preserves_frozen_inputs_until_migration(self):
        path = self.probe_env()
        def failed(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_failed'):
            self.rollout(runner=failed)
        before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        self.probe_env(b'https://old.example.com/sub/replacement')
        for retry in (False, True):
            with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
                self.rollout(probe_env_file=path, retry_failed=retry)
        path.unlink()
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            self.rollout(retry_failed=True)
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}, before)

    def test_killed_manual_parent_cannot_retry_with_detached_worker_alive(self):
        worker = '''import os,pathlib,sys,time
root=pathlib.Path(sys.argv[1])
(root/'worker-started').write_text(str(os.getpid()))
for _ in range(500):
    if (root/'allow-worker').exists():
        (root/'old-worker-mutation').write_text('late')
        break
    time.sleep(.01)
'''
        helper = '''import importlib.util,pathlib,subprocess,sys
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('manual_fixture',sys.argv[1])
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
repo,root,bundle=map(pathlib.Path,sys.argv[2:5])
def run(command,cwd,stage,**kwargs):
    if stage=='upgrade':
        subprocess.run([sys.executable,'-I','-c',sys.argv[7],str(root)],
                       start_new_session=True,check=True)
with patch.object(d,'run',side_effect=run),patch.object(d,'subscription_probe_from_env',return_value=None):
    d.rollout(repo,root,bundle,sys.argv[5],sys.argv[6],False)
'''
        parent = subprocess.Popen([D.sys.executable, '-I', '-c', helper, D.__file__, str(self.repo),
                                   str(self.root), str(self.bundle), self.commit, self.version, worker],
                                  env={'PATH': '/usr/bin:/bin'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def wait_for(name):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if (self.root / name).exists():
                    return
                time.sleep(.01)
            self.fail('fixture timeout: ' + name)
        try:
            wait_for('worker-started')
            parent.kill()
            self.assertEqual(parent.wait(timeout=5), -signal.SIGKILL)
            journal = (self.root / 'operation.json').read_bytes()
            self.assertTrue(json.loads(journal)['mutator_dispatched'])
            for retry in (False, True):
                with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
                    self.rollout(retry_failed=retry)
            self.assertEqual(self.calls, [])
            self.assertEqual((self.root / 'operation.json').read_bytes(), journal)
            (self.root / 'allow-worker').write_text('finish bounded fixture')
            wait_for('old-worker-mutation')
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=5)
            (self.root / 'allow-worker').write_text('finish bounded fixture')

    def test_probe_read_only_failure_cleans_snapshot_and_binding(self):
        self.probe_env()
        def failed(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('fixture_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failed)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'subscription-probe-url').exists())
        self.assertFalse(list(self.root.glob('probe-binding-*')))

    def test_invalid_probe_env_fails_before_canonical_update(self):
        path = self.probe_env(b'not-a-url')
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_env_invalid$'):
            self.rollout(probe_env_file=path)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertFalse(list(self.root.glob('install.config.before-*')))

    def test_probe_default_uses_canonical_config_directory_outside_checkout(self):
        canonical = self.repo / 'canonical'
        canonical.mkdir()
        config = canonical / 'install.config'
        D.atomic_write(config, self.original)
        secret = b'https://old.example.com/sub/canonical-token'
        canonical_env = canonical / '.env'
        D.atomic_write(canonical_env, b'private fixture input\n')
        self.probe_inputs[canonical_env] = b'ULTRA_SUBSCRIPTION_PROBE_URL=' + secret + b'\n'
        self.probe_env(b'https://old.example.com/sub/wrong-checkout-token')
        def runner(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                snapshot = Path(command[command.index('--subscription-probe-url-file') + 1])
                self.assertEqual(snapshot.read_bytes(), secret)
        self.rollout(config_path=config, runner=runner)

    def test_numeric_version_exact_commit_round_trip_and_path_limit(self):
        self.assertRegex(self.version, r'^v[0-9]+\.[0-9]+\.[0-9]+$')
        self.assertEqual(int(self.version[5:]), int(self.commit, 16))
        self.assertLess(len(self.version), 95)

    def test_subscription_probe_requires_explicit_private_regular_file(self):
        probe = self.repo / 'probe'
        raw = b'fixture input\n'
        probe.write_bytes(raw)
        probe.chmod(0o600)
        self.assertEqual(D.subscription_probe_input(probe), raw)
        for mode in (0o644, 0o400):
            probe.chmod(mode)
            with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
                D.subscription_probe_input(probe)
        probe.chmod(0o600)
        hardlink = self.repo / 'hardlink'
        os.link(probe, hardlink)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(probe)
        hardlink.unlink()
        link = self.repo / 'link'
        link.symlink_to(probe)
        with self.assertRaises(OSError):
            D.subscription_probe_input(link)
        for data in (b'', b'x' * 4097):
            probe.write_bytes(data)
            with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
                D.subscription_probe_input(probe)

    def test_subscription_probe_rejects_directory_fifo_and_parent_symlink(self):
        fifo = self.repo / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(fifo)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(self.repo)
        alias = self.repo / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        probe = self.root / 'probe'
        probe.write_bytes(b'fixture input')
        probe.chmod(0o600)
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_input(alias / 'probe')
        info = probe.stat()
        foreign = SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1, st_nlink=1, st_size=info.st_size)
        with patch.object(D.os, 'fstat', return_value=foreign):
            with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
                D.subscription_probe_input(probe)
        path = self.probe_env()
        path.write_bytes(b'x' * (1024 * 1024 + 1))
        with self.assertRaisesRegex(D.DeployError, '^subscription_probe_private_file_required$'):
            D.subscription_probe_from_env(path)

    def test_canonical_config_lock_is_shared_across_worktree_path_aliases(self):
        alias = self.repo / 'other-worktree'
        alias.symlink_to(self.repo, target_is_directory=True)
        self.assertEqual(D.canonical_config_lock(self.config), D.canonical_config_lock(alias / 'install.config'))

    def test_only_two_canonical_values_change_without_shell_evaluation(self):
        self.rollout()
        raw = self.config.read_bytes()
        self.assertIn(b'OTHER="literal $() ${HOME}"\n', raw)
        self.assertIn(self.version.encode(), raw)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)
        self.assertEqual([stage for stage, _ in self.calls], ['doctor', 'upgrade', 'status'])
        self.assertIn('operator-upgrade', self.calls[1][1])
        self.assertIn('--source-commit', self.calls[1][1])
        self.assertIn('--manifest-sha256', self.calls[1][1])
        self.assertIn('--config-sha256', self.calls[1][1])
        self.assertFalse((self.root / 'operation.json').exists())

    def test_success_removes_one_time_baseline_setting_and_preserves_readable_mode(self):
        self.config.chmod(0o644)
        self.config.write_bytes(self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n')
        original = self.config.read_bytes()
        self.rollout()
        self.assertNotIn(b'ULTRA_UPGRADE_BASELINE_FILE=', self.config.read_bytes())
        self.assertEqual(D.config_values(self.config.read_bytes())['ULTRA_AUTOMATION_VERSION'], self.version)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), original)

    def test_failed_upgrade_retains_one_time_baseline_setting(self):
        self.config.write_bytes(self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n')
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.assertIn(b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json', self.config.read_bytes())

    def test_completed_legacy_journal_cannot_assert_authoritative_drain(self):
        desired = D.config_candidate(self.original, self.version, self.bundle)
        pending = desired + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n'
        completed = D.remove_config_key(pending, 'ULTRA_UPGRADE_BASELINE_FILE')
        record = {'schema': 1, 'commit': self.commit, 'version': self.version, 'adopt': False,
                  'backup': 'install.config.before-' + self.version + '-1', 'previous_sha256': D.sha(self.original),
                  'config_sha256': D.sha(pending), 'stage': 'completed', 'mutator_dispatched': True,
                  'transport_binding': None, 'manifest_sha256': None, 'final_config_sha256': D.sha(completed),
                  'remote_attempt': None}
        self.config.write_bytes(completed)
        D.atomic_write(self.root / 'operation.json', json.dumps(record).encode())
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            self.rollout()
        self.assertTrue((self.root / 'operation.json').exists())
        self.assertEqual(self.config.read_bytes(), completed)
        self.assertEqual(self.calls, [])

    def test_signed_upgrade_baseline_cannot_prove_legacy_worker_drain(self):
        journal = {'schema': 1, 'commit': self.commit, 'version': 'v2.4.2', 'remote_attempt': 'a' * 64,
                   'manifest_sha256': None, 'mutator_dispatched': True}
        manifest = {'source_commit': self.commit, 'version': 'v2.4.2',
                    'assets': [{'name': 'asset-' + str(i)} for i in range(14)]}
        manifest_raw = json.dumps(manifest, sort_keys=True).encode()
        journal['manifest_sha256'] = D.sha(manifest_raw)
        journal_raw = json.dumps(journal, sort_keys=True).encode()
        old_release = self.repo / 'old-release'
        old_release.mkdir()
        manifest_path = old_release / 'release-manifest.json'
        journal_path = self.repo / 'old-operation.json'
        descriptor_path = self.repo / 'baseline.json'
        manifest_path.write_bytes(manifest_raw); manifest_path.chmod(0o600)
        journal_path.write_bytes(journal_raw); journal_path.chmod(0o600)
        descriptor = {'schema': 1, 'journal': str(journal_path), 'journal_sha256': D.sha(journal_raw),
                      'manifest': str(manifest_path), 'manifest_sha256': D.sha(manifest_raw),
                      'bridge': {}, 'exits': {}}
        descriptor_path.write_text(json.dumps(descriptor)); descriptor_path.chmod(0o600)
        config = self.original + ('ULTRA_UPGRADE_BASELINE_FILE=' + str(descriptor_path) + '\n').encode()
        remote_root = Path('/var/lib/ultra-ansible/operator-inputs/manual-new-attempt')
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            D.stage_upgrade_baseline(config, self.version, remote_root)
        self.assertEqual(journal_path.read_bytes(), journal_raw)
        journal_path.write_bytes(journal_raw + b' ')
        with self.assertRaisesRegex(D.DeployError, 'baseline_local_pin_changed'):
            D.stage_upgrade_baseline(config, self.version, remote_root)

    def test_staging_archive_contains_only_the_two_baseline_inputs(self):
        manifest = {'source_commit': self.commit, 'version': self.version,
                    'assets': [{'name': 'fixture', 'sha256': D.sha(b'fixture'), 'size': 7}]}
        raw_manifest = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw_manifest)
        (self.bundle / 'fixture').write_bytes(b'fixture')
        config = self.original
        extras = {'baseline/descriptor.json': b'{"schema":1}',
                  'baseline/operator-journal.json': b'{"schema":1}'}
        def process(command, **kwargs):
            with tarfile.open(fileobj=kwargs['stdin'], mode='r|*') as archive:
                members = [(member.name, archive.extractfile(member).read()) for member in archive]
            self.assertEqual([name for name, _ in members], ['release/release-manifest.json', 'release/fixture',
                'install.config', 'baseline/descriptor.json', 'baseline/operator-journal.json'])
            self.assertEqual(kwargs['timeout'], 1800)
            return subprocess.CompletedProcess(command, 0, json.dumps({'architecture': 'arm64',
                'manifest_sha256': D.sha(raw_manifest), 'config_sha256': D.sha(config),
                'attempt': D.remote_attempt(config, self.version)}).encode())
        with patch.object(D.subprocess, 'run', process):
            receipt = D.stage_remote(self.repo, self.root, self.bundle, config,
                ['ssh', '-F', '/dev/null', 'root@192.0.2.10'], self.commit, self.version,
                D.sha(raw_manifest), extras)
        self.assertEqual(receipt['architecture'], 'arm64')

    def test_legacy_dispatch_blocks_before_any_input_or_transport_access(self):
        for stage in ('prepared', 'bridge_staging', 'doctor', 'adoption_apply', 'upgrade', 'status', 'completed'):
            for retry in (False, True):
                with self.subTest(stage=stage, retry=retry):
                    record = {'schema': 1, 'commit': 'b8b8126' + '0' * 33,
                              'stage': stage, 'mutator_dispatched': True,
                              'quiescent': True, 'drained': True, 'execution_safety_protocol': 999,
                              'quiescence_evidence': {'verified': True}}
                    raw = json.dumps(record).encode()
                    D.atomic_write(self.root / 'operation.json', raw)
                    with patch.object(D, 'canonical_file', side_effect=AssertionError('config reopened')), \
                         patch.object(D, 'operator_transport', side_effect=AssertionError('transport reopened')), \
                         patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('credential reopened')):
                        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
                            self.rollout(retry_failed=retry)
                    self.assertEqual((self.root / 'operation.json').read_bytes(), raw)
                    self.assertEqual(self.config.read_bytes(), self.original)
                    self.assertEqual(self.calls, [])

    def test_retry_failed_is_explicitly_forwarded_to_operator_upgrade(self):
        self.rollout(retry_failed=True)
        command = self.calls[1][1]
        self.assertIn('operator-upgrade', command)
        self.assertIn('--retry-failed', command)

    def test_forward_only_archives_dispatched_upgrade_and_is_explicitly_forwarded(self):
        old = {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def failed_forward(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'upgrade':
                self.assertIn('--forward-only', command)
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, '^fixture_failed$'):
            self.rollout(forward_only=True, runner=failed_forward)
        archived = list(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(len(archived), 1)
        self.assertEqual(json.loads(archived[0].read_bytes()), old)
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertTrue(record['forward_only'])
        self.assertIn('--forward-only', self.calls[1][1])

    def test_forward_only_staging_failure_restores_dispatched_journal(self):
        old = {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        raw = json.dumps(old).encode()
        D.atomic_write(self.root / 'operation.json', raw)
        def fail_preflight(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('bridge_staging_failed')
        with self.assertRaisesRegex(D.DeployError, '^bridge_staging_failed$'):
            self.rollout(forward_only=True, runner=fail_preflight)
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes()), old)
        self.assertEqual(json.loads(next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()), old)

    def test_forward_only_requires_exact_failed_upgrade_and_rejects_conflicts(self):
        with self.assertRaisesRegex(D.DeployError, '^manual_forward_only_requires_dispatched_upgrade$'):
            self.rollout(forward_only=True)
        old = {'schema': 1, 'commit': 'b' * 40, 'version': 'v0.0.2', 'stage': 'completed',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        with self.assertRaisesRegex(D.DeployError, '^manual_forward_only_requires_dispatched_upgrade$'):
            self.rollout(forward_only=True)
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes()), old)
        old['stage'] = 'upgrade'
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        with self.assertRaisesRegex(D.DeployError, '^manual_forward_only_upgrade_only$'):
            self.rollout(forward_only=True, retry_failed=True)

    def test_readable_canonical_config_keeps_its_mode(self):
        self.config.chmod(0o644)
        self.rollout(config_path=self.config)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertIn(self.version.encode(), self.config.read_bytes())
        self.assertEqual(next(self.root.glob('install.config.before-*')).stat().st_mode & 0o777, 0o600)

    def test_readable_canonical_config_keeps_mode_when_preflight_fails(self):
        self.config.chmod(0o644)

        def failing_doctor(command, cwd, stage, capture=False, env=None):
            raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(config_path=self.config, runner=failing_doctor)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)

    def test_explicit_adoption_compares_then_applies_without_redundant_upgrade(self):
        self.rollout(adopt=True)
        self.assertEqual([stage for stage, _ in self.calls], ['doctor', 'adoption_check', 'adoption_apply', 'status'])
        self.assertIn('--adopt-runtime', self.calls[1][1])
        self.assertIn('--adopt-runtime', self.calls[2][1])

    def test_preflight_failure_restores_previous_config(self):
        for failing in ['doctor', 'adoption_check']:
            with self.subTest(stage=failing):
                def runner(command, cwd, stage, capture=False, env=None):
                    if stage == failing:
                        raise D.DeployError('fixture_failure')
                with self.assertRaises(D.DeployError):
                    self.rollout(adopt=True, runner=runner)
                self.assertEqual(self.config.read_bytes(), self.original)
                self.assertFalse((self.root / 'operation.json').exists())

    def test_mutating_dispatch_failure_retains_config_and_blocks_other_commit(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.assertIn(self.version.encode(), self.config.read_bytes())
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertEqual(record['stage'], 'upgrade')
        record['commit'] = '0' * 40
        (self.root / 'operation.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_retry_dispatched_operation_is_blocked_and_keeps_original_backup(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.calls.clear()
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            self.rollout(retry_failed=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)

    def test_retry_preflight_failure_never_restores_after_prior_mutator_dispatch(self):
        def failing_upgrade(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failing_upgrade)
        updated = self.config.read_bytes()
        def failing_doctor(command, cwd, stage, capture=False, env=None):
            raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failing_doctor)
        self.assertEqual(self.config.read_bytes(), updated)
        self.assertTrue((self.root / 'operation.json').exists())

    def test_edited_config_during_failed_operation_is_rejected(self):
        def runner(command, cwd, stage, capture=False, env=None):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=runner)
        self.config.write_bytes(self.config.read_bytes() + b'CHANGED=1\n')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_prepared_journal_recovers_crash_before_config_update(self):
        desired = D.config_candidate(self.original, self.version, self.bundle)
        record = {'schema': 1, 'commit': self.commit, 'version': self.version, 'adopt': False,
                  'backup': 'install.config.before-' + self.version + '-1', 'previous_sha256': D.sha(self.original), 'config_sha256': D.sha(desired), 'stage': 'prepared'}
        D.atomic_write(self.root / 'operation.json', json.dumps(record).encode())
        D.atomic_write(self.root / record['backup'], self.original)
        self.rollout()
        self.assertEqual(self.config.read_bytes(), desired)

    def test_private_config_and_symlink_requirements(self):
        for mode in (0o640, 0o664):
            with self.subTest(mode=oct(mode)):
                self.config.chmod(mode)
                with self.assertRaisesRegex(D.DeployError, 'readable_file'):
                    self.rollout()
        fifo = self.repo / 'install.config.fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(D.DeployError, '^canonical_config_requires_owned_regular_readable_file$'):
            D.canonical_file(fifo)
        self.config.unlink()
        self.config.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(D.DeployError, 'readable_file'):
            self.rollout()

    def test_duplicate_release_keys_fail_closed(self):
        with self.assertRaisesRegex(D.DeployError, 'duplicate'):
            D.config_candidate(self.original + b'ULTRA_AUTOMATION_VERSION=v9.9.9\n', self.version, self.bundle)

    def test_attempt_identity_normalizes_derived_fields_without_recursion(self):
        for raw in [self.original, b'BRIDGE_IP=192.0.2.10\n']:
            attempt = D.remote_attempt(raw, self.version)
            derived = D.config_candidate(raw, self.version, '/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + attempt + '/release')
            self.assertEqual(D.remote_attempt(derived, self.version), attempt)
            self.assertNotEqual(D.remote_attempt(derived + b'CORRECTION=1\n', self.version), attempt)

    def test_completed_baseline_keeps_attempt_only_for_unchanged_config(self):
        baseline = self.repo / 'baseline.json'
        configured = self.original.replace(b'OTHER="literal $() ${HOME}"\n',
            ('ULTRA_UPGRADE_BASELINE_FILE=' + str(baseline) + '\n').encode() + b'OTHER="literal $() ${HOME}"\n')
        attempt = D.remote_attempt(configured, self.version)
        release = '/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + attempt + '/release'
        installed = D.config_candidate(configured, self.version, release)
        completed = D.remove_config_key(installed, 'ULTRA_UPGRADE_BASELINE_FILE')
        backup = self.root / ('install.config.before-' + self.version + '-1')
        D.atomic_write(backup, configured)
        def staged_config(raw, version, remote_root):
            return D.config_candidate(raw, version, remote_root / 'release', remote_root / 'baseline/descriptor.json'), {'baseline/descriptor.json': b'{}'}
        with patch.object(D, 'stage_upgrade_baseline', side_effect=staged_config):
            replay = D.completed_baseline_replay(self.root, completed, self.version, self.commit)
        self.assertEqual(replay[0], attempt)
        self.assertEqual(D.remove_config_key(replay[1], 'ULTRA_UPGRADE_BASELINE_FILE'), completed)
        changed = completed + b'CORRECTED_POLICY=1\n'
        with patch.object(D, 'stage_upgrade_baseline', side_effect=staged_config):
            self.assertIsNone(D.completed_baseline_replay(self.root, changed, self.version, self.commit))

    def test_nested_lock_fails_closed(self):
        with D.lock(self.root / 'lock'):
            with self.assertRaisesRegex(D.DeployError, 'already_running'):
                with D.lock(self.root / 'lock'):
                    self.fail('conflicting lock accepted')

    def test_subprocess_output_is_suppressed_on_failure(self):
        with patch.object(D.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            with self.assertRaisesRegex(D.DeployError, '^upgrade_failed_exit_7$'):
                D.run(['fixture'], self.repo, 'upgrade')
        self.assertEqual(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)

    def test_dirty_tree_fails_before_build_or_deploy(self):
        with patch.object(D, '__file__', str(self.repo / 'scripts/manual-deploy.py')), patch.object(D.shutil, 'which', return_value='/fixture'), patch.object(D.sys, 'argv', ['manual-deploy.py']), patch.object(D, 'run', side_effect=[' M tracked']) as run:
            with self.assertRaisesRegex(D.DeployError, 'tracked_tree_dirty'):
                D.main()
        self.assertEqual(run.call_count, 1)

    def test_bundle_identity_mismatch_fails_before_loading_contract(self):
        manifest = {'version': 'v9.9.9', 'source_commit': self.commit}
        (self.bundle / 'release-manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(D.DeployError, 'candidate_identity_mismatch'):
            D.verify_bundle(self.repo, self.bundle, self.commit, self.version)

    def test_build_and_existing_candidate_use_exact_isolated_source(self):
        validations = []
        def runner(command, cwd, stage, capture=False, env=None):
            self.calls.append((stage, command))
            if stage == 'source_clone':
                Path(command[-1]).mkdir()
            if stage == 'release_build':
                (cwd / 'dist').mkdir()
                (cwd / 'dist/release-manifest.json').write_text('{}')
                (cwd / 'dist/ultra-install-linux-amd64').write_bytes(b'fixture')
        (self.bundle / 'release-manifest.json').unlink()
        self.bundle.rmdir()
        with patch.object(D, 'prepare_runtime_environment', return_value={}), patch.object(D, 'run', runner), patch.object(D, 'verify_bundle', side_effect=lambda *args: validations.append(args)):
            bundle = D.build_candidate(self.repo, self.root, self.commit, self.version)
            self.assertEqual(bundle, self.bundle)
            self.assertEqual((bundle / 'ultra-install-linux-amd64').stat().st_mode & 0o777, 0o500)
            self.assertEqual((bundle / 'release-manifest.json').stat().st_mode & 0o777, 0o400)
            D.build_candidate(self.repo, self.root, self.commit, self.version)
            self.assertEqual([s for s, _ in self.calls].count('release_build'), 1)
            self.assertEqual([cmd[-1] for stage, cmd in self.calls if stage == 'source_checkout'], [self.commit, self.commit])
            (bundle / 'candidate.json').chmod(0o600)
            (bundle / 'candidate.json').write_text('{}')
            with self.assertRaisesRegex(D.DeployError, 'candidate_identity_mismatch'):
                D.build_candidate(self.repo, self.root, self.commit, self.version)
        bundle.chmod(0o700)  # allow fixture cleanup
        self.assertGreaterEqual(len(validations), 3)
        self.assertFalse(list(self.root.glob('.source-*')))

    def test_build_uses_private_scratch_only_without_explicit_tmpdir_and_cleans_it(self):
        for configured in (None, '', '/operator/explicit/tmp'):
            with self.subTest(tmpdir=configured):
                if self.bundle.exists():
                    self.bundle.chmod(0o700)
                    shutil.rmtree(self.bundle)
                seen=[]
                def runner(command,cwd,stage,capture=False,env=None):
                    if stage=='source_clone':Path(command[-1]).mkdir()
                    if stage=='release_build':
                        seen.append(env['TMPDIR'])
                        if configured:
                            self.assertEqual(env['TMPDIR'],configured)
                        else:
                            path=Path(env['TMPDIR'])
                            self.assertTrue(path.is_absolute())
                            self.assertEqual(path.parent,self.root)
                            self.assertEqual(path.stat().st_mode & 0o777,0o700)
                        raise D.DeployError('fixture_build_failure')
                environment={} if configured is None else {'TMPDIR':configured}
                with patch.object(D,'prepare_runtime_environment',return_value=environment),patch.object(D,'run',runner):
                    with self.assertRaisesRegex(D.DeployError,'fixture_build_failure'):
                        D.build_candidate(self.repo,self.root,self.commit,self.version)
                self.assertEqual(len(seen),1)
                if not configured:self.assertFalse(Path(seen[0]).exists())
                self.assertFalse(list(self.root.glob('.build-tmp-*')))


class NativeDeploy(unittest.TestCase):
    rollout = ManualDeploy.rollout
    probe_env = ManualDeploy.probe_env
    read_probe_input = ManualDeploy.read_probe_input
    run_fixture = ManualDeploy.run_fixture

    def setUp(self):
        ManualDeploy.setUp(self)
        self.operator = self.repo / 'adopt-fixture' / 'compare'
        self.operator.mkdir(parents=True, mode=0o700)
        self.identity = self.repo / 'operator-key'
        self.identity.write_bytes(b'PRIVATE KEY MUST NOT BE READ BY WRAPPER')
        self.identity.chmod(0o600)
        self.pins = self.repo / 'pins'
        self.pins.write_bytes(b'fixture pins')
        self.pins.chmod(0o600)
        self.inventory = {'all': {'vars': {'ansible_user': 'root',
            'ansible_ssh_private_key_file': str(self.identity),
            'ansible_ssh_common_args': '-F /dev/null -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=' + str(self.pins)},
            'children': {'bridge': {'hosts': {'bridge': {'ansible_host': '192.0.2.10'}}},
                         'exits': {'hosts': {'exit_0': {'ansible_host': '192.0.2.20'}}}}}}
        self.original += (b'BRIDGE_IP=192.0.2.10\nMAIN_EXIT_IP=192.0.2.20\nBRIDGE_SSH_KEY=/tmp/bridge-key\nMAIN_EXIT_SSH_KEY=/tmp/exit-key\nDATABASE_IP=192.0.2.30\nDATABASE_SSH_KEY=/tmp/database-key\nULTRA_AUTOMATION_STATIC_NODES=\'[{"address":"192.0.2.20"}]\'\nSECRETS_ENV_FILE=/etc/ultra-relay/.env\n' +
                          b'ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=' + str(self.pins).encode() + b'\n')
        self.config.write_bytes(self.original)
        self.write_inventory()
        self.manifest = json.dumps({'source_commit': self.commit, 'version': self.version, 'assets': []}).encode()
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest)
        self.environment = patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY': str(self.operator / 'inventory.json')})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.pin_probe = patch.object(D.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0))
        self.pin_probe.start()
        self.addCleanup(self.pin_probe.stop)
        def staged_receipt(*args):
            config, version, manifest_sha = args[3], args[6], args[7]
            return {'architecture': 'arm64', 'manifest_sha256': manifest_sha, 'config_sha256': D.sha(config),
                    'attempt': D.remote_attempt(config, version)}
        self.staged_receipt = staged_receipt
        self.stage = patch.object(D, 'stage_remote', side_effect=staged_receipt)
        self.stage_mock = self.stage.start()
        self.addCleanup(self.stage.stop)

    def write_inventory(self):
        request = json.dumps({'inventory': self.inventory, 'variables': {}}).encode()
        for name, data in [('inventory.json', json.dumps(self.inventory).encode()), ('request.json', request),
                           ('job.json', json.dumps({'operation': 'adopt', 'request_sha256': D.sha(request)}).encode())]:
            D.atomic_write(self.operator / name, data)

    def test_projected_dump_transport_attestation_uses_frozen_staged_digest(self):
        self.dump_config()
        self.failed_forward_fixture()
        record = json.loads((self.root / 'operation.json').read_bytes())
        def attest(command, cwd, stage, **kwargs):
            self.assertEqual(stage, 'legacy_operation_attestation')
            self.assertEqual(D.shlex.split(command[-1])[-1], record['staged_config_sha256'])
            return json.dumps(record)
        with patch.object(D, 'run', side_effect=attest):
            result = D.attest_legacy_manual_operation(
                self.repo, record, ['ssh'], record['transport_binding'], self.config.read_bytes())
        self.assertEqual(result, record)


    def test_dump_continuation_to_new_head_projects_new_candidate(self):
        self.dump_config()
        old = self.failed_forward_fixture()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        self.rollout(continue_forward_only=True, runner=attest)
        self.assertNotIn(b'DATABASE_DUMP=', self.stage_mock.call_args.args[3])
        self.assertIn(b'DATABASE_DUMP=', self.config.read_bytes())

    def test_dump_continuation_from_legacy_to_new_head_keeps_predecessor(self):
        self.dump_config()
        with patch.object(D, 'deployment_config_projection', return_value=None):
            old = self.failed_forward_fixture()
        frozen = (self.root / 'operation.json').read_bytes()
        self.assertNotIn('config_projection', json.loads(frozen))
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        self.rollout(continue_forward_only=True, runner=attest)
        self.assertNotIn(b'DATABASE_DUMP=', self.stage_mock.call_args.args[3])
        history = next(self.root.glob('operation.forward-only-retry-*.json'))
        self.assertEqual(history.read_bytes(), frozen)
        self.assertIn(b'DATABASE_DUMP=', self.config.read_bytes())


    def dump_config(self):
        self.original += b'DATABASE_DUMP=/private/operator-only.dump\n'
        self.config.write_bytes(self.original)

    def test_upgrade_projects_dump_without_changing_canonical_input(self):
        self.dump_config()
        self.rollout()
        staged = self.stage_mock.call_args.args[3]
        self.assertNotIn(b'DATABASE_DUMP=', staged)
        self.assertIn(b'DATABASE_DUMP=/private/operator-only.dump\n', self.config.read_bytes())
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)
        attempt = D.remote_attempt(staged, self.version)
        self.assertNotEqual(attempt, D.remote_attempt(self.original, self.version))
        policy = next(command for stage, command in self.calls if stage == 'canonical_policy')
        self.assertIn('--lifecycle', policy)
        for stage in ('doctor', 'upgrade', 'status'):
            command = next(command for call_stage, command in self.calls if call_stage == stage)
            self.assertIn('lifecycle_' + stage, command[-1])
        for stage, command in self.calls:
            if stage == 'canonical_policy':
                continue
            tokens = D.shlex.split(command[-1])
            self.assertEqual(tokens[8:10], [D.sha(staged), attempt])

    def test_dump_projection_is_upgrade_only_and_rejects_unknown_policy(self):
        self.dump_config()
        self.rollout(adopt=True)
        self.assertIn(b'DATABASE_DUMP=', self.stage_mock.call_args.args[3])
        self.assertEqual(D.projected_upgrade_config(self.original), self.original)
        with self.assertRaisesRegex(D.DeployError, 'manual_config_projection_invalid'):
            D.projected_upgrade_config(self.original, 'future')

    def test_upgrade_v2_projects_controller_pins_without_changing_operator_config(self):
        configured = self.original + b'DATABASE_DUMP=/operator/private.dump\n'
        staged = D.projected_upgrade_config(configured, 'upgrade-v2')
        self.assertIn(b'ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/etc/ultra-recovery/known_hosts\n', staged)
        self.assertNotIn(b'DATABASE_DUMP=', staged)
        self.assertIn(b'ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=' + str(self.pins).encode() + b'\n', configured)
        with self.assertRaisesRegex(D.DeployError, 'manual_controller_pins_config_required'):
            D.projected_upgrade_config(b'INSTALL_SCHEMA_VERSION=2\n', 'upgrade-v2')
        with self.assertRaisesRegex(D.DeployError, 'duplicate_canonical_release_key'):
            D.projected_upgrade_config(configured + b'ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/other\n', 'upgrade-v2')

    def test_projected_prepared_restart_keeps_exact_staged_identity(self):
        self.dump_config()
        def fail(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with self.assertRaisesRegex(D.DeployError, 'fixture_failure'):
            self.rollout(runner=fail)
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertEqual(record['config_projection'], 'upgrade-v2')
        staged = self.stage_mock.call_args.args[3]
        record.update(stage='prepared', mutator_dispatched=False)
        D.atomic_write(self.root / 'operation.json', json.dumps(record).encode())
        self.calls.clear()
        self.rollout()
        self.assertEqual(self.stage_mock.call_args.args[3], staged)

    def test_legacy_prepared_restart_retains_unprojected_identity(self):
        self.dump_config()
        projection = D.deployment_config_projection
        def legacy(record, transport, adopt, commit, version):
            return None
        def fail(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failure')
        with patch.object(D, 'deployment_config_projection', side_effect=legacy):
            with self.assertRaisesRegex(D.DeployError, 'fixture_failure'):
                self.rollout(runner=fail)
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertNotIn('config_projection', record)
        staged = self.stage_mock.call_args.args[3]
        record.update(stage='prepared', mutator_dispatched=False)
        D.atomic_write(self.root / 'operation.json', json.dumps(record).encode())
        self.rollout()
        self.assertEqual(self.stage_mock.call_args.args[3], staged)
        self.assertIn(b'DATABASE_DUMP=', staged)

    def test_projected_dump_forward_continuation_keeps_frozen_candidate(self):
        self.dump_config()
        old = self.failed_forward_fixture()
        record_raw = (self.root / 'operation.json').read_bytes()
        record = json.loads(record_raw)
        config = self.config.read_bytes()
        self.assertNotEqual(record['staged_config_sha256'], D.sha(config))
        self.rollout(continue_forward_only=True,
            runner=self.continuation_runner(old, {'prior_candidate': {}, 'operation_absent': True}))
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.config.read_bytes(), config)

    def test_projection_marker_cannot_be_removed_from_frozen_continuation(self):
        self.dump_config()
        old = self.failed_forward_fixture()
        record = json.loads((self.root / 'operation.json').read_bytes())
        del record['config_projection']
        raw = json.dumps(record).encode()
        D.atomic_write(self.root / 'operation.json', raw)
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_inputs_changed'):
            self.rollout(continue_forward_only=True, runner=self.continuation_runner(old))
        self.assertEqual((self.root / 'operation.json').read_bytes(), raw)
        self.assertFalse(self.stage_mock.called)

    def test_dump_baseline_replay_binds_projection_and_preserves_backup(self):
        self.dump_config()
        configured = self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n'
        projected = D.projected_upgrade_config(configured, 'upgrade-v1')
        attempt = D.remote_attempt(projected, self.version)
        remote_root = Path('/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + attempt)
        installed = D.config_candidate(configured, self.version, remote_root / 'release')
        completed = D.remove_config_key(installed, 'ULTRA_UPGRADE_BASELINE_FILE')
        backup = self.root / ('install.config.before-' + self.version + '-1')
        D.atomic_write(backup, configured)
        def stage(raw, version, root):
            self.assertNotIn(b'DATABASE_DUMP=', raw)
            return D.config_candidate(raw, version, root / 'release', root / 'baseline/descriptor.json'), {}
        with patch.object(D, 'stage_upgrade_baseline', side_effect=stage):
            replay = D.completed_baseline_replay(self.root, completed, self.version, self.commit, 'upgrade-v1')
        self.assertEqual(replay[0], attempt)
        self.assertNotIn(b'DATABASE_DUMP=', replay[1])
        self.assertEqual(backup.read_bytes(), configured)
        self.assertIsNone(D.completed_baseline_replay(self.root, completed, self.version, self.commit))
        with patch.object(D, 'stage_upgrade_baseline', side_effect=stage):
            self.assertIsNone(D.completed_baseline_replay(
                self.root, completed + b'OTHER_POLICY=changed\n', self.version, self.commit, 'upgrade-v1'))


    def test_native_contract_and_server_canonical_path(self):
        self.rollout(adopt=True)
        expected = '/var/lib/ultra-ansible/operator-inputs/manual-' + self.commit + '-' + D.remote_attempt(self.original, self.version) + '/release'
        self.assertIn(expected.encode(), self.config.read_bytes())
        self.assertNotIn(str(self.bundle).encode(), self.config.read_bytes())
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy', 'doctor', 'adoption_check', 'adoption_apply', 'status'])
        self.assertEqual(self.calls[0][1][1:3], ['plan', '--config'])
        for stage, command in self.calls[1:]:
            self.assertEqual(command[:3], ['ssh', '-F', '/dev/null'])
            self.assertEqual(command[-2], 'root@192.0.2.10')
            self.assertFalse(any('ProxyCommand=' in token for token in command))
            remote = D.shlex.split(command[-1])
            self.assertEqual(remote[:3], ['python3', '-I', '-c'])
            self.assertEqual(remote[4:11], ['run', self.commit, self.version, D.sha(self.manifest), D.sha(self.stage_mock.call_args.args[3]), D.remote_attempt(self.original, self.version), 'arm64'])
            self.assertEqual(remote[11], stage)
            self.assertEqual(remote[12], '0')
        self.assertIn("'--bridge-native'", D.REMOTE_PROGRAM)
        self.assertIn("'upgrade':['operator-upgrade'", D.REMOTE_PROGRAM)

    def test_native_retry_failed_is_bound_to_upgrade_handoff(self):
        self.rollout(retry_failed=True)
        command = next(command for stage, command in self.calls if stage == 'upgrade')
        remote = D.shlex.split(command[-1])
        self.assertEqual(remote[11], 'lifecycle_upgrade')
        self.assertEqual(remote[12], '1')

    def test_forward_only_transport_options_are_confined_to_upgrade(self):
        old = {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
               'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        self.rollout(forward_only=True)
        calls = {stage: D.shlex.split(command[-1]) for stage, command in self.calls if stage in ('doctor', 'upgrade', 'status')}
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        forward_sha = D.sha(archived.read_bytes())
        self.assertEqual(calls['doctor'][13], '0')
        self.assertEqual(calls['doctor'][15], forward_sha)
        self.assertEqual(calls['upgrade'][13], '1')
        self.assertEqual(calls['upgrade'][15], forward_sha)
        self.assertEqual(calls['status'][13], '0')
        self.assertEqual(calls['status'][15], forward_sha)

    def failed_forward_fixture(self):
        old_commit = 'b' * 40
        old = {'schema': 1, 'commit': old_commit, 'version': 'v0.0.' + str(int(old_commit, 16)),
               'stage': 'upgrade', 'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def fail(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_failed'):
            self.rollout(forward_only=True, runner=fail)
        self.calls.clear()
        self.stage_mock.reset_mock()
        return old

    def continuation_runner(self, old, change=None):
        record = json.loads((self.root / 'operation.json').read_bytes())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'forward_continuation_attestation':
                state = Path('/var/lib/ultra-ansible') / ('upgrade-' + old['version'])
                args = D.shlex.split(command[-1])
                target_version, prior_version, prior_sha = args[-10], args[-5], args[-1]
                prior_state = Path('/var/lib/ultra-ansible') / ('upgrade-' + prior_version)
                target_state = Path('/var/lib/ultra-ansible') / ('upgrade-' + target_version)
                chain = {'phase': 'restart' if record['commit'] == self.commit else 'start',
                    'proof_sha256': record['forward_journal_sha256'],
                    'prior_journal_sha256': prior_sha,
                    'original_id': str(D.uuid.UUID(bytes=hashlib.sha256(str(state).encode()).digest()[:16], version=4)),
                    'prior_id': str(D.uuid.UUID(bytes=hashlib.sha256(str(prior_state).encode()).digest()[:16], version=4)),
                    'new_id': str(D.uuid.UUID(bytes=hashlib.sha256(str(target_state).encode()).digest()[:16], version=4)),
                    'prior_evidence_sha256': 'a' * 64, 'original_handoff_sha256': 'b' * 64,
                    'original_evidence_sha256': 'c' * 64, 'original_retirement_sha256': 'd' * 64}
                receipt = {'architecture': 'arm64', 'manifest_sha256': record['manifest_sha256'],
                    'config_sha256': record['staged_config_sha256'], 'attempt': record['remote_attempt'],
                    'forward_journal_sha256': record['forward_journal_sha256'],
                    'prior_candidate': None, 'chain_attestation': chain,
                    'lifecycle_id': str(D.uuid.UUID(bytes=hashlib.sha256(str(state).encode()).digest()[:16], version=4))}
                if len(args)<24:
                    receipt.pop('chain_attestation')
                receipt.update(change or {})
                return json.dumps(receipt)
        return runner

    def test_continue_forward_only_retains_original_proof_and_exact_candidate(self):
        old = self.failed_forward_fixture()
        original_proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        config = self.config.read_bytes()
        with patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('must not read env')):
            self.rollout(continue_forward_only=True, runner=self.continuation_runner(old, {'prior_candidate': {}, 'operation_absent': True}))
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-abandoned-*.json')], [original_proof])
        upgrade = D.shlex.split(next(command for stage, command in self.calls if stage == 'upgrade')[-1])
        self.assertEqual(upgrade[13], '1')
        self.assertEqual(upgrade[15], D.sha(original_proof))
        self.assertEqual(upgrade[16], '1')
        self.assertNotIn('--retry-failed', upgrade)

    def new_candidate_fixture(self):
        self.commit = 'c' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.bundle = self.root / self.version
        self.bundle.mkdir()
        self.manifest = json.dumps({'source_commit': self.commit, 'version': self.version, 'assets': []}).encode()
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest)

    def test_continue_new_head_retains_pre_handoff_receipt_without_chain_attestation(self):
        old=self.failed_forward_fixture()
        runner=self.continuation_runner(old,{'chain_attestation':None})
        self.new_candidate_fixture()
        self.rollout(continue_forward_only=True,runner=runner)
        upgrade=D.shlex.split(next(command for stage,command in self.calls if stage=='upgrade')[-1])
        self.assertEqual(upgrade[16],'1')
        self.assertEqual(upgrade[-6],json.loads(next(self.root.glob('operation.forward-only-retry-*.json')).read_bytes())['commit'])

    def test_continue_new_head_rejects_absent_candidate_before_mutating_recovery_state(self):
        self.probe_env()
        old = self.failed_forward_fixture()
        attest = self.continuation_runner(old, {'prior_candidate': {}, 'operation_absent': True})
        self.new_candidate_fixture()
        canonical = self.repo / 'canonical.config'
        self.config.rename(canonical)
        canonical.chmod(0o644)
        config = canonical.read_bytes()
        before = {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mode & 0o777)
                  for p in self.root.rglob('*') if p.is_file()}
        with patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('must not read env')):
            with self.assertRaisesRegex(D.DeployError, '^manual_forward_continuation_missing_prior_candidate$'):
                self.rollout(config_path=canonical, continue_forward_only=True, runner=attest)
        self.assertEqual(canonical.read_bytes(), config)
        self.assertEqual(canonical.stat().st_mode & 0o777, 0o644)
        self.assertFalse(self.config.exists())
        self.assertEqual({str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mode & 0o777)
                          for p in self.root.rglob('*') if p.is_file()}, before)
        self.assertFalse(list(self.root.glob('operation.forward-only-retry-*.json')))
        self.assertFalse(self.stage_mock.called)
        self.assertEqual([stage for stage, _ in self.calls], ['canonical_policy', 'forward_continuation_attestation'])

    def test_continue_new_head_archives_failed_candidate_as_history_preserving_production_proof(self):
        old = self.failed_forward_fixture()
        failed_raw = (self.root / 'operation.json').read_bytes()
        failed = json.loads(failed_raw)
        proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        def runner(command, cwd, stage, **kwargs):
            response = attest(command, cwd, stage, **kwargs)
            if stage == 'forward_continuation_attestation':
                tokens=D.shlex.split(command[-1])
                self.assertEqual(tokens[-6:-1],[failed['commit'],failed['version'],failed['remote_attempt'],
                    failed['manifest_sha256'],failed['staged_config_sha256']])
                self.assertEqual(tokens[-1],D.sha(failed_raw))
                self.assertIsNone(json.loads(response)['prior_candidate'])
                self.assertNotIn('operation_absent', json.loads(response))
            if stage == 'upgrade':
                record = json.loads((self.root / 'operation.json').read_bytes())
                self.assertEqual(record['commit'], self.commit)
                self.assertNotEqual(record['commit'], failed['commit'])
                self.assertNotEqual(record['version'], failed['version'])
                self.assertEqual(record['forward_journal_sha256'], D.sha(proof))
                self.assertNotEqual(record['forward_journal_sha256'], D.sha(failed_raw))
                history = self.root / record['forward_retry_history']
                self.assertEqual(history.read_bytes(), failed_raw)
                self.assertEqual(history.stat().st_mode & 0o777, 0o600)
                self.assertEqual(record['forward_retry_history_sha256'], D.sha(failed_raw))
                raise D.DeployError('new_failure')
            return response
        canonical = self.repo / 'canonical.config'
        self.config.rename(canonical)
        canonical.chmod(0o644)
        with patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('must not read env')):
            with self.assertRaisesRegex(D.DeployError, 'new_failure'):
                self.rollout(config_path=canonical, continue_forward_only=True, runner=runner)
        self.assertEqual(canonical.stat().st_mode & 0o777, 0o644)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.stage_mock.call_args.args[8]['forward-operation.json'], proof)
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-abandoned-*.json')], [proof])
        self.assertEqual(len(list(self.root.glob('operation.forward-only-retry-*.json'))), 1)
        self.assertEqual([s for s, _ in self.calls].count('forward_continuation_attestation'), 2)
        same_candidate = self.continuation_runner(old)
        prior_sha = json.loads((self.root / 'operation.json').read_bytes())['forward_prior_journal_sha256']
        attested_prior = []
        self.stage_mock.reset_mock()
        def resume(command, cwd, stage, **kwargs):
            response = same_candidate(command, cwd, stage, **kwargs)
            if stage == 'forward_continuation_attestation':
                self.assertIn(prior_sha, command[-1])
                attested_prior.append(prior_sha)
            if stage == 'upgrade':
                tokens = D.shlex.split(command[-1])
                record = json.loads((self.root / 'operation.json').read_bytes())
                history = json.loads((self.root / record['forward_retry_history']).read_bytes())
                self.assertTrue(tokens[-13].endswith('/forward-prior-operation.json'))
                self.assertEqual(tokens[-12], prior_sha)
                self.assertEqual(tokens[-11:-6], [self.commit, self.version, D.sha(self.manifest),
                    record['staged_config_sha256'], record['remote_attempt']])
                self.assertEqual(tokens[-6:-1], [history['commit'], history['version'], history['remote_attempt'],
                    history['manifest_sha256'], history['staged_config_sha256']])
                self.assertEqual(tokens[-1], prior_sha)
            return response
        with patch.object(D, 'subscription_probe_from_env', side_effect=AssertionError('must not read env')):
            self.rollout(config_path=canonical, continue_forward_only=True, runner=resume)
        self.assertEqual(attested_prior, [prior_sha])
        self.assertFalse(self.stage_mock.called)

    def test_continue_new_head_doctor_failure_restores_failed_operation_and_frozen_probe(self):
        self.probe_env()
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        probe = (self.root / 'subscription-probe-url').read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        def runner(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('doctor_failed_exit_1')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'doctor_failed_exit_1'):
            self.rollout(continue_forward_only=True, runner=runner)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual((self.root / 'subscription-probe-url').read_bytes(), probe)

    def test_continue_new_head_second_attestation_failure_restores_original_recovery_state(self):
        self.probe_env()
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        probe = (self.root / 'subscription-probe-url').read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        attestations = 0
        def runner(command, cwd, stage, **kwargs):
            nonlocal attestations
            if stage == 'forward_continuation_attestation':
                attestations += 1
                if attestations == 2:
                    pending = json.loads((self.root / 'operation.json').read_bytes())
                    self.assertEqual(pending['stage'], 'forward_continuation_preflight')
                    self.assertIs(pending['mutator_dispatched'], False)
                    raise D.DeployError('second_attestation_failed')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'second_attestation_failed'):
            self.rollout(continue_forward_only=True, runner=runner)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual((self.root / 'subscription-probe-url').read_bytes(), probe)
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-retry-*.json')], [before])
        self.assertFalse(any(stage == 'upgrade' for stage, _ in self.calls))
        self.rollout(continue_forward_only=True, runner=attest)

    def test_continue_new_head_write_failures_restore_or_recover_at_every_local_boundary(self):
        # Exercise both errors before replacement and death after a durable
        # replacement, including recovery interrupted while restoring config.
        for boundary in ['history', 'backup', 'probe', 'journal', 'config', 'binding', 'bridge_staging', 'doctor', 'forward_continuation_preflight']:
            for after in [False, True]:
                with self.subTest(boundary=boundary, after=after):
                    fixture = NativeDeploy(methodName='runTest')
                    fixture.setUp()
                    try:
                        fixture.probe_env()
                        old = fixture.failed_forward_fixture()
                        before = (fixture.root / 'operation.json').read_bytes()
                        config = fixture.config.read_bytes()
                        probe = (fixture.root / 'subscription-probe-url').read_bytes()
                        attest = fixture.continuation_runner(old)
                        fixture.new_candidate_fixture()
                        real_write = D.atomic_write
                        injected = False
                        def write(path, raw, **kwargs):
                            nonlocal injected
                            selected = ((boundary == 'history' and path.name.startswith('operation.forward-only-retry-')) or
                                (boundary == 'backup' and path.name.startswith('install.config.before-' + fixture.version)) or
                                (boundary == 'probe' and path.name == 'subscription-probe-url') or
                                (boundary == 'journal' and path.name == 'operation.json' and json.loads(raw).get('stage') == 'prepared') or
                                (boundary == 'config' and path == fixture.config) or
                                (boundary == 'binding' and path.name.startswith('probe-binding-' + fixture.commit)) or
                                (boundary in ['bridge_staging', 'doctor', 'forward_continuation_preflight'] and
                                 path.name == 'operation.json' and json.loads(raw).get('stage') == boundary))
                            if selected and not injected:
                                injected = True
                                if after:
                                    real_write(path, raw, **kwargs)
                                raise OSError('injected_write_failure')
                            return real_write(path, raw, **kwargs)
                        with patch.object(D, 'atomic_write', side_effect=write):
                            # Simulate process death preventing in-process
                            # restoration; the next invocation must recover.
                            with patch.object(D, 'restore_forward_preflight', side_effect=OSError('interrupted_recovery')):
                                with self.assertRaises(OSError):
                                    fixture.rollout(continue_forward_only=True, runner=attest)
                        self.assertTrue(injected)
                        self.assertFalse(any(stage == 'upgrade' for stage, _ in fixture.calls))
                        recovered = False
                        def check_recovered(command, cwd, stage, **kwargs):
                            nonlocal recovered
                            if stage == 'canonical_policy':
                                self.assertEqual((fixture.root / 'operation.json').read_bytes(), before)
                                self.assertEqual(fixture.config.read_bytes(), config)
                                self.assertEqual((fixture.root / 'subscription-probe-url').read_bytes(), probe)
                                recovered = True
                            return attest(command, cwd, stage, **kwargs)
                        fixture.rollout(continue_forward_only=True, runner=check_recovered)
                        self.assertTrue(recovered)
                    finally:
                        fixture.doCleanups()

    def test_continue_recovers_when_config_restored_but_old_journal_restore_was_interrupted(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        real_write = D.atomic_write
        def fail_restore(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('doctor_failure')
            return attest(command, cwd, stage, **kwargs)
        def write(path, raw, **kwargs):
            if path == self.root / 'operation.json' and raw == before:
                self.assertEqual(self.config.read_bytes(), config)
                raise OSError('journal_restore_interrupted')
            return real_write(path, raw, **kwargs)
        with patch.object(D, 'atomic_write', side_effect=write):
            with self.assertRaisesRegex(OSError, 'journal_restore_interrupted'):
                self.rollout(continue_forward_only=True, runner=fail_restore)
        self.assertIs(json.loads((self.root / 'operation.json').read_bytes())['mutator_dispatched'], False)
        self.assertEqual(self.config.read_bytes(), config)
        pending = (self.root / 'operation.json').read_bytes()
        for arguments in [{'forward_only': True}, {'retry_failed': True}, {'adopt': True},
                          {'probe_env_file': self.repo / 'unused-private-input'}]:
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_arguments_invalid'):
                    self.rollout(continue_forward_only=True, **arguments)
                self.assertEqual((self.root / 'operation.json').read_bytes(), pending)
                self.assertEqual(self.config.read_bytes(), config)
        self.rollout(continue_forward_only=True, runner=attest)

    def test_ordinary_retry_rejects_all_unfinished_forward_journals_without_touching_recovery_state(self):
        self.probe_env()
        self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        original = json.loads(journal.read_bytes())
        config = self.config.read_bytes()
        probe = (self.root / 'subscription-probe-url').read_bytes()
        proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        for stage, dispatched in [('prepared', False), ('bridge_staging', False), ('doctor', False),
                                  ('forward_continuation_preflight', False), ('upgrade', True), ('status', True)]:
            for retry in [False, True]:
                with self.subTest(stage=stage, retry=retry):
                    pending = json.dumps(dict(original, stage=stage, mutator_dispatched=dispatched)).encode()
                    D.atomic_write(journal, pending)
                    self.calls.clear()
                    self.stage_mock.reset_mock()
                    with patch.object(D, 'atomic_write', side_effect=AssertionError('must not write')):
                        with self.assertRaisesRegex(D.DeployError, 'manual_forward_operation_requires_explicit_continuation'):
                            self.rollout(retry_failed=retry)
                    self.assertEqual(journal.read_bytes(), pending)
                    self.assertEqual(self.config.read_bytes(), config)
                    self.assertEqual((self.root / 'subscription-probe-url').read_bytes(), probe)
                    self.assertEqual(next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes(), proof)
                    self.assertEqual(self.calls, [])
                    self.assertFalse(self.stage_mock.called)

    def test_continue_preflight_recovery_rejects_unrelated_or_changed_journals(self):
        old = self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        before = journal.read_bytes()
        config = self.config.read_bytes()
        original = json.loads(before)
        for change in [{'stage': 'prepared', 'mutator_dispatched': False},
                       {'stage': 'prepared', 'mutator_dispatched': False, 'forward_retry_history': '../operation.json'},
                       {'stage': 'upgrade', 'mutator_dispatched': False}]:
            raw = json.dumps(dict(original, **change)).encode()
            D.atomic_write(journal, raw)
            with self.assertRaises(D.DeployError):
                self.rollout(continue_forward_only=True)
            self.assertEqual(journal.read_bytes(), raw)
            self.assertEqual(self.config.read_bytes(), config)
        D.atomic_write(journal, before)

    def test_continue_new_head_attestation_failure_leaves_config_journal_and_archives_unchanged(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        config = self.config.read_bytes()
        attest = self.continuation_runner(old, {'lifecycle_id': 'foreign'})
        self.new_candidate_fixture()
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_receipt_invalid'):
            self.rollout(continue_forward_only=True, runner=attest)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertFalse(self.stage_mock.called)
        self.assertFalse(list(self.root.glob('operation.forward-only-retry-*.json')))

    def test_forward_only_cannot_archive_failed_forward_candidate_as_predecessor(self):
        self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_operation_requires_explicit_continuation'):
            self.rollout(forward_only=True)
        self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertEqual(len(list(self.root.glob('operation.forward-only-abandoned-*.json'))), 1)
        self.assertFalse(self.stage_mock.called)

    def test_forward_only_retry_reuses_predecessor_proof_and_remains_continuable(self):
        old_commit = 'b' * 40
        old = {'schema': 1, 'commit': old_commit, 'version': 'v0.0.' + str(int(old_commit, 16)),
               'stage': 'upgrade', 'mutator_dispatched': True, 'remote_attempt': 'c' * 64,
               'manifest_sha256': 'd' * 64, 'staged_config_sha256': 'e' * 64}
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())

        def fail_preflight(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('preflight_failed')

        with self.assertRaisesRegex(D.DeployError, 'preflight_failed'):
            self.rollout(forward_only=True, runner=fail_preflight)
        original_proof = next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes()), old)

        def fail_dispatch(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('dispatch_failed')

        with self.assertRaisesRegex(D.DeployError, 'dispatch_failed'):
            self.rollout(forward_only=True, runner=fail_dispatch)
        archives = list(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), original_proof)

        self.rollout(continue_forward_only=True, runner=self.continuation_runner(old))
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertEqual([path.read_bytes() for path in self.root.glob('operation.forward-only-abandoned-*.json')],
                         [original_proof])

    def test_continue_forward_only_doctor_failure_retains_retryable_original_journal(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        attest = self.continuation_runner(old)
        def runner(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('doctor_failed_exit_1')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'doctor_failed_exit_1'):
            self.rollout(continue_forward_only=True, runner=runner)
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes()), json.loads(before))
        self.assertFalse(self.stage_mock.called)

    def test_continue_forward_only_rejects_changed_receipt_without_replacing_journal(self):
        old = self.failed_forward_fixture()
        before = (self.root / 'operation.json').read_bytes()
        for change in ({'forward_journal_sha256': 'f' * 64}, {'lifecycle_id': 'foreign'},
                       {'config_sha256': 'f' * 64}, {'attempt': 'f' * 64}, {'architecture': 'amd64'}):
            with self.subTest(change=change):
                with self.assertRaises(D.DeployError):
                    self.rollout(continue_forward_only=True, runner=self.continuation_runner(old, change))
                self.assertEqual((self.root / 'operation.json').read_bytes(), before)
        self.assertFalse(self.stage_mock.called)

    def test_continue_forward_only_rejects_changed_local_bindings(self):
        self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        before = journal.read_bytes()
        base = json.loads(before)
        for key, value in [('commit', 'f' * 40), ('manifest_sha256', 'f' * 64),
                           ('remote_attempt', 'f' * 64), ('staged_config_sha256', 'f' * 64),
                           ('transport_binding', {}), ('forward_journal_sha256', 'f' * 64),
                           ('forward_only', False)]:
            with self.subTest(key=key):
                D.atomic_write(journal, json.dumps(dict(base, **{key: value})).encode())
                with self.assertRaises(D.DeployError):
                    self.rollout(continue_forward_only=True)
        D.atomic_write(journal, before)
        proof = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        proof.write_bytes(b'{}')
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_proof_changed'):
            self.rollout(continue_forward_only=True)
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.calls, [])

    def legacy_record(self):
        attempt = D.remote_attempt(self.original, self.version)
        release = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + self.commit + '-' + attempt) / 'release'
        self.original = D.config_candidate(self.original, self.version, release)
        self.config.write_bytes(self.original)
        _, binding = D.operator_transport(str(self.operator / 'inventory.json'), self.original)
        return {'schema': 1, 'commit': self.commit, 'version': self.version, 'stage': 'upgrade',
                'mutator_dispatched': True, 'remote_attempt': D.remote_attempt(self.original, self.version), 'manifest_sha256': 'd' * 64,
                'config_sha256': D.sha(self.original), 'transport_binding': binding}

    def pre_direct_transport_binding(self):
        # Reproduce the released fingerprint independently of the compatibility
        # implementation, including the old common identity for exit_0.
        info = self.identity.lstat()
        target = {'host': '192.0.2.10',
                  'identity_file': [str(self.identity), info.st_ino, info.st_size, info.st_mtime_ns],
                  'pins_file': str(self.pins), 'pins_sha256': D.sha(self.pins.read_bytes())}
        jump_identity = Path(self.inventory['all']['children']['exits']['hosts']['exit_0'].get(
            'ansible_ssh_private_key_file', str(self.identity)))
        jump_info = jump_identity.lstat()
        jump = dict(target, host='192.0.2.20', identity_file=[str(jump_identity), jump_info.st_ino,
                    jump_info.st_size, jump_info.st_mtime_ns])
        return D.sha(json.dumps({'source_sha256': D.sha((self.operator / 'inventory.json').read_bytes()),
                                 'target': target, 'jump': jump}, sort_keys=True).encode())

    def assert_direct_recovery_calls(self):
        for stage, command in self.calls:
            if command[0] == 'ssh':
                self.assertEqual(command[-2], 'root@192.0.2.10')
                self.assertIn('ProxyJump=none', command)
                self.assertFalse(any('ProxyCommand=' in token for token in command))

    def test_pre_direct_legacy_forward_only_requires_exact_binding_and_attestation(self):
        old = dict(self.legacy_record(), transport_binding=self.pre_direct_transport_binding())
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'legacy_operation_attestation':
                return json.dumps(dict(old, staged_config_sha256=old['config_sha256']))
            if stage == 'upgrade':
                raise D.DeployError('fixture_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_failed'):
            self.rollout(forward_only=True, runner=runner)
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(json.loads(archived.read_bytes()), dict(old, staged_config_sha256=old['config_sha256']))
        self.assertEqual(self.calls[0][0], 'legacy_operation_attestation')
        self.assert_direct_recovery_calls()
        _, direct_binding = D.operator_transport(str(self.operator / 'inventory.json'), self.config.read_bytes())
        self.assertEqual(json.loads((self.root / 'operation.json').read_bytes())['transport_binding'], direct_binding)
        self.assertNotEqual(direct_binding, old['transport_binding'])

    def test_pre_direct_forward_only_existing_staged_digest_requires_attestation(self):
        old = dict(self.legacy_record(), transport_binding=self.pre_direct_transport_binding())
        old['staged_config_sha256'] = old['config_sha256']
        raw = json.dumps(old).encode()
        journal = self.root / 'operation.json'
        D.atomic_write(journal, raw)
        def reject(command, cwd, stage, **kwargs):
            self.assertEqual(stage, 'legacy_operation_attestation')
            raise D.DeployError('fixture_attestation_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_attestation_failed'):
            self.rollout(forward_only=True, runner=reject)
        self.assertEqual(journal.read_bytes(), raw)
        self.assertEqual(self.config.read_bytes(), self.original)
        bad = dict(old, staged_config_sha256='f' * 64)
        D.atomic_write(journal, json.dumps(bad).encode())
        with self.assertRaisesRegex(D.DeployError, 'manual_legacy_operation_binding_changed'):
            self.rollout(forward_only=True)
        self.assertFalse(self.calls)
        self.assertFalse(self.stage_mock.called)
        D.atomic_write(journal, raw)
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'legacy_operation_attestation':
                return json.dumps(old)
        self.rollout(forward_only=True, runner=runner)
        self.assertEqual(json.loads(next(self.root.glob('operation.forward-only-abandoned-*.json')).read_bytes()), old)
        self.assertEqual(self.calls[0][0], 'legacy_operation_attestation')
        self.assert_direct_recovery_calls()

    def test_pre_direct_continuation_preserves_history_and_restores_preflight(self):
        old = self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        record = json.loads(journal.read_bytes())
        record['transport_binding'] = self.pre_direct_transport_binding()
        D.atomic_write(journal, json.dumps(record).encode())
        before = journal.read_bytes()
        config = self.config.read_bytes()
        attest = self.continuation_runner(old)
        self.new_candidate_fixture()
        def fail_doctor(command, cwd, stage, **kwargs):
            if stage == 'doctor':
                raise D.DeployError('fixture_doctor_failure')
            return attest(command, cwd, stage, **kwargs)
        with self.assertRaisesRegex(D.DeployError, 'fixture_doctor_failure'):
            self.rollout(continue_forward_only=True, runner=fail_doctor)
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(self.config.read_bytes(), config)
        self.rollout(continue_forward_only=True, runner=attest)
        self.assert_direct_recovery_calls()
        self.assertEqual([p.read_bytes() for p in self.root.glob('operation.forward-only-retry-*.json')], [before, before])

    def test_pre_direct_same_candidate_continuation_is_attested_before_dispatch(self):
        old = self.failed_forward_fixture()
        journal = self.root / 'operation.json'
        record = json.loads(journal.read_bytes())
        record['transport_binding'] = self.pre_direct_transport_binding()
        D.atomic_write(journal, json.dumps(record).encode())
        before = journal.read_bytes()
        with self.assertRaisesRegex(D.DeployError, 'manual_forward_continuation_receipt_invalid'):
            self.rollout(continue_forward_only=True, runner=self.continuation_runner(old, {'attempt': 'f' * 64}))
        self.assertEqual(journal.read_bytes(), before)
        self.assertFalse(self.stage_mock.called)
        self.assertNotIn('upgrade', [stage for stage, _ in self.calls])
        self.rollout(continue_forward_only=True, runner=self.continuation_runner(old))
        self.assert_direct_recovery_calls()

    def test_pre_direct_adoption_journal_is_not_supported_recovery(self):
        old = dict(self.legacy_record(), transport_binding=self.pre_direct_transport_binding(),
                   stage='adoption_apply', adopt=True)
        raw = json.dumps(old).encode()
        journal = self.root / 'operation.json'
        D.atomic_write(journal, raw)
        for arguments in ({}, {'retry_failed': True}, {'forward_only': True}, {'continue_forward_only': True}):
            with self.subTest(arguments=arguments), self.assertRaises(D.DeployError):
                self.rollout(**arguments)
            self.assertEqual(journal.read_bytes(), raw)
            self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.calls)
        self.assertFalse(self.stage_mock.called)

    def test_pre_direct_recovery_rejects_changed_legacy_identity_or_pins(self):
        for change in ('identity', 'pins', 'missing_pin', 'source', 'jump_identity'):
            with self.subTest(change=change):
                jump_identity = self.repo / 'exit-operator-key'
                jump_identity.write_bytes(b'fixture exit key metadata only')
                jump_identity.chmod(0o600)
                self.inventory['all']['children']['exits']['hosts']['exit_0']['ansible_ssh_private_key_file'] = str(jump_identity)
                self.write_inventory()
                old = self.legacy_record()
                old['transport_binding'] = self.pre_direct_transport_binding()
                raw = json.dumps(old).encode()
                D.atomic_write(self.root / 'operation.json', raw)
                if change == 'identity':
                    info = self.identity.stat()
                    os.utime(self.identity, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                elif change == 'pins':
                    self.pins.write_bytes(b'changed pins')
                elif change == 'source':
                    self.inventory['all']['vars']['fixture_changed'] = True
                    self.write_inventory()
                elif change == 'jump_identity':
                    info = jump_identity.stat()
                    os.utime(jump_identity, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                else:
                    D.subprocess.run.return_value = subprocess.CompletedProcess([], 1)
                with self.assertRaises(D.DeployError):
                    self.rollout(forward_only=True)
                self.assertEqual((self.root / 'operation.json').read_bytes(), raw)
                self.assertEqual(self.config.read_bytes(), self.original)
                self.assertFalse(self.calls)
                self.assertFalse(self.stage_mock.called)
                D.subprocess.run.return_value = subprocess.CompletedProcess([], 0)

    def test_legacy_forward_only_archives_attested_hash_and_preserves_original_fields(self):
        old = self.legacy_record()
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'legacy_operation_attestation':
                self.assertTrue(kwargs['capture'])
                self.assertEqual(command[:3], ['ssh', '-F', '/dev/null'])
                return json.dumps(dict(old, staged_config_sha256=old['config_sha256']))
        self.rollout(forward_only=True, runner=runner)
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(json.loads(archived.read_bytes()), dict(old, staged_config_sha256=old['config_sha256']))
        self.assertEqual(self.calls[0][0], 'legacy_operation_attestation')

    def test_legacy_forward_only_attests_exact_baseline_relocation(self):
        # The old local baseline files no longer need to exist for this read.
        self.original += b'ULTRA_UPGRADE_BASELINE_FILE=/nonexistent/private-baseline.json\n'
        old = self.legacy_record()
        old_root = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + self.commit + '-' + old['remote_attempt'])
        expected = D.config_candidate(self.original, self.version, old_root / 'release', old_root / 'baseline/descriptor.json')
        self.assertNotEqual(D.sha(expected), old['config_sha256'])
        D.atomic_write(self.root / 'operation.json', json.dumps(old).encode())
        def runner(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'legacy_operation_attestation':
                self.assertEqual(D.shlex.split(command[-1])[-1], D.sha(expected))
                return json.dumps(dict(old, staged_config_sha256=D.sha(expected)))
        self.rollout(forward_only=True, runner=runner)
        archived = next(self.root.glob('operation.forward-only-abandoned-*.json'))
        self.assertEqual(json.loads(archived.read_bytes()), dict(old, staged_config_sha256=D.sha(expected)))

    def test_legacy_forward_only_rejection_preserves_config_and_journal(self):
        for kind in ('transport', 'config', 'attempt', 'version', 'release', 'failure', 'receipt', 'digest', 'malformed'):
            with self.subTest(kind=kind):
                old = self.legacy_record()
                if kind == 'transport': old['transport_binding'] = 'x' * 64
                if kind == 'config': old['config_sha256'] = 'f' * 64
                if kind == 'attempt': old['remote_attempt'] = 'f' * 64
                if kind in ('version', 'release'):
                    self.original = D.config_candidate(self.original, 'v0.0.1' if kind == 'version' else self.version,
                        '/wrong' if kind == 'release' else D.config_values(self.original)['ULTRA_AUTOMATION_RELEASE_DIR'])
                    self.config.write_bytes(self.original)
                    old['config_sha256'] = D.sha(self.original)
                raw = json.dumps(old).encode()
                D.atomic_write(self.root / 'operation.json', raw)
                def runner(command, cwd, stage, **kwargs):
                    if stage == 'legacy_operation_attestation':
                        if kind == 'failure': raise D.DeployError('fixture_ssh_failure')
                        if kind == 'malformed': return 'not json'
                        receipt = dict(old, staged_config_sha256=old['config_sha256'])
                        if kind == 'receipt': receipt['commit'] = 'f' * 40
                        if kind == 'digest': receipt['staged_config_sha256'] = 'f' * 64
                        return json.dumps(receipt)
                with self.assertRaises(D.DeployError):
                    self.rollout(forward_only=True, runner=runner)
                self.assertEqual((self.root / 'operation.json').read_bytes(), raw)
                self.assertEqual(self.config.read_bytes(), self.original)
                self.assertFalse(list(self.root.glob('operation.forward-only-abandoned-*')))
                self.assertFalse(list(self.root.glob('install.config.before-*')))
                self.stage_mock.assert_not_called()

    def test_native_probe_archive_handoff_preserves_dispatched_cleanup_journal(self):
        secret = b'https://old.example.com/sub/fixture-token'
        self.probe_env(secret)
        original_run = self.run_fixture
        def failed_cleanup(command, cwd, stage, **kwargs):
            original_run(command, cwd, stage)
            self.assertNotIn(secret.decode(), repr(command))
            if stage == 'probe_cleanup':
                raise D.DeployError('fixture_cleanup_failed')
        with self.assertRaisesRegex(D.DeployError, 'fixture_cleanup_failed'):
            self.rollout(runner=failed_cleanup)
        extra = self.stage_mock.call_args.args[8]
        self.assertEqual(extra['subscription-probe-url'], secret)
        self.assertEqual(extra['subscription-probe.sha256'], D.sha(secret).encode())
        upgrade = next(command for stage, command in self.calls if stage == 'upgrade')
        self.assertEqual(D.shlex.split(upgrade[-1])[14], D.sha(secret))
        record = json.loads((self.root / 'operation.json').read_bytes())
        self.assertEqual(record['stage'], 'completed')
        self.assertEqual(record['probe_sha256'], D.sha(secret))
        self.assertNotIn(secret, (self.root / 'operation.json').read_bytes())
        self.probe_env(b'https://old.example.com/sub/new-token')
        self.calls.clear()
        self.rollout()
        self.assertEqual([stage for stage, _ in self.calls], ['canonical_policy', 'probe_cleanup'])
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertFalse((self.root / 'subscription-probe-url').exists())

    def test_native_predispatch_failure_cleans_private_copies(self):
        self.probe_env()
        def failed(command, cwd, stage, **kwargs):
            self.run_fixture(command, cwd, stage)
            if stage == 'doctor':
                raise D.DeployError('fixture_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failed)
        self.assertEqual([stage for stage, _ in self.calls], ['canonical_policy', 'doctor', 'probe_cleanup'])
        self.assertFalse((self.root / 'subscription-probe-url').exists())
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_stage_remote_probe_sends_exact_pair_without_env_or_credential_argv(self):
        secret = b'https://old.example.com/sub/fixture-token'
        manifest = {'source_commit': self.commit, 'version': self.version, 'assets': []}
        raw = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw)
        files = {'subscription-probe-url': secret, 'subscription-probe.sha256': D.sha(secret).encode()}
        def process(command, **kwargs):
            self.assertNotIn(secret.decode(), repr(command))
            with tarfile.open(fileobj=kwargs['stdin'], mode='r|') as archive:
                entries = {member.name: archive.extractfile(member).read() for member in archive}
            self.assertEqual(entries, {'release/release-manifest.json': raw, 'install.config': self.original, **files})
            self.assertEqual(D.shlex.split(command[-1])[-1], D.sha(secret))
            return subprocess.CompletedProcess(command, 0, json.dumps({'architecture': 'arm64',
                'manifest_sha256': D.sha(raw), 'config_sha256': D.sha(self.original),
                'attempt': D.remote_attempt(self.original, self.version)}).encode())
        with patch.object(D.subprocess, 'run', process):
            D.stage_remote(self.repo, self.root, self.bundle, self.original, ['ssh', 'fixture'],
                           self.commit, self.version, D.sha(raw), files)

    def test_native_interrupted_staging_is_retryable_without_dispatch(self):
        self.stage_mock.side_effect = D.DeployError('bridge_staging_failed')
        with self.assertRaisesRegex(D.DeployError, 'bridge_staging_failed'):
            self.rollout(adopt=True)
        self.assertFalse((self.root / 'operation.json').exists())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy'])
        self.stage_mock.side_effect = self.staged_receipt
        self.rollout(adopt=True)
        self.assertEqual(next(self.root.glob('install.config.before-*')).read_bytes(), self.original)

    def test_native_same_commit_replay_keeps_remote_attempt_after_baseline_cleanup(self):
        self.config.write_bytes(self.original + b'ULTRA_UPGRADE_BASELINE_FILE=/private/baseline.json\n')
        baseline_setting = self.config.read_bytes()
        original_prepare = D.stage_upgrade_baseline
        def prepared(config, version, remote_root):
            if not D.config_values(config).get('ULTRA_UPGRADE_BASELINE_FILE'):
                return original_prepare(config, version, remote_root)
            staged = D.config_candidate(config, version, remote_root / 'release', remote_root / 'baseline/descriptor.json')
            return staged, {'baseline/descriptor.json': b'{}', 'baseline/operator-journal.json': b'{}'}
        with patch.object(D, 'stage_upgrade_baseline', side_effect=prepared):
            first_attempt = D.remote_attempt(D.projected_upgrade_config(baseline_setting, 'upgrade-v2'), self.version)
            self.rollout()
            self.assertNotIn(b'ULTRA_UPGRADE_BASELINE_FILE=', self.config.read_bytes())
            first_config = self.stage_mock.call_args.args[3]
            self.rollout()
        first, second = self.stage_mock.call_args_list
        self.assertEqual(first.args[3], first_config)
        self.assertEqual(second.args[3], first_config)
        with patch.object(D, 'stage_upgrade_baseline', side_effect=prepared):
            self.assertEqual(D.completed_baseline_replay(
                self.root, self.config.read_bytes(), self.version, self.commit, 'upgrade-v2')[0], first_attempt)
        self.assertEqual(first.args[1], second.args[1])
        self.assertEqual(D.remote_attempt(first.args[3], self.version), D.remote_attempt(second.args[3], self.version))

    def test_native_changed_transport_or_manifest_rejects_resume(self):
        def failure(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('upgrade_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failure)
        self.pins.write_bytes(b'new pins')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()
        self.pins.write_bytes(b'fixture pins')
        (self.bundle / 'release-manifest.json').write_bytes(self.manifest + b' ')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_native_wrong_topology_and_provenance_fail_before_config_change(self):
        self.inventory['all']['children']['bridge']['hosts']['bridge']['ansible_host'] = '192.0.2.99'
        self.write_inventory()
        with self.assertRaisesRegex(D.DeployError, 'topology_changed'):
            self.rollout()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.stage_mock.call_count, 0)
        self.inventory['all']['children']['bridge']['hosts']['bridge']['ansible_host'] = '192.0.2.10'
        self.write_inventory()
        D.atomic_write(self.operator / 'job.json', b'{"operation":"adopt","request_sha256":"wrong"}')
        with self.assertRaisesRegex(D.DeployError, 'provenance_invalid'):
            self.rollout()

    def test_native_stale_exit_set_fails_before_staging(self):
        self.inventory['all']['children']['exits']['hosts']['exit_0']['ansible_host'] = '192.0.2.99'
        self.write_inventory()
        with self.assertRaisesRegex(D.DeployError, 'topology_changed'):
            self.rollout()
        self.assertFalse(self.stage_mock.called)

    def test_native_missing_key_pins_or_endpoint_pin_fails_before_staging(self):
        for path in [self.identity, self.pins]:
            raw = path.read_bytes()
            path.unlink()
            with self.assertRaises(OSError):
                self.rollout()
            path.write_bytes(raw)
            path.chmod(0o600)
        with patch.object(D.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(D.DeployError, 'endpoint_pin_missing'):
                self.rollout()
        self.assertFalse(self.stage_mock.called)

    def test_native_wrapper_does_not_read_identity_contents(self):
        original = Path.read_bytes
        def read(path):
            if path == self.identity:
                raise AssertionError('wrapper read private key')
            return original(path)
        with patch.object(Path, 'read_bytes', read):
            self.rollout()

    def test_native_identity_replacement_and_mode_change_fail_resume(self):
        def failure(command, cwd, stage, **kwargs):
            if stage == 'upgrade':
                raise D.DeployError('upgrade_failed')
        with self.assertRaises(D.DeployError):
            self.rollout(runner=failure)
        self.identity.chmod(0o644)
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()
        self.identity.chmod(0o600)
        self.identity.write_bytes(b'replaced credential')
        with self.assertRaisesRegex(D.DeployError, 'manual_operation_quiescence_migration_required'):
            self.rollout()

    def test_native_forbidden_secrets_fail_before_any_copy_or_stage(self):
        for key in ['TELEGRAM_BOT_TOKEN', 'PROVIDER_API_KEY', 'MINISIGN_SECRET_KEY', 'MINISIGN_PASSWORD',
                    'MINISIGN_PRIVATE_KEY_FILE', 'ULTRA_RELEASE_SIGNING_PRIVATE_KEY',
                    'RELEASE_SIGNING_PASSPHRASE', 'EXAMPLE_PROVIDER_API_KEY', 'example_provider_api_key', 'ultra_db_dsn',
                    'ULTRA_CUTOVER_SUBSCRIPTION_URL']:
            with self.subTest(key=key):
                raw = self.original + key.encode() + b'=sensitive-fixture\n'
                self.config.write_bytes(raw)
                with self.assertRaisesRegex(D.DeployError, '^canonical_config_contains_forbidden_secret$'):
                    self.rollout()
                self.assertFalse(self.stage_mock.called)
                self.assertEqual(self.calls, [])
                self.assertEqual(self.config.read_bytes(), raw)
                self.assertFalse(list(self.root.glob('install.config.before-*')))

    def test_native_go_policy_rejection_precedes_backup_and_staging(self):
        def reject(command, cwd, stage, **kwargs):
            self.assertEqual(stage, 'canonical_policy')
            self.assertEqual(command[1], 'plan')
            raise D.DeployError('canonical_policy_failed_exit_1')
        with self.assertRaisesRegex(D.DeployError, 'canonical_policy_failed_exit_1'):
            self.rollout(runner=reject)
        self.assertFalse(self.stage_mock.called)
        self.assertFalse(list(self.root.glob('install.config.before-*')))
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_native_staging_sends_only_manifest_assets_and_exact_config(self):
        manifest = {'source_commit': self.commit, 'version': self.version,
                    'assets': [{'name': 'fixture', 'sha256': D.sha(b'fixture'), 'size': 7}]}
        raw_manifest = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw_manifest)
        (self.bundle / 'fixture').write_bytes(b'fixture')
        secret = self.repo / '.env'
        secret.write_bytes(b'not-to-be-read')
        real_read = Path.read_bytes
        def read(path):
            if path == secret:
                raise AssertionError('local .env read')
            return real_read(path)
        def process(command, **kwargs):
            stream = kwargs['stdin']
            with tarfile.open(fileobj=stream, mode='r|*') as archive:
                members = [(member.name, archive.extractfile(member).read()) for member in archive]
            self.assertEqual(members, [('release/release-manifest.json', raw_manifest),
                                      ('release/fixture', b'fixture'), ('install.config', self.original)])
            self.assertEqual(D.shlex.split(command[-1])[4], 'stage')
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertEqual(kwargs['timeout'], 1800)
            return subprocess.CompletedProcess(command, 0, json.dumps({'architecture': 'arm64',
                'manifest_sha256': D.sha(raw_manifest), 'config_sha256': D.sha(self.original),
                'attempt': D.remote_attempt(self.original, self.version)}).encode())
        with patch.object(Path, 'read_bytes', read), patch.object(D.subprocess, 'run', process):
            architecture = D.stage_remote(self.repo, self.root, self.bundle, self.original,
                ['ssh', '-F', '/dev/null', 'root@192.0.2.10'], self.commit, self.version, D.sha(raw_manifest))
        self.assertEqual(architecture['architecture'], 'arm64')

    def test_native_staging_timeout_is_bounded_and_reported(self):
        manifest = {'source_commit': self.commit, 'version': self.version,
                    'assets': [{'name': 'fixture', 'sha256': D.sha(b'fixture'), 'size': 7}]}
        raw_manifest = json.dumps(manifest).encode()
        (self.bundle / 'release-manifest.json').write_bytes(raw_manifest)
        (self.bundle / 'fixture').write_bytes(b'fixture')
        def timeout(command, **kwargs):
            self.assertEqual(kwargs['timeout'], 1800)
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        fake_subprocess = type('Subprocess', (), {'run': staticmethod(timeout),
            'TimeoutExpired': subprocess.TimeoutExpired, 'PIPE': subprocess.PIPE,
            'DEVNULL': subprocess.DEVNULL})
        self.stage.stop()
        try:
            with patch.object(D, 'subprocess', fake_subprocess):
                with self.assertRaisesRegex(D.DeployError, '^bridge_staging_timeout$'):
                    D.stage_remote(self.repo, self.root, self.bundle, self.original,
                        ['ssh', '-F', '/dev/null', 'root@192.0.2.10'], self.commit, self.version, D.sha(raw_manifest))
        finally:
            self.stage.start()

    def test_native_canonical_route_survives_deleted_adopt_directory(self):
        shutil.rmtree(self.operator.parent)
        self.original = re.sub(rb'^ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=.*\n', b'', self.original, flags=re.MULTILINE)
        self.config.write_bytes(self.original)
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY': '', 'ULTRA_OPERATOR_IDENTITY': str(self.identity),
                                     'ULTRA_OPERATOR_KNOWN_HOSTS': str(self.pins)}):
            self.rollout(adopt=True)
        staged = self.stage_mock.call_args.args[3]
        self.assertEqual(staged, self.config.read_bytes())
        self.assertNotIn(str(self.identity).encode(), staged)
        self.assertNotIn(str(self.pins).encode(), staged)
        self.assertEqual([s for s, _ in self.calls], ['canonical_policy', 'doctor', 'adoption_check', 'adoption_apply', 'status'])
        transport = self.stage_mock.call_args.args[4]
        self.assertEqual(transport[-1], 'root@192.0.2.10')
        self.assertFalse(any('ProxyCommand=' in token for token in transport))

    def test_native_canonical_route_requires_both_local_references(self):
        self.original = re.sub(rb'^ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=.*\n', b'', self.original, flags=re.MULTILINE)
        self.config.write_bytes(self.original)
        with patch.dict(os.environ, {'ULTRA_OPERATOR_INVENTORY': '', 'ULTRA_OPERATOR_IDENTITY': str(self.identity),
                                     'ULTRA_OPERATOR_KNOWN_HOSTS': ''}):
            with self.assertRaisesRegex(D.DeployError, 'identity_and_pins_required'):
                self.rollout()
        self.assertFalse(self.stage_mock.called)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_native_read_only_failure_then_config_correction_changes_attempt(self):
        def reject(command, cwd, stage, **kwargs):
            if stage == 'adoption_check':
                raise D.DeployError('adoption_check_failed_exit_1')
        with self.assertRaisesRegex(D.DeployError, 'adoption_check_failed_exit_1'):
            self.rollout(adopt=True, runner=reject)
        first_config = self.stage_mock.call_args.args[3]
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'operation.json').exists())
        self.config.write_bytes(self.original + b'CORRECTED_POLICY=1\n')
        self.rollout(adopt=True)
        corrected = self.stage_mock.call_args.args[3]
        self.assertNotEqual(D.config_values(first_config)['ULTRA_AUTOMATION_RELEASE_DIR'],
                            D.config_values(corrected)['ULTRA_AUTOMATION_RELEASE_DIR'])


class RemoteProgram(unittest.TestCase):
    def test_installed_runtime_source_bound_to_doctor_and_upgrade(self):
        marker = ('secrets-source.json', b'{"secrets_source":"installed-runtime"}')
        staged = self.execute('stage', self.archive(mutate=lambda entries: entries + [marker]))
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertFalse((self.root / '.env').exists())
        self.assertFalse((self.root / 'stage.env').exists())
        for action in ('doctor', 'upgrade'):
            result = self.execute('run', None, self.architecture, action)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads(self.result.read_bytes())
            self.assertEqual(args.count('--secrets-source'), 1)
            self.assertEqual(args[args.index('--secrets-source') + 1], 'installed-runtime')
            self.assertEqual(args[args.index('--config') + 1], str(self.root / 'install.config'))
            self.assertEqual(args[0], 'doctor' if action == 'doctor' else 'operator-upgrade')
        changed = self.execute('stage', self.archive())
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn(b'manual_secrets_source_changed', changed.stderr)

    def test_lifecycle_actions_reach_installer_with_explicit_context(self):
        staged = self.execute('stage', self.archive())
        self.assertEqual(staged.returncode, 0, staged.stderr)
        for action, command in (('lifecycle_doctor', 'doctor'),
                                ('lifecycle_upgrade', 'operator-upgrade'),
                                ('lifecycle_status', 'status')):
            result = self.execute('run', None, self.architecture, action)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads(self.result.read_bytes())
            self.assertEqual(args[0], command)
            self.assertIn('--lifecycle', args)

    def test_runtime_source_rejects_adoption_and_invalid_selectors(self):
        marker = ('secrets-source.json', b'{"secrets_source":"installed-runtime"}')
        staged = self.execute('stage', self.archive(mutate=lambda entries: entries + [marker]))
        self.assertEqual(staged.returncode, 0, staged.stderr)
        for action in ('adoption_check', 'adoption_apply'):
            result = self.execute('run', None, self.architecture, action)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'manual_secrets_source_action_invalid', result.stderr)
        D.atomic_write(self.root / 'secrets-source.json', b'{"secrets_source":"arbitrary-source"}')
        result = self.execute('run', None, self.architecture, 'doctor')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'manual_secrets_source_invalid', result.stderr)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.parent = self.directory / 'state' / 'inputs'
        self.parent.parent.mkdir(mode=0o700)
        self.parent.mkdir(mode=0o700)
        self.commit = 'a' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.result = self.directory / 'executed.json'
        self.architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}[D.platform.machine()]
        binary = ('#!/usr/bin/env python3\nimport json,sys\nopen(' + repr(str(self.result)) + ',"w").write(json.dumps(sys.argv[1:]))\n').encode()
        self.assets = {'ultra-install-linux-' + self.architecture: binary}
        self.assets.update({'fixture-' + str(i): b'fixture' for i in range(13)})
        self.manifest = json.dumps({'source_commit': self.commit, 'version': self.version,
            'assets': [{'name': name, 'size': len(raw), 'sha256': D.sha(raw)} for name, raw in self.assets.items()]}).encode()
        self.config = b'SECRETS_ENV_FILE=/etc/ultra-relay/.env\n'
        # Run the actual remote implementation against a temporary local root;
        # adapt only the production root/UID checks for an unprivileged fixture.
        self.program = D.REMOTE_PROGRAM.replace("Path('/var/lib/ultra-ansible/operator-inputs')", 'Path(' + repr(str(self.parent)) + ')')
        self.program = self.program.replace('need(os.geteuid()==0)', 'need(True)').replace('info.st_uid==0', 'info.st_uid==os.geteuid()')
        self.root = self.parent / ('manual-' + self.commit + '-' + D.remote_attempt(self.config, self.version))

    def archive(self, mutate=None, forward_journal=None, forward_prior_operation=None, manifest=None, config=None):
        entries = [('release/release-manifest.json', self.manifest if manifest is None else manifest)]
        entries += [('release/' + name, data) for name, data in self.assets.items()]
        entries += [('install.config', self.config if config is None else config)]
        if forward_journal is not None:
            entries.append(('forward-operation.json', forward_journal))
        if forward_prior_operation is not None:
            entries.append(('forward-prior-operation.json', forward_prior_operation))
        if mutate:
            entries = mutate(entries)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w|') as archive:
            for name, raw in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        return stream.getvalue()

    def execute(self, mode, data=None, *args, probe_sha='', forward_only=False, forward_sha='', prior_sha='', prior_version='v0.0.1', identity=None):
        if mode == 'run':
            args = (*args, *(['0'] * max(0, 4 - len(args))))
            args = (*args[:3], '1' if forward_only else '0', *args[4:])
            if forward_sha:
                args = (*args, probe_sha, forward_sha)
            elif probe_sha:
                args = (*args, probe_sha)
            if prior_sha:
                args = (*args, str(self.parent.parent / ('upgrade-'+prior_version)),
                        str(self.root / 'forward-prior-operation.json'), prior_sha)
        else:
            if forward_sha:
                args = (*args, probe_sha, forward_sha, prior_sha)
            elif probe_sha:
                args = (*args, probe_sha)
        commit, version, manifest, config, attempt = identity or (
            self.commit, self.version, self.manifest, self.config, D.remote_attempt(self.config, self.version))
        return subprocess.run([D.sys.executable, '-I', '-c', self.program, mode, commit, version,
            D.sha(manifest), D.sha(config), attempt, *args], input=data, capture_output=True)

    def absent_operation_fixture(self):
        old_commit = 'b' * 40
        old_version = 'v0.0.' + str(int(old_commit, 16))
        old_attempt = 'd' * 64
        old_inputs = self.parent / ('manual-' + old_commit + '-' + old_attempt)
        (old_inputs / 'release').mkdir(parents=True, mode=0o700)
        old_inputs.chmod(0o700)
        old_manifest = json.dumps({'source_commit': old_commit, 'version': old_version}).encode()
        old_config = b'INSTALL_SCHEMA_VERSION=2\n'
        D.atomic_write(old_inputs / 'release/release-manifest.json', old_manifest)
        D.atomic_write(old_inputs / 'install.config', old_config)
        proof = {'schema': 1, 'commit': old_commit, 'version': old_version,
                 'remote_attempt': old_attempt, 'stage': 'upgrade', 'mutator_dispatched': True,
                 'manifest_sha256': D.sha(old_manifest), 'staged_config_sha256': D.sha(old_config)}
        proof_raw = json.dumps(proof).encode()
        prior_commit = 'c' * 40
        prior_version = 'v0.0.' + str(int(prior_commit, 16))
        prior = json.dumps({'commit': prior_commit, 'version': prior_version, 'remote_attempt': 'e' * 64}).encode()
        staged = self.execute('stage', self.archive(forward_journal=proof_raw, forward_prior_operation=prior),
                              forward_sha=D.sha(proof_raw), prior_sha=D.sha(prior))
        self.assertEqual(staged.returncode, 0, staged.stderr)
        operation = self.parent.parent / ('upgrade-' + self.version)
        old_directory = self.parent.parent / ('upgrade-' + old_version)
        old_id = str(D.uuid.UUID(bytes=hashlib.sha256(str(old_directory).encode()).digest()[:16], version=4))
        D.atomic_write(self.parent.parent / 'lifecycle.json', json.dumps({'id': old_id, 'phase': 'applying'}).encode())
        return operation, old_inputs, old_id, proof_raw, D.sha(prior), prior_version

    def chain_fixture(self, root_is_prior=False):
        state=self.parent.parent
        prior_commit='c'*40
        prior_version='v0.0.'+str(int(prior_commit,16))
        prior_attempt='e'*64
        old_commit='b'*40
        old_version='v0.0.'+str(int(old_commit,16))
        old_attempt='d'*64
        def identity(path):
            return str(D.uuid.UUID(bytes=hashlib.sha256(str(path).encode()).digest()[:16],version=4))
        old=state/('upgrade-'+old_version)
        prior=state/('upgrade-'+prior_version)
        target=state/('upgrade-'+self.version)
        old_id,prior_id,new_id=map(identity,(old,prior,target))
        def inputs(commit,version,attempt):
            directory=self.parent/('manual-'+commit+'-'+attempt)
            (directory/'release').mkdir(parents=True,mode=0o700)
            directory.chmod(0o700)
            manifest=json.dumps({'source_commit':commit,'version':version}).encode()
            config=b'fixture config'
            D.atomic_write(directory/'release/release-manifest.json',manifest)
            D.atomic_write(directory/'install.config',config)
            return D.sha(manifest),D.sha(config)
        old_manifest,old_config=inputs(old_commit,old_version,old_attempt)
        prior_manifest,prior_config=(None,None) if root_is_prior else inputs(prior_commit,prior_version,prior_attempt)
        proof=json.dumps({'schema':1,'commit':old_commit,'version':old_version,'remote_attempt':old_attempt,
            'stage':'upgrade','mutator_dispatched':True,'manifest_sha256':old_manifest,
            'staged_config_sha256':old_config}).encode()
        proof_sha=D.sha(proof)
        history=json.dumps({'schema':1,'commit':prior_commit,'version':prior_version,'remote_attempt':prior_attempt,
            'stage':'upgrade','mutator_dispatched':True,'manifest_sha256':prior_manifest,
            'staged_config_sha256':prior_config,'forward_journal_sha256':proof_sha}).encode()
        history_sha=D.sha(history)
        inventory={'all':{'children':{'bridge':{'hosts':{'bridge':{}}}}}}
        (old/'activate').mkdir(parents=True,mode=0o700)
        old.chmod(0o700)
        request=json.dumps({'inventory':inventory,'variables':{'ultra_lifecycle_id':old_id}}).encode()
        for name,raw in {'activate/request.json':request,'activate/job.json':b'{}',
                         'activate/receipt.json':b'{}','operator-plan.json':b'{}'}.items():
            D.atomic_write(old/name,raw)
        prior.mkdir(mode=0o700)
        for name in ['operator-plan.json','execution-mode.json','identity','inventory.frozen.json']:
            D.atomic_write(prior/name,b'{}')
        for name in ['inspect','hosts','domain-inspect','architectures','recovery-bundle',
                     'forward-maintenance-fixture','handoff-drain-fixture']:
            directory=prior/name
            directory.mkdir(mode=0o700)
            if name=='architectures':
                D.atomic_write(directory/'bridge.json',b'{}')
            elif name!='recovery-bundle':
                for artifact in ['request.json','job.json','receipt.json','result.json']:
                    D.atomic_write(directory/artifact,b'{}')
        D.atomic_write(prior/'forward-handoff.json',json.dumps({'schema':1,'proof_sha256':proof_sha,
            'old_id':old_id,'new_id':prior_id,'drain_directory':str(prior/'handoff-drain-fixture')}).encode())
        ledger=json.dumps({'version':1,'ids':[old_id],'handoff':{'old_id':old_id,'new_id':prior_id}}).encode()
        D.atomic_write(state/'lifecycle-retired.json',ledger)
        D.atomic_write(state/'lifecycle.json',json.dumps({'id':prior_id,'phase':'applying'}).encode())
        prior_root_manifest=(json.dumps({'source_commit':prior_commit,'version':prior_version,
            'assets':[{'name':name,'size':len(raw),'sha256':D.sha(raw)} for name,raw in self.assets.items()]},
            sort_keys=True,separators=(',',':')).encode())
        prior_config_raw=b'fixture config'
        if root_is_prior:
            prior_manifest=D.sha(prior_root_manifest)
            prior_config=D.sha(prior_config_raw)
            history=json.dumps({'schema':1,'commit':prior_commit,'version':prior_version,
                'remote_attempt':prior_attempt,'stage':'upgrade','mutator_dispatched':True,
                'manifest_sha256':prior_manifest,'staged_config_sha256':prior_config,
                'forward_journal_sha256':proof_sha}).encode()
            history_sha=D.sha(history)
        root_identity=(prior_commit,prior_version,prior_root_manifest,prior_config_raw,prior_attempt) if root_is_prior else None
        root_prior=(json.dumps({'commit':old_commit,'version':old_version,'remote_attempt':old_attempt,
            'manifest_sha256':old_manifest,'staged_config_sha256':old_config,
            'forward_journal_sha256':proof_sha},sort_keys=True,separators=(',',':')).encode() if root_is_prior else history)
        root_prior_sha=D.sha(root_prior)
        staged=self.execute('stage',self.archive(forward_journal=proof,forward_prior_operation=root_prior,
                                manifest=root_identity[2] if root_identity else None,
                                config=root_identity[3] if root_identity else None),
                            forward_sha=proof_sha,prior_sha=root_prior_sha,identity=root_identity)
        self.assertEqual(staged.returncode,0,staged.stderr)
        chain_args=[self.commit,self.version,D.sha(self.manifest),D.sha(self.config),D.remote_attempt(self.config,self.version),
                    prior_commit,prior_version,prior_attempt,prior_manifest,prior_config,history_sha]
        def continued():
            return self.execute('continue',None,'',proof_sha,root_prior_sha,*chain_args,identity=root_identity)
        first=continued()
        self.assertEqual(first.returncode,0,first.stderr)
        attestation=json.loads(first.stdout)['chain_attestation']
        target.mkdir(mode=0o700)
        chain={key:value for key,value in attestation.items() if key!='phase'}
        chain.update(schema=1,original_retirement_json=ledger.decode())
        D.atomic_write(target/'forward-chain.json',json.dumps(chain).encode())
        def dispatched():
            return self.execute('run',None,self.architecture,'upgrade','0','1','',proof_sha,'1',
                str(prior),str(self.root/'forward-prior-operation.json'),history_sha,*chain_args,forward_only=True)
        return continued,dispatched,target,prior,old_id,prior_id,new_id,proof_sha,history_sha,chain_args,root_prior_sha

    def test_chain_continue_from_prior_root_keeps_inherited_journal_distinct(self):
        continued,_,_,_,_,_,_,proof_sha,chain_prior_sha,_,root_prior_sha=self.chain_fixture(root_is_prior=True)
        # B's root carries the authenticated A journal, while the requested C
        # transition names B's own journal as its immediate predecessor.
        self.assertNotEqual(root_prior_sha,chain_prior_sha)
        result=continued()
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual(receipt['chain_attestation']['proof_sha256'],proof_sha)
        self.assertEqual(receipt['chain_attestation']['prior_journal_sha256'],chain_prior_sha)

    def test_chain_continue_and_run_validate_A_owned_prefix_and_B_owned_restart(self):
        continued,dispatched,target,prior,old_id,prior_id,new_id,proof_sha,history_sha,args,_=self.chain_fixture()
        for phase in ['start','restart']:
            with self.subTest(phase=phase):
                if phase=='restart':
                    request=json.dumps({'inventory':{'all':{'children':{'bridge':{'hosts':{'bridge':{}}}}}},
                        'variables':{'ultra_lock_directory':str(self.parent.parent),
                                     'ultra_forward_old_id':prior_id,'ultra_lifecycle_id':new_id}},
                        sort_keys=True,separators=(',',':')).encode()
                    request_sha=D.sha(request)
                    result={'verified':True,'old_id':prior_id,'new_id':new_id}
                    job={'schema_version':1,'operation':'drain-upgrade-workers',
                         'request_sha256':request_sha,'binary_sha256':request_sha}
                    drain=target/'handoff-drain-fixture'
                    drain.mkdir(mode=0o700)
                    raws={'request.json':request,'job.json':json.dumps(job).encode(),
                          'receipt.json':json.dumps(dict(job,state='succeeded',result=result)).encode(),
                          'result.json':json.dumps(result).encode()}
                    for name,raw in raws.items(): D.atomic_write(drain/name,raw)
                    intent={'schema':1,'proof_sha256':proof_sha,'old_id':prior_id,'new_id':new_id,
                            'drain_directory':str(drain)}
                    for key,name in [('request_sha256','request.json'),('job_sha256','job.json'),
                                     ('receipt_sha256','receipt.json'),('result_sha256','result.json')]:
                        intent[key]=D.sha(raws[name])
                    D.atomic_write(target/'forward-handoff.json',json.dumps(intent).encode())
                    D.atomic_write(self.parent.parent/'lifecycle-retired.json',json.dumps({'version':1,
                        'ids':[old_id,prior_id],'handoff':{'old_id':prior_id,'new_id':new_id}}).encode())
                    D.atomic_write(self.parent.parent/'lifecycle.json',json.dumps({'id':new_id,'phase':'applying'}).encode())
                receipt=continued()
                self.assertEqual(receipt.returncode,0,receipt.stderr)
                self.assertEqual(json.loads(receipt.stdout)['chain_attestation']['phase'],phase)
                run=dispatched()
                self.assertEqual(run.returncode,0,run.stderr)
                executed=json.loads(self.result.read_bytes())
                self.assertIn('--forward-prior-journal-sha256',executed)
                self.assertIn(history_sha,executed)
                self.result.unlink()
                chain=target/'forward-chain.json'
                raw=chain.read_bytes()
                changed=json.loads(raw)
                changed['prior_evidence_sha256']='f'*64
                D.atomic_write(chain,json.dumps(changed).encode())
                self.assertNotEqual(continued().returncode,0)
                self.assertNotEqual(dispatched().returncode,0)
                self.assertFalse(self.result.exists())
                D.atomic_write(chain,raw)
                args[-1]='bad'
                self.assertNotEqual(continued().returncode,0)
                self.assertNotEqual(dispatched().returncode,0)
                args[-1]=history_sha

    def test_continuation_accepts_absent_operation_under_lock_and_retries_same_candidate(self):
        operation, _, old_id, proof, prior_sha, prior_version = self.absent_operation_fixture()
        before = {str(p): p.read_bytes() for p in self.parent.parent.rglob('*') if p.is_file()}
        continued = self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha)
        self.assertEqual(continued.returncode, 0, continued.stderr)
        receipt = json.loads(continued.stdout)
        self.assertEqual(receipt['prior_candidate'], {})
        self.assertIs(receipt['operation_absent'], True)
        self.assertEqual(receipt['lifecycle_id'], old_id)
        self.assertFalse(operation.exists())
        self.assertEqual({str(p): p.read_bytes() for p in self.parent.parent.rglob('*') if p.is_file()}, before)
        self.assertFalse(self.result.exists())
        dispatched = self.execute('run', None, self.architecture, 'upgrade', '0', '1', '', D.sha(proof), '1',
                                  forward_only=True, prior_sha=prior_sha, prior_version=prior_version)
        self.assertEqual(dispatched.returncode, 0, dispatched.stderr)
        self.assertIn('--forward-only', json.loads(self.result.read_bytes()))

    def test_new_head_chain_request_retains_O_owned_pre_handoff_protocol(self):
        _,_,_,proof,prior_sha,_=self.absent_operation_fixture()
        # New-head probes include chain inputs, but O still owns the lifecycle.
        # The absent A prefix must retain its existing pre-handoff receipt.
        target_commit='f'*40
        args=[target_commit,'v0.0.'+str(int(target_commit,16)),'1'*64,'2'*64,'3'*64,
              self.commit,self.version,D.remote_attempt(self.config,self.version),
              D.sha(self.manifest),D.sha(self.config),'4'*64]
        result=self.execute('continue',None,'',D.sha(proof),prior_sha,*args)
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertTrue(receipt['operation_absent'])
        self.assertNotIn('chain_attestation',receipt)
        operation=self.parent.parent/('upgrade-'+self.version)
        operation.mkdir(mode=0o700)
        for name in ['execution-mode.json','operator-plan.json']:
            D.atomic_write(operation/name,b'{}')
        result=self.execute('continue',None,'',D.sha(proof),prior_sha,*args)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('chain_attestation',json.loads(result.stdout))
        (self.root/'install.config').chmod(0o644)
        self.assertNotEqual(self.execute('continue',None,'',D.sha(proof),prior_sha,*args).returncode,0)

    def test_absent_operation_continuation_rejects_busy_lock(self):
        _, _, _, proof, prior_sha, _ = self.absent_operation_fixture()
        with D.lock(self.parent / 'manual-deploy.lock'):
            rejected = self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stderr, b'ultra_forward_attestation:remote_setup:lock_busy\n')
        self.assertFalse(self.result.exists())

    def test_absent_operation_is_rechecked_before_dispatch_after_attestation(self):
        operation, _, _, proof, prior_sha, prior_version = self.absent_operation_fixture()
        continued = self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha)
        self.assertEqual(continued.returncode, 0, continued.stderr)
        # A competing dispatch after attestation must not reuse the absence proof.
        operation.mkdir(mode=0o700)
        for name in ['operator-plan.json', 'execution-mode.json']:
            D.atomic_write(operation / name, b'{}')
        (operation / 'activate').mkdir(mode=0o700)
        dispatched = self.execute('run', None, self.architecture, 'upgrade', '0', '1', '', D.sha(proof), '1',
                                  forward_only=True, prior_sha=prior_sha, prior_version=prior_version)
        self.assertNotEqual(dispatched.returncode, 0)
        self.assertFalse(self.result.exists())

    def test_absent_operation_continuation_rejects_changed_bindings(self):
        _, old_inputs, old_id, proof, prior_sha, _ = self.absent_operation_fixture()
        lifecycle = self.parent.parent / 'lifecycle.json'
        for path in [self.root / 'install.config', self.root / 'release/fixture-0',
                     self.root / 'forward-operation.json', self.root / 'forward-prior-operation.json',
                     old_inputs / 'release/release-manifest.json', old_inputs / 'install.config']:
            with self.subTest(path=str(path)):
                original = path.read_bytes()
                D.atomic_write(path, b'changed')
                self.assertNotEqual(self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha).returncode, 0)
                D.atomic_write(path, original)
        for state in [{'id': 'foreign', 'phase': 'applying'}, {'id': old_id, 'phase': 'released'}]:
            with self.subTest(lifecycle=state):
                D.atomic_write(lifecycle, json.dumps(state).encode())
                self.assertNotEqual(self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha).returncode, 0)
        D.atomic_write(lifecycle, json.dumps({'id': old_id, 'phase': 'applying'}).encode())
        for key, value in [('schema', 2), ('stage', 'status'), ('mutator_dispatched', False), ('remote_attempt', 'bad')]:
            with self.subTest(proof=key):
                changed = json.loads(proof)
                changed[key] = value
                changed_raw = json.dumps(changed).encode()
                D.atomic_write(self.root / 'forward-operation.json', changed_raw)
                self.assertNotEqual(self.execute('continue', forward_sha=D.sha(changed_raw), prior_sha=prior_sha).returncode, 0)
        self.assertFalse(self.result.exists())

    def test_absent_operation_exception_rejects_existing_unsafe_paths(self):
        operation, _, _, proof, prior_sha, _ = self.absent_operation_fixture()
        for kind in ['dangling symlink', 'directory symlink', 'file', 'public directory', 'activation', 'drain']:
            with self.subTest(kind=kind):
                if kind == 'dangling symlink':
                    operation.symlink_to(self.parent.parent / 'missing')
                elif kind == 'directory symlink':
                    operation.symlink_to(self.root, target_is_directory=True)
                elif kind == 'file':
                    D.atomic_write(operation, b'{}')
                else:
                    operation.mkdir(mode=0o700)
                    if kind == 'public directory':
                        operation.chmod(0o755)
                    else:
                        for name in ['operator-plan.json', 'execution-mode.json']:
                            D.atomic_write(operation / name, b'{}')
                        (operation / ('activate' if kind == 'activation' else 'handoff-drain-unsafe')).mkdir(mode=0o700)
                rejected = self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(self.result.exists())
                if operation.is_symlink() or operation.is_file():
                    operation.unlink()
                else:
                    D.shutil.rmtree(operation)

    def test_partial_broker_bootstrap_continuation_accepts_prior_digest_and_missing_ledger(self):
        old_commit = 'b' * 40
        old_version = 'v0.0.' + str(int(old_commit, 16))
        proof = json.dumps({'commit': old_commit, 'version': old_version}).encode()
        forward_sha = D.sha(proof)
        prior = json.dumps({'commit': old_commit, 'version': old_version}).encode()
        prior_sha = D.sha(prior)
        staged = self.execute('stage', self.archive(forward_journal=proof, forward_prior_operation=prior),
                              forward_sha=forward_sha, prior_sha=prior_sha)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        operation = self.parent.parent / ('upgrade-' + self.version)
        operation.mkdir(mode=0o700)
        for name in ['operator-plan.json', 'execution-mode.json']:
            D.atomic_write(operation / name, b'{}')
        old_state = self.parent.parent / ('upgrade-' + old_version)
        old_id = str(D.uuid.UUID(bytes=hashlib.sha256(str(old_state).encode()).digest()[:16], version=4))
        D.atomic_write(self.parent.parent / 'lifecycle.json', json.dumps({'id': old_id, 'phase': 'applying'}).encode())
        new_id = str(D.uuid.UUID(bytes=hashlib.sha256(str(operation).encode()).digest()[:16], version=4))
        drain = operation / 'handoff-drain-fixture'
        drain.mkdir(mode=0o700)
        drain_request = json.dumps({'inventory': {}, 'variables': {
            'ultra_lock_directory': str(self.parent.parent), 'ultra_forward_old_id': old_id,
            'ultra_lifecycle_id': new_id}}, sort_keys=True, separators=(',', ':')).encode()
        drain_sha = D.sha(drain_request)
        drain_result = {'verified': True, 'old_id': old_id, 'new_id': new_id}
        drain_receipt = {'schema_version': 1, 'operation': 'drain-upgrade-workers',
                         'request_sha256': drain_sha, 'binary_sha256': drain_sha,
                         'state': 'succeeded', 'code': '', 'result': drain_result}
        drain_rows = {'request.json': drain_request,
                      'job.json': json.dumps({k: v for k, v in drain_receipt.items() if k not in ('state', 'code', 'result')}).encode(),
                      'receipt.json': json.dumps(drain_receipt).encode(),
                      'result.json': json.dumps(drain_result).encode()}
        for name, raw in drain_rows.items():
            D.atomic_write(drain / name, raw)
        bootstrap = operation / 'broker-bootstrap-fixture'
        bootstrap.mkdir(mode=0o700)
        request = json.dumps({'inventory': {}, 'variables': {
            'ultra_lock_directory': str(self.parent.parent), 'ultra_forward_old_id': old_id,
            'ultra_forward_candidate_id': new_id,
            'ultra_controller_directory': '/opt/ultra-ansible/releases/managed-'+self.version}},
            sort_keys=True, separators=(',', ':')).encode()
        request_sha = D.sha(request)
        result = {'verified': True, 'old_id': old_id,
                  'controller_directory': '/opt/ultra-ansible/releases/managed-'+self.version}
        receipt = {'schema_version': 1, 'operation': 'bootstrap-forward-broker',
                   'request_sha256': request_sha, 'binary_sha256': request_sha,
                   'state': 'succeeded', 'code': '', 'result': result}
        rows = {'request.json': request,
                'job.json': json.dumps({k: v for k, v in receipt.items() if k not in ('state', 'code', 'result')}).encode(),
                'receipt.json': json.dumps(receipt).encode(), 'result.json': json.dumps(result).encode()}
        for name, raw in rows.items():
            D.atomic_write(bootstrap / name, raw)
        continued = self.execute('continue', forward_sha=forward_sha, prior_sha=prior_sha)
        self.assertEqual(continued.returncode, 0, continued.stderr)
        self.assertEqual(json.loads(continued.stdout)['prior_candidate']['version'], self.version)
        self.assertFalse((self.parent.parent / 'lifecycle-retired.json').exists())
        unrelated_old='d'*8+'-'+'d'*4+'-'+'d'*4+'-'+'d'*4+'-'+'d'*12
        unrelated_new='e'*8+'-'+'e'*4+'-'+'e'*4+'-'+'e'*4+'-'+'e'*12
        ledger={'version':1,'ids':[unrelated_old],
                'handoff':{'old_id':unrelated_old,'new_id':unrelated_new}}
        D.atomic_write(self.parent.parent/'lifecycle-retired.json',json.dumps(ledger).encode())
        ledger_continued=self.execute('continue',forward_sha=forward_sha,prior_sha=prior_sha)
        self.assertEqual(ledger_continued.returncode,0,ledger_continued.stderr)
        doctor = self.execute('run', None, self.architecture, 'doctor', '0', '0', '', forward_sha, '0',
                              forward_only=False, forward_sha='', prior_sha=prior_sha, prior_version=old_version)
        # The prior pointer is parsed by the run protocol before any installer action.
        self.assertEqual(doctor.returncode, 0, doctor.stderr)


    def failed_broker_guard_fixture(self):
        operation, _, old_id, proof, prior_sha, _ = self.absent_operation_fixture()
        operation.mkdir(mode=0o700)
        for name in ['operator-plan.json', 'execution-mode.json']:
            D.atomic_write(operation / name, b'{}')
        old_version = json.loads(proof)['version']
        old_operation = self.parent.parent / ('upgrade-' + old_version)
        (old_operation / 'activate').mkdir(parents=True, mode=0o700)
        old_operation.chmod(0o700)
        identity = {'directory': '/opt/ultra-ansible/releases/managed-' + old_version,
                    'installer_sha256': '1' * 64, 'runtime_sha256': '2' * 64, 'unit_sha256': '3' * 64}
        inventory = {'all': {'children': {'bridge': {'hosts': {'bridge': {
            'ultra_controller_directory': identity['directory'],
            'ultra_install_sha256': identity['installer_sha256'],
            'ultra_controller_runtime_sha256': identity['runtime_sha256'],
            'ultra_target_controller_unit_sha256': identity['unit_sha256']}}}}}}
        old_request = json.dumps({'inventory': inventory, 'variables': {'ultra_lifecycle_id': old_id}}).encode()
        old_job = {'schema_version': 1, 'operation': 'upgrade',
                   'request_sha256': D.sha(old_request), 'binary_sha256': D.sha(old_request)}
        D.atomic_write(old_operation / 'activate/request.json', old_request)
        for name in ['job.json', 'receipt.json']:
            D.atomic_write(old_operation / 'activate' / name, json.dumps(old_job).encode())
        new_id = str(D.uuid.UUID(bytes=hashlib.sha256(str(operation).encode()).digest()[:16], version=4))
        stage = operation / 'broker-bootstrap-fixture'
        stage.mkdir(mode=0o700)
        request = json.dumps({'inventory': inventory, 'variables': {
            'ultra_lock_directory': str(self.parent.parent), 'ultra_forward_old_id': old_id,
            'ultra_forward_candidate_id': new_id, 'ultra_forward_expected_brokers': [identity],
            'ultra_controller_directory': '/opt/ultra-ansible/releases/managed-' + self.version}}).encode()
        job = {'schema_version': 1, 'operation': 'bootstrap-forward-broker',
               'request_sha256': D.sha(request), 'binary_sha256': D.sha(request)}
        diagnostic = {'stage': 'Verify frozen broker identity and predecessor gate before replacement',
                      'node': 'bridge', 'code': 'task_failed'}
        receipt = dict(job, state='failed', code='ansible_failed', exit_code=2, diagnostic=diagnostic)
        for name, value in [('request.json', request), ('job.json', json.dumps(job).encode()),
                            ('receipt.json', json.dumps(receipt).encode()),
                            ('diagnostic.json', json.dumps(diagnostic).encode())]:
            D.atomic_write(stage / name, value)
        return operation, stage, proof, prior_sha

    def test_continuation_accepts_only_pre_mutation_failed_broker_guard(self):
        operation, stage, proof, prior_sha = self.failed_broker_guard_fixture()
        before = {str(p): p.read_bytes() for p in self.parent.parent.rglob('*') if p.is_file()}
        continued = self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha)
        self.assertEqual(continued.returncode, 0, continued.stderr)
        self.assertEqual(json.loads(continued.stdout)['prior_candidate']['version'], self.version)
        self.assertFalse((stage / 'result.json').exists())
        self.assertFalse((operation / 'forward-handoff.json').exists())
        self.assertFalse(self.result.exists())
        self.assertEqual({str(p): p.read_bytes() for p in self.parent.parent.rglob('*') if p.is_file()}, before)

    def test_failed_broker_guard_rejects_changed_or_missing_evidence(self):
        operation, stage, proof, prior_sha = self.failed_broker_guard_fixture()
        def reject():
            result = self.execute('continue', forward_sha=D.sha(proof), prior_sha=prior_sha)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.result.exists())
        changes = [('receipt.json', 'state', 'running'), ('receipt.json', 'code', 'controller_failed'),
                   ('receipt.json', 'exit_code', 1), ('receipt.json', 'exit_code', True),
                   ('receipt.json', 'operation', 'upgrade'), ('job.json', 'operation', 'upgrade'),
                   ('job.json', 'request_sha256', 'f' * 64), ('receipt.json', 'binary_sha256', 'f' * 64),
                   ('receipt.json', 'result', {'verified': True}),
                   ('diagnostic.json', 'stage', 'Install only immutable broker runtime and service'),
                   ('diagnostic.json', 'node', 'exit'), ('diagnostic.json', 'code', 'host_unreachable')]
        for name, key, value in changes:
            with self.subTest(file=name, field=key, value=value):
                path = stage / name
                raw = path.read_bytes()
                changed = json.loads(raw)
                changed[key] = value
                D.atomic_write(path, json.dumps(changed).encode())
                reject()
                D.atomic_write(path, raw)
        for name in ['request.json', 'job.json', 'receipt.json', 'diagnostic.json']:
            with self.subTest(missing=name):
                path = stage / name
                raw = path.read_bytes()
                path.unlink()
                reject()
                D.atomic_write(path, raw)
        # Even matching diagnostics cannot bless a later, mutating task.
        receipt_raw = (stage / 'receipt.json').read_bytes()
        diagnostic_raw = (stage / 'diagnostic.json').read_bytes()
        diagnostic = json.loads(diagnostic_raw)
        diagnostic['stage'] = 'Restart even if an earlier attempt already installed this runtime'
        receipt = json.loads(receipt_raw)
        receipt['diagnostic'] = diagnostic
        D.atomic_write(stage / 'diagnostic.json', json.dumps(diagnostic).encode())
        D.atomic_write(stage / 'receipt.json', json.dumps(receipt).encode())
        reject()
        D.atomic_write(stage / 'diagnostic.json', diagnostic_raw)
        D.atomic_write(stage / 'receipt.json', receipt_raw)
        # Request hashes alone cannot substitute another fleet or broker.
        request_raw = (stage / 'request.json').read_bytes()
        job_raw = (stage / 'job.json').read_bytes()
        for key, value in [('ultra_forward_old_id', 'foreign'), ('ultra_forward_candidate_id', 'foreign'),
                           ('ultra_forward_expected_brokers', []), ('ultra_controller_directory', '/tmp/foreign')]:
            with self.subTest(variable=key):
                request = json.loads(request_raw)
                request['variables'][key] = value
                raw = json.dumps(request).encode()
                D.atomic_write(stage / 'request.json', raw)
                for name, saved in [('job.json', job_raw), ('receipt.json', receipt_raw)]:
                    item = json.loads(saved)
                    item['request_sha256'] = item['binary_sha256'] = D.sha(raw)
                    D.atomic_write(stage / name, json.dumps(item).encode())
                reject()
        with self.subTest(inventory='changed with matching request hashes'):
            request = json.loads(request_raw)
            request['inventory']['all']['children']['bridge']['hosts']['bridge']['ansible_host'] = '192.0.2.99'
            raw = json.dumps(request).encode()
            D.atomic_write(stage / 'request.json', raw)
            for name, saved in [('job.json', job_raw), ('receipt.json', receipt_raw)]:
                item = json.loads(saved)
                item['request_sha256'] = item['binary_sha256'] = D.sha(raw)
                D.atomic_write(stage / name, json.dumps(item).encode())
            reject()
        D.atomic_write(stage / 'request.json', request_raw)
        D.atomic_write(stage / 'job.json', job_raw)
        D.atomic_write(stage / 'receipt.json', receipt_raw)
        old_version = json.loads(proof)['version']
        old_activate = self.parent.parent / ('upgrade-' + old_version) / 'activate'
        for name in ['request.json', 'job.json', 'receipt.json']:
            with self.subTest(missing_predecessor=name):
                path = old_activate / name
                raw = path.read_bytes()
                path.unlink()
                reject()
                D.atomic_write(path, raw)
        with self.subTest(missing_prior_journal_digest=True):
            self.assertNotEqual(self.execute('continue', forward_sha=D.sha(proof)).returncode, 0)
        for path in [stage / 'result.json', operation / 'forward-handoff.json']:
            D.atomic_write(path, b'{}')
            reject()
            path.unlink()
        (operation / 'activate').mkdir(mode=0o700)
        reject()
        (operation / 'activate').rmdir()
        lifecycle = self.parent.parent / 'lifecycle.json'
        original = json.loads(lifecycle.read_bytes())
        for state in [dict(original, phase='released'), dict(original, id='foreign')]:
            D.atomic_write(lifecycle, json.dumps(state).encode())
            reject()

    def test_continuation_attests_existing_inputs_and_pre_handoff_lifecycle(self):
        old_commit = 'b' * 40
        old_version = 'v0.0.' + str(int(old_commit, 16))
        proof = json.dumps({'commit': old_commit, 'version': old_version}).encode()
        digest = D.sha(proof)
        staged = self.execute('stage', self.archive(forward_journal=proof), forward_sha=digest)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        operation = self.parent.parent / ('upgrade-' + self.version)
        operation.mkdir(mode=0o700)
        for name in ['operator-plan.json', 'execution-mode.json']:
            D.atomic_write(operation / name, b'{}')
        old_directory = self.parent.parent / ('upgrade-' + old_version)
        old_id = str(D.uuid.UUID(bytes=hashlib.sha256(str(old_directory).encode()).digest()[:16], version=4))
        lifecycle = self.parent.parent / 'lifecycle.json'
        D.atomic_write(lifecycle, json.dumps({'id': old_id, 'phase': 'applying'}).encode())
        receipt = self.execute('continue', forward_sha=digest)
        self.assertEqual(receipt.returncode, 0, receipt.stderr)
        self.assertEqual(json.loads(receipt.stdout)['lifecycle_id'], old_id)
        self.assertIsNone(json.loads(receipt.stdout)['prior_candidate'])
        self.assertNotIn('operation_absent', json.loads(receipt.stdout))
        self.assertFalse(self.result.exists())
        dispatched = self.execute('run', None, self.architecture, 'upgrade', '0', '1', '', digest, '1', forward_only=True)
        self.assertEqual(dispatched.returncode, 0, dispatched.stderr)
        self.assertIn('--forward-only', json.loads(self.result.read_bytes()))
        self.result.unlink()
        for mutation in ['activate', 'lifecycle', 'proof', 'asset']:
            with self.subTest(mutation=mutation):
                if mutation == 'activate':
                    (operation / 'activate').mkdir()
                elif mutation == 'lifecycle':
                    D.atomic_write(lifecycle, b'{"id":"foreign","phase":"applying"}')
                elif mutation == 'proof':
                    D.atomic_write(self.root / 'forward-operation.json', b'{}')
                else:
                    D.atomic_write(self.root / 'release' / 'fixture-0', b'changed')
                rejected = self.execute('continue', forward_sha=digest)
                self.assertNotEqual(rejected.returncode, 0)
                dispatched = self.execute('run', None, self.architecture, 'upgrade', '0', '1', '', digest, '1', forward_only=True)
                self.assertNotEqual(dispatched.returncode, 0)
                self.assertFalse(self.result.exists())
                if mutation == 'activate':
                    (operation / 'activate').rmdir()
                elif mutation == 'lifecycle':
                    D.atomic_write(lifecycle, json.dumps({'id': old_id, 'phase': 'applying'}).encode())
                elif mutation == 'proof':
                    D.atomic_write(self.root / 'forward-operation.json', proof)

    def test_continuation_accepts_saved_handoff_and_rejects_tampering_and_supersede(self):
        old_commit='b'*40
        old_version='v0.0.'+str(int(old_commit,16))
        old_attempt='c'*64
        old_manifest=json.dumps({'source_commit':old_commit,'version':old_version,'assets':[]}).encode()
        old_config=b'ULTRA_AUTOMATION_VERSION='+old_version.encode()+b'\n'
        old_inputs=self.parent/('manual-'+old_commit+'-'+old_attempt)
        (old_inputs/'release').mkdir(parents=True,mode=0o700)
        old_inputs.chmod(0o700)
        D.atomic_write(old_inputs/'release/release-manifest.json',old_manifest)
        D.atomic_write(old_inputs/'install.config',old_config)
        proof={'schema':1,'commit':old_commit,'version':old_version,'remote_attempt':old_attempt,
               'stage':'upgrade','mutator_dispatched':True,'manifest_sha256':D.sha(old_manifest),
               'staged_config_sha256':D.sha(old_config)}
        proof_raw=json.dumps(proof,separators=(',',':')).encode()
        digest=D.sha(proof_raw)
        failed=self.parent.parent/('upgrade-'+self.version)
        failed.mkdir(mode=0o700)
        for name in ['execution-mode.json','operator-plan.json']:
            D.atomic_write(failed/name,b'{}')
        previous=self.parent.parent/('upgrade-'+old_version)
        (previous/'activate').mkdir(parents=True,mode=0o700)
        previous.chmod(0o700)
        for name in ['execution-mode.json','operator-plan.json']:
            D.atomic_write(previous/name,b'{}')
        (previous/'inspect').mkdir(mode=0o700)
        D.atomic_write(previous/'inspect/request.json',b'{}')
        (previous/'activate/bundle').mkdir(mode=0o700)
        D.atomic_write(previous/'activate/inventory.json',b'{}')
        D.atomic_write(previous/'activate/variables.json',b'{}')
        D.atomic_write(previous/'activate/bundle/controller.py',b'# retained immutable bundle')
        old_id=str(D.uuid.UUID(bytes=hashlib.sha256(str(previous).encode()).digest()[:16],version=4))
        new_id=str(D.uuid.UUID(bytes=hashlib.sha256(str(failed).encode()).digest()[:16],version=4))
        inventory={'all':{'children':{'bridge':{'hosts':{'bridge':{}}},'exits':{'hosts':{'exit_0':{}}}}}}
        prior_request=json.dumps({'inventory':inventory,'variables':{'ultra_lifecycle_id':old_id}},sort_keys=True,separators=(',',':')).encode()
        D.atomic_write(previous/'activate/request.json',prior_request)
        prior_job=json.dumps({'schema_version':1,'operation':'upgrade','request_sha256':D.sha(prior_request),
                              'binary_sha256':D.sha(prior_request)}).encode()
        D.atomic_write(previous/'activate/job.json',prior_job)
        D.atomic_write(previous/'activate/receipt.json',prior_job)
        D.atomic_write(self.parent.parent/'lifecycle.json',json.dumps({'id':old_id,'phase':'applying'}).encode())
        drain=failed/'handoff-drain-fixture'
        drain.mkdir(mode=0o700)
        request=json.dumps({'inventory':inventory,'variables':{'ultra_lock_directory':str(self.parent.parent),
            'ultra_forward_old_id':old_id,'ultra_lifecycle_id':new_id}},sort_keys=True,separators=(',',':')).encode()
        reqsha=D.sha(request)
        result={'verified':True,'old_id':old_id,'new_id':new_id}
        receipt={'schema_version':1,'operation':'drain-upgrade-workers','request_sha256':reqsha,
                 'binary_sha256':reqsha,'state':'succeeded','code':'','result':result}
        raws={'request.json':request,'job.json':json.dumps({k:v for k,v in receipt.items() if k not in ('state','code','result')}).encode(),
              'receipt.json':json.dumps(receipt).encode(),'result.json':json.dumps(result).encode()}
        for name,raw in raws.items(): D.atomic_write(drain/name,raw)
        (drain/'bundle').mkdir(mode=0o700)
        D.atomic_write(drain/'inventory.json',json.dumps(inventory).encode())
        D.atomic_write(drain/'variables.json',json.dumps({'ultra_lock_directory':str(self.parent.parent),
            'ultra_forward_old_id':old_id,'ultra_lifecycle_id':new_id}).encode())
        D.atomic_write(drain/'bundle/controller.py',b'# retained immutable bundle')
        # Real controller output includes its lock and private HOME workspace.
        workspace=drain/'.ansible'
        (workspace/'tmp').mkdir(parents=True,mode=0o700)
        workspace.chmod(0o700)
        D.atomic_write(workspace/'tmp/cache',b'generated')
        D.atomic_write(drain/'execution.lock',b'')
        intent={'schema':1,'proof_sha256':digest,'old_id':old_id,'new_id':new_id,'drain_directory':str(drain),
                'request_sha256':reqsha,'job_sha256':D.sha(raws['job.json']),
                'receipt_sha256':D.sha(raws['receipt.json']),'result_sha256':D.sha(raws['result.json'])}
        D.atomic_write(failed/'forward-handoff.json',json.dumps(intent).encode())
        bootstrap=failed/'broker-bootstrap-fixture'
        bootstrap.mkdir(mode=0o700)
        bootstrap_result={'verified':True,'old_id':old_id,'controller_directory':'/opt/ultra-ansible/releases/managed-fixture'}
        bootstrap_request=json.dumps({'inventory':inventory,'variables':{'ultra_lock_directory':str(self.parent.parent)}},
                                    sort_keys=True,separators=(',',':')).encode()
        bootstrap_sha=D.sha(bootstrap_request)
        bootstrap_receipt={'schema_version':1,'operation':'bootstrap-forward-broker','request_sha256':bootstrap_sha,
                           'binary_sha256':bootstrap_sha,'state':'succeeded','code':'','result':bootstrap_result}
        bootstrap_raws={'request.json':bootstrap_request,'job.json':json.dumps({k:v for k,v in bootstrap_receipt.items() if k not in ('state','code','result')}).encode(),
                        'receipt.json':json.dumps(bootstrap_receipt).encode(),'result.json':json.dumps(bootstrap_result).encode()}
        for name,raw in bootstrap_raws.items(): D.atomic_write(bootstrap/name,raw)
        (bootstrap/'bundle').mkdir(mode=0o700)
        D.atomic_write(bootstrap/'bundle/controller.py',b'# retained immutable bundle')
        ledger={'version':1,'ids':[],'handoff':{'old_id':'d'*8+'-'+'d'*4+'-'+'d'*4+'-'+'d'*4+'-'+'d'*12,
                                                 'new_id':'e'*8+'-'+'e'*4+'-'+'e'*4+'-'+'e'*4+'-'+'e'*12}}
        retired=self.parent.parent/'lifecycle-retired.json'
        D.atomic_write(retired,json.dumps(ledger).encode())
        staged=self.execute('stage',self.archive(forward_journal=proof_raw),forward_sha=digest)
        self.assertEqual(staged.returncode,0,staged.stderr)
        valid=self.execute('continue',forward_sha=digest)
        self.assertEqual(valid.returncode,0,valid.stderr)
        self.assertEqual(json.loads(valid.stdout)['prior_candidate']['commit'],self.commit)
        for artifact in ['.ansible','execution.lock']:
            path=drain/artifact
            for kind in ['wrong_type','symlink','mode','owner','nested_symlink','nested_mode']:
                if kind.startswith('nested') and artifact!='.ansible':
                    continue
                with self.subTest(artifact=artifact,unsafe=kind):
                    saved=drain/(artifact+'.saved')
                    if kind in ['wrong_type','symlink']:
                        path.rename(saved)
                    try:
                        if kind=='wrong_type':
                            if artifact=='.ansible': D.atomic_write(path,b'file')
                            else: path.mkdir(mode=0o700)
                        elif kind=='symlink': path.symlink_to(saved)
                        elif kind=='mode': path.chmod(0o755 if artifact=='.ansible' else 0o644)
                        elif kind=='owner':
                            if os.geteuid()!=0: self.skipTest('foreign ownership requires root')
                            os.chown(path,1,-1)
                        elif kind=='nested_symlink': (path/'tmp/link').symlink_to(path/'tmp/cache')
                        elif kind=='nested_mode': (path/'tmp/cache').chmod(0o644)
                        # Keep the renamed artifact outside the exact stage inventory.
                        if saved.exists(): saved.rename(self.directory/'artifact-saved')
                        rejected=self.execute('continue',forward_sha=digest)
                        self.assertNotEqual(rejected.returncode,0)
                    finally:
                        outside=self.directory/'artifact-saved'
                        if outside.exists(): outside.rename(saved)
                        if kind in ['wrong_type','symlink']:
                            if path.is_symlink() or path.is_file(): path.unlink()
                            else: path.rmdir()
                            saved.rename(path)
                        elif kind=='mode': path.chmod(0o700 if artifact=='.ansible' else 0o600)
                        elif kind=='owner' and os.geteuid()==0: os.chown(path,0,-1)
                        elif kind=='nested_symlink': (path/'tmp/link').unlink()
                        elif kind=='nested_mode': (path/'tmp/cache').chmod(0o600)
        mutations=[
            ('extra_operation',lambda: D.atomic_write(failed/'unexpected',b'new')),
            ('extra_drain',lambda: D.atomic_write(drain/'unexpected',b'new')),
            ('activation',lambda: (failed/'activate').mkdir()),
            ('lifecycle',lambda: D.atomic_write(self.parent.parent/'lifecycle.json',b'{"id":"foreign","phase":"applying"}')),
            ('retirement',lambda: D.atomic_write(retired,json.dumps({'version':1,'ids':[old_id,new_id],
                'handoff':{'old_id':old_id,'new_id':new_id}}).encode())),
            ('job_digest',lambda: D.atomic_write(drain/'job.json',b'{}')),
        ]
        for name,mutate in mutations:
            with self.subTest(name=name):
                mutate()
                rejected=self.execute('continue',forward_sha=digest)
                self.assertNotEqual(rejected.returncode,0)
                if name=='extra_operation': (failed/'unexpected').unlink()
                elif name=='extra_drain': (drain/'unexpected').unlink()
                elif name=='activation': (failed/'activate').rmdir()
                elif name=='lifecycle': D.atomic_write(self.parent.parent/'lifecycle.json',json.dumps({'id':old_id,'phase':'applying'}).encode())
                elif name=='retirement': D.atomic_write(retired,json.dumps(ledger).encode())
                elif name=='job_digest': D.atomic_write(drain/'job.json',raws['job.json'])

    def test_remote_probe_exact_archive_private_argv_cleanup_and_replay(self):
        secret = b'https://old.example.com/sub/fixture-token'
        probe_sha = D.sha(secret)
        def archive(raw=secret, binding=probe_sha.encode()):
            return self.archive(lambda rows: rows + [('subscription-probe-url', raw),
                                                    ('subscription-probe.sha256', binding)])
        staged = self.execute('stage', archive(), probe_sha=probe_sha)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertNotIn(secret, staged.stdout + staged.stderr)
        path = self.root / 'subscription-probe-url'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_bytes(), secret)
        upgraded = self.execute('run', None, self.architecture, 'upgrade', '1', probe_sha=probe_sha)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        argv = json.loads(self.result.read_bytes())
        self.assertEqual(argv[argv.index('--subscription-probe-url-file') + 1], str(path))
        self.assertNotIn(secret.decode(), repr(argv))
        for _ in range(2):
            cleaned = self.execute('cleanup', probe_sha=probe_sha)
            self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
            self.assertFalse(path.exists())
        self.assertEqual((self.root / 'subscription-probe.sha256').read_bytes(), probe_sha.encode())
        missing = self.execute('run', None, self.architecture, 'upgrade', probe_sha=probe_sha)
        self.assertNotEqual(missing.returncode, 0)
        replay = self.execute('stage', archive(), probe_sha=probe_sha)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(path.read_bytes(), secret)
        replacement = b'https://old.example.com/sub/replacement'
        rejected = self.execute('stage', archive(replacement, D.sha(replacement).encode()), probe_sha=D.sha(replacement))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(path.read_bytes(), secret)
        for data in (archive(b'changed'), self.archive(lambda rows: rows + [('subscription-probe.sha256', probe_sha.encode())]),
                     archive(binding=b'x' * 64)):
            rejected = self.execute('stage', data, probe_sha=probe_sha)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertNotIn(secret, rejected.stdout + rejected.stderr)
        path.chmod(0o644)
        self.assertNotEqual(self.execute('run', None, self.architecture, 'upgrade', probe_sha=probe_sha).returncode, 0)

    def test_actual_stage_native_commands_and_no_secret_copy(self):
        staged = self.execute('stage', self.archive())
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {'release', 'install.config'})
        self.assertEqual((self.root / 'install.config').read_bytes(), self.config)
        self.assertEqual(json.loads(staged.stdout)['architecture'], self.architecture)
        executable = self.root / 'release' / ('ultra-install-linux-' + self.architecture)
        self.assertEqual(executable.stat().st_mode & 0o777, 0o700)
        for action, expected in [('doctor', ['doctor']), ('adoption_check', ['adopt', '--adopt-runtime', '--bridge-native', '--check']),
                                 ('adoption_apply', ['apply', '--adopt-runtime', '--bridge-native']),
                                 ('upgrade', ['operator-upgrade', '--release-dir', str(self.root / 'release'),
                                              '--source-commit', self.commit, '--version', self.version,
                                              '--manifest-sha256', D.sha(self.manifest), '--config-sha256', D.sha(self.config)]),
                                 ('status', ['status'])]:
            run = self.execute('run', None, self.architecture, action)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv = json.loads(self.result.read_bytes())
            self.assertEqual(argv[:len(expected)], expected)
            self.assertEqual(argv[-2:], ['--config', str(self.root / 'install.config')])
        retried = self.execute('run', None, self.architecture, 'upgrade', '1')
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertIn('--retry-failed', json.loads(self.result.read_bytes()))
        journal = b'{"stage":"upgrade"}'
        journal_sha = D.sha(journal)
        staged_forward = self.execute('stage', self.archive(forward_journal=journal), forward_sha=journal_sha)
        self.assertEqual(staged_forward.returncode, 0, staged_forward.stderr)
        self.assertEqual((self.root / 'forward-operation.json').read_bytes(), journal)
        doctor = self.execute('run', None, self.architecture, 'doctor', forward_sha=journal_sha)
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertEqual(json.loads(self.result.read_bytes())[0], 'doctor')
        forwarded = self.execute('run', None, self.architecture, 'upgrade', forward_only=True, forward_sha=journal_sha)
        self.assertEqual(forwarded.returncode, 0, forwarded.stderr)
        forwarded_argv = json.loads(self.result.read_bytes())
        self.assertIn('--forward-only', forwarded_argv)
        self.assertEqual(forwarded_argv[forwarded_argv.index('--forward-journal-file') + 1], str(self.root / 'forward-operation.json'))
        self.assertEqual(forwarded_argv[forwarded_argv.index('--forward-journal-sha256') + 1], journal_sha)
        status = self.execute('run', None, self.architecture, 'status', forward_sha=journal_sha)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(self.result.read_bytes())[0], 'status')
        cleaned = self.execute('cleanup', forward_sha=journal_sha)
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse((self.root / 'forward-operation.json').exists())
        # A lost SSH acknowledgement leaves the local operation journal intact;
        # the remote cleanup must therefore accept an already absent proof.
        cleaned_again = self.execute('cleanup', forward_sha=journal_sha)
        self.assertEqual(cleaned_again.returncode, 0, cleaned_again.stderr)
        again = self.execute('stage', self.archive())
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_actual_stage_rejects_legacy_baseline_before_same_commit_replay(self):
        local_state = self.directory / 'local-state'
        local_state.mkdir(mode=0o700)
        old_commit, old_attempt = 'b' * 40, 'c' * 64
        old_assets = [{'name': 'asset-' + str(i)} for i in range(14)]
        old_manifest = json.dumps({'source_commit': old_commit, 'version': 'v2.4.2',
                                   'assets': old_assets}, sort_keys=True).encode()
        old_manifest_path = local_state / 'release-manifest.json'
        old_manifest_path.write_bytes(old_manifest); old_manifest_path.chmod(0o400)
        journal = {'schema': 1, 'commit': old_commit, 'version': 'v2.4.2', 'remote_attempt': old_attempt,
                   'manifest_sha256': D.sha(old_manifest), 'mutator_dispatched': True}
        journal_raw = json.dumps(journal, sort_keys=True).encode()
        journal_path = local_state / 'operation.json'
        journal_path.write_bytes(journal_raw); journal_path.chmod(0o600)
        descriptor_path = local_state / 'upgrade-baseline.json'
        descriptor = {'schema': 1, 'journal': str(journal_path), 'journal_sha256': D.sha(journal_raw),
                      'manifest': str(old_manifest_path), 'manifest_sha256': D.sha(old_manifest)}
        descriptor_path.write_text(json.dumps(descriptor, sort_keys=True)); descriptor_path.chmod(0o600)
        original = (b'SECRETS_ENV_FILE=/etc/ultra-relay/.env\n'
                    + ('ULTRA_UPGRADE_BASELINE_FILE=' + str(descriptor_path) + '\n').encode()
                    + b'POLICY=unchanged\n')
        attempt = D.remote_attempt(original, self.version)
        self.root = self.parent / ('manual-' + self.commit + '-' + attempt)
        production_root = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + self.commit + '-' + attempt)
        prepare_baseline = D.stage_upgrade_baseline
        def fixture_prepare(raw_config, version, remote_root):
            self.assertEqual(remote_root, production_root)
            staged, files = prepare_baseline(raw_config, version, production_root)
            staged = staged.replace(str(production_root / 'baseline/descriptor.json').encode(),
                                    str(self.root / 'baseline/descriptor.json').encode())
            staged_descriptor = json.loads(files['baseline/descriptor.json'])
            staged_descriptor['manifest'] = staged_descriptor['manifest'].replace(
                '/var/lib/ultra-ansible/operator-inputs', str(self.parent))
            staged_descriptor['journal'] = staged_descriptor['journal'].replace(
                str(production_root), str(self.root))
            files['baseline/descriptor.json'] = (json.dumps(staged_descriptor, sort_keys=True, separators=(',', ':')) + '\n').encode()
            return staged, files
        with self.assertRaisesRegex(D.DeployError, '^manual_operation_quiescence_migration_required$'):
            D.stage_upgrade_baseline(original, self.version, production_root)
        self.assertFalse(self.root.exists())

    def test_actual_stage_baseline_requires_exact_private_inventory_and_rechecks_it(self):
        old_commit, old_attempt, old_manifest_sha = 'b' * 40, 'c' * 64, 'd' * 64
        journal = {'schema': 1, 'commit': old_commit, 'remote_attempt': old_attempt,
                   'manifest_sha256': old_manifest_sha, 'mutator_dispatched': True}
        journal_raw = json.dumps(journal, sort_keys=True).encode()
        self.config += b'ULTRA_UPGRADE_BASELINE_FILE=' + (str(self.parent / 'baseline/descriptor.json')).encode() + b'\n'
        self.root = self.parent / ('manual-' + self.commit + '-' + D.remote_attempt(self.config, self.version))
        old_release = self.parent / ('manual-' + old_commit + '-' + old_attempt) / 'release'
        descriptor = {'schema': 1, 'journal': str(self.root / 'baseline/operator-journal.json'),
                      'journal_sha256': D.sha(journal_raw),
                      'manifest': str(old_release / 'release-manifest.json'),
                      'manifest_sha256': old_manifest_sha}
        descriptor_raw = json.dumps(descriptor, sort_keys=True).encode()
        entries = [('release/release-manifest.json', self.manifest)]
        entries += [('release/' + name, data) for name, data in self.assets.items()]
        entries += [('install.config', self.config), ('baseline/descriptor.json', descriptor_raw),
                    ('baseline/operator-journal.json', journal_raw)]
        def archive_with(rows):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w|') as archive:
                for name, raw in rows:
                    entry = tarfile.TarInfo(name); entry.size = len(raw)
                    archive.addfile(entry, io.BytesIO(raw))
            return stream.getvalue()
        staged = self.execute('stage', archive_with(entries))
        self.assertNotEqual(staged.returncode, 0)
        self.assertIn(b'manual_operation_quiescence_migration_required', staged.stderr)
        self.assertFalse(self.root.exists())
        self.assertFalse(list(self.parent.glob('.manual-*')))
        self.assertFalse(self.result.exists())

    def test_bad_asset_incomplete_stage_and_unexpected_files_never_publish(self):
        for mutate in [lambda rows: rows[:-1], lambda rows: rows + [('../escape', b'bad')],
                       lambda rows: rows + [('.env', b'never')],
                       lambda rows: [(n, b'changed' if n == 'release/fixture-0' else raw) for n, raw in rows]]:
            with self.subTest(mutation=mutate):
                result = self.execute('stage', self.archive(mutate))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.root.exists())
                self.assertFalse(list(self.parent.glob('.manual-*')))
                self.assertFalse(self.result.exists())
        # A genuinely interrupted stream must also fail without publishing.
        result = self.execute('stage', self.archive()[:1024])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.root.exists())

    def test_reverify_before_mutator_and_frozen_config_identity(self):
        self.assertEqual(self.execute('stage', self.archive()).returncode, 0)
        (self.root / 'release' / 'fixture-0').write_bytes(b'changed')
        result = self.execute('run', None, self.architecture, 'adoption_apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.result.exists())
        (self.root / 'release' / 'fixture-0').write_bytes(b'fixture')
        (self.root / 'install.config').write_bytes(b'changed')
        result = self.execute('run', None, self.architecture, 'upgrade')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.result.exists())
        self.assertNotEqual(self.execute('stage', self.archive()).returncode, 0)

    def test_wrong_commit_and_manifest_hash_fail_closed(self):
        altered = self.manifest.replace(self.commit.encode(), b'b' * 40)
        result = self.execute('stage', self.archive(lambda rows: [(n, altered if n.endswith('release-manifest.json') else raw) for n, raw in rows]))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.root.exists())

    def test_corrected_config_same_commit_gets_new_immutable_attempt(self):
        self.assertEqual(self.execute('stage', self.archive()).returncode, 0)
        old_root, old_config = self.root, self.config
        self.config += b'CORRECTED_POLICY=1\n'
        result = self.execute('stage', self.archive())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((old_root / 'install.config').read_bytes(), old_config)
        staged = [p for p in self.parent.glob('manual-*') if p.is_dir()]
        self.assertEqual(len(staged), 2)
        new_root = next(p for p in staged if p != old_root)
        self.assertEqual((new_root / 'install.config').read_bytes(), self.config)


class RuntimeReuse(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.source = self.repo / 'source'
        (self.source / 'scripts').mkdir(parents=True)
        (self.source / 'deploy/ansible').mkdir(parents=True)
        self.requirements = self.source / 'deploy/ansible/requirements.txt'
        self.requirements.write_text('fixture==1.0\n')
        self.helper = Path(__file__).with_name('manual-deploy-runtime.py')
        shutil.copyfile(self.helper, self.source / 'scripts/manual-deploy-runtime.py')
        self.cache = self.repo / 'dist'
        self.cache.mkdir()
        self.members = {'requirements.lock': b'fixture==1.0 --hash=sha256:' + hashlib.sha256(b'wheel').hexdigest().encode() + b'\n',
                        'wheels/fixture-1.0-py3-none-any.whl': b'wheel'}
        self.write_pair()
        spec = importlib.util.spec_from_file_location('runtime_test', self.helper)
        self.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runtime)

    def write_pair(self):
        for architecture in ['amd64', 'arm64']:
            with tarfile.open(self.cache / ('ultra-ansible-runtime-linux-' + architecture + '.tar.gz'), 'w:gz') as archive:
                for name, raw in self.members.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
        names = ['ultra-ansible-runtime-linux-' + architecture + '.tar.gz' for architecture in ['amd64', 'arm64']]
        names += ['fixture-' + str(n) for n in range(11)]
        for name in names[2:]:
            (self.cache / name).write_bytes(b'fixture')
        checksums = ''.join(hashlib.sha256((self.cache / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
        (self.cache / 'checksums.txt').write_text(checksums)
        rows = [{'name': name, 'size': len((self.cache / name).read_bytes()), 'sha256': hashlib.sha256((self.cache / name).read_bytes()).hexdigest()} for name in names + ['checksums.txt']]
        (self.cache / 'release-manifest.json').write_text(json.dumps({'schema_version': 1, 'source_commit': 'a' * 40, 'assets': rows}))

    def test_verified_pair_works_without_pip_and_is_frozen_inside_source(self):
        with patch.dict(os.environ, {'GOCACHE': '/read-only/operator/go-build-cache'}), \
                patch.object(D, 'run', side_effect=AssertionError('pip must not run')):
            environment = D.prepare_runtime_environment(self.repo, self.source)
        frozen = Path(environment['ULTRA_VERIFIED_RUNTIME_DIR'])
        self.assertEqual(frozen.parent, self.source)
        self.assertEqual(environment['GOCACHE'], str(self.source / '.manual-go-build-cache'))
        self.runtime.validate_pair(frozen, self.requirements)
        self.assertEqual((frozen / 'ultra-ansible-runtime-linux-amd64.tar.gz').read_bytes(),
                         (self.cache / 'ultra-ansible-runtime-linux-amd64.tar.gz').read_bytes())

    def test_real_make_runtime_hook_copies_verified_archives_without_pip(self):
        # Execute the actual checked-in ansible-dist recipe in a disposable tree.
        makefile = Path(__file__).resolve().parents[1] / 'Makefile'
        text = makefile.read_text()
        recipe = text[text.index('ansible-dist:\n'):text.index('\ntest-ansible:', text.index('ansible-dist:\n'))]
        (self.source / 'Makefile').write_text(recipe + '\n')
        ansible = self.source / 'deploy/ansible'
        for name in ['ansible.cfg', 'controller.py']:
            (ansible / name).write_text('fixture')
        for name in ['playbooks', 'roles', 'library', 'callback_plugins']:
            (ansible / name).mkdir()
        environment = os.environ.copy()
        environment['ULTRA_VERIFIED_RUNTIME_DIR'] = str(self.cache)
        result = subprocess.run(['make', 'ansible-dist'], cwd=self.source, env=environment, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        for architecture in ['amd64', 'arm64']:
            name = 'ultra-ansible-runtime-linux-' + architecture + '.tar.gz'
            self.assertEqual((self.source / 'dist' / name).read_bytes(), (self.cache / name).read_bytes())

    def test_missing_cache_requires_pip_and_discards_inherited_override(self):
        (self.cache / 'release-manifest.json').unlink()
        with patch.dict(os.environ, {'ULTRA_VERIFIED_RUNTIME_DIR': '/unverified'}), patch.object(D, 'run') as run:
            environment = D.prepare_runtime_environment(self.repo, self.source)
        self.assertNotIn('ULTRA_VERIFIED_RUNTIME_DIR', environment)
        self.assertEqual(run.call_args.args[0][-2:], ['pip', '--version'])

    def test_archive_hash_tampering_is_rejected(self):
        with (self.cache / 'ultra-ansible-runtime-linux-amd64.tar.gz').open('ab') as stream:
            stream.write(b'tamper')
        with self.assertRaisesRegex(AssertionError, 'hash mismatch'):
            self.runtime.validate_pair(self.cache, self.requirements)

    def test_different_exact_requirements_are_rejected_without_network_fallback(self):
        self.requirements.write_text('fixture==2.0\n')
        with patch.object(D, 'run', side_effect=AssertionError('network fallback forbidden')):
            with self.assertRaisesRegex(AssertionError, 'pins mismatch'):
                D.prepare_runtime_environment(self.repo, self.source)

    def test_wheel_hash_mismatch_is_rejected(self):
        self.members['wheels/fixture-1.0-py3-none-any.whl'] = b'changed'
        self.write_pair()
        with self.assertRaisesRegex(AssertionError, 'wheel hash mismatch'):
            self.runtime.validate_pair(self.cache, self.requirements)

    def test_wrong_architecture_and_missing_python_abis_are_rejected(self):
        raw = self.members.pop('wheels/fixture-1.0-py3-none-any.whl')
        self.members['wheels/fixture-1.0-cp312-cp312-manylinux2014_aarch64.whl'] = raw
        self.write_pair()
        with self.assertRaisesRegex(AssertionError, 'architecture mismatch'):
            self.runtime.validate_pair(self.cache, self.requirements)
        self.members['wheels/fixture-1.0-cp312-cp312-manylinux2014_x86_64.whl'] = self.members.pop('wheels/fixture-1.0-cp312-cp312-manylinux2014_aarch64.whl')
        self.write_pair()
        with self.assertRaisesRegex(AssertionError, 'Python ABI missing'):
            self.runtime.validate_pair(self.cache, self.requirements)

    def test_unsafe_archive_paths_are_rejected(self):
        self.members['../escape.whl'] = b'escape'
        self.write_pair()
        with self.assertRaisesRegex(ValueError, 'unsafe runtime archive'):
            self.runtime.validate_pair(self.cache, self.requirements)


class LegacyForwardAttestation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / 'state'
        self.state.mkdir(mode=0o700)
        self.parent = self.state / 'operator-inputs'
        self.parent.mkdir(mode=0o700)
        D.atomic_write(self.parent / 'manual-deploy.lock', b'')
        self.commit = 'a' * 40
        self.version = 'v0.0.' + str(int(self.commit, 16))
        self.attempt = 'b' * 64
        self.config = b'INSTALL_SCHEMA_VERSION=2\n'
        self.manifest = {'source_commit': self.commit, 'version': self.version, 'assets': []}
        self.manifest_raw = json.dumps(self.manifest).encode()
        self.root = self.parent / ('manual-' + self.commit + '-' + self.attempt)
        self.root.mkdir(mode=0o700)
        (self.root / 'release').mkdir(mode=0o700)
        D.atomic_write(self.root / 'install.config', self.config)
        D.atomic_write(self.root / 'release/release-manifest.json', self.manifest_raw)
        self.directory = self.state / ('upgrade-' + self.version)
        self.directory.mkdir(mode=0o700)
        self.activate = self.directory / 'activate'
        self.activate.mkdir(mode=0o700)
        import uuid
        operation_id = str(uuid.UUID(bytes=hashlib.sha256(str(self.directory).encode()).digest()[:16], version=4))
        request = {'inventory': {'all': {'children': {'bridge': {'hosts': {'bridge': {}}}, 'exits': {'hosts': {'exit_0': {}}}}}},
                   'variables': {'ultra_lifecycle_id': operation_id, 'ultra_release_manifest_sha256': D.sha(self.manifest_raw),
                                 'ultra_release_manifest': self.manifest}}
        self.request_raw = json.dumps(request).encode()
        D.atomic_write(self.activate / 'request.json', self.request_raw)
        self.job = {'schema_version': 1, 'operation': 'upgrade', 'request_sha256': D.sha(self.request_raw)}
        for name in ('job.json', 'receipt.json'):
            D.atomic_write(self.activate / name, json.dumps(self.job).encode())
        self.program = D.REMOTE_LEGACY_ATTEST.replace("Path('/var/lib/ultra-ansible')", 'Path(' + repr(str(self.state)) + ')')
        self.program = self.program.replace('os.geteuid()==0', 'True').replace('info.st_uid==0', 'info.st_uid==os.geteuid()')

    def execute(self):
        return subprocess.run([D.sys.executable, '-I', '-c', self.program, self.commit, self.version,
                               self.attempt, D.sha(self.manifest_raw), D.sha(self.config)], capture_output=True)

    def test_attestation_returns_only_exact_identities_without_writing(self):
        before = {str(p): p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'schema': 1, 'commit': self.commit, 'version': self.version,
            'remote_attempt': self.attempt, 'manifest_sha256': D.sha(self.manifest_raw), 'staged_config_sha256': D.sha(self.config)})
        self.assertEqual({str(p): p.read_bytes() for p in self.state.rglob('*') if p.is_file()}, before)
        self.assertNotIn(self.config, result.stdout)

    def test_attestation_rejects_changed_config_manifest_request_job_receipt(self):
        for path in (self.root / 'install.config', self.root / 'release/release-manifest.json',
                     self.activate / 'request.json', self.activate / 'job.json', self.activate / 'receipt.json'):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                D.atomic_write(path, b'{}')
                self.assertNotEqual(self.execute().returncode, 0)
                D.atomic_write(path, original)

    def test_attestation_rejects_cross_operation_and_unbound_request_receipts(self):
        for key, value in (('ultra_lifecycle_id', 'other-operation'), ('ultra_release_manifest_sha256', 'c' * 64),
                           ('ultra_release_manifest', dict(self.manifest, source_commit='c' * 40))):
            request = json.loads(self.request_raw)
            request['variables'][key] = value
            raw = json.dumps(request).encode()
            D.atomic_write(self.activate / 'request.json', raw)
            for name in ('job.json', 'receipt.json'):
                D.atomic_write(self.activate / name, json.dumps(dict(self.job, request_sha256=D.sha(raw))).encode())
            self.assertNotEqual(self.execute().returncode, 0)

    def test_attestation_rejects_public_symlink_missing_and_busy_evidence(self):
        path = self.root / 'install.config'
        path.chmod(0o644)
        self.assertNotEqual(self.execute().returncode, 0)
        path.chmod(0o600)
        target = self.root / 'copy.config'
        path.rename(target)
        path.symlink_to(target)
        self.assertNotEqual(self.execute().returncode, 0)
        path.unlink()
        self.assertNotEqual(self.execute().returncode, 0)
        target.rename(path)
        with D.lock(self.parent / 'manual-deploy.lock'):
            self.assertNotEqual(self.execute().returncode, 0)


class PerRoleOperatorIdentity(unittest.TestCase):
    def test_defaults_to_pinned_bridge_identity_from_config(self):
        config = b'BRIDGE_SSH_KEY=/secure/bridge-key\nULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/secure/known_hosts\n'
        with patch.dict(os.environ, {'ULTRA_OPERATOR_IDENTITY':'', 'ULTRA_OPERATOR_KNOWN_HOSTS':'',
                                     'ULTRA_OPERATOR_INVENTORY':''}):
            D.configure_operator_transport(config)
            self.assertEqual(os.environ['ULTRA_OPERATOR_IDENTITY'], '/secure/bridge-key')
            self.assertEqual(os.environ['ULTRA_OPERATOR_KNOWN_HOSTS'], '/secure/known_hosts')

    def test_explicit_local_controller_keeps_local_transport_without_operator_selector(self):
        config = b'BRIDGE_SSH_KEY=/secure/bridge-key\nULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/secure/known_hosts\n'
        with patch.dict(os.environ, {'ULTRA_OPERATOR_IDENTITY':'', 'ULTRA_OPERATOR_KNOWN_HOSTS':'',
                                     'ULTRA_OPERATOR_LOCAL_CONTROLLER':'1',
                                     'ULTRA_OPERATOR_INVENTORY':''}):
            D.configure_operator_transport(config)
            self.assertEqual(os.environ['ULTRA_OPERATOR_IDENTITY'], '')
            self.assertEqual(os.environ['ULTRA_OPERATOR_KNOWN_HOSTS'], '')

    def test_manual_transport_connects_directly_to_bridge(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            bridge=root/'bridge-key';exit=root/'exit-key';pins=root/'known_hosts'
            for path in (bridge,exit,pins):
                path.write_bytes(b'synthetic fixture only');path.chmod(0o600)
            config=("BRIDGE_IP=192.0.2.10\nMAIN_EXIT_IP=192.0.2.20\nDATABASE_IP=192.0.2.30\nBRIDGE_SSH_KEY="+str(bridge)+
                    "\nDATABASE_SSH_KEY=/tmp/database-key\nULTRA_AUTOMATION_KNOWN_HOSTS_FILE="+str(pins)+
                    "\nULTRA_AUTOMATION_STATIC_NODES='[{\"name\":\"primary\",\"address\":\"192.0.2.20\"}]'\n").encode()
            with patch.dict(os.environ,{'ULTRA_OPERATOR_IDENTITY':'','ULTRA_OPERATOR_KNOWN_HOSTS':''}), \
                    patch.object(D.subprocess,'run',return_value=subprocess.CompletedProcess([],0)):
                argv,_=D.operator_transport(None,config)
            self.assertEqual(argv[-1],'root@192.0.2.10')
            self.assertEqual(argv[argv.index('-i')+1],str(bridge))
            self.assertFalse(any('ProxyCommand=' in token or str(exit) in token for token in argv))

    def test_retired_key_contract_matches_go_parser(self):
        import ast
        import inspect
        import re
        tree = ast.parse(inspect.getsource(D.config_values))
        legacy = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'legacy_keys' for target in node.targets))
        python_keys = ast.literal_eval(legacy.value)
        canonical = (Path(__file__).resolve().parents[1] / 'internal/installplan/canonical.go').read_text()
        retired = canonical.split('case "BRIDGE"', 1)[1].split(':', 1)[0]
        self.assertEqual(python_keys, {'BRIDGE', *re.findall(r'"([A-Z0-9_]+)"', retired)})

    def test_old_config_aliases_are_rejected_without_fallback(self):
        for key in ('BRIDGE', 'BRIDGE_SSH_HOST', 'BRIDGE_SSH_IDENTITY', 'EXIT',
                    'EXIT_SSH_IDENTITY', 'EXIT2', 'EXIT2_SSH_IDENTITY', 'DB_HOST',
                    'IDENTITY', 'FRONT', 'BACK', 'DB_SSH_IDENTITY', 'DB_ENABLE',
                   'DB_REPLICA', 'DB_SSH_USER', 'EXIT2_NAME', 'EXIT2_DIAL', 'EXIT2_PRIORITY'):
            with self.subTest(key=key), self.assertRaisesRegex(D.DeployError, '^operator_legacy_config_key_forbidden$'):
                D.config_values((key + '=192.0.2.10\n').encode())


if __name__ == '__main__':
    unittest.main()
