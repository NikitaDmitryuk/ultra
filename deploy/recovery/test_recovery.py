import argparse
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import recovery

class RecoveryTests(unittest.TestCase):
    def test_diagnostics_exports_only_confirmed_destinations_without_private_config(self):
        config={'source':'bridge','diagnostic_status':True,'independent':False,
                'recipient':'private-config-marker','identity_file':'private-path',
                'destinations':[{'host':'nl-address','name':'NL'},{'host':'unavailable-address','name':'US'}]}
        with mock.patch.object(recovery.grp,'getgrnam',return_value=argparse.Namespace(gr_gid=123)), mock.patch.object(recovery,'atomic_json') as write:
            recovery.diagnostic_status(config,['nl-address'],100,110)
            write.assert_called_once_with('/var/lib/ultra-relay/recovery-status.json',
                    {'source':'bridge','snapshot_at':100,'completed_at':110,'targets':['NL'],'independent':False},group=123)
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = recovery.repository(self.root / 'repo', 'bridge', True)
    def tearDown(self):
        self.tmp.cleanup()
    def args(self, name, data, stamp):
        return argparse.Namespace(repository=str(self.repo), source='bridge', name=name, sha256=hashlib.sha256(data).hexdigest(), snapshot=stamp)
    def test_interrupted_transfer_never_replaces_good_generation(self):
        stamp = int(time.time())
        name = 'backup-' + str(stamp) + '-' + 'a'*32 + '.age'
        args = self.args(name, b'complete', stamp)
        recovery.receive(args, io.BytesIO(b'complete'))
        with self.assertRaises(ValueError): recovery.receive(args, io.BytesIO(b'partial'))
        self.assertEqual((self.repo / name).read_bytes(), b'complete')
        self.assertFalse(list(self.repo.glob('.incoming-*')))
    def test_immutable_collision_is_rejected(self):
        stamp=int(time.time());name='backup-'+str(stamp)+'-'+'b'*32+'.age'
        recovery.receive(self.args(name,b'first',stamp),io.BytesIO(b'first'))
        with self.assertRaises(ValueError):recovery.receive(self.args(name,b'second',stamp),io.BytesIO(b'second'))
    def test_repeat_repairs_status_after_rename_before_acknowledgement(self):
        stamp = int(time.time())
        name = 'backup-' + str(stamp) + '-' + 'd'*32 + '.age'
        args = self.args(name, b'complete', stamp)
        with mock.patch.object(recovery, 'atomic_json', side_effect=OSError('crash after rename')):
            with self.assertRaises(OSError): recovery.receive(args, io.BytesIO(b'complete'))
        recovery.receive(args, io.BytesIO(b'complete'))
        self.assertEqual(json.loads((self.repo/'last-success.json').read_text())['snapshot_at'], stamp)
    def test_remote_artifact_requires_checksum_not_presence(self):
        artifact = self.root / ('artifact-' + 'a'*64 + '.age')
        artifact.write_bytes(b'versioned encrypted binary')
        output = recovery.digest(artifact).encode() + b'  /var/lib/ultra-recovery/example\n'
        with mock.patch.object(recovery, 'ssh', return_value=argparse.Namespace(stdout=output)):
            recovery.verify_remote_artifact({}, {'host':'exit'}, artifact)
        with mock.patch.object(recovery, 'ssh', return_value=argparse.Namespace(stdout=b'wrong')):
            with self.assertRaises(ValueError): recovery.verify_remote_artifact({}, {'host':'exit'}, artifact)
    def test_binary_change_during_capture_never_confirms_generation(self):
        state = self.root / 'spec.json'; state.write_text('{}')
        binary = self.root / 'binary'; binary.write_bytes(b'before')
        config = {'source':'bridge', 'repository':str(self.repo), 'database':'test_only',
                  'state_paths':[str(state)], 'artifact_paths':[str(binary)],
                  'recipient':'unused', 'destinations':[{'host':'exit', 'required':True}]}
        original_pack = recovery.pack
        def changed_pack(*args):
            result = original_pack(*args)
            binary.write_bytes(b'after')
            return result
        with mock.patch.object(recovery, 'pack', side_effect=changed_pack):
            with self.assertRaisesRegex(ValueError, 'binary artifacts changed'): recovery.create(config)
        self.assertFalse((self.repo / 'last-success.json').exists())
        self.assertFalse(list(self.repo.glob('artifact-*.age')))
    def test_capture_receipt_matches_delivered_cipher_and_artifact(self):
        state=self.root/'spec.json';state.write_text('{}')
        binary=self.root/'binary';binary.write_bytes(b'fixture-binary')
        config={'source':'bridge','repository':str(self.repo),'database':'ultra_test','state_paths':[str(state)],
                'artifact_paths':[str(binary)],'recipient':'fixture-public','diagnostic_status':False,
                'destinations':[{'id':'owned-node','host':'owned-address','required':True}]}
        delivered={}
        def run(args,**kwargs):
            kwargs['stdout'].write(b'fixture-pg-dump')
            return argparse.Namespace(returncode=0)
        def encrypt(source,target,recipient):target.write_bytes(source.read_bytes())
        def deliver(config,destination,source,encrypted,snapshot):delivered[encrypted.name]=encrypted.read_bytes()
        with mock.patch.object(recovery,'run',side_effect=run),mock.patch.object(recovery,'encrypt',side_effect=encrypt),mock.patch.object(recovery,'verify_remote_artifact',side_effect=ValueError('missing')),mock.patch.object(recovery,'deliver',side_effect=deliver):
            recovery.create(config)
        receipt=json.loads((self.repo/'last-success.json').read_text())
        self.assertEqual(receipt['source'],'bridge')
        self.assertEqual(receipt['delivered_target_ids'],['owned-node'])
        self.assertEqual(receipt['backup_sha256'],hashlib.sha256(delivered[receipt['backup_name']]).hexdigest())
        self.assertEqual(receipt['artifact_sha256'],hashlib.sha256(delivered[receipt['artifact_name']]).hexdigest())

    def test_destination_specific_pins_override_defaults(self):
        config={'identity_file':'global-key','known_hosts':'global-pins'}
        destination={'host':'root@192.0.2.1','identity_file':'node-key','known_hosts':'node-pins'}
        with mock.patch.object(recovery,'run',return_value=argparse.Namespace(returncode=0))as run:
            recovery.ssh(config,destination,['true'])
        argv=run.call_args.args[0]
        self.assertIn('node-key',argv);self.assertIn('UserKnownHostsFile=node-pins',argv)
        self.assertNotIn('global-key',argv);self.assertIn('StrictHostKeyChecking=yes',argv)

    def test_retention_keeps_hour_day_and_last_stale(self):
        now=1800000000
        names=['backup-'+str(now-age)+'-'+('a'*32)+'.age' for age in (1,60,3601,3700,7200,86401,86402,16*86400)]
        keep=recovery.retention(names,now)
        self.assertIn(names[0],keep);self.assertIn(names[1],keep)
        self.assertIn(names[2],keep);self.assertNotIn(names[3],keep)
        self.assertEqual(recovery.retention([names[-1]],now),{names[-1]})
    def test_manifest_and_private_extraction(self):
        source=self.root/'secret';source.write_text('example-private-state');source.chmod(0o600)
        bundle=self.root/'bundle.tar.gz'
        recovery.pack(bundle,{'kind':'backup'}, {'state/etc/ultra/test':source})
        recovery.unpack(bundle,self.root/'stage')
        self.assertEqual((self.root/'stage/state/etc/ultra/test').stat().st_mode&0o777,0o600)
        bundle.write_bytes(b'corrupt')
        with self.assertRaises(Exception):recovery.inspect_bundle(bundle)
    def test_live_runtime_db_excluded(self):
        state=self.root/'state';state.mkdir();(state/'runtime.db').write_text('changing');(state/'spec.json').write_text('{}')
        files=recovery.collect([str(state)])
        self.assertEqual(len(files),1)
    def test_only_exact_derived_subscription_cache_is_excluded(self):
        self.assertEqual(recovery.EXCLUDED_FILES,{
            Path('/var/lib/ultra-bot/subscriptions.json'),
            Path('/var/lib/ultra-relay/recovery-status.json'),
            Path('/var/lib/ultra-relay/recovery-reconcile-status.json'),
        })
        bot=self.root/'ultra-bot';bot.mkdir()
        derived=bot/'subscriptions.json';derived.write_text('first derived generation')
        settings=bot/'settings.json';settings.write_text('stable settings')
        other=bot/'other';other.mkdir()
        canonical=other/'subscriptions.json';canonical.write_text('canonical data')
        with mock.patch.object(recovery,'EXCLUDED_FILES',{derived}):
            before=recovery.collect([str(bot)])
            derived.write_text('a changed and longer derived generation')
            after=recovery.collect([str(bot)])
        self.assertEqual(before,after)
        self.assertNotIn(str(derived.relative_to('/')),before)
        self.assertIn(str(settings.relative_to('/')),before)
        self.assertIn(str(canonical.relative_to('/')),before)

    def test_exact_derived_health_receipts_do_not_invalidate_capture(self):
        relay=self.root/'ultra-relay';relay.mkdir()
        derived=[relay/'recovery-status.json',relay/'recovery-reconcile-status.json']
        for path in derived:path.write_text('first derived health')
        other=relay/'keys';other.mkdir()
        keys=[other/path.name for path in derived]
        for path in keys:path.write_text('required canonical key fixture')
        with mock.patch.object(recovery,'EXCLUDED_FILES',set(derived)):
            before=recovery.collect([str(relay)])
            for path in derived:path.write_text('newer and longer health receipt')
            after=recovery.collect([str(relay)])
        self.assertEqual(before,after)
        for path in derived:self.assertNotIn(str(path.relative_to('/')),before)
        for path in keys:self.assertIn(str(path.relative_to('/')),before)

    def test_binary_staging_is_excluded_but_state_is_retained(self):
        state=self.root/'state';state.mkdir();(state/'settings.json').write_text('{}')
        candidate=state/'candidates';candidate.mkdir();(candidate/'large-relay').write_bytes(b'candidate')
        release=state/'releases';release.mkdir();(release/'old-relay').write_bytes(b'old')
        with mock.patch.object(recovery,'EXCLUDED_DIRECTORIES',{candidate,release}):
            files=recovery.collect([str(state)])
        self.assertEqual(list(files),[str((state/'settings.json').relative_to('/'))])
        self.assertIn(Path('/var/lib/ultra-relay/candidates'),recovery.EXCLUDED_DIRECTORIES)
    def test_declared_geo_artifact_is_not_repeated_in_state(self):
        state=self.root/'state';state.mkdir();(state/'keyring.json').write_text('private-keyring-marker')
        geo=state/'geo';geo.mkdir();(geo/'geosite.dat').write_bytes(b'large-static-asset')
        files=recovery.collect([str(state)],[str(geo)])
        self.assertEqual(list(files),[str((state/'keyring.json').relative_to('/'))])
        self.assertEqual(len(recovery.collect([str(geo)])),1)
    def test_bundle_bound_includes_database(self):
        source=self.root/'large';source.write_bytes(b'x'*100)
        with mock.patch.object(recovery,'MAX_BYTES',10):
            with self.assertRaises(ValueError):recovery.pack(self.root/'out',{}, {'database.dump':source})

class EncryptedRecoveryTests(unittest.TestCase):
    def setUp(self):
        import shutil, subprocess
        if not shutil.which('age') or not shutil.which('age-keygen'):self.skipTest('age CLI unavailable')
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.identity=self.root/'identity.txt'
        subprocess.run(['age-keygen','-o',str(self.identity)],check=True,capture_output=True)
        self.recipient=subprocess.run(['age-keygen','-y',str(self.identity)],check=True,capture_output=True,text=True).stdout.strip()
        binary=self.root/'binary';binary.write_text('dummy-binary');binary.chmod(0o700)
        artifacts={'usr/local/bin/ultra-relay':{'sha256':recovery.digest(binary),'bytes':binary.stat().st_size,'mode':0o700}}
        artifact_id=hashlib.sha256(json.dumps(artifacts,sort_keys=True).encode()).hexdigest()
        artifact_name='artifact-'+artifact_id+'.age'
        artifact_plain=self.root/'artifact.tar.gz'
        recovery.pack(artifact_plain,{'kind':'artifact','source':'bridge'},{'usr/local/bin/ultra-relay':binary})
        recovery.encrypt(artifact_plain,self.root/artifact_name,self.recipient)
        dump=self.root/'dump';dump.write_text('dummy-pg-dump')
        self.stamp=int(time.time());plain=self.root/'backup.tar.gz'
        recovery.pack(plain,{'kind':'backup','source':'bridge','artifact':artifact_name,'snapshot_at':self.stamp},{'database.dump':dump})
        self.bundle=self.root/('backup-'+str(self.stamp)+'-'+'c'*32+'.age')
        recovery.encrypt(plain,self.bundle,self.recipient)
    def tearDown(self):
        if hasattr(self,'tmp'):self.tmp.cleanup()
    def args(self,command):
        return argparse.Namespace(command=command,identity=str(self.identity),target=str(self.root/'stage'),fence_file=str(self.root/'fence.json'),bundle=str(self.bundle))
    def test_real_age_verify_and_fractional_fence_restore(self):
        recovery.atomic_json(self.root/'fence.json',{'source':'bridge','confirmed_offline':True,'confirmed_at':time.time()-0.125})
        self.assertEqual(recovery.restore(self.args('verify'))['snapshot_at'],self.stamp)
        recovery.restore(self.args('restore'))
        self.assertEqual((self.root/'stage/database.dump').read_text(),'dummy-pg-dump')
        self.assertTrue((self.root/'stage/artifacts/usr/local/bin/ultra-relay').exists())
    def test_missing_artifact_fails_verify_before_staging(self):
        for path in self.root.glob('artifact-*.age'):path.unlink()
        with self.assertRaises(ValueError):recovery.restore(self.args('verify'))
        self.assertFalse((self.root/'stage').exists())
    def test_stale_fence_fails_without_staged_secrets(self):
        recovery.atomic_json(self.root/'fence.json',{'source':'bridge','confirmed_offline':True,'confirmed_at':time.time()-3601})
        with self.assertRaises(ValueError):recovery.restore(self.args('restore'))
        self.assertFalse((self.root/'stage').exists())

    def test_verify_can_stage_a_disposable_rehearsal_without_fencing_live_primary(self):
        args=self.args('verify');args.test_stage=True
        recovery.restore(args)
        self.assertEqual((self.root/'stage/database.dump').read_text(),'dummy-pg-dump')
