import argparse
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.parse
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
        self.retirement_path = self.root / 'lifecycle-retired.json'
        retirement_patch = mock.patch.object(recovery, 'CONTROLLER_RETIREMENT_PATH', str(self.retirement_path))
        retirement_patch.start()
        self.addCleanup(retirement_patch.stop)
        dsn_patch = mock.patch.object(recovery.db_connection, 'dsn_from_runtime',
                                      side_effect=lambda database: urllib.parse.urlsplit(
                                          'postgres://app:fixture%3Asecret@127.0.0.1:25432/' + database))
        dsn_patch.start()
        self.addCleanup(dsn_patch.stop)
    def tearDown(self):
        self.tmp.cleanup()
    def test_logical_dump_excludes_managed_monitor_schema(self):
        config={'source':'bridge','repository':str(self.repo),'database':'ultra_test',
                'state_paths':[],'artifact_paths':[],'recipient':'unused',
                'destinations':[{'host':'fixture-exit','required':True}]}
        def run(args, **kwargs):
            if args[0] == 'pg_dump':
                self.assertIn('--exclude-schema=ultra_monitor', args)
                raise RuntimeError('fixture dump invocation observed')
            return argparse.Namespace(stdout=b'', returncode=0)
        def encrypt(source, target, recipient):
            target.write_bytes(b'fixture-encrypted-artifact')
        with mock.patch.object(recovery, 'run', side_effect=run), mock.patch.object(recovery, 'encrypt', side_effect=encrypt):
            with self.assertRaisesRegex(RuntimeError, 'fixture dump invocation observed'):
                recovery.create(config)
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
        binary=self.root/'binary';binary.write_bytes(b'fixture-binary'*1024)
        ledger=self.root/'lifecycle-retired.json';ledger.write_text('{"version":1,"ids":["retired"]}')
        ledger.chmod(0o600)
        config={'source':'bridge','repository':str(self.repo),'database':'ultra_test','state_paths':[str(state)],
                'optional_state_paths':[str(ledger)],
                'artifact_paths':[str(binary)],'recipient':'fixture-public','diagnostic_status':False,
                'destinations':[{'id':'owned-node','host':'owned-address','required':True}]}
        delivered={}
        def run(args,**kwargs):
            if args[0] == 'pg_restore':
                return argparse.Namespace(returncode=0, stdout=b'1; 2615 2200 SCHEMA - public owner\n')
            if args[0] == 'pg_dump':
                self.assertNotIn('fixture:secret', args)
                passfile = Path(kwargs['env']['PGPASSFILE'])
                self.assertEqual(passfile.stat().st_mode & 0o777, 0o600)
                self.assertIn(r'app:fixture\:secret', passfile.read_text())
            kwargs['stdout'].write(b'fixture-pg-dump')
            return argparse.Namespace(returncode=0)
        def encrypt(source,target,recipient):target.write_bytes(source.read_bytes())
        def deliver(config,destination,source,encrypted,snapshot):delivered[encrypted.name]=encrypted.read_bytes()
        with mock.patch.object(recovery,'MAX_BYTES',4096),mock.patch.object(recovery,'MAX_ARTIFACT_BYTES',32768),mock.patch.object(recovery,'CONTROLLER_RETIREMENT_PATH',str(ledger)),mock.patch.object(recovery,'run',side_effect=run),mock.patch.object(recovery,'encrypt',side_effect=encrypt),mock.patch.object(recovery,'verify_remote_artifact',side_effect=ValueError('missing')),mock.patch.object(recovery,'deliver',side_effect=deliver):
            recovery.create(config)
        receipt=json.loads((self.repo/'last-success.json').read_text())
        self.assertEqual(receipt['source'],'bridge')
        self.assertTrue(receipt['dump_verified'])
        self.assertEqual(receipt['delivered_target_ids'],['owned-node'])
        self.assertEqual(receipt['backup_sha256'],hashlib.sha256(delivered[receipt['backup_name']]).hexdigest())
        self.assertEqual(receipt['artifact_sha256'],hashlib.sha256(delivered[receipt['artifact_name']]).hexdigest())
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(delivered[receipt['backup_name']])) as archive:
            manifest=json.load(archive.extractfile('manifest.json'))
            self.assertEqual(manifest['controller_enforcement_floor'],1)
            self.assertIn('state/'+str(ledger).lstrip('/'),manifest['files'])
            self.assertEqual(archive.extractfile('state/'+str(ledger).lstrip('/')).read(),ledger.read_bytes())

    def test_dump_validation_rejects_corrupt_empty_and_missing_archives(self):
        dump = self.root / 'database.dump'
        with self.assertRaisesRegex(ValueError, 'database dump validation failed'):
            recovery.validate_database_dump(dump)
        dump.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'database dump validation failed'):
            recovery.validate_database_dump(dump)
        dump.write_bytes(b'custom-archive')
        with mock.patch.object(recovery, 'run', side_effect=ValueError('recovery command failed')):
            with self.assertRaisesRegex(ValueError, 'recovery command failed'):
                recovery.validate_database_dump(dump)
        with mock.patch.object(recovery, 'run', return_value=argparse.Namespace(stdout=b'; header only\n')):
            with self.assertRaisesRegex(ValueError, 'database dump validation failed'):
                recovery.validate_database_dump(dump)
        with mock.patch.object(recovery, 'run', return_value=argparse.Namespace(stdout=b'1; 2615 2200 SCHEMA - public owner\n')) as run:
            recovery.validate_database_dump(dump)
            run.assert_called_once_with(['pg_restore', '--list', str(dump)], stdout=recovery.subprocess.PIPE)

    def test_invalid_dump_never_delivers_or_confirms_a_generation(self):
        state = self.root / 'spec.json'
        state.write_text('{}')
        binary = self.root / 'binary'
        binary.write_bytes(b'fixture-binary')
        config = {'source': 'bridge', 'repository': str(self.repo), 'database': 'fixture',
                  'state_paths': [str(state)], 'artifact_paths': [str(binary)],
                  'recipient': 'fixture', 'destinations': [{'host': '192.0.2.2', 'required': True}]}
        def run(args, **kwargs):
            kwargs['stdout'].write(b'corrupt-dump')
        def encrypt(source, target, recipient):
            target.write_bytes(source.read_bytes())
        with mock.patch.object(recovery, 'run', side_effect=run), \
             mock.patch.object(recovery, 'encrypt', side_effect=encrypt), \
             mock.patch.object(recovery, 'validate_database_dump', side_effect=ValueError('invalid dump')), \
             mock.patch.object(recovery, 'deliver') as deliver:
            with self.assertRaisesRegex(ValueError, 'invalid dump'):
                recovery.create(config)
        deliver.assert_not_called()
        self.assertFalse((self.repo / 'last-success.json').exists())

    def test_optional_lifecycle_state_is_reselected_and_rejects_symlinks(self):
        ledger=self.root/'lifecycle-retired.json'
        config={'state_paths':[], 'optional_state_paths':[str(ledger)]}
        self.assertEqual(recovery.capture_state_paths(config),[])
        ledger.write_text('{}')
        ledger.chmod(0o600)
        self.assertEqual(recovery.capture_state_paths(config),[str(ledger)])
        ledger.unlink();ledger.symlink_to(self.root/'missing')
        with self.assertRaisesRegex(ValueError,'controller_enforcement_migration_required'):
            recovery.capture_state_paths(config)
        ledger.unlink();ledger.mkdir()
        with self.assertRaisesRegex(ValueError,'controller_enforcement_migration_required'):
            recovery.capture_state_paths(config)

    def test_retirement_floor_is_captured_even_when_policy_is_old(self):
        ledger = self.root / 'lifecycle-retired.json'
        config = {'state_paths': [], 'optional_state_paths': []}
        with mock.patch.object(recovery, 'CONTROLLER_RETIREMENT_PATH', str(ledger)):
            self.assertEqual(recovery.capture_state_paths(config), [])
            ledger.write_text('{"version":1,"ids":["fixture"]}')
            ledger.chmod(0o600)
            self.assertEqual(recovery.capture_state_paths(config), [str(ledger)])
            ledger.unlink()
            ledger.symlink_to(self.root / 'missing')
            with self.assertRaisesRegex(ValueError, 'controller_enforcement_migration_required'):
                recovery.capture_state_paths(config)

    def test_current_database_anchor_is_preserved_even_with_an_old_backup_policy(self):
        operation = '11111111-2222-3333-4444-555555555555'
        lifecycle = self.root / 'lifecycle.json'
        lifecycle.write_text(json.dumps({'id': operation, 'phase': 'applying'}))
        lifecycle.chmod(0o600)
        root = self.root / 'upgrade'
        directory = root / operation
        directory.mkdir(parents=True)
        anchor = directory / 'database-preservation.json'
        config = {'state_paths': []}
        with mock.patch.object(recovery, 'LIFECYCLE_PATH', str(lifecycle)), \
             mock.patch.object(recovery, 'DATABASE_PRESERVATION_ROOT', root):
            self.assertEqual(recovery.capture_state_paths(config), [str(lifecycle)])
            anchor.write_text('{"cluster":"fixture-cluster","oid":16384}')
            anchor.chmod(0o600)
            self.assertEqual(set(recovery.capture_state_paths(config)), {str(lifecycle), str(anchor)})
            anchor.unlink()
            anchor.symlink_to(self.root / 'missing')
            with self.assertRaisesRegex(ValueError, 'database_preservation_capture_invalid'):
                recovery.capture_state_paths(config)
    def test_first_retirement_publication_during_dump_invalidates_generation(self):
        state=self.root/'spec.json';state.write_text('{}')
        binary=self.root/'binary';binary.write_bytes(b'fixture-binary')
        ledger=self.root/'lifecycle-retired.json'
        config={'source':'bridge','repository':str(self.repo),'database':'fixture_db',
                'state_paths':[str(state)],'optional_state_paths':[str(ledger)],
                'artifact_paths':[str(binary)],'recipient':'fixture-public',
                'destinations':[{'host':'fixture-target','required':True}]}
        def dump(*args,**kwargs):
            kwargs['stdout'].write(b'fixture-dump')
            ledger.write_text('{"version":1,"ids":["retired"]}')
            ledger.chmod(0o600)
        def encrypt(source,target,recipient):target.write_bytes(source.read_bytes())
        with mock.patch.object(recovery,'run',side_effect=dump), \
             mock.patch.object(recovery,'encrypt',side_effect=encrypt), \
             mock.patch.object(recovery,'deliver') as deliver:
            with self.assertRaisesRegex(ValueError,'configuration changed during capture'):
                recovery.create(config)
        deliver.assert_not_called()
        self.assertFalse((self.repo/'last-success.json').exists())
        self.assertFalse(list(self.repo.glob('backup-*.age')))

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

    def test_ephemeral_subscription_probe_is_never_captured_from_operation_state(self):
        state=self.root/'var/lib/ultra-ansible'
        attempt=state/'domain-cutover'/'operation-123'
        attempt.mkdir(parents=True)
        staged=attempt/'subscription-probe-url'
        staged.write_text('https://sync.example.com/sub/fixture-token')
        raw_request=attempt/'request.json'
        raw_request.write_text('{"variables":{"ultra_cutover_subscription_url":"https://sync.example.com/sub/fixture-token"}}')
        raw_variables=attempt/'variables.json'
        raw_variables.write_text('{"ultra_cutover_subscription_url":"https://sync.example.com/sub/fixture-token"}')
        raw_vars_yml=attempt/'variables.yml'
        raw_vars_yml.write_text('ultra_cutover_subscription_url: https://sync.example.com/sub/fixture-token\n')

        replay=state/'domain-cutover'/'operation-456'
        replay.mkdir(parents=True)
        request=replay/'request.json'
        request.write_text('{"ultra_cutover_subscription_url_file":"subscription-probe-url","ultra_cutover_subscription_url_sha256":"abc123"}')
        variables=replay/'variables.json'
        variables.write_text('{"ultra_cutover_subscription_url_file":"subscription-probe-url","ultra_cutover_subscription_url_sha256":"abc123"}')
        unrelated=[attempt/'receipt.json',attempt/'notes.json',replay/'variables.yml']
        unrelated[0].write_text('{"status":"complete"}')
        unrelated[1].write_text('{"unrelated":"kept"}')
        unrelated[2].write_text('unrelated_setting: kept\n')

        files=recovery.collect([str(state)])

        for sensitive in (staged,raw_request,raw_variables,raw_vars_yml):
            self.assertNotIn(str(sensitive.relative_to('/')),files)
        for neighbor in (request,variables,*unrelated):
            self.assertIn(str(neighbor.relative_to('/')),files)
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

    def test_artifact_collection_has_separate_boundary(self):
        source=self.root/'binary';source.write_bytes(b'x'*100)
        with mock.patch.object(recovery,'MAX_BYTES',50),mock.patch.object(recovery,'MAX_ARTIFACT_BYTES',100):
            with self.assertRaisesRegex(ValueError,'state exceeds backup limits'):
                recovery.collect([str(source)])
            self.assertEqual(len(recovery.collect([str(source)],max_bytes=recovery.MAX_ARTIFACT_BYTES)),1)
            source.write_bytes(b'x'*101)
            with self.assertRaisesRegex(ValueError,'state exceeds backup limits'):
                recovery.collect([str(source)],max_bytes=recovery.MAX_ARTIFACT_BYTES)

    def test_manifest_counts_toward_pack_inspect_and_unpack_boundaries(self):
        source=self.root/'binary';source.write_bytes(b'x'*100)
        bundle=self.root/'bundle.tar.gz'
        for kind, limit_name in (('backup','MAX_BYTES'),('artifact','MAX_ARTIFACT_BYTES')):
            with self.subTest(kind=kind):
                manifest=recovery.pack(bundle,{'kind':kind},{'binary':source})
                total=100+len(json.dumps(manifest,sort_keys=True).encode())
                with mock.patch.object(recovery,limit_name,total):
                    recovery.pack(bundle,{'kind':kind},{'binary':source})
                    self.assertEqual(recovery.inspect_bundle(bundle,max_bytes=total),manifest)
                    recovery.unpack(bundle,self.root/kind,max_bytes=total)
                with mock.patch.object(recovery,limit_name,total-1):
                    with self.assertRaisesRegex(ValueError,'bundle exceeds backup limits'):
                        recovery.pack(self.root/'rejected',{'kind':kind},{'binary':source})
                with self.assertRaisesRegex(ValueError,'archive exceeds limits'):
                    recovery.inspect_bundle(bundle,max_bytes=total-1)
                with self.assertRaisesRegex(ValueError,'archive exceeds limits'):
                    recovery.unpack(bundle,self.root/('rejected-'+kind),max_bytes=total-1)
                self.assertFalse((self.root/('rejected-'+kind)).exists())

    def test_ciphertext_bound_and_receiver_reserve_stay_at_state_limit(self):
        stamp=int(time.time());name='artifact-'+'a'*64+'.age'
        encrypted=self.root/name;encrypted.write_bytes(b'x'*100)
        with mock.patch.object(recovery,'MAX_BYTES',100),mock.patch.object(recovery,'MAX_ARTIFACT_BYTES',200):
            recovery.validate_ciphertext(encrypted)
            reserve=100+1024**3
            args=self.args(name,b'x'*100,stamp)
            with mock.patch.object(recovery.shutil,'disk_usage',return_value=argparse.Namespace(free=reserve)):
                recovery.receive(args,io.BytesIO(b'x'*100))
                with self.assertRaisesRegex(ValueError,'encrypted backup exceeds bounds'):
                    recovery.receive(self.args(name,b'x'*101,stamp),io.BytesIO(b'x'*101))
            with mock.patch.object(recovery.shutil,'disk_usage',return_value=argparse.Namespace(free=reserve-1)):
                with self.assertRaisesRegex(ValueError,'receiver disk reserve reached'):
                    recovery.receive(args,io.BytesIO(b'x'*100))
            encrypted.write_bytes(b'x'*101)
            with mock.patch.object(recovery,'ssh') as ssh:
                with self.assertRaisesRegex(ValueError,'encrypted backup exceeds bounds'):
                    recovery.deliver({}, {}, 'bridge',encrypted,stamp)
                ssh.assert_not_called()

    def test_oversized_new_and_cached_artifact_never_delivers(self):
        binary=self.root/'binary';binary.write_bytes(b'x'*100)
        config={'source':'bridge','repository':str(self.repo),'database':'ultra_test',
                'state_paths':[],'artifact_paths':[str(binary)],'recipient':'unused',
                'destinations':[{'host':'exit','required':True}]}
        def encrypt(source,target,recipient): target.write_bytes(b'x'*51)
        with mock.patch.object(recovery,'MAX_BYTES',50),mock.patch.object(recovery,'MAX_ARTIFACT_BYTES',1024),mock.patch.object(recovery,'encrypt',side_effect=encrypt),mock.patch.object(recovery,'deliver') as deliver:
            with self.assertRaisesRegex(ValueError,'encrypted backup exceeds bounds'): recovery.create(config)
            self.assertFalse(list(self.repo.glob('artifact-*.age')))
            artifacts=recovery.collect([str(binary)],max_bytes=recovery.MAX_ARTIFACT_BYTES)
            artifact_id=hashlib.sha256(json.dumps(artifacts,sort_keys=True).encode()).hexdigest()
            (self.repo/('artifact-'+artifact_id+'.age')).write_bytes(b'x'*51)
            with self.assertRaisesRegex(ValueError,'encrypted backup exceeds bounds'): recovery.create(config)
            deliver.assert_not_called()
            self.assertFalse((self.repo/'last-success.json').exists())

    def test_oversized_backup_ciphertext_never_delivers(self):
        config={'source':'bridge','repository':str(self.repo),'database':'ultra_test',
                'state_paths':[],'artifact_paths':[],'recipient':'unused',
                'destinations':[{'host':'exit','required':True}]}
        def run(args,**kwargs):
            if args[0]=='pg_dump': kwargs['stdout'].write(b'fixture-dump')
            return argparse.Namespace(stdout=b'1; fixture TOC\n',returncode=0)
        def encrypt(source,target,recipient):
            target.write_bytes(b'x'*(1025 if target.name.startswith('backup-') else 10))
        with mock.patch.object(recovery,'MAX_BYTES',1024),mock.patch.object(recovery,'run',side_effect=run),mock.patch.object(recovery,'encrypt',side_effect=encrypt),mock.patch.object(recovery,'deliver') as deliver:
            with self.assertRaisesRegex(ValueError,'encrypted backup exceeds bounds'): recovery.create(config)
            deliver.assert_not_called()
            self.assertFalse((self.repo/'last-success.json').exists())

    def test_verify_and_restore_stage_larger_artifact_with_small_ciphertext(self):
        binary=self.root/'binary';binary.write_bytes(b'x'*8192)
        artifacts=recovery.collect([str(binary)])
        artifact_id=hashlib.sha256(json.dumps(artifacts,sort_keys=True).encode()).hexdigest()
        artifact=self.root/('artifact-'+artifact_id+'.age')
        recovery.pack(artifact,{'kind':'artifact','source':'bridge'},
                      {name:binary for name in artifacts})
        dump=self.root/'dump';dump.write_bytes(b'fixture-dump')
        bundle=self.root/'backup.age'
        recovery.pack(bundle,{'kind':'backup','source':'bridge','artifact':artifact.name},
                      {'database.dump':dump})
        identity=self.root/'identity';identity.write_text('fixture');identity.chmod(0o600)
        def decrypt(args):
            Path(args[args.index('-o')+1]).write_bytes(Path(args[-1]).read_bytes())
        with mock.patch.object(recovery,'MAX_BYTES',2048),mock.patch.object(recovery,'MAX_ARTIFACT_BYTES',16384),mock.patch.object(recovery,'run',side_effect=decrypt):
            for command in ('verify','restore'):
                with self.subTest(command=command):
                    target=self.root/command
                    fence=self.root/'fence';fence.write_text(json.dumps({'source':'bridge','confirmed_offline':True,'confirmed_at':time.time()}));fence.chmod(0o600)
                    args=argparse.Namespace(command=command,identity=str(identity),target=str(target),
                                            bundle=str(bundle),test_stage=True,fence_file=str(fence))
                    recovery.restore(args)
                    self.assertEqual((target/'artifacts'/next(iter(artifacts))).read_bytes(),binary.read_bytes())

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
