"""Pinned operation binaries remain recoverable without recompressing every dump."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import recovery
import restore_host


class VersionedStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.relay = self.root / 'var/lib/ultra-relay/vultr'
        self.bot = self.root / 'var/lib/ultra-bot/candidates'
        self.patterns = ((self.relay, ('*/ultra-relay',)),
                         (self.bot, ('*/ultra-bot', '*/before/ultra-bot')))
        self.binaries = [self.relay / 'operation-one/ultra-relay',
                         self.relay / 'operation-two/ultra-relay',
                         self.bot / 'candidate-one/ultra-bot',
                         self.bot / 'candidate-one/before/ultra-bot']
        self.metadata = [self.relay / 'operation-one/known_hosts',
                         self.root / 'var/lib/ultra-relay/identity',
                         self.relay / 'operation-one/operation.json',
                         self.bot / 'candidate-one/before/settings.json',
                         self.bot / 'candidate-one/receipt.json',
                         self.bot / 'candidate-one/nested/ultra-bot']
        for index, path in enumerate(self.binaries + self.metadata):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('unique-fixture-' + str(index)).encode())
            path.chmod(0o700 if path in self.binaries else 0o600)
        self.repo = recovery.repository(self.root / 'repo', 'bridge', True)
        self.config = {'source': 'bridge', 'repository': str(self.repo), 'database': 'test_only',
                       'state_paths': [str(self.root / 'var/lib/ultra-relay'), str(self.root / 'var/lib/ultra-bot')],
                       'artifact_paths': [], 'recipient': 'fixture',
                       'destinations': [{'host': 'fixture-exit', 'required': True}]}
        self.delivered = {}
        self.encryptions = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(recovery, 'VERSIONED_STATE_PATHS', self.patterns))
        self.stack.enter_context(mock.patch.object(recovery, 'run', side_effect=self.dump))
        self.stack.enter_context(mock.patch.object(recovery, 'encrypt', side_effect=self.encrypt))
        self.stack.enter_context(mock.patch.object(recovery, 'verify_remote_artifact', side_effect=ValueError('missing')))
        self.stack.enter_context(mock.patch.object(recovery, 'deliver', side_effect=self.deliver))

    @staticmethod
    def dump(args, **kwargs):
        kwargs['stdout'].write(b'fixture-database')
        return argparse.Namespace(returncode=0)

    def encrypt(self, source, target, recipient):
        self.encryptions.append(target.name)
        target.write_bytes(source.read_bytes())

    def deliver(self, config, destination, source, encrypted, snapshot):
        self.delivered[encrypted.name] = encrypted.read_bytes()

    def capture(self):
        recovery.create(self.config)
        receipt = json.loads((self.repo / 'last-success.json').read_text())
        bundle = self.root / 'delivered.tar.gz'
        bundle.write_bytes(self.delivered[receipt['backup_name']])
        return receipt, bundle

    def test_roundtrip_preserves_pinned_retry_inputs_and_bot_before_images(self):
        originals = {path: (path.read_bytes(), path.stat().st_mode & 0o777)
                     for path in self.binaries + self.metadata}
        receipt, bundle = self.capture()
        state = recovery.inspect_bundle(bundle)
        artifacts = recovery.inspect_bundle(self.repo / receipt['artifact_name'])
        self.assertEqual(set(artifacts['files']), {str(path.relative_to('/')) for path in self.binaries})
        self.assertEqual(set(state['files']), {'database.dump'} |
                         {'state/' + str(path.relative_to('/')) for path in self.metadata})
        self.assertLess(sum(row['bytes'] for row in artifacts['files'].values()), recovery.MAX_BYTES)
        stage = self.root / 'stage'
        captured = self.root / 'captured'
        recovery.unpack(bundle, captured)
        recovery.unpack(self.repo / receipt['artifact_name'], captured / 'artifacts')
        # Strip only the temporary fixture root to exercise real restore
        # destination validation with the production /var/lib paths.
        state_bundle = self.root / 'restore-state.tar.gz'
        artifact_bundle = self.root / 'restore-artifact.tar.gz'
        state = recovery.pack(state_bundle, {'kind': 'backup'}, {
            'state/' + str(path.relative_to(self.root)): captured / 'state' / path.relative_to('/')
            for path in self.metadata})
        artifacts = recovery.pack(artifact_bundle, {'kind': 'artifact'}, {
            str(path.relative_to(self.root)): captured / 'artifacts' / path.relative_to('/')
            for path in self.binaries})
        recovery.unpack(state_bundle, stage)
        recovery.unpack(artifact_bundle, stage / 'artifacts')
        restored = self.root / 'restored'
        restore_host.install_files(stage, state, artifacts, restored)
        for path, (data, mode) in originals.items():
            target = restored / path.relative_to(self.root)
            self.assertEqual(target.read_bytes(), data, str(path))
            self.assertEqual(target.stat().st_mode & 0o777, mode, str(path))
        # Cloud configuration job identity hashes the pinned code, identity and
        # known_hosts bytes, while the operation/retry metadata stays in state.
        inputs = [self.binaries[0], self.metadata[0], self.metadata[1], self.metadata[2]]
        self.assertEqual([recovery.digest(path) for path in inputs],
                         [recovery.digest(restored / path.relative_to(self.root)) for path in inputs])

    def test_unchanged_capture_reuses_artifact_and_bytes_or_modes_version_it(self):
        first, _ = self.capture()
        second, _ = self.capture()
        self.assertEqual(first['artifact_name'], second['artifact_name'])
        self.assertEqual(self.encryptions.count(first['artifact_name']), 1)
        self.binaries[-1].write_bytes(b'changed rollback binary')
        third, _ = self.capture()
        self.assertNotEqual(second['artifact_name'], third['artifact_name'])
        self.binaries[-1].chmod(0o750)
        fourth, _ = self.capture()
        self.assertNotEqual(third['artifact_name'], fourth['artifact_name'])

    def test_unselected_paths_are_not_added_and_exact_file_selection_works(self):
        self.config['state_paths'] = [str(self.binaries[-1])]
        self.assertEqual(recovery.capture_artifact_paths(self.config), [str(self.binaries[-1])])
        self.config['state_paths'] = [str(self.metadata[-1])]
        self.assertEqual(recovery.capture_artifact_paths(self.config), [])

    def test_artifact_bound_includes_existing_assets_and_fails_before_delivery(self):
        asset = self.root / 'existing-geo.dat'
        asset.write_bytes(b'x' * 100)
        self.config['artifact_paths'] = [str(asset)]
        binary_bytes = sum(path.stat().st_size for path in self.binaries)
        with mock.patch.object(recovery, 'MAX_BYTES', binary_bytes + asset.stat().st_size - 1):
            with self.assertRaisesRegex(ValueError, 'exceeds backup limits'):
                self.capture()
        self.assertFalse(self.delivered)
        self.assertFalse(list(self.repo.glob('artifact-*.age')))

    def test_new_binary_during_capture_rejects_inconsistent_generation(self):
        original = recovery.pack
        def pack(*args):
            result = original(*args)
            if args[1]['kind'] == 'backup':
                new = self.relay / 'new-operation/ultra-relay'
                new.parent.mkdir()
                new.write_bytes(b'new operation binary')
            return result
        with mock.patch.object(recovery, 'pack', side_effect=pack):
            with self.assertRaisesRegex(ValueError, 'configuration changed|binary artifacts changed'):
                self.capture()
        self.assertFalse(self.delivered)

    def test_actual_512_mib_limit_rejects_oversized_artifact_before_delivery(self):
        # Sparse file and mocked digest exercise the real bound without a large
        # disk allocation or a half-gigabyte hashing pass in the test suite.
        with self.binaries[0].open('wb') as stream:
            stream.truncate(recovery.MAX_BYTES + 1)
        with mock.patch.object(recovery, 'digest', return_value='a' * 64):
            with self.assertRaisesRegex(ValueError, 'exceeds backup limits'):
                self.capture()
        self.assertFalse(self.delivered)
        self.assertFalse(list(self.repo.glob('artifact-*.age')))

    def test_old_state_archives_still_restore_pinned_code(self):
        path = self.binaries[0]
        bundle = self.root / 'old.tar.gz'
        state = recovery.pack(bundle, {'kind': 'backup'},
                              {'state/' + str(path.relative_to(self.root)): path})
        stage = self.root / 'old-stage'
        recovery.unpack(bundle, stage)
        restored = self.root / 'old-restored'
        restore_host.install_files(stage, state, {'files': {}}, restored)
        target = restored / path.relative_to(self.root)
        self.assertEqual(target.read_bytes(), path.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
