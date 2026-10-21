#!/usr/bin/env python3
"""Focused contract tests for the read-only forward broker identity guard."""
import importlib.util
import hashlib
import io
import json
import os
import shutil
import tarfile
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'ultra_forward_broker_guard', ROOT / 'deploy/ansible/library/ultra_forward_broker_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


OLD = '11111111-1111-4111-8111-111111111111'
NEW = '22222222-2222-4222-8222-222222222222'
PREVIOUS = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.144',
            'installer_sha256': 'a' * 64, 'runtime_sha256': 'b' * 64, 'unit_sha256': 'c' * 64}
TARGET = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.145',
          'installer_sha256': 'd' * 64, 'runtime_sha256': 'e' * 64, 'unit_sha256': 'f' * 64}
PRIOR_TARGET = {'directory': '/opt/ultra-ansible/releases/managed-v0.0.144',
                'installer_sha256': '1' * 64, 'runtime_sha256': '2' * 64, 'unit_sha256': '3' * 64}


class ForwardBrokerGuardTests(unittest.TestCase):
    def setUp(self):
        self.params = {'action': 'before', 'old_id': OLD, 'candidate_id': NEW,
                       'expected_brokers': [PREVIOUS], 'target_broker': TARGET}

    def run_verify(self, matches):
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle') as lifecycle, \
                patch.object(guard, 'broker_matches', side_effect=lambda value: id(value) in matches):
            result = guard.verify(self.params)
        lifecycle.assert_called_once_with(OLD, NEW)
        return result

    def test_before_accepts_only_frozen_old_identity(self):
        self.assertTrue(self.run_verify({id(PREVIOUS)})['verified'])
        with self.assertRaisesRegex(ValueError, 'forward_broker_predecessor_mismatch'):
            self.run_verify(set())

    def test_after_requires_the_exact_candidate_identity(self):
        self.params['action'] = 'after'
        self.assertEqual(self.run_verify({id(TARGET)})['controller_directory'], TARGET['directory'])
        with self.assertRaisesRegex(ValueError, 'forward_broker_target_mismatch'):
            self.run_verify({id(PREVIOUS)})

    def test_before_accepts_three_frozen_previous_retry_and_signed_candidate_identities(self):
        self.params['expected_brokers'] = [PREVIOUS, PRIOR_TARGET, TARGET]
        self.assertTrue(self.run_verify({id(PRIOR_TARGET)})['verified'])

    def test_rejects_more_than_three_candidate_identities(self):
        self.params['expected_brokers'] = [PREVIOUS, PRIOR_TARGET, TARGET, PREVIOUS]
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'broker_matches'):
            with self.assertRaisesRegex(ValueError, 'forward_broker_identity_invalid'):
                guard.verify(self.params)

    def test_lifecycle_verification_precedes_identity_acceptance(self):
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle', side_effect=ValueError('gate_changed')), \
                patch.object(guard, 'broker_matches') as broker:
            with self.assertRaisesRegex(ValueError, 'gate_changed'):
                guard.verify(self.params)
        broker.assert_not_called()

    def test_rejects_malformed_identity_even_when_expected(self):
        self.params['expected_brokers'] = [{'directory': '/tmp/controller',
                                            'installer_sha256': 'x',
                                            'runtime_sha256': 'b' * 64,
                                            'unit_sha256': 'c' * 64}]
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'broker_matches', return_value=True):
            with self.assertRaisesRegex(ValueError, 'forward_broker_identity_invalid'):
                guard.verify(self.params)

    def test_rejects_unknown_or_duplicate_retirement_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'lifecycle.json').touch()
            (root / 'lifecycle-retired.json').touch()
            def read(path, limit=65536):
                if Path(path).name == 'lifecycle.json':
                    return {'id': OLD, 'phase': 'applying'}
                return {'version': 1, 'ids': [OLD, OLD]}
            with patch.object(guard, 'ROOT', root), patch.object(guard, 'private_json', side_effect=read):
                with self.assertRaisesRegex(ValueError, 'forward_broker_retirement_invalid'):
                    guard.check_lifecycle(OLD, NEW)


class RetainedPreviousBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commit = '0' * 39 + '7'
        self.version = 'v0.0.7'
        self.directory = '/opt/ultra-ansible/releases/managed-' + self.version
        self.inputs = self.root / 'operator-inputs'
        self.candidate = self.inputs / ('manual-' + self.commit + '-' + 'a' * 64)
        self.release = self.candidate / 'release'
        self.release.mkdir(parents=True, mode=0o700)
        for path in (self.root, self.inputs, self.candidate):
            path.chmod(0o700)
        self.template = 'ExecStart={{ ultra_controller_directory }}/ultra-install\n'
        self.write_archive()
        self.installer = self.release / 'ultra-install-linux-amd64'
        self.installer.write_bytes(b'installer')
        self.runtime = self.release / 'ultra-ansible-runtime-linux-amd64.tar.gz'
        self.runtime.write_bytes(b'runtime archive')
        self.manifest = {'schema_version': 1, 'version': self.version,
                         'source_commit': self.commit, 'assets': []}
        self.refresh_manifest()
        self.previous = {'directory': self.directory,
                         'unit_sha256': hashlib.sha256(self.template.replace(
                             '{{ ultra_controller_directory }}', self.directory).encode()).hexdigest()}
        # Fixtures run as the invoking user; emulate root ownership only. Actual
        # type, link count, permissions and bytes remain real filesystem evidence.
        original_lstat = Path.lstat
        self.bad_owner = set()
        def root_lstat(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            fields['st_uid'] = 1000 if str(path) in self.bad_owner else 0
            return SimpleNamespace(**fields)
        self.addCleanup(patch.stopall)
        patch.object(Path, 'lstat', root_lstat).start()
        patch.object(guard, 'ROOT', self.root).start()
        patch.object(guard.platform, 'machine', return_value='x86_64').start()

    def write_archive(self, duplicate=False, symlink=False, missing=False):
        path = self.release / 'ultra-ansible.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            if not missing:
                member = tarfile.TarInfo('roles/controller/templates/ultra-ansible-controller.service.j2')
                data = self.template.encode()
                member.size = len(data)
                if symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/tmp/unit'
                archive.addfile(member, io.BytesIO(data))
                if duplicate:
                    archive.addfile(member, io.BytesIO(data))
        path.chmod(0o600)

    def refresh_manifest(self):
        self.manifest['assets'] = []
        for name in ('ultra-install-linux-amd64', 'ultra-ansible-runtime-linux-amd64.tar.gz',
                     'ultra-ansible.tar.gz'):
            path = self.release / name
            path.chmod(0o600)
            self.manifest['assets'].append({'name': name, 'size': path.stat().st_size,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        self.write_manifest()

    def write_manifest(self):
        path = self.release / 'release-manifest.json'
        path.write_text(json.dumps(self.manifest))
        path.chmod(0o600)

    def identity(self):
        return guard.retained_previous_identity(self.previous)

    def test_accepts_exact_independent_controller_release(self):
        identity = self.identity()
        self.assertEqual(identity['directory'], self.directory)
        self.assertEqual(identity['unit_sha256'], self.previous['unit_sha256'])
        self.assertEqual(identity['installer_sha256'], hashlib.sha256(b'installer').hexdigest())
        self.assertEqual(identity['runtime_sha256'], hashlib.sha256(b'runtime archive').hexdigest())

    def test_before_uses_retained_proof_and_still_checks_live_identity(self):
        params = {'action': 'before', 'old_id': OLD, 'candidate_id': NEW,
                  'expected_brokers': [PREVIOUS], 'target_broker': TARGET,
                  'previous_broker': self.previous}
        identity = self.identity()
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'broker_matches', side_effect=lambda value: value == identity):
            self.assertTrue(guard.verify(params)['verified'])
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'broker_matches', return_value=False):
            with self.assertRaisesRegex(ValueError, 'forward_broker_predecessor_mismatch'):
                guard.verify(params)

    def test_normal_match_and_after_do_not_use_fallback(self):
        params = {'action': 'before', 'old_id': OLD, 'candidate_id': NEW,
                  'expected_brokers': [PREVIOUS], 'target_broker': TARGET,
                  'previous_broker': self.previous}
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'retained_previous_identity') as retained, \
                patch.object(guard, 'broker_matches', return_value=True):
            guard.verify(params)
            params['action'] = 'after'
            guard.verify(params)
        retained.assert_not_called()
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'check_lifecycle'), \
                patch.object(guard, 'retained_previous_identity') as retained, \
                patch.object(guard, 'broker_matches', return_value=False):
            with self.assertRaisesRegex(ValueError, 'forward_broker_target_mismatch'):
                guard.verify(params)
        retained.assert_not_called()

    def test_rejects_missing_or_ambiguous_release(self):
        second = self.inputs / ('manual-' + self.commit + '-' + 'b' * 64)
        shutil.copytree(self.candidate, second)
        with self.assertRaises(ValueError):
            self.identity()
        shutil.rmtree(second)
        shutil.rmtree(self.candidate)
        with self.assertRaises(ValueError):
            self.identity()

    def test_rejects_changed_asset_bytes(self):
        for path in (self.installer, self.runtime, self.release / 'ultra-ansible.tar.gz'):
            with self.subTest(path=path.name):
                saved = path.read_bytes()
                path.write_bytes(b'x' * len(saved))
                with self.assertRaises(ValueError):
                    self.identity()
                path.write_bytes(saved)

    def test_rejects_missing_assets(self):
        for path in (self.installer, self.runtime, self.release / 'ultra-ansible.tar.gz'):
            with self.subTest(path=path.name):
                saved = path.read_bytes()
                path.unlink()
                with self.assertRaises(OSError):
                    self.identity()
                path.write_bytes(saved)
                path.chmod(0o600)

    def test_rejects_symlinked_retained_components(self):
        for path in (self.inputs, self.candidate, self.release,
                     self.release / 'release-manifest.json', self.installer, self.runtime,
                     self.release / 'ultra-ansible.tar.gz'):
            with self.subTest(path=path.name):
                saved = path.with_name(path.name + '-saved')
                path.rename(saved)
                path.symlink_to(saved, target_is_directory=saved.is_dir())
                with self.assertRaises(ValueError):
                    self.identity()
                path.unlink()
                saved.rename(path)

    def test_rejects_untrusted_ownership_and_permissions(self):
        for path in (self.root, self.inputs, self.candidate, self.release,
                     self.release / 'release-manifest.json', self.installer, self.runtime,
                     self.release / 'ultra-ansible.tar.gz'):
            with self.subTest(path=path.name):
                self.bad_owner.add(str(path))
                with self.assertRaises(ValueError):
                    self.identity()
                self.bad_owner.clear()
                mode = path.stat().st_mode & 0o777
                path.chmod(mode | 0o020)
                with self.assertRaises(ValueError):
                    self.identity()
                path.chmod(mode)

    def test_rejects_hardlinked_manifest_and_assets(self):
        for path in (self.release / 'release-manifest.json', self.installer, self.runtime,
                     self.release / 'ultra-ansible.tar.gz'):
            with self.subTest(path=path.name):
                link = path.with_name(path.name + '-link')
                os.link(path, link)
                with self.assertRaises(ValueError):
                    self.identity()
                link.unlink()

    def test_rejects_manifest_identity_and_asset_mismatches(self):
        original = json.loads(json.dumps(self.manifest))
        for name in ('version', 'source_commit', 'schema', 'missing asset', 'duplicate asset',
                     'bad digest', 'wrong size', 'boolean size'):
            with self.subTest(name=name):
                self.manifest = json.loads(json.dumps(original))
                if name == 'version': self.manifest['version'] = 'v0.0.8'
                elif name == 'source_commit': self.manifest['source_commit'] = 'f' * 40
                elif name == 'schema': self.manifest['schema_version'] = True
                elif name == 'missing asset': self.manifest['assets'].pop()
                elif name == 'duplicate asset': self.manifest['assets'].append(self.manifest['assets'][0])
                elif name == 'bad digest': self.manifest['assets'][0]['sha256'] = 'x' * 64
                elif name == 'wrong size': self.manifest['assets'][0]['size'] += 1
                elif name == 'boolean size': self.manifest['assets'][0]['size'] = True
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.identity()

    def test_rejects_wrong_unit_and_untrusted_archive_template(self):
        self.previous['unit_sha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.identity()
        self.previous['unit_sha256'] = hashlib.sha256(self.template.replace(
            '{{ ultra_controller_directory }}', self.directory).encode()).hexdigest()
        for option in ('duplicate', 'symlink', 'missing'):
            with self.subTest(option=option):
                self.write_archive(**{option: True})
                self.refresh_manifest()
                with self.assertRaises(ValueError):
                    self.identity()

    def test_rejects_partial_malformed_and_noncanonical_frozen_identity(self):
        for value in ({'directory': self.directory}, {'unit_sha256': 'a' * 64},
                      {**self.previous, 'extra': True},
                      {**self.previous, 'unit_sha256': 'x'},
                      {**self.previous, 'directory': self.directory.replace('v0.0.7', 'v0.0.07')},
                      {**self.previous, 'directory': '/tmp/controller'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                guard.retained_previous_identity(value)


if __name__ == '__main__':
    unittest.main()
