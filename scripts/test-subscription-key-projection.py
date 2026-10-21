#!/usr/bin/env python3
"""Synthetic private keyring delivery, history preservation and conflict tests."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('subscription_keys', ROOT / 'deploy/ansible/library/ultra_subscription_keys.py')
keys = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(keys)


def data(active='v2', versions=('v1', 'v2')):
    return json.dumps({'active': active, 'keys': {version: base64.b64encode(bytes([index + 1]) * 32).decode()
                                              for index, version in enumerate(versions)}}).encode()


class ProjectionTests(unittest.TestCase):
    def fixture(self, root):
        source, target = root / keys.SOURCE.lstrip('/'), root / keys.DESTINATION.lstrip('/')
        source.parent.mkdir(parents=True, mode=0o700)
        target.parent.mkdir(parents=True, mode=0o700)
        source.write_bytes(data())
        source.chmod(0o600)
        return source, target

    def install(self, root):
        return keys.install(keys.SOURCE, keys.DESTINATION, root, os.geteuid(), os.getegid())

    def test_initial_copy_is_exact_private_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = self.fixture(root)
            self.assertTrue(self.install(root))
            self.assertEqual(source.read_bytes(), target.read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse(self.install(root))

    def test_history_is_merged_without_dropping_remote_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = self.fixture(root)
            prior = json.loads(data())
            prior['keys']['older'] = base64.b64encode(b'x' * 32).decode()
            prior['active'] = 'v1'
            target.write_text(json.dumps(prior))
            target.chmod(0o600)
            self.assertTrue(self.install(root))
            merged = json.loads(target.read_bytes())
            self.assertEqual(merged['active'], 'v2')
            self.assertEqual(merged['keys'], prior['keys'])
            self.assertFalse(self.install(root))

    def test_existing_key_id_conflict_never_replaces_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, target = self.fixture(root)
            prior = json.loads(data())
            prior['keys']['v1'] = base64.b64encode(b'x' * 32).decode()
            raw = json.dumps(prior).encode()
            target.write_bytes(raw)
            target.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'key_id_conflict'):
                self.install(root)
            self.assertEqual(target.read_bytes(), raw)

    def test_only_canonical_service_owned_state_root_accepts_systemd_mode(self):
        for variant in ['root700', 'root755', 'root750', 'root770', 'wrong owner', 'wrong group', 'automation755', 'root symlink']:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, target = self.fixture(root)
                state, automation = root / 'var/lib/ultra-relay', target.parent
                state.chmod(0o700 if variant == 'root700' else 0o755)
                if variant == 'root750': state.chmod(0o750)
                if variant == 'root770': state.chmod(0o770)
                if variant == 'automation755': automation.chmod(0o755)
                if variant == 'root symlink':
                    state.rename(state.with_name('other-state'))
                    state.symlink_to(state.with_name('other-state'), target_is_directory=True)
                service_uid, service_gid = os.geteuid() + 100, os.getegid() + 100
                original = Path.lstat

                def observed(path, *args, **kwargs):
                    value = original(path, *args, **kwargs)
                    if path in (state, automation):
                        fields = list(value)
                        fields[4] = service_uid + (1 if variant == 'wrong owner' and path == state else 0)
                        fields[5] = service_gid + (1 if variant == 'wrong group' and path == state else 0)
                        return os.stat_result(fields)
                    return value

                with patch.object(Path, 'lstat', observed), patch.object(keys.os, 'fchown'):
                    if variant in ['root700', 'root755']:
                        self.assertTrue(keys.install(keys.SOURCE, keys.DESTINATION, root, service_uid, service_gid))
                        self.assertEqual(target.read_bytes(), source.read_bytes())
                        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                    else:
                        with self.assertRaisesRegex(ValueError, 'parent_untrusted'):
                            keys.install(keys.SOURCE, keys.DESTINATION, root, service_uid, service_gid)

    def test_unsafe_sources_and_destinations_fail_closed(self):
        for mutation in ('source mode', 'source symlink', 'source hardlink', 'target mode', 'target symlink', 'duplicate ID'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, target = self.fixture(root)
                if mutation == 'source mode':
                    source.chmod(0o644)
                elif mutation == 'source symlink':
                    source.rename(source.with_suffix('.old'))
                    source.symlink_to(source.with_suffix('.old'))
                elif mutation == 'source hardlink':
                    os.link(source, source.with_suffix('.linked'))
                elif mutation == 'target mode':
                    target.write_bytes(data())
                    target.chmod(0o644)
                elif mutation == 'target symlink':
                    target.symlink_to(source)
                else:
                    encoded = base64.b64encode(b'a' * 32).decode()
                    source.write_text('{"active":"v1","keys":{"v1":"' + encoded + '","v1":"' + encoded + '"}}')
                with self.assertRaises((ValueError, OSError)):
                    self.install(root)


if __name__ == '__main__':
    unittest.main()
