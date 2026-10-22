#!/usr/bin/env python3
"""One supervised postactivation producer for ordinary and prepared requests."""
import hashlib
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
import reconcile
import live_tools


class DeploymentReconcileTests(unittest.TestCase):
    def test_exact_current_same_unit_and_both_schemas(self):
        for schema in (1, 2):
            envelope = {'schema': schema, 'args': ['operator-upgrade', '--manifest-sha256', hashlib.sha256(b'manifest').hexdigest(), '--config', '/config', '--config-sha256', hashlib.sha256(b'config').hexdigest()]}
            if schema == 2: envelope['preparation'] = {'bound': True}
            raw = json.dumps(envelope).encode(); identity = hashlib.sha256(raw).hexdigest()
            operation = Path('/var/lib/ultra-ansible/deploy-operations') / identity
            terminal = operation / 'post-activation-1.json'
            files = {str(operation.parent / 'current.json'): json.dumps({'schema': 1, 'request_sha256': identity}).encode(),
                     str(operation / 'request.json'): raw, str(operation / 'state.json'): json.dumps({'request_sha256': identity, 'state': 'running', 'stage': 'upgrade'}).encode(),
                     str(operation / 'post-activation-1.started.json'): json.dumps({'request_sha256': identity, 'watermark': 100, 'started_at': 101}).encode(),
                     '/opt/ultra-recovery/release-manifest.json': b'manifest', '/config': b'config'}
            with patch.object(live_tools, 'regular', side_effect=lambda path, *a, **k: files[str(path)]), \
                 patch.object(live_tools, 'verify', return_value={'manifest_sha256': hashlib.sha256(b'manifest').hexdigest()}), \
                 patch.object(reconcile.os.path, 'lexists', return_value=False), \
                 patch.object(reconcile.Path, 'read_text', return_value='0::/system.slice/ultra-deploy-' + identity + '.service\n'):
                self.assertEqual(reconcile.deployment_context(identity, terminal, 101, 100), envelope)
                files[str(operation / 'state.json')] = json.dumps({'request_sha256': identity, 'state': 'running', 'stage': 'status'}).encode()
                self.assertEqual(reconcile.deployment_context(identity, terminal, 101, 100), envelope)
                files['/config'] = b'changed'
                with self.assertRaises(ValueError): reconcile.deployment_context(identity, terminal, 101, 100)
                files['/config'] = b'config'
                with patch.object(reconcile.Path, 'read_text', return_value='0::/system.slice/foreign.service\n'):
                    with self.assertRaises(ValueError): reconcile.deployment_context(identity, terminal, 101, 100)
                with self.assertRaises(ValueError): reconcile.deployment_context(identity, '/tmp/foreign.json', 101, 100)
                with self.assertRaises(ValueError): reconcile.deployment_context(identity, terminal, 101, 99)

    def test_ordinary_foreground_always_captures_then_reconciles_and_publishes_exact_terminal(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / 'post-activation-1.json'; events = []
            with patch.object(reconcile, 'deployment_context', return_value={'schema': 1}), \
                 patch.object(reconcile, 'read_config', return_value={'backup': True}), \
                 patch.object(reconcile, 'create', side_effect=lambda value: events.append('capture')), \
                 patch.object(reconcile, 'reconcile', side_effect=lambda value: events.append('reconcile')):
                reconcile.reconcile_deployment({'backup_config': '/config','bundle_dir':'/opt/ultra-recovery','installer_binary':'/opt/ultra-ansible/current/ultra-install','ansible_executable':'/opt/ultra-ansible/current/venv/bin/ansible-playbook'}, 'a'*64, target, 101, 100)
            self.assertEqual(events, ['capture', 'reconcile'])
            receipt = json.loads(target.read_bytes())
            self.assertEqual(receipt['protocol'], 'ultra-deploy-post-activation-v1')
            self.assertEqual(receipt['request_sha256'], 'a'*64)
            self.assertEqual(receipt['started_at'], 101)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_foreground_cannot_use_an_old_snapshot_or_arbitrary_dispatcher(self):
        base={'bundle_dir':'/opt/ultra-recovery','installer_binary':'/opt/ultra-ansible/current/ultra-install',
              'ansible_executable':'/opt/ultra-ansible/current/venv/bin/ansible-playbook'}
        for field in base:
            config=dict(base);config[field]='/old-first-snapshot/anything'
            with self.subTest(field=field),self.assertRaises(ValueError):reconcile.require_canonical_dispatcher(config)
        reconcile.require_canonical_dispatcher(base)

    def test_unknown_foreground_never_publishes_a_terminal(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / 'post-activation-1.json'
            with patch.object(reconcile, 'deployment_context', return_value={'schema': 1}), \
                 patch.object(reconcile, 'read_config', return_value={}), \
                 patch.object(reconcile, 'create', side_effect=ValueError('SSH uncertainty')), \
                 patch.object(reconcile, 'reconcile') as child:
                with self.assertRaises(ValueError): reconcile.reconcile_deployment({'backup_config': '/config','bundle_dir':'/opt/ultra-recovery','installer_binary':'/opt/ultra-ansible/current/ultra-install','ansible_executable':'/opt/ultra-ansible/current/venv/bin/ansible-playbook'}, 'a'*64, target, 101, 100)
            child.assert_not_called(); self.assertFalse(target.exists())


if __name__ == '__main__': unittest.main()
