"""Local fault tests for the backend TLS/SNI journal; never run services."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name):
    fake = types.ModuleType('ansible.module_utils.basic')
    fake.AnsibleModule = object
    with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.module_utils': types.ModuleType('ansible.module_utils'), 'ansible.module_utils.basic': fake}):
        source = Path(__file__).parents[1] / 'ansible/library' / (name + '.py')
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


backend = load('ultra_backend_domain')
backend_dns = load('ultra_backend_dns')
owned_dns = load('ultra_dns')


class BackendTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / 'transaction'
        self.environment = self.put('etc/ultra-relay/environment', b'ULTRA_BOT_DOMAIN=old.example.com\nULTRA_BOT_PORT=8444\nSECRET=do-not-print\n')
        self.site = self.put('etc/nginx/conf.d/ultra-subscription.conf', b'server_name sync.example.com;\nproxy_ssl_name old.example.com;\n')
        self.vpn = self.put('etc/nginx/conf.d/ultra-vpn.conf', b'server_name edge.example.com;\nproxy_ssl_name old.example.com;\n')
        self.manifest = self.put('var/lib/ultra-ingress/managed.json', json.dumps({
            '/etc/nginx/conf.d/ultra-subscription.conf': backend.digest(self.site.read_bytes()),
            '/etc/nginx/conf.d/ultra-vpn.conf': backend.digest(self.vpn.read_bytes())}).encode())
        self.before = {path: path.read_bytes() for path in (self.environment, self.site, self.vpn, self.manifest)}

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def prepare(self):
        return backend.prepare(self.directory, 'old.example.com', 'core.example.com', 'sync.example.com', self.root)

    def rollback(self):
        return backend.rollback(self.directory, 'old.example.com', 'core.example.com', 'sync.example.com', self.root)

    def test_failure_before_journal_recovers_without_mutating_old_backend(self):
        # DNS failure has no listener; certbot failure can leave an owned listener.
        for provisioned in (False, True):
            with self.subTest(provisioned=provisioned):
                if provisioned:
                    listener = self.put('etc/nginx/conf.d/ultra-backend-acme.conf',
                                        b'server { listen 80; server_name core.example.com; }')
                    manifest = json.loads(self.manifest.read_bytes())
                    manifest['/etc/nginx/conf.d/ultra-backend-acme.conf'] = backend.digest(listener.read_bytes())
                    self.manifest.write_text(json.dumps(manifest))
                before = {path: path.read_bytes() for path in self.before}
                self.assertFalse((self.directory / 'state.json').exists())
                self.assertEqual(self.rollback()['phase'], 'unmodified')
                self.assertEqual(self.rollback()['phase'], 'unmodified')
                for path, data in before.items():
                    self.assertEqual(path.read_bytes(), data)
                self.assertFalse((self.directory / 'state.json').exists())

    def test_missing_journal_with_partial_backend_changes_stays_blocked(self):
        for path, data in ((self.environment, b'ULTRA_BOT_DOMAIN=core.example.com\n'),
                           (self.site, b'proxy_ssl_name core.example.com;\n'),
                           (self.vpn, b'proxy_ssl_name core.example.com;\n')):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    self.rollback()
                self.assertEqual(path.read_bytes(), data)
                path.write_bytes(original)

    def test_missing_journal_with_ownership_drift_stays_blocked(self):
        pending = self.manifest.with_name('managed.json.pending')
        pending.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'pending_ownership'):
            self.rollback()
        pending.unlink()
        self.put('etc/nginx/conf.d/ultra-backend-acme.conf', b'foreign listener')
        with self.assertRaisesRegex(ValueError, 'foreign_challenge'):
            self.rollback()

    def test_existing_journal_rollback_still_rejects_drift_and_policy_changes(self):
        self.prepare()
        backend.transition(self.directory, 'activate')
        with self.assertRaisesRegex(ValueError, 'policy'):
            backend.rollback(self.directory, 'old.example.com', 'other.example.com', 'sync.example.com', self.root)
        self.site.write_bytes(b'operator edit')
        with self.assertRaisesRegex(ValueError, 'drift'):
            self.rollback()
        self.assertEqual(self.site.read_bytes(), b'operator edit')

    def test_prepare_is_durable_before_mutation_and_preserves_public_names(self):
        state = self.prepare()
        self.assertEqual(state['phase'], 'prepared')
        self.assertEqual((self.directory / 'state.json').stat().st_mode & 0o777, 0o600)
        for path, data in self.before.items():
            self.assertEqual(path.read_bytes(), data)
        backend.transition(self.directory, 'activate')
        self.assertIn(b'ULTRA_BOT_DOMAIN=core.example.com', self.environment.read_bytes())
        self.assertIn(b'ULTRA_BOT_PUBLIC_URL=https://sync.example.com', self.environment.read_bytes())
        self.assertIn(b'SECRET=do-not-print', self.environment.read_bytes())
        self.assertIn(b'server_name edge.example.com;', self.vpn.read_bytes())
        self.assertIn(b'proxy_ssl_name core.example.com;', self.site.read_bytes())
        state = backend.transition(self.directory, 'verify')
        self.assertEqual(state['phase'], 'verified')
        backend.transition(self.directory, 'verify')
        backend.transition(self.directory, 'rollback')
        backend.transition(self.directory, 'verify-rollback')
        for path, data in self.before.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertFalse((self.root / 'etc/letsencrypt/renewal-hooks/deploy/ultra-backend-domain').exists())
        self.assertEqual(self.prepare()['phase'], 'prepared')
        backend.transition(self.directory, 'activate')
        backend.transition(self.directory, 'verify')

    def test_failure_mid_apply_resumes_only_journalled_content(self):
        self.prepare()
        original = backend.atomic
        def fail_on_site(path, data, mode):
            if path == self.site:
                raise OSError('injected_write_failure')
            return original(path, data, mode)
        with patch.object(backend, 'atomic', side_effect=fail_on_site):
            with self.assertRaises(OSError): backend.transition(self.directory, 'activate')
        self.assertIn(b'core.example.com', self.environment.read_bytes())
        self.assertEqual(self.site.read_bytes(), self.before[self.site])
        backend.transition(self.directory, 'rollback')
        for path, data in self.before.items(): self.assertEqual(path.read_bytes(), data)

    def test_interrupted_activation_can_resume_the_same_journal(self):
        state = self.prepare()
        item = state['files'][0]
        self.environment.write_bytes(base64.b64decode(item['after']))
        state['phase'] = 'applying'
        (self.directory / 'state.json').write_text(json.dumps(state))
        self.assertEqual(backend.transition(self.directory, 'activate')['phase'], 'applied')
        self.assertEqual(backend.transition(self.directory, 'verify')['phase'], 'verified')

    def test_post_activation_drift_blocks_acceptance_and_overwrite(self):
        self.prepare()
        backend.transition(self.directory, 'activate')
        self.site.write_bytes(b'operator edit')
        for action in ('verify', 'rollback'):
            with self.assertRaisesRegex(ValueError, 'drift'): backend.transition(self.directory, action)
        self.assertEqual(self.site.read_bytes(), b'operator edit')

    def test_foreign_proxy_fails_before_runtime_changes(self):
        self.site.write_bytes(self.site.read_bytes() + b'# manual\n')
        with self.assertRaisesRegex(ValueError, 'foreign'): self.prepare()
        self.assertEqual(self.environment.read_bytes(), self.before[self.environment])
        self.assertFalse((self.directory / 'state.json').exists())

    def test_changed_backend_and_symlink_fail_without_replacement(self):
        self.environment.write_bytes(b'ULTRA_BOT_DOMAIN=unexpected.example.com\n')
        with self.assertRaisesRegex(ValueError, 'drift'): self.prepare()
        self.environment.unlink()
        self.environment.symlink_to(self.site)
        with self.assertRaisesRegex(ValueError, 'symlink'): self.prepare()

    def test_rollback_acceptance_requires_rollback_receipt_and_original_bytes(self):
        self.prepare()
        backend.transition(self.directory, 'activate')
        with self.assertRaisesRegex(ValueError, 'not_rolled_back'):
            backend.transition(self.directory, 'verify-rollback')
        backend.transition(self.directory, 'rollback')
        backend.transition(self.directory, 'verify-rollback')
        self.environment.write_bytes(b'operator change')
        with self.assertRaisesRegex(ValueError, 'drift'):
            backend.transition(self.directory, 'verify-rollback')

    def test_recovery_inventory_includes_new_lineage_and_its_acme_account(self):
        backup = self.put('etc/ultra-recovery/backup.json', b'{"state_paths":["/etc/ultra-relay"]}')
        self.put('etc/letsencrypt/renewal/core.example.com.conf', b'account = abc123\n')
        account = self.root / 'etc/letsencrypt/accounts/acme.example.net/directory/abc123'
        account.mkdir(parents=True)
        self.prepare()
        backend.transition(self.directory, 'activate')
        paths = json.loads(backup.read_text())['state_paths']
        self.assertIn('/etc/letsencrypt/archive/core.example.com', paths)
        self.assertIn('/etc/letsencrypt/accounts/acme.example.net/directory/abc123', paths)
        backend.transition(self.directory, 'rollback')
        self.assertEqual(json.loads(backup.read_text()), {'state_paths': ['/etc/ultra-relay']})

    def test_prepare_existing_transaction_checks_policy(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'policy'):
            backend.prepare(self.directory, 'old.example.com', 'other.example.com', 'sync.example.com', self.root)


class BackendDNSPolicyTests(unittest.TestCase):
    def test_public_policy_drift_is_rejected_before_dns_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = {'config': {'zone': 'example.com', 'ttl': 300}, 'desired': {
                'subscription': {'name': 'sync', 'data': '192.0.2.1'}, 'vpn': {'name': 'edge', 'data': '192.0.2.1'}}}
            (root / 'dns.json').write_text(json.dumps(policy))
            (root / 'dns-receipt.json').write_text(json.dumps({'records': {}}))
            application = types.SimpleNamespace(private=lambda p: p, same=lambda row, target: row == target)
            with self.assertRaisesRegex(ValueError, 'public_dns_policy_drift'):
                backend_dns.reconcile(application, 'core.example.com', 'example.com', '192.0.2.1', root)


class DNSSeedCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'receipt.json'
        self.public = {'version': 1, 'zone': 'example.com', 'records': {
            'subscription': {'id': 's', 'type': 'A', 'name': 'sync', 'data': '192.0.2.1', 'ttl': 300},
            'vpn': {'id': 'v', 'type': 'A', 'name': 'edge', 'data': '192.0.2.1', 'ttl': 300}}}
        self.current = json.loads(json.dumps(self.public))
        self.current['records']['backend'] = {'id': 'b', 'type': 'A', 'name': 'core', 'data': '192.0.2.1', 'ttl': 300}
        self.path.write_text(json.dumps(self.current))
        self.application = types.SimpleNamespace(json=json, private=lambda p: p,
            save=lambda p, state: p.write_text(json.dumps(state)))

    def test_public_seed_retains_complete_existing_backend_receipt(self):
        before = self.path.read_bytes()
        owned_dns.seed_receipt(self.application, self.path, self.public, 'example.com')
        self.assertEqual(self.path.read_bytes(), before)
        owned_dns.seed_receipt(self.application, self.path, self.current, 'example.com')
        self.assertEqual(self.path.read_bytes(), before)

    def test_public_record_ids_and_backend_identity_cannot_change(self):
        for role, key, value in [('subscription', 'id', 'different'), ('vpn', 'id', 'different'),
                                 ('backend', 'id', 'foreign'), ('backend', 'data', '192.0.2.99')]:
            seed = json.loads(json.dumps(self.current))
            seed['records'][role][key] = value
            with self.assertRaisesRegex(ValueError, 'ownership_drift'):
                owned_dns.seed_receipt(self.application, self.path, seed, 'example.com')

    def test_malformed_preserved_backend_is_rejected(self):
        self.current['records']['backend']['type'] = 'CNAME'
        self.path.write_text(json.dumps(self.current))
        with self.assertRaisesRegex(ValueError, 'backend_receipt_required'):
            owned_dns.seed_receipt(self.application, self.path, self.public, 'example.com')
