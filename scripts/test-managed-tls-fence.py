#!/usr/bin/env python3
"""Exercise managed TLS fencing only against isolated synthetic hosts."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('tls_fence', ROOT / 'deploy/ansible/library/ultra_tunnel_tls_fence.py')
fence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fence)
TEMPLATE = ROOT / 'deploy/ansible/roles/tunnel_certificate/templates/deploy-certificate.sh.j2'


def write(root, name, raw, mode=0o600):
    path = root / name.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(raw)
    path.chmod(mode)


class Host:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.fail = None
        self.active = False
        self.polls = 0
        self.timer = 'active'
        self.unmanaged = False
        write(root, fence.STATE + '/pair.lock', b'')
        (root / 'etc/systemd/system').mkdir(parents=True, mode=0o700)
        service = b'[Service]\nType=oneshot\nExecStart=/usr/bin/certbot -q renew\n'
        timer = b'[Timer]\nOnCalendar=daily\nPersistent=true\n[Install]\nWantedBy=timers.target\n'
        write(root, '/usr/lib/systemd/system/certbot.service', service, 0o644)
        write(root, '/usr/lib/systemd/system/certbot.timer', timer, 0o644)
        self.hook = TEMPLATE.read_bytes().replace(b'{{ ultra_tunnel_domain }}', b'tunnel.example.com')
        write(root, fence.HOOK, self.hook, 0o700)
        self.request = json.dumps({'transaction': 'tls-test-1', 'domain': 'tunnel.example.com'})
        self.tool = fence.Fence(root, self.run, lambda _: None, self.processes)

    def processes(self):
        if self.unmanaged:
            raise ValueError('tunnel_fence_unmanaged_renewal')

    def run(self, argv):
        self.calls.append(argv)
        if self.fail == argv[1]:
            self.fail = None
            raise ValueError('tunnel_fence_command_failed')
        if argv[0] == '/usr/bin/openssl':
            if '-pubkey' in argv or '-pubout' in argv:
                return 'public-key-fixture\n'
            return 'certificate-valid-fixture\n'
        if argv[1] == 'show':
            name = argv[-1]
            masked = (self.root / 'etc/systemd/system' / name).is_symlink()
            active = self.timer if name.endswith('.timer') else ('activating' if self.active else 'inactive')
            if name.endswith('.service') and self.active:
                self.polls += 1
                if self.polls > 1:
                    # The already-running hook must not be blocked before its
                    # service is drained; it can deploy its renewed pair.
                    if (self.root / fence.STATE.lstrip('/') / 'blocked').exists():
                        raise AssertionError('active renewal was blocked before drain')
                    self.active = False
                    active = 'inactive'
            values = {'LoadState': 'masked' if masked else 'loaded', 'ActiveState': active,
                      'MainPID': '17' if self.active and name.endswith('.service') else '0', 'ControlPID': '0',
                      'ControlGroup': '/system.slice/' + name,
                      'FragmentPath': '/dev/null' if masked else '/usr/lib/systemd/system/' + name, 'DropInPaths': '',
                      'UnitFileState': 'masked' if masked else 'enabled' if name.endswith('.timer') else 'static'}
            selected = [argument.removeprefix('--property=') for argument in argv if argument.startswith('--property=')]
            return ''.join(key + '=' + values[key] + '\n' for key in selected)
        if argv[1:] == ['stop', 'certbot.timer']:
            self.timer = 'inactive'
        elif argv[1:] == ['start', 'certbot.timer']:
            self.timer = 'active'
        elif argv[1:] != ['daemon-reload']:
            raise AssertionError('unexpected command: ' + str(argv))
        return ''

    def closure(self):
        domain = 'tunnel.example.com'
        leaf, chain, key = b'leaf-certificate-fixture\n', b'chain-certificate-fixture\n', b'private-key-fixture-sentinel'
        cert = leaf + chain
        write(self.root, '/etc/ultra-relay/fullchain.pem', cert)
        write(self.root, '/etc/ultra-relay/privkey.pem', key)
        spec = {'role': 'exit', 'tunnel_tls_provision': 'acme_letsencrypt', 'mimic_preset': 'standard',
                'tunnel_transport': 'splithttp', 'splithttp_host': domain, 'splithttp_path': '/ultra-xhttp',
                'splithttp_tls': {'server_name': domain, 'sni_mode': 'send'},
                'exit': {'tunnel_uuid': 'private-tunnel-fixture', 'port': 9443, 'address': '192.0.2.2'},
                'exit_cert': {'cert_file': '/etc/ultra-relay/fullchain.pem', 'key_file': '/etc/ultra-relay/privkey.pem'},
                'vless_port': 9443}
        write(self.root, '/etc/ultra-relay/spec.json', json.dumps(spec).encode())
        live = '/etc/letsencrypt/live/' + domain
        archive = '/etc/letsencrypt/archive/' + domain
        kinds = ('cert', 'chain', 'fullchain', 'privkey')
        config = 'archive_dir = ' + archive + '\n'
        config += ''.join(kind + ' = ' + live + '/' + kind + '.pem\n' for kind in kinds)
        config += ('[renewalparams]\naccount = abc123\nauthenticator = webroot\n'
                   'server = https://acme-v02.api.letsencrypt.org/directory\n'
                   'webroot_path = /var/www/ultra-tunnel-acme,\n'
                   '[[webroot_map]]\n' + domain + ' = /var/www/ultra-tunnel-acme\n')
        write(self.root, '/etc/letsencrypt/renewal/' + domain + '.conf', config.encode())
        for kind in kinds:
            raw = key if kind == 'privkey' else cert if kind == 'fullchain' else leaf if kind == 'cert' else chain
            write(self.root, archive + '/' + kind + '1.pem', raw)
            path = self.tool.path(live + '/' + kind + '.pem')
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.symlink_to('../../archive/' + domain + '/' + kind + '1.pem')
        account = '/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/abc123/'
        for name in ('meta.json', 'regr.json', 'private_key.json'):
            write(self.root, account + name, b'{"fixture":"private-account-sentinel"}')
        nginx = ('server {\n    listen 80;\n    server_name ' + domain + ';\n'
                 '    location ^~ /.well-known/acme-challenge/ { root /var/www/ultra-tunnel-acme; }\n'
                 '    location / { return 404; }\n}\n')
        write(self.root, '/etc/nginx/conf.d/ultra-tunnel-acme.conf', nginx.encode(), 0o644)
        self.tool.path('/var/www/ultra-tunnel-acme').mkdir(parents=True, mode=0o755)
        self.tool.path('/var/www/ultra-tunnel-acme').chmod(0o755)

    def execute(self, action, request=None):
        return self.tool.execute(action, request or self.request, fence.sha(self.hook), attempts=3)


class FenceTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'openssl unavailable')
    def test_real_crypto_validation_uses_private_copies_and_public_ca_hostname(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            ca = Path(tmp) / 'test-ca'
            ca.mkdir(mode=0o700)

            def openssl(*args):
                result = subprocess.run(['/usr/bin/openssl', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode:
                    raise ValueError('fixture_openssl_failed')
                return result.stdout.decode()

            openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca / 'ca.key'), '-out', str(ca / 'ca.crt'),
                    '-days', '3', '-subj', '/CN=Private Fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE')
            openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca / 'leaf.key'), '-out', str(ca / 'leaf.csr'),
                    '-subj', '/CN=tunnel.example.com', '-addext', 'subjectAltName=DNS:tunnel.example.com')
            openssl('x509', '-req', '-in', str(ca / 'leaf.csr'), '-CA', str(ca / 'ca.crt'), '-CAkey', str(ca / 'ca.key'),
                    '-CAcreateserial', '-out', str(ca / 'leaf.crt'), '-days', '2', '-copy_extensions', 'copy')
            openssl('rehash', str(ca))
            cert, key = (ca / 'leaf.crt').read_bytes() + (ca / 'ca.crt').read_bytes(), (ca / 'leaf.key').read_bytes()
            for name, data in (('/etc/ultra-relay/fullchain.pem', cert), ('/etc/ultra-relay/privkey.pem', key),
                               ('/etc/letsencrypt/archive/tunnel.example.com/fullchain1.pem', cert),
                               ('/etc/letsencrypt/archive/tunnel.example.com/privkey1.pem', key),
                               ('/etc/letsencrypt/archive/tunnel.example.com/cert1.pem', (ca / 'leaf.crt').read_bytes()),
                               ('/etc/letsencrypt/archive/tunnel.example.com/chain1.pem', (ca / 'ca.crt').read_bytes())):
                host.tool.path(name).write_bytes(data)
            host.execute('acquire')
            original_runner = host.tool.runner

            def real_runner(argv):
                if argv[0] != '/usr/bin/openssl':
                    return original_runner(argv)
                args = list(argv[1:])
                if '-CApath' in args:
                    args[args.index('-CApath') + 1] = str(ca)
                return openssl(*args)

            host.tool.runner = real_runner
            host.execute('capture')
            closure = host.tool.closure('tunnel.example.com')
            host.tool.validate_pair(closure, 'tunnel.example.com')
            with self.assertRaises(ValueError):
                host.tool.validate_pair(closure, 'other.example.com')
            # Trusting a supplied chain alone does not establish public CA
            # trust: the production CApath must reject this private fixture CA.
            host.tool.runner = lambda argv: openssl(*argv[1:]) if argv[0] == '/usr/bin/openssl' else original_runner(argv)
            with self.assertRaises(ValueError):
                host.tool.validate_pair(closure, 'tunnel.example.com')

    def test_private_checkpoint_capture_verify_and_no_secret_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            host.execute('acquire')
            captured = host.execute('capture')
            self.assertEqual(captured, host.execute('capture'))
            self.assertEqual(captured, host.execute('verify'))
            exported = json.dumps(captured)
            for secret in ('private-key-fixture', 'private-account-sentinel', 'private-tunnel-fixture', 'data'):
                self.assertNotIn(secret, exported)
            checkpoint = host.tool.path(fence.STATE + '/preservation-' + captured['binding'] + '.json')
            self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o600)
            self.assertIn(b'images', checkpoint.read_bytes())

    def test_readonly_inspection_and_exact_generation_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            shutil.rmtree(host.tool.path(fence.STATE))
            self.assertTrue(host.execute('inspect')['verified'])
            self.assertFalse(host.tool.path(fence.STATE).exists())
            self.assertEqual(host.timer, 'active')
            host.execute('acquire')
            host.execute('capture')
            changed = json.dumps({'transaction': 'tls-test-2', 'domain': 'tunnel.example.com'})
            for action in ('inspect', 'acquire', 'verify', 'restore', 'release'):
                with self.subTest(action=action), self.assertRaises(ValueError):
                    host.execute(action, changed)
            self.assertTrue(host.execute('inspect')['verified'])

    def test_missing_pair_restore_is_private_idempotent_and_crash_retryable(self):
        for crash in (False, True):
            with self.subTest(crash=crash), tempfile.TemporaryDirectory() as tmp:
                host = Host(Path(tmp))
                host.closure()
                host.execute('acquire')
                before = host.execute('capture')
                pair = [host.tool.path('/etc/ultra-relay/' + name) for name in ('fullchain.pem', 'privkey.pem')]
                original = [path.read_bytes() for path in pair]
                for path in pair:
                    path.unlink()
                self.assertTrue(host.execute('check-restore')['needs_restore'])
                if crash:
                    sync = host.tool.sync
                    def fail_after_first(path):
                        sync(path)
                        raise ValueError('synthetic_crash_after_first_pair_file')
                    host.tool.sync = fail_after_first
                    with self.assertRaises(ValueError):
                        host.execute('restore')
                    host.tool.sync = sync
                    self.assertEqual(sum(path.exists() for path in pair), 1)
                self.assertFalse(host.execute('restore')['needs_restore'])
                self.assertFalse(host.execute('check-restore')['needs_restore'])
                self.assertEqual(before, host.execute('verify'))
                for path, raw in zip(pair, original):
                    self.assertEqual(path.read_bytes(), raw)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_restore_rejects_foreign_pair_or_nonpair_before_any_write(self):
        for mutation in ('foreign', 'symlink', 'renewal', 'active'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                host = Host(Path(tmp))
                host.closure()
                host.execute('acquire')
                host.execute('capture')
                cert = host.tool.path('/etc/ultra-relay/fullchain.pem')
                cert.unlink()
                key = host.tool.path('/etc/ultra-relay/privkey.pem')
                if mutation == 'foreign':
                    key.write_bytes(b'foreign-key')
                elif mutation == 'symlink':
                    key.unlink()
                    key.symlink_to('/tmp/foreign-key')
                elif mutation == 'renewal':
                    host.tool.path('/etc/letsencrypt/renewal/tunnel.example.com.conf').write_bytes(b'foreign')
                else:
                    runner = host.tool.runner
                    def active_relay(argv):
                        result = runner(argv)
                        return result.replace('ActiveState=inactive', 'ActiveState=active') if argv[-1] == 'ultra-relay.service' else result
                    host.tool.runner = active_relay
                with self.assertRaises(Exception):
                    host.execute('restore')
                self.assertFalse(cert.exists())
                self.assertEqual(host.tool.journal()['state'], 'frozen')

    def test_compensation_inspection_missing_pair_retry_and_foreign_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            with self.assertRaises(ValueError):
                host.execute('inspect-compensation')
            host.execute('acquire')
            host.execute('capture')
            key = host.tool.path('/etc/ultra-relay/privkey.pem')
            old = key.read_bytes()
            key.unlink()
            # Simulate first rollback interrupted before restoring the pair.
            with self.assertRaises(FileNotFoundError):
                host.execute('inspect')
            result = host.execute('inspect-compensation')
            self.assertTrue(result['needs_restore'])
            self.assertFalse(key.exists())  # Inspection does not restore it.
            changed = json.dumps({'transaction': 'tls-test-2', 'domain': 'tunnel.example.com'})
            with self.assertRaises(ValueError):
                host.execute('inspect-compensation', changed)
            key.write_bytes(b'foreign')
            key.chmod(0o600)
            with self.assertRaises(ValueError):
                host.execute('inspect-compensation')
            self.assertEqual(key.read_bytes(), b'foreign')
            key.unlink()
            self.assertTrue(host.execute('inspect-compensation')['needs_restore'])
            host.execute('restore')
            self.assertEqual(key.read_bytes(), old)
            self.assertTrue(host.execute('inspect')['verified'])
            host.tool.execute('release', host.request, fence.sha(host.hook), require_checkpoint=True)
            self.assertTrue(host.execute('inspect-compensation')['verified'])
            key.unlink()
            with self.assertRaises(FileNotFoundError):
                host.execute('inspect-compensation')

    def test_corrupt_pair_metadata_cannot_restore_an_exposed_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            host.execute('acquire')
            result = host.execute('capture')
            path = host.tool.path(fence.STATE + '/preservation-' + result['binding'] + '.json')
            value = json.loads(path.read_bytes())
            value['closure']['images']['/etc/ultra-relay/privkey.pem']['mode'] = 0o644
            path.write_text(json.dumps(value))
            key = host.tool.path('/etc/ultra-relay/privkey.pem')
            key.unlink()
            with self.assertRaises(ValueError):
                host.execute('restore')
            self.assertFalse(key.exists())

    def test_required_checkpoint_release_retries_after_renewal_without_old_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            host.execute('acquire')
            with self.assertRaises(ValueError):
                host.tool.execute('release', host.request, fence.sha(host.hook), require_checkpoint=True)
            host.execute('capture')
            result = host.tool.execute('release', host.request, fence.sha(host.hook), require_checkpoint=True)
            self.assertEqual(result['state'], 'released')
            host.tool.path('/etc/ultra-relay/privkey.pem').write_bytes(b'next-renewed-key')
            self.assertEqual(result, host.tool.execute('release', host.request, fence.sha(host.hook), require_checkpoint=True))

    def test_checkpoint_requires_fence_and_rejects_renewal_drift(self):
        for mutation in ('pair', 'renewal', 'account', 'link', 'sni', 'webroot', 'nginx'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                host = Host(Path(tmp))
                host.closure()
                with self.assertRaises(ValueError):
                    host.execute('capture')
                host.execute('acquire')
                host.execute('capture')
                if mutation == 'pair':
                    host.tool.path('/etc/ultra-relay/privkey.pem').write_bytes(b'foreign-key')
                elif mutation == 'renewal':
                    path = host.tool.path('/etc/letsencrypt/renewal/tunnel.example.com.conf')
                    path.write_bytes(path.read_bytes() + b'\nforeign = changed\n')
                elif mutation == 'account':
                    host.tool.path('/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/abc123/private_key.json').write_bytes(b'foreign-account')
                elif mutation == 'link':
                    path = host.tool.path('/etc/letsencrypt/live/tunnel.example.com/fullchain.pem')
                    path.unlink()
                    path.symlink_to('/tmp/foreign')
                elif mutation == 'sni':
                    path = host.tool.path('/etc/ultra-relay/spec.json')
                    spec = json.loads(path.read_bytes())
                    spec['splithttp_tls']['sni_mode'] = 'omit'
                    path.write_text(json.dumps(spec))
                elif mutation == 'webroot':
                    host.tool.path('/var/www/ultra-tunnel-acme').chmod(0o700)
                else:
                    host.tool.path('/etc/nginx/conf.d/ultra-tunnel-acme.conf').write_bytes(b'foreign route')
                with self.assertRaises(ValueError):
                    host.execute('verify')

    def test_checkpoint_validates_pair_chain_name_and_expiry(self):
        for command in ('x509', 'pkey', 'verify'):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                host = Host(Path(tmp))
                host.closure()
                host.execute('acquire')
                host.fail = command
                with self.assertRaises(ValueError):
                    host.execute('capture')
                self.assertFalse(list(host.tool.path(fence.STATE).glob('preservation-*.json')))

    def test_unknown_global_renewal_behavior_is_not_attested(self):
        for mutation in ('global config', 'foreign hook', 'foreign lineage'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                host = Host(Path(tmp))
                host.closure()
                host.execute('acquire')
                if mutation == 'global config':
                    write(host.root, '/etc/letsencrypt/cli.ini', b'deploy-hook = /tmp/foreign\n')
                elif mutation == 'foreign hook':
                    write(host.root, '/etc/letsencrypt/renewal-hooks/deploy/foreign', b'#!/bin/sh\nexit 0\n', 0o700)
                else:
                    write(host.root, '/etc/letsencrypt/renewal/foreign.example.com.conf', b'foreign')
                with self.assertRaises(ValueError):
                    host.execute('capture')
                self.assertFalse(list(host.tool.path(fence.STATE).glob('preservation-*.json')))

    def test_acquire_retry_reboot_status_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            initial_hook = host.tool.read(fence.HOOK)
            first = host.execute('acquire')
            self.assertEqual(first['state'], 'frozen')
            self.assertEqual(host.timer, 'inactive')
            self.assertEqual(first, host.execute('acquire'))
            # A new process after reboot sees persistent masks and journal.
            host.tool = fence.Fence(Path(tmp), host.run, lambda _: None, host.processes)
            self.assertEqual(host.execute('status')['state'], 'frozen')
            self.assertEqual(host.execute('release')['state'], 'released')
            self.assertEqual(host.execute('release')['state'], 'released')
            self.assertEqual(host.timer, 'active')
            self.assertEqual(host.tool.read(fence.HOOK), initial_hook)
            self.assertFalse(os.path.lexists(host.tool.path(fence.STATE + '/blocked')))

    def test_drain_active_managed_renewal_without_killing(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.active = True
            self.assertEqual(host.execute('acquire')['state'], 'frozen')
            self.assertGreaterEqual(host.polls, 2)
            self.assertNotIn(['/usr/bin/systemctl', 'stop', 'certbot.service'], host.calls)

    def test_drain_timeout_retains_owned_masks_and_supports_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            with self.assertRaisesRegex(ValueError, 'not_drained'):
                host.tool.execute('acquire', host.request, fence.sha(host.hook), attempts=0)
            self.assertEqual(host.tool.journal()['state'], 'freezing')
            self.assertTrue(host.tool.path('/etc/systemd/system/certbot.service').is_symlink())
            self.assertFalse(os.path.lexists(host.tool.path(fence.STATE + '/blocked')))
            host.execute('release')
            self.assertEqual(host.timer, 'active')

    def test_released_fence_cannot_verify_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.closure()
            host.execute('acquire')
            host.execute('capture')
            host.execute('release')
            with self.assertRaisesRegex(ValueError, 'not_frozen'):
                host.execute('verify')

    def test_crash_after_mask_is_recoverable_and_keeps_timer_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.fail = 'daemon-reload'
            with self.assertRaisesRegex(ValueError, 'command_failed'):
                host.execute('acquire')
            self.assertEqual(host.tool.journal()['state'], 'freezing')
            self.assertTrue(host.tool.path('/etc/systemd/system/certbot.service').is_symlink())
            self.assertEqual(host.execute('acquire')['state'], 'frozen')

    def test_abort_partial_freeze_restores_original_timer(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.fail = 'daemon-reload'
            with self.assertRaises(ValueError):
                host.execute('acquire')
            self.assertEqual(host.execute('release')['state'], 'released')
            self.assertEqual(host.timer, 'active')

    def test_lost_release_reply_restores_timer_on_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.execute('acquire')
            host.fail = 'start'
            with self.assertRaises(ValueError):
                host.execute('release')
            self.assertEqual(host.tool.journal()['state'], 'releasing')
            self.assertFalse(os.path.lexists(host.tool.path(fence.STATE + '/blocked')))
            self.assertEqual(host.execute('release')['state'], 'released')
            self.assertEqual(host.timer, 'active')

    def test_foreign_request_drift_and_unmanaged_renewal_fail_closed(self):
        for mutation in ('request', 'hook', 'unit', 'mask', 'marker', 'unmanaged'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                host = Host(Path(tmp))
                host.execute('acquire')
                request = host.request
                if mutation == 'request':
                    request = request.replace('tls-test-1', 'tls-test-2')
                elif mutation == 'hook':
                    host.tool.path(fence.HOOK).write_bytes(b'foreign hook')
                elif mutation == 'unit':
                    host.tool.path('/usr/lib/systemd/system/certbot.service').write_bytes(b'foreign unit')
                elif mutation == 'mask':
                    path = host.tool.path('/etc/systemd/system/certbot.service')
                    path.unlink()
                    path.symlink_to('/tmp/foreign')
                elif mutation == 'marker':
                    host.tool.path(fence.STATE + '/blocked').write_bytes(b'foreign')
                else:
                    host.unmanaged = True
                with self.assertRaises(ValueError):
                    host.execute('status', request)
                self.assertTrue(os.path.lexists(host.tool.path(fence.STATE + '/blocked')))

    def test_unknown_hook_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.tool.path(fence.HOOK).write_bytes(host.hook + b'unknown edit\n')
            with self.assertRaisesRegex(ValueError, 'hook_unverified'):
                host.execute('acquire')
            self.assertIsNone(host.tool.journal())
            self.assertFalse(host.tool.path('/etc/systemd/system/certbot.service').exists())

    def test_template_and_known_legacy_hook_adoption_restore_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            self.assertEqual(host.hook, fence.hook_bytes('tunnel.example.com'))
            legacy = fence.hook_bytes('tunnel.example.com', legacy=True)
            host.tool.path(fence.HOOK).write_bytes(legacy)
            # Existing installations predate the fence state directory.
            host.tool.path(fence.STATE + '/pair.lock').unlink()
            host.tool.path(fence.STATE).rmdir()
            host.active = True
            self.assertEqual(host.execute('acquire')['state'], 'frozen')
            self.assertEqual(host.tool.read(fence.HOOK), host.hook)
            self.assertEqual(host.execute('status')['state'], 'frozen')
            self.assertEqual(host.execute('release')['state'], 'released')
            self.assertEqual(host.tool.read(fence.HOOK), legacy)
            self.assertEqual(host.execute('release')['state'], 'released')

    def test_legacy_adoption_crash_after_atomic_hook_replace_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            legacy = fence.hook_bytes('tunnel.example.com', legacy=True)
            host.tool.path(fence.HOOK).write_bytes(legacy)
            original = host.tool.atomic

            def lost_reply(name, raw, mode=0o600):
                original(name, raw, mode)
                if name == fence.HOOK:
                    raise ValueError('lost_reply')

            host.tool.atomic = lost_reply
            with self.assertRaisesRegex(ValueError, 'lost_reply'):
                host.execute('acquire')
            host.tool.atomic = original
            self.assertEqual(host.execute('acquire')['state'], 'frozen')
            host.execute('release')
            self.assertEqual(host.tool.read(fence.HOOK), legacy)

    def test_shared_pair_lock_rejects_overlapping_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            with host.tool.lock('pair.lock'):
                with self.assertRaisesRegex(ValueError, 'busy'):
                    host.execute('acquire')
            self.assertEqual(host.execute('acquire')['state'], 'frozen')

    def test_real_shell_hook_refuses_fence_before_reading_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(Path(tmp))
            host.execute('acquire')
            script = host.hook.replace(b'/var/lib/ultra-tunnel-tls', str(host.tool.path(fence.STATE)).encode())
            # No certificate exists. Failure must come from the fence test,
            # before even invoking openssl or reading the private pair.
            path = Path(tmp) / 'hook.sh'
            path.write_bytes(script)
            result = subprocess.run(['/bin/sh', '-x', str(path)], env={'PATH': '/usr/bin:/bin', 'RENEWED_LINEAGE': '/etc/letsencrypt/live/tunnel.example.com'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'openssl', result.stderr)
            unrelated = subprocess.run(['/bin/sh', str(path)], env={'PATH': '/usr/bin:/bin', 'RENEWED_LINEAGE': '/etc/letsencrypt/live/other.example.com'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(unrelated.returncode, 0)


if __name__ == '__main__':
    unittest.main()
