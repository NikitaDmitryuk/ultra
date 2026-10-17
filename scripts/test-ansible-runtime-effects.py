#!/usr/bin/env python3
"""Runtime dependency transactions execute only against private synthetic hosts."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('effects', ROOT / 'deploy/ansible/library/ultra_runtime_effects.py')
effects = importlib.util.module_from_spec(spec)
spec.loader.exec_module(effects)


def write(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(raw)
    path.chmod(mode)


def assets():
    return {effects.WATCHDOG[0]: (ROOT / 'deploy/ansible/roles/warp/files/ultra-warp-watchdog').read_text(),
            effects.WATCHDOG[1]: (ROOT / 'deploy/ansible/roles/warp/templates/ultra-warp-watchdog.service.j2').read_text(),
            effects.WATCHDOG[2]: (ROOT / 'deploy/ansible/roles/warp/templates/ultra-warp-watchdog.timer.j2').read_text()}


class Host:
    def __init__(self, root):
        self.root = root
        self.port, self.connected, self.registration = 40000, True, b'private-registration-fixture'
        self.timer = {'active': 'active', 'enabled': 'enabled'}
        self.service = {'active': 'inactive', 'enabled': 'static'}
        self.bot = {'active': 'active', 'enabled': 'enabled'}
        self.calls, self.fail, self.trusted_cert = [], None, True
        self.daemon_active = True
        write(root / 'usr/sbin/ufw', b'fixture-executable', 0o755)
        write(root / 'etc/systemd/system/ultra-bot.service', b'[Service]\nExecStart=/usr/local/bin/ultra-bot\n', 0o644)
        before = b'*filter\n:ufw-user-input - [0:0]\n\n### RULES ###\n\n### END RULES ###\n\nCOMMIT\n'
        for name in effects.FIREWALL:
            write(root / name.lstrip('/'), before, 0o640)
        for name, source in assets().items():
            write(root / name.lstrip('/'), source.replace('{{ ultra_warp_port }}', str(self.port)).encode(), 0o755 if name == effects.WATCHDOG[0] else 0o644)
        for name in effects.CERTIFICATE:
            write(root / name.lstrip('/'), b'private-certificate-key-fixture')

    def runner(self, argv, allowed=(0,)):
        self.calls.append(argv)
        if argv[0].endswith('systemctl'):
            name = argv[-1]
            unit = self.bot if name == 'ultra-bot.service' else self.timer if name.endswith('.timer') else self.service
            if name == 'warp-svc.service':
                unit = {'active': 'active' if self.daemon_active else 'inactive', 'enabled': 'enabled'}
            verb = argv[1]
            if verb == 'is-active':
                return (unit['active'] + '\n').encode()
            if verb == 'is-enabled':
                return (unit['enabled'] + '\n').encode()
            if verb in ('start', 'stop'):
                unit['active'] = 'active' if verb == 'start' else 'inactive'
            if verb in ('enable', 'disable'):
                unit['enabled'] = 'enabled' if verb == 'enable' else 'disabled'
            return b''
        if argv[0].endswith('warp-cli'):
            verb = argv[2]
            if verb == 'registration':
                return self.registration
            if verb == 'settings':
                return ('Mode: WarpProxy\nProxy Port: ' + str(self.port) + '\nUnrelated: stable\n').encode()
            if verb == 'status':
                return ('Status: ' + ('Connected' if self.connected else 'Disconnected') + '\n').encode()
            if verb == 'proxy':
                self.port = int(argv[-1])
            if verb in ('connect', 'disconnect'):
                self.connected = verb == 'connect'
            if self.fail == verb:
                self.fail = None
                raise ValueError('effect_command_failed')
            return b''
        if argv[0].endswith('ufw'):
            if argv[1] == 'status':
                return b'Status: active\n'
            if argv[1] == 'allow':
                source = argv[3] if 'from' in argv else ''
                port = argv[argv.index('port') + 1] if source else argv[2].split('/')[0]
                marker = argv[argv.index('comment') + 1]
                names = effects.FIREWALL[:1] if source else effects.FIREWALL
                for name in names:
                    target = self.root / name.lstrip('/')
                    network = source or ('::/0' if 'user6' in name else '0.0.0.0/0')
                    destination = '::/0' if 'user6' in name else '0.0.0.0/0'
                    added = ('### tuple ### allow tcp ' + port + ' ' + destination + ' any ' + network + ' in comment=' + marker.encode().hex() + '\n-A ufw-user-input -p tcp --dport ' + port + (' -s ' + source if source else '') + ' -j ACCEPT\n\n').encode()
                    target.write_bytes(target.read_bytes().replace(b'### END RULES ###', added + b'### END RULES ###'))
                if self.fail == 'allow':
                    self.fail = None
                    raise ValueError('effect_command_failed')
            return b''
        if argv[0].endswith('openssl'):
            if argv[1] == 'verify' and not self.trusted_cert:
                raise ValueError('effect_command_failed')
            if '-pubkey' in argv or '-pubout' in argv:
                return b'public-key-fixture'
            if '-outform' in argv:
                return b'certificate-der-fixture'
            return b''
        raise AssertionError('unexpected fixed command')


class RuntimeEffectsTests(unittest.TestCase):
    def fixture(self, tmp):
        root = Path(tmp)
        host = Host(root)
        operation = effects.Effects(root, host.runner)
        operation.wait_proxy = lambda port: None
        request = json.dumps({'request': {'transaction': 'test-runtime-1'}})
        return root, host, operation, request

    def test_listener_grant_exact_rollback_and_lost_command_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, host, operation, request = self.fixture(tmp)
            plan = {'role': 'exit', 'classes': ['listener', 'coordinated_tunnel'], 'ports': [9444], 'source': '192.0.2.1', 'tls': False}
            before = {name: effects.image(root / name.lstrip('/')) for name in effects.FIREWALL}
            operation.prepare(request, plan, {})
            host.fail = 'allow'
            with self.assertRaisesRegex(ValueError, 'command_failed'):
                operation.transition(request, plan, {}, 'apply')
            operation.transition(request, plan, {}, 'apply')
            operation.transition(request, plan, {}, 'verify')
            state = operation.transition(request, plan, {}, 'commit')
            self.assertTrue(state['grants'])
            operation.transition(request, plan, {}, 'commit')
            operation.transition(request, plan, {}, 'rollback')
            self.assertEqual(before, {name: effects.image(root / name.lstrip('/')) for name in effects.FIREWALL})
            self.assertTrue(any(call[1:] == ['reload'] for call in host.calls))

    def test_firewall_drift_and_foreign_rule_never_clobbered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, host, operation, request = self.fixture(tmp)
            plan = {'role': 'bridge', 'classes': ['listener'], 'ports': [7444], 'tls': False}
            target = root / effects.FIREWALL[0].lstrip('/')
            foreign = b'-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n'
            target.write_bytes(target.read_bytes().replace(b'### END RULES ###', foreign + b'### END RULES ###'))
            operation.prepare(request, plan, {})
            operation.transition(request, plan, {}, 'apply')
            self.assertIn(foreign, target.read_bytes())
            changed = target.read_bytes().replace(b'--dport 22', b'--dport 23')
            target.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, 'third_state'):
                operation.transition(request, plan, {}, 'rollback')
            self.assertEqual(target.read_bytes(), changed)

    def test_interrupted_attempt_cannot_claim_matching_foreign_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, host, operation, request = self.fixture(tmp)
            plan = {'role': 'exit', 'classes': ['listener'], 'ports': [9444], 'source': '192.0.2.1', 'tls': False}
            state = operation.prepare(request, plan, {})
            state['state'] = 'applying'
            operation.save(operation.journal(json.loads(request)), state)
            target = root / effects.FIREWALL[0].lstrip('/')
            foreign = b'### tuple ### allow tcp 9444 0.0.0.0/0 any 192.0.2.1 in\n-A ufw-user-input -p tcp --dport 9444 -s 192.0.2.1 -j ACCEPT\n'
            content = target.read_bytes().replace(b'### END RULES ###', foreign + b'### END RULES ###')
            target.write_bytes(content)
            with self.assertRaisesRegex(ValueError, 'marker_missing'):
                operation.transition(request, plan, {}, 'rollback')
            self.assertEqual(target.read_bytes(), content)

    def test_warp_enable_disable_port_failure_restore_registration_and_files(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as tmp:
                root, host, operation, request = self.fixture(tmp)
                plan = {'role': 'exit', 'classes': ['warp_service'], 'ports': [], 'warp': enabled, 'warp_port': 40001 if enabled else 0, 'tls': False}
                before = {name: effects.image(root / name.lstrip('/')) for name in effects.WATCHDOG}
                registration = host.registration
                operation.prepare(request, plan, assets())
                host.fail = 'connect' if enabled else 'disconnect'
                with self.assertRaisesRegex(ValueError, 'command_failed'):
                    operation.transition(request, plan, assets(), 'apply')
                operation.transition(request, plan, assets(), 'apply')
                operation.transition(request, plan, assets(), 'verify')
                self.assertEqual(host.connected, enabled)
                self.assertEqual(host.timer['enabled'], 'enabled' if enabled else 'disabled')
                operation.transition(request, plan, assets(), 'rollback')
                self.assertEqual(host.registration, registration)
                self.assertEqual((host.port, host.connected), (40000, True))
                self.assertEqual(host.timer, {'enabled': 'enabled', 'active': 'active'})
                self.assertEqual(before, {name: effects.image(root / name.lstrip('/')) for name in effects.WATCHDOG})

    def test_bot_enable_disable_then_later_failure_restores_exact_active_enabled(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as tmp:
                root, host, operation, request = self.fixture(tmp)
                host.bot = {'enabled': 'disabled' if enabled else 'enabled', 'active': 'inactive' if enabled else 'active'}
                original = dict(host.bot)
                plan = {'role': 'bridge', 'classes': ['listener'], 'ports': [], 'tls': False, 'bot_service': True, 'bot_enabled': enabled}
                operation.prepare(request, plan, {})
                host.bot['active'] = 'inactive'  # Native bridge quiescence precedes image activation.
                try:
                    operation.transition(request, plan, {}, 'apply')
                    operation.transition(request, plan, {}, 'verify')
                    operation.transition(request, plan, {}, 'accept')  # Called after fresh fleet payload.
                    self.assertEqual(host.bot, {'enabled': 'enabled' if enabled else 'disabled', 'active': 'active' if enabled else 'inactive'})
                    raise RuntimeError('induced_later_publish_failure')
                except RuntimeError:
                    operation.transition(request, plan, {}, 'rollback')
                    operation.transition(request, plan, {}, 'accept-rollback')
                self.assertEqual(host.bot, original)

    def test_warp_bootstrap_and_registration_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, host, operation, request = self.fixture(tmp)
            plan = {'role': 'exit', 'classes': ['warp_service'], 'ports': [], 'warp': True, 'warp_port': 40001, 'tls': False}
            host.daemon_active = False
            with self.assertRaisesRegex(ValueError, 'active_daemon_required'):
                operation.prepare(request, plan, assets())
            host.daemon_active = True
            operation.prepare(request, plan, assets())
            host.registration = b'foreign-registration'
            with self.assertRaisesRegex(ValueError, 'third_state'):
                operation.transition(request, plan, assets(), 'apply')
            self.assertFalse(any('new' in call for call in host.calls))

    def test_tls_policy_reuses_exact_pair_and_requires_trust_or_frozen_pin(self):
        for provision in ('self_signed', 'user_provided'):
            with self.subTest(provision=provision), tempfile.TemporaryDirectory() as tmp:
                root, host, operation, request = self.fixture(tmp)
                plan = {'role': 'exit', 'classes': ['tunnel_tls_provision'], 'ports': [], 'tls': True, 'tls_name': 'tunnel.example.com', 'tls_provision': provision, 'certificate_pin': hashlib.sha256(b'certificate-der-fixture').hexdigest()}
                before = {name: effects.image(root / name.lstrip('/')) for name in effects.CERTIFICATE}
                operation.prepare(request, plan, {})
                operation.transition(request, plan, {}, 'apply')
                operation.transition(request, plan, {}, 'verify')
                operation.transition(request, plan, {}, 'rollback')
                self.assertEqual(before, {name: effects.image(root / name.lstrip('/')) for name in effects.CERTIFICATE})
                changed = dict(plan, certificate_pin='f' * 64)
                if provision == 'self_signed':
                    with self.assertRaisesRegex(ValueError, 'frozen_db_pin_required'):
                        operation.inspect(changed, {})
                else:
                    host.trusted_cert = False
                    with self.assertRaisesRegex(ValueError, 'command_failed'):
                        operation.inspect(changed, {})
                write(root / effects.CERTIFICATE[1].lstrip('/'), b'foreign-key')
                with self.assertRaisesRegex(ValueError, 'third_state'):
                    operation.transition(request, plan, {}, 'rollback')

    def test_request_drift_and_missing_tls_pair_fail_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, host, operation, request = self.fixture(tmp)
            plan = {'role': 'exit', 'classes': ['listener'], 'ports': [9444], 'tls': False}
            operation.prepare(request, plan, {})
            with self.assertRaisesRegex(ValueError, 'request_changed'):
                operation.transition(request.replace('test-runtime-1', 'test-runtime-1'), {**plan, 'ports': [9445]}, {}, 'apply')
            (root / effects.CERTIFICATE[0].lstrip('/')).unlink()
            with self.assertRaisesRegex(ValueError, 'existing_private_pair_required'):
                operation.inspect({**plan, 'tls': True, 'tls_provision': 'self_signed'}, {})

    def test_foreign_systemd_enable_alias_is_not_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, host, operation, request = self.fixture(tmp)
            parent = root / 'etc/systemd/system/custom.target.wants'
            parent.mkdir(parents=True)
            alias = parent / 'ultra-bot.service'
            alias.symlink_to('/etc/systemd/system/ultra-bot.service')
            plan = {'role': 'bridge', 'classes': ['listener'], 'ports': [], 'tls': False, 'bot_service': True, 'bot_enabled': False}
            with self.assertRaisesRegex(ValueError, 'nonstandard_unit_link'):
                operation.prepare(request, plan, {})
            self.assertTrue(alias.is_symlink())
            self.assertFalse(any(call[1] in ('enable', 'disable') for call in host.calls if call[0].endswith('systemctl')))

    def test_coordinated_playbook_quiesces_before_exits_and_commit_never_restarts(self):
        play = (ROOT / 'deploy/ansible/playbooks/upgrade-runtime.yml').read_text()
        self.assertLess(play.index('Validate complete fleet bindings'), play.index('Quiesce bridge traffic'))
        self.assertLess(play.index('Quiesce bridge traffic'), play.index('Transition exits serially'))
        self.assertLess(play.index('Transition exits serially'), play.index('Transition bridge and verify'))
        commit = play.split('- name: Commit only', 1)[1].split('- name: Return only exact fleet', 1)[0]
        self.assertNotIn('systemd_service', commit)
        self.assertIn('action: commit', commit)


if __name__ == '__main__':
    unittest.main()
