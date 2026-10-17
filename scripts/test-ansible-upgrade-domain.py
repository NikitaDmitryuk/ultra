#!/usr/bin/env python3
"""Offline domain transaction and backend/ingress receipt composition checks."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    source = ROOT / 'deploy/ansible/library' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, source)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


backend = load('ultra_backend_domain')
domain = load('ultra_upgrade_domain')
probe = load('ultra_cutover_probe')


def write(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value)
    path.chmod(mode)


def encoded(value):
    return base64.b64encode(value).decode() if value is not None else None


class UpgradeDomainTests(unittest.TestCase):
    def make_inspection_root(self, root, ingress):
        spec = {'role': 'bridge', 'primary_xhttp': {'published': True, 'port': 443,
                'server_name': 'edge.example.com', 'host': 'public.example.com',
                'path': '/old', 'backend_port': 18443, 'fingerprint': 'firefox'},
                'experimental_profile_file': '/etc/ultra-relay/experimental-profile.json'}
        write(root / 'etc/ultra-relay/spec.json', json.dumps(spec).encode())
        write(root / 'etc/ultra-relay/environment', b'ULTRA_BOT_PORT=8444\n')
        files = {
            '/etc/nginx/conf.d/ultra-subscription.conf': b'server_name sync.example.com;\nproxy_ssl_name bot.example.com;\n',
            '/etc/nginx/conf.d/ultra-vpn.conf': b'server_name edge.example.com;\n',
        }
        hashes = {}
        for name, data in files.items():
            write(root / name.lstrip('/'), data, 0o644)
            hashes[name] = hashlib.sha256(data).hexdigest()
        status_port = 18082
        experimental_port = 18444
        profile = {'host': 'public.example.com', 'endpoint': {'port': experimental_port,
                   'server_name': 'edge.example.com', 'path': '/connect', 'mode': 'stream-up',
                   'fingerprint': 'firefox'}, 'status_port': status_port}
        profile_raw = json.dumps(profile).encode()
        write(root / 'etc/ultra-relay/experimental-profile.json', profile_raw, 0o644)
        hashes['/etc/ultra-relay/experimental-profile.json'] = hashlib.sha256(profile_raw).hexdigest()
        write(root / 'var/lib/ultra-ingress/managed.json', json.dumps(hashes).encode())
        write(root / 'etc/ultra-recovery/dns.json', json.dumps({'config': {'zone': 'example.com'}}).encode())
        nodes = [{'name': 'NL', 'address': '192.0.2.2', 'provider': 'fixture',
                  'budget': {'monthly_bytes': 1024, 'is_fallback': False}}]
        write(root / 'etc/ultra-recovery/deployment.json', json.dumps({
            'bridge_url': 'https://sync.example.com/healthz', 'bridge_ipv4': '192.0.2.1',
            'bridge_provider': 'fixture', 'static_nodes': nodes,
            'ingress_mode': 'direct', 'ingress': ingress,
        }).encode())
        write(root / 'etc/ultra-recovery/backup.json', json.dumps({'recipient': 'age1fixture', 'state_paths': [], 'artifact_paths': []}).encode(), 0o600)
        write(root / 'etc/ultra-recovery/reconcile.json', json.dumps({'bridge_provider': 'fixture', 'static_nodes': nodes}).encode(), 0o600)
        write(root / 'etc/ultra-recovery/admin-chat-id', b'123\n', 0o600)
        return nodes

    def test_private_probe_file_binds_exact_bytes_and_observed_hostname(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'subscription-probe-url'
            raw = b'https://old.example.com/sub/fixture-token\n'
            write(path, raw)
            parameters = {'subscription_url_file': str(path),
                          'subscription_url_sha256': hashlib.sha256(raw).hexdigest(),
                          'subscription_source_domain': 'old.example.com',
                          'subscription_domain': 'new.example.com'}
            self.assertEqual(probe.private_subscription_url(parameters), raw.decode().rstrip('\n'))
            # The source hostname is verified independently of the target used
            # by acceptance; only the token path is reused for the target call.
            with self.assertRaises(ValueError):
                probe.private_subscription_url(dict(parameters, subscription_source_domain='new.example.com'))
            write(path, raw.rstrip(b'\n'))
            with self.assertRaises(ValueError):
                probe.private_subscription_url(parameters)
            write(path, raw, 0o644)
            with self.assertRaises(ValueError):
                probe.private_subscription_url(parameters)
            path.chmod(0o600)
            link = Path(tmp) / 'linked-probe'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                probe.private_subscription_url(dict(parameters, subscription_url_file=str(link)))
            alias = Path(tmp) / 'linked-directory'
            alias.symlink_to(Path(tmp), target_is_directory=True)
            with self.assertRaises(ValueError):
                probe.private_subscription_url(dict(parameters, subscription_url_file=str(alias / path.name)))
            hardlink = Path(tmp) / 'hardlink'
            hardlink.hardlink_to(path)
            with self.assertRaises(ValueError):
                probe.private_subscription_url(parameters)

    def test_inspection_binds_public_path_and_bot_port_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nodes = [{'name': 'NL', 'address': '192.0.2.2', 'provider': 'fixture',
                      'budget': {'monthly_bytes': 1024, 'is_fallback': False}}]
            ingress = {'email': 'ops@example.com', 'forward_host': '',
                       'staging_port': 18443, 'status_port': 18082,
                       'experimental_port': 18444}
            nodes = self.make_inspection_root(root, ingress)
            desired = {'email': 'ops@example.com', 'forward_host': '', 'ingress_mode': 'direct',
                       'staging_port': 18443, 'status_port': 18082, 'experimental_port': 18444,
                       'age_recipient': 'age1fixture', 'bridge_provider': 'fixture', 'static_nodes': nodes,
                       'admin_telegram_id': 123, 'bridge_ipv4': '192.0.2.1',
                       'state_paths': [], 'artifact_paths': []}
            environment = root / 'etc/ultra-relay/environment'
            actual_stat = Path.stat
            relay_uid = 12345

            def service_stat(path, *args, **kwargs):
                result = actual_stat(path, *args, **kwargs)
                if path == environment:
                    values = list(result)
                    values[4] = relay_uid
                    return os.stat_result(values)
                return result

            with patch.object(Path, 'stat', service_stat), \
                    patch.object(domain.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=relay_uid)):
                evidence = domain.inspect(root, desired)
            self.assertEqual(evidence['path'], '/old')
            self.assertEqual(evidence['bot_port'], 8444)
            self.assertEqual(evidence['dns_ttl'], 300)
            for key in ('acme_email_matches', 'forward_host_matches', 'ingress_mode_matches',
                        'staging_port_matches', 'status_port_matches', 'experimental_port_matches'):
                self.assertTrue(evidence[key], key)
            for key in ('age_recipient_matches', 'bridge_provider_matches', 'static_nodes_match', 'admin_id_matches'):
                self.assertTrue(evidence[key], key)
            self.assertEqual(evidence['bridge_url'], 'https://sync.example.com/healthz')
            self.assertEqual(evidence['bridge_ipv4'], '192.0.2.1')
            self.assertTrue(evidence['state_paths_match'])
            self.assertTrue(evidence['artifact_paths_match'])

    def test_legacy_missing_runtime_ports_are_reconstructed_only_from_managed_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingress = {'email': 'ops@example.com', 'forward_host': ''}
            self.make_inspection_root(root, ingress)
            desired = {'email': 'ops@example.com', 'forward_host': '', 'ingress_mode': 'direct',
                       'staging_port': 18443, 'status_port': 18082, 'experimental_port': 18444,
                       'age_recipient': 'age1fixture', 'bridge_provider': 'fixture',
                       'static_nodes': [{'name': 'NL', 'address': '192.0.2.2', 'provider': 'fixture',
                           'budget': {'monthly_bytes': 1024, 'is_fallback': False}}],
                       'admin_telegram_id': 123, 'bridge_ipv4': '192.0.2.1',
                       'state_paths': [], 'artifact_paths': []}
            evidence = domain.inspect(root, desired)
            self.assertTrue(evidence['status_port_matches'])
            self.assertTrue(evidence['experimental_port_matches'])
            self.assertFalse(evidence['staging_port_matches'])
            self.assertTrue(evidence['staging_port_unrecorded'])

    def test_legacy_runtime_port_reconstruction_rejects_unmanaged_or_conflicting_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingress = {'email': 'ops@example.com', 'forward_host': '', 'status_port': 18083}
            self.make_inspection_root(root, ingress)
            deployment = root / 'etc/ultra-recovery/deployment.json'
            with self.assertRaisesRegex(ValueError, 'domain_experiment_profile_conflict'):
                domain.inspect(root, {})
            receipt_path = root / 'var/lib/ultra-ingress/managed.json'
            receipt = json.loads(receipt_path.read_text())
            receipt['/etc/ultra-relay/experimental-profile.json'] = '0' * 64
            write(receipt_path, json.dumps(receipt).encode())
            data = json.loads(deployment.read_text())
            data['ingress'].pop('status_port')
            write(deployment, json.dumps(data).encode())
            with self.assertRaisesRegex(ValueError, 'domain_experiment_profile_unmanaged'):
                domain.inspect(root, {})

    def test_inspection_fails_closed_when_policy_evidence_is_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = {'role': 'bridge', 'primary_xhttp': {'published': True, 'port': 443,
                    'server_name': 'edge.example.com', 'host': 'public.example.com',
                    'path': '/old', 'backend_port': 18443, 'fingerprint': 'firefox'}}
            write(root / 'etc/ultra-relay/spec.json', json.dumps(spec).encode())
            write(root / 'etc/ultra-relay/environment', b'ULTRA_BOT_PORT=8444\n')
            files = {
                '/etc/nginx/conf.d/ultra-subscription.conf': b'server_name sync.example.com;\nproxy_ssl_name bot.example.com;\n',
                '/etc/nginx/conf.d/ultra-vpn.conf': b'server_name edge.example.com;\n',
            }
            hashes = {}
            for name, data in files.items():
                write(root / name.lstrip('/'), data, 0o644)
                hashes[name] = hashlib.sha256(data).hexdigest()
            write(root / 'var/lib/ultra-ingress/managed.json', json.dumps(hashes).encode())
            write(root / 'etc/ultra-recovery/dns.json', json.dumps({'config': {'zone': 'example.com'}}).encode())
            write(root / 'etc/ultra-recovery/deployment.json', json.dumps({
                'ingress_mode': 'direct', 'ingress': {'email': 'ops@example.com', 'forward_host': '',
                    'staging_port': '18443', 'status_port': 18082, 'experimental_port': 18444},
            }).encode())
            with self.assertRaisesRegex(ValueError, 'domain_policy_uncertain'):
                domain.inspect(root, {})

    def test_bot_port_only_is_journalled_applied_and_compensated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / 'etc/ultra-relay/environment'
            manifest = root / 'var/lib/ultra-ingress/managed.json'
            write(environment, b'ULTRA_BOT_DOMAIN=bot.example.com\nULTRA_BOT_PORT=8444\n', 0o600)
            before_proxy = b'proxy_pass https://127.0.0.1:8444;\nproxy_ssl_name bot.example.com;\n'
            write(root / 'etc/nginx/conf.d/ultra-subscription.conf', before_proxy, 0o644)
            write(manifest, json.dumps({'/etc/nginx/conf.d/ultra-subscription.conf': backend.digest(before_proxy)}).encode())
            directory = root / 'transaction'
            state = backend.prepare(directory, 'bot.example.com', 'bot.example.com', 'sync.example.com', root,
                                    preserve_recovery=True, old_port=8444, new_port=9444)
            image = next(item for item in state['files'] if item['path'] == str(environment))
            self.assertIn(b'ULTRA_BOT_PORT=8444', base64.b64decode(image['before']))
            self.assertIn(b'ULTRA_BOT_PORT=9444', base64.b64decode(image['after']))
            self.assertEqual(state['policy']['old_port'], 8444)
            self.assertEqual(state['policy']['new_port'], 9444)
            self.assertEqual(state['phase'], 'prepared')

    def test_bot_port_only_updates_owned_proxy_pass_in_before_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / 'etc/ultra-relay/environment'
            proxy = root / 'etc/nginx/conf.d/ultra-subscription.conf'
            manifest = root / 'var/lib/ultra-ingress/managed.json'
            write(environment, b'ULTRA_BOT_DOMAIN=bot.example.com\nULTRA_BOT_PORT=8444\n', 0o600)
            before_proxy = b'proxy_pass https://127.0.0.1:8444;\nproxy_ssl_name bot.example.com;\n'
            write(proxy, before_proxy, 0o644)
            write(manifest, json.dumps({'/etc/nginx/conf.d/ultra-subscription.conf': backend.digest(before_proxy)}).encode())
            state = backend.prepare(root / 'transaction', 'bot.example.com', 'bot.example.com', 'sync.example.com', root,
                                    preserve_recovery=True, old_port=8444, new_port=9444)
            image = next(item for item in state['files'] if item['path'] == str(proxy))
            self.assertEqual(base64.b64decode(image['before']), before_proxy)
            self.assertIn(b'proxy_pass https://127.0.0.1:9444;', base64.b64decode(image['after']))
            self.assertEqual(state['policy']['old_port'], 8444)
            self.assertEqual(state['policy']['new_port'], 9444)

    def test_backend_receipt_composes_with_retained_ingress_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proxy, alias, receipt = root / 'proxy.conf', root / 'alias.conf', root / 'var/lib/ultra-ingress/managed.json'
            before, after, unrelated = b'proxy old', b'proxy new', b'retained ingress'
            write(proxy, after, 0o644)
            write(alias, unrelated, 0o644)
            old = {str(proxy): backend.digest(before)}
            candidate = {str(proxy): backend.digest(after)}
            current = {**candidate, str(alias): backend.digest(unrelated)}
            item = {'path': str(receipt), 'before': encoded(json.dumps(old).encode()), 'after': encoded(json.dumps(candidate).encode()), 'mode': 0o600}
            merged = json.loads(backend.receipt_transition(item, json.dumps(current).encode(), 'rollback'))
            self.assertEqual(merged, {**old, str(alias): backend.digest(unrelated)})
            # Interrupted backend writes may leave the old receipt and new file.
            self.assertEqual(json.loads(backend.receipt_transition(item, json.dumps(old).encode(), 'activate')), candidate)
            write(alias, b'foreign changed file', 0o644)
            with self.assertRaisesRegex(ValueError, 'owned_file_drift'):
                backend.receipt_transition(item, json.dumps(current).encode(), 'rollback')
            write(alias, unrelated, 0o644)
            changed = {**current, str(proxy): 'f' * 64}
            with self.assertRaisesRegex(ValueError, 'receipt_drift'):
                backend.receipt_transition(item, json.dumps(changed).encode(), 'rollback')

    def test_fixed_relay_owner_is_accepted_preserved_and_journalled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / 'etc/ultra-relay/environment'
            specification = root / 'etc/ultra-relay/spec.json'
            proxy = root / 'etc/nginx/conf.d/ultra-subscription.conf'
            receipt = root / 'var/lib/ultra-ingress/managed.json'
            write(environment, b'ULTRA_BOT_DOMAIN=old.example.com\n')
            write(specification, b'{"role":"bridge"}')
            write(proxy, b'proxy_ssl_name old.example.com;\n', 0o644)
            write(receipt, json.dumps({'/etc/nginx/conf.d/ultra-subscription.conf': backend.digest(proxy.read_bytes())}).encode())
            actual_stat = Path.stat
            service_uid, service_gid = 12345, 12346

            def service_stat(path, *args, **kwargs):
                result = actual_stat(path, *args, **kwargs)
                if path in (environment, specification):
                    values = list(result)
                    values[4], values[5] = service_uid, service_gid
                    return os.stat_result(values)
                return result

            with patch.object(Path, 'stat', service_stat), patch.object(backend.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=service_uid)), patch.object(backend.os, 'fchown') as chown:
                self.assertEqual(backend.read(environment), environment.read_bytes())
                self.assertEqual(domain.trusted(specification, allow_relay_owner=True), specification.read_bytes())
                self.assertEqual(domain.trusted(environment, True, allow_relay_owner=True), environment.read_bytes())
                with self.assertRaisesRegex(ValueError, 'untrusted_file'):
                    domain.trusted(specification)
                with self.assertRaisesRegex(ValueError, 'untrusted_file'):
                    domain.trusted(environment, True)
                state = backend.prepare(root / 'transaction', 'old.example.com', 'bot.example.com', 'sync.example.com', root, preserve_recovery=True)
                image = next(item for item in state['files'] if item['path'] == str(environment))
                self.assertEqual((image['uid'], image['gid'], image['mode']), (service_uid, service_gid, 0o600))
                backend.atomic(environment, b'changed', 0o600)
                self.assertEqual(chown.call_args.args[1:], (service_uid, service_gid))
                with patch.object(backend.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=service_uid + 1)):
                    with self.assertRaisesRegex(ValueError, 'untrusted_file'):
                        backend.read(environment)

    def test_exact_ingress_checkpoint_detects_owned_drift_and_partial_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            operation = '/var/lib/ultra-ingress/ansible-' + 'a' * 64
            directory = root / operation.lstrip('/')
            live = '/etc/nginx/conf.d/ultra-vpn.conf'
            manifest = root / 'var/lib/ultra-ingress/managed.json'
            before, after = b'old listener', b'new listener'
            write(root / live.lstrip('/'), before, 0o644)
            write(manifest, json.dumps({live: backend.digest(before)}).encode())
            domain.checkpoint(operation, 'baseline', root)
            write(directory / 'owned-before.json', json.dumps({'images': [{'path': live, 'present': True, 'content': encoded(before)}]}).encode())
            write(root / live.lstrip('/'), after, 0o644)
            write(manifest, json.dumps({live: backend.digest(after)}).encode())
            domain.checkpoint(operation, 'seal', root)
            domain.checkpoint(operation, 'validate', root)
            write(root / live.lstrip('/'), b'foreign', 0o644)
            write(manifest, json.dumps({live: backend.digest(b'foreign')}).encode())
            with self.assertRaisesRegex(ValueError, 'checkpoint_file_drift'):
                domain.checkpoint(operation, 'validate', root)
            write(root / live.lstrip('/'), before, 0o644)
            write(manifest, json.dumps({live: backend.digest(before)}).encode())
            domain.checkpoint(operation, 'validate', root)
            with self.assertRaisesRegex(ValueError, 'checkpoint_changed'):
                domain.checkpoint(operation, 'seal', root)

    def test_upgrade_hooks_keep_old_endpoints_until_acceptance_and_commit(self):
        source = (ROOT / 'cmd/ultra-install/ansible_upgrade.go').read_text()
        start = source.index('domainGeneration = generation')
        flow = re.sub(r'\s+', ' ', source[start:])
        stages = ['"prepare", generation)', '"prepare", generation, retryFailed)', '"upgrade", inventory', '"apply", generation)', '"publish-release"', '"verify-release"', '"accept", generation)', '"commit-release"', '[]string{"promote", "retire", "retire-dns", "finalize"}']
        positions = [flow.index(stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        compensation = flow.split('if domainErr := domainTransaction.phase(cleanup', 1)[1]
        self.assertLess(compensation.index('"rollback", generation)'), compensation.index('"rollback-dns", generation)'))
        self.assertLess(compensation.index('"rollback-dns", generation)'), compensation.index('runUpgradeRuntimePhase'))
        self.assertIn('upgrade_domain_post_commit_retirement_incomplete', source)
        self.assertIn('"finalize", generation', source)
        self.assertIn('upgrade_domain_metadata_finalize_incomplete', source)
        playbook = (ROOT / 'deploy/ansible/playbooks/upgrade-domain.yml').read_text()
        self.assertIn('state_paths: "{{ ultra_backup_state_paths | default([]) }}"', playbook)
        self.assertIn('artifact_paths: "{{ ultra_backup_artifact_paths | default([]) }}"', playbook)
        role = (ROOT / 'deploy/ansible/roles/upgrade_domain/tasks/main.yml').read_text()
        self.assertNotIn('ultra_backend_dns:', role)
        self.assertIn('preserve_recovery: true', role)
        self.assertIn('ingress_defer_finalize: true', role)
        self.assertLess(role.index('Reload old listeners'), role.index('Apply retained-alias cutover'))


if __name__ == '__main__':
    unittest.main()
