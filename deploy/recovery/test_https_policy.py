"""Exercise each deployment HTTPS client's policy before any network side effect."""
import importlib.util
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock
import warnings

import dns
import domain_cutover
import restore_host
import test_vm_fixture

spec = importlib.util.spec_from_file_location(
    'ingress_probe', Path(__file__).parent.parent / 'ansible/library/ultra_ingress_probe.py')
subscription = importlib.util.module_from_spec(spec)
# This test exercises the pure TLS function, not the Ansible entrypoint.
with mock.patch.dict('sys.modules', {'ansible.module_utils.basic': mock.Mock()}):
    spec.loader.exec_module(subscription)


class BeforeConnect(Exception):
    pass


class HTTPSPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the local test certificate, never an operator's CA or key.
        test_vm_fixture.FixtureTLSTests.setUpClass.__func__(cls)

    def contexts(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = Path(temporary) / 'dns.json'
            policy.write_text(json.dumps({'config': {'zone': 'example.test'}, 'desired': {
                'subscription': {'name': 'sync'}, 'vpn': {'name': 'edge'}}}))
            host = object.__new__(restore_host.Host)
            host.plan = {'subscription_domain': 'sync.example.test',
                         'public_host': 'edge.example.test', 'new_bridge_address': '192.0.2.1'}
            probes = (
                ('cutover', lambda: domain_cutover.https('localhost', '192.0.2.1', 443, '/healthz')),
                ('subscription', lambda: subscription.tls_ready('127.0.0.1', 'localhost', 443)),
                ('restore', host.direct_ingress),
            )
            for name, probe in probes:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(self.cert)
                # Model an older/permissive platform default. The application
                # must enforce its minimum instead of inheriting that default.
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', DeprecationWarning)
                    context.minimum_version = ssl.TLSVersion.TLSv1
                context.set_ciphers('ALL:@SECLEVEL=0')
                with mock.patch.object(ssl, 'create_default_context', return_value=context), \
                     mock.patch('socket.create_connection', side_effect=BeforeConnect), \
                     mock.patch.object(dns, 'private', return_value=policy):
                    with self.assertRaises(BeforeConnect):
                        probe()
                yield name, context

    def handshake(self, context, version, hostname='localhost'):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.cert, self.key)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            server_context.minimum_version = version
            server_context.maximum_version = version
        server_context.set_ciphers('ALL:@SECLEVEL=0')
        client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = context.wrap_bio(client_in, client_out, server_hostname=hostname)
        server = server_context.wrap_bio(server_in, server_out, server_side=True)
        pending = [client, server]
        for _ in range(20):
            for connection in pending[:]:
                try:
                    connection.do_handshake()
                    pending.remove(connection)
                except ssl.SSLWantReadError:
                    pass
            server_in.write(client_out.read())
            client_in.write(server_out.read())
            if not pending:
                client.write(b'checked HTTPS payload')
                server_in.write(client_out.read())
                self.assertEqual(server.read(), b'checked HTTPS payload')
                return client.version()
        self.fail('TLS handshake did not complete')

    def test_clients_reject_legacy_tls_and_keep_certificate_validation(self):
        for name, context in self.contexts():
            with self.subTest(probe=name):
                self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                    with self.assertRaises(ssl.SSLError):
                        self.handshake(context, version)
                for version, negotiated in ((ssl.TLSVersion.TLSv1_2, 'TLSv1.2'),
                                            (ssl.TLSVersion.TLSv1_3, 'TLSv1.3')):
                    self.assertEqual(self.handshake(context, version), negotiated)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    self.handshake(context, ssl.TLSVersion.TLSv1_2, hostname='wrong.example.test')


if __name__ == '__main__':
    unittest.main()
