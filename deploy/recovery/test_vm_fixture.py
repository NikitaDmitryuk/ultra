import importlib.util
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
import warnings

spec = importlib.util.spec_from_file_location('ultra_vm_fixture', Path(__file__).with_name('vm_fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        cls.cert, cls.key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(cls.key), '-out', str(cls.cert), '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        ], check=True, capture_output=True)

    def handshake(self, version):
        server_context = fixture.tls_context(self.cert, self.key)
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(self.cert)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            client_context.minimum_version = version
            client_context.maximum_version = version
        # Permit legacy client ciphers so rejection occurs at the server's
        # protocol boundary rather than at the client's local security policy.
        client_context.set_ciphers('ALL:@SECLEVEL=0')
        client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(client_in, client_out, server_hostname='localhost')
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
                return client, server, client_out, server_in
        self.fail('TLS handshake did not complete')

    def test_legacy_tls_rejected_by_server(self):
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            with self.subTest(version=version):
                with self.assertRaises(ssl.SSLError) as error:
                    self.handshake(version)
                self.assertEqual(error.exception.reason, 'UNSUPPORTED_PROTOCOL')

    def test_modern_tls_transfers_data_with_verified_certificate(self):
        for version, name in ((ssl.TLSVersion.TLSv1_2, 'TLSv1.2'),
                              (ssl.TLSVersion.TLSv1_3, 'TLSv1.3')):
            with self.subTest(version=version):
                client, server, client_out, server_in = self.handshake(version)
                self.assertEqual(client.version(), name)
                self.assertEqual(server.version(), name)
                client.write(b'fixture TLS control')
                server_in.write(client_out.read())
                self.assertEqual(server.read(), b'fixture TLS control')


if __name__ == '__main__':
    unittest.main()
