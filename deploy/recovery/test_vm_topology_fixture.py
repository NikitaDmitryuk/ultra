import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import vm_topology_fixture as fixture
from test_vm_doh import question
import vm_doh
import socket


class HealthFixture(unittest.TestCase):
    def test_default_health_urls_have_exact_payload_and_dns(self):
        for domain,path in (('speed.cloudflare.com','/__down?bytes=65536'),('httpbingo.org','/bytes/65536')):
            self.assertEqual(vm_doh.reply(question(domain))[-4:],socket.inet_aton('8.8.4.4'))
            for method in ('GET','HEAD'):
                handler=object.__new__(fixture.Handler)
                handler.path=path;handler.command=method;handler.headers={};handler.wfile=io.BytesIO()
                handler.send_response=mock.Mock();handler.send_header=mock.Mock();handler.end_headers=mock.Mock()
                handler.answer()
                handler.send_response.assert_called_once_with(200)
                handler.send_header.assert_any_call('Content-Length','65536')
                self.assertEqual(handler.wfile.getvalue(),b'x'*65536 if method=='GET' else b'')

    def test_new_fixture_domain_reissues_leaf_preserving_ca_and_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            ca,cert,key=fixture.ensure_certificate(root)
            original_ca=ca.read_bytes();original_key=key.read_bytes()
            with mock.patch.object(fixture,'DOMAINS',(*fixture.DOMAINS,'extra.fixture.test')):
                fixture.ensure_certificate(root)
            self.assertEqual(ca.read_bytes(),original_ca)
            self.assertEqual(key.read_bytes(),original_key)
            subprocess.run(['openssl','verify','-CAfile',str(ca),'-verify_hostname','extra.fixture.test',str(cert)],check=True,capture_output=True)
