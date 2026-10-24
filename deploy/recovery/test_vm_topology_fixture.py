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

class ManagedDNSFixture(unittest.TestCase):
    def test_provider_crud_is_persistent_and_never_accepts_foreign_zone_or_resource(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'records.json';store=fixture.ManagedDNSStore(path)
            token='Bearer '+fixture.FIXTURE_PROVIDER_TOKEN;base='/v2/domains/fixture.test/records'
            target={'type':'A','name':'proof','data':'198.18.0.10','ttl':120}
            code,value=store.request('POST',base,token,target)
            self.assertEqual(code,201);identifier=value['record']['id']
            target=dict(target,data='198.18.0.11')
            self.assertEqual(store.request('PATCH',base+'/'+identifier,token,target)[0],200)
            reloaded=fixture.ManagedDNSStore(path)
            self.assertEqual(reloaded.request('GET',base,token)[1]['records'][0]['data'],'198.18.0.11')
            for method,url,data in [('POST','/v2/instances',target),('DELETE','/v2/instances/fixture-1',None),
                                    ('POST','/v2/domains/example.com/records',target),('POST',base,dict(target,data='192.0.2.1'))]:
                self.assertGreaterEqual(store.request(method,url,token,data)[0],400)
            self.assertEqual(store.request('POST',base,'Bearer foreign',target)[0],403)
            self.assertEqual(store.request('DELETE',base+'/'+identifier,token)[0],204)
            self.assertEqual(store.request('GET',base,token)[1]['records'],[])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_real_dns_wire_has_two_authoritative_ns_and_tracks_provider_A_updates(self):
        import struct
        namespace={'__name__':'fixture_dns_test'};exec(fixture.MANAGED_DNS_PROGRAM,namespace)
        answer=namespace['answer'];rows=[{'name':'proof','data':'198.18.0.10'}]
        response=answer(question('fixture.test',2),lambda:rows)
        self.assertEqual(struct.unpack('!HHHHHH',response[:12])[3],2)
        self.assertIn(b'\x03ns1\x05vultr\x03com',response)
        self.assertIn(b'\x03ns2\x05vultr\x03com',response)
        self.assertEqual(answer(question('proof.fixture.test'),lambda:rows)[-4:],socket.inet_aton('198.18.0.10'))
        rows[0]['data']='198.18.0.11'
        self.assertEqual(answer(question('proof.fixture.test'),lambda:rows)[-4:],socket.inet_aton('198.18.0.11'))
        response=answer(question('arbitrary.example.com'),lambda: (_ for _ in ()).throw(AssertionError('external lookup')))
        self.assertEqual(struct.unpack('!HHHHHH',response[:12])[1] & 0xf,3)
        self.assertEqual(answer(question('ns1.vultr.com'))[-4:],socket.inet_aton('127.0.0.55'))

    def test_dns_listener_does_not_collide_with_systemd_resolved_stubs(self):
        self.assertNotIn("UDPServer(('127.0.0.53',53)", fixture.MANAGED_DNS_PROGRAM)
        self.assertNotIn("UDPServer(('127.0.0.54',53)", fixture.MANAGED_DNS_PROGRAM)
        self.assertIn("UDPServer(('127.0.0.55',53)", fixture.MANAGED_DNS_PROGRAM)

    def test_managed_fixture_certificate_covers_provider_and_actual_ca_route_domains(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'managed-dns-enabled.json').write_text('{}')
            ca,cert,key=fixture.ensure_certificate(root)
            for hostname in ('api.vultr.com','exit.fixture.test','sync.fixture.test','admin.fixture.test','vpn.fixture.test'):
                subprocess.run(['openssl','verify','-CAfile',str(ca),'-verify_hostname',hostname,str(cert)],check=True,capture_output=True)
