import socket
import struct
import unittest
from unittest import mock
import vm_doh


def question(name,kind=1):
    return struct.pack('!HHHHHH',123,0x100,1,0,0,0)+b''.join(bytes([len(part)])+part.encode() for part in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)


class SyntheticDNS(unittest.TestCase):
    def test_configured_payload_domain_maps_only_to_fixture(self):
        result=vm_doh.reply(question('www.cloudflare.com'))
        self.assertEqual(struct.unpack('!HHHHHH',result[:12]),(123,0x8180,1,1,0,0))
        self.assertEqual(result[-4:],socket.inet_aton('8.8.4.4'))
    def test_public_alias_is_narrowly_redirected_only_in_marked_guest(self):
        with mock.patch.object(vm_doh.Path, 'is_file', return_value=False), mock.patch.object(vm_doh.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'synthetic_target_required'):
                vm_doh.prepare_network()
            run.assert_not_called()
        with mock.patch.object(vm_doh.Path, 'is_file', return_value=True), mock.patch.object(vm_doh.subprocess, 'run', return_value=mock.Mock(returncode=1)) as run:
            vm_doh.prepare_network()
            commands=[call.args[0] for call in run.call_args_list]
            self.assertIn(['ip','route','replace','8.8.4.4/32','via','198.18.0.2'],commands)
            self.assertIn(['iptables','-w','-t','nat','-A','OUTPUT','-d','8.8.4.4/32','-p','tcp','--dport','443','-j','DNAT','--to-destination','198.18.0.20:443'],commands)
            self.assertLess(commands.index(['ip','route','replace','8.8.4.4/32','via','198.18.0.2']),next(i for i,c in enumerate(commands) if c[0]=='iptables'))
            self.assertFalse(any('default' in command for command in commands))
            self.assertFalse(any(command[:3]==['ip','address','replace'] and '8.8.4.4/32' in command for command in commands))

    def test_existing_nat_rules_are_not_duplicated(self):
        with mock.patch.object(vm_doh.Path, 'is_file', return_value=True), mock.patch.object(vm_doh.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run:
            vm_doh.prepare_network()
            self.assertFalse(any('-A' in call.args[0] for call in run.call_args_list))

    def test_subscription_domain_maps_to_stable_ingress(self):
        self.assertEqual(vm_doh.reply(question('vpn.fixture.test'))[-4:],socket.inet_aton('198.18.0.11'))
    def test_unlisted_domain_is_nxdomain_and_ipv6_has_no_answer(self):
        result=vm_doh.reply(question('api.vultr.com'))
        self.assertEqual(struct.unpack('!HHHHHH',result[:12]),(123,0x8183,1,0,0,0))
        self.assertEqual(struct.unpack('!HHHHHH',vm_doh.reply(question('www.cloudflare.com',28))[:12]),(123,0x8180,1,0,0,0))
    def test_compressed_query_is_rejected(self):
        with self.assertRaises(ValueError):vm_doh.reply(struct.pack('!HHHHHH',123,0x100,1,0,0,0)+b'\xc0\x0c\0\x01\0\x01')

class HTTP2Fixture(unittest.TestCase):
    def test_actual_h2_frames_receive_wire_dns_response(self):
        try:
            from h2.config import H2Configuration
            from h2.connection import H2Connection
            from h2.events import ResponseReceived, DataReceived
        except ImportError:
            self.skipTest('python3-h2 is a synthetic fixture dependency')
        client=H2Connection(config=H2Configuration(client_side=True,header_encoding='utf-8'))
        client.initiate_connection()
        client.send_headers(1,[(':method','POST'),(':scheme','https'),(':authority','1.1.1.1'),(':path','/dns-query')])
        client.send_data(1,question('speed.cloudflare.com'),end_stream=True)
        request=client.data_to_send()
        class Connection:
            def __init__(self):self.input=[request,b''];self.output=b''
            def selected_alpn_protocol(self):return 'h2'
            def settimeout(self,value):pass
            def recv(self,size):return self.input.pop(0)
            def sendall(self,data):self.output+=data
        handler=object.__new__(vm_doh.Handler);handler.connection=Connection()
        handler.handle()
        events=client.receive_data(handler.connection.output)
        response=next(event for event in events if isinstance(event,ResponseReceived))
        self.assertIn((':status','200'),response.headers)
        body=b''.join(event.data for event in events if isinstance(event,DataReceived))
        self.assertEqual(body[-4:],socket.inet_aton('8.8.4.4'))
