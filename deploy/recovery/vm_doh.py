#!/usr/bin/env python3
"""TLS-valid HTTP/1+HTTP/2 DoH fixture (python3-h2); synthetic names only."""
import argparse
import base64
import http.server
import ipaddress
import socket
import ssl
import struct
import threading
import urllib.parse
from pathlib import Path
import subprocess


def prepare_network():
    if not Path('/etc/ultra-fixture-marker').is_file():
        raise ValueError('synthetic_target_required')
    # VLESS freedom blocks 198.18/15 before dial. Keep its security policy intact:
    # a public-looking synthetic destination is translated to the restricted
    # QEMU guestfwd target only in this marked test guest.
    # Restricted guests deliberately have no default route. A /32 route is
    # needed before the kernel can apply OUTPUT DNAT; no Internet route is added.
    subprocess.run(['ip', 'route', 'replace', '8.8.4.4/32', 'via', '198.18.0.2'], check=True)
    rule = ['OUTPUT', '-d', '8.8.4.4/32', '-p', 'tcp', '--dport', '443',
            '-j', 'DNAT', '--to-destination', '198.18.0.20:443']
    if subprocess.run(['iptables', '-w', '-t', 'nat', '-C', *rule], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        subprocess.run(['iptables', '-w', '-t', 'nat', '-A', *rule], check=True)
    for address in ('1.1.1.1', '8.8.8.8'):
        subprocess.run(['ip', 'address', 'replace', address+'/32', 'dev', 'lo'], check=True)
        rule=['OUTPUT','-d',address+'/32','-p','tcp','--dport','443','-j','DNAT','--to-destination',address+':18445']
        if subprocess.run(['iptables','-w','-t','nat','-C',*rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
            subprocess.run(['iptables','-w','-t','nat','-A',*rule],check=True)

ADDRESSES = {name:'8.8.4.4' for name in ('www.cloudflare.com','cloudflare.com','www.google.com','www.gstatic.com','www.microsoft.com','api.telegram.org','speed.cloudflare.com','httpbingo.org')}
ADDRESSES['vpn.fixture.test']='198.18.0.11'


def reply(query):
    if len(query)<12 or len(query)>4096:raise ValueError('bounded_dns_message_required')
    identifier,flags,count,_,_,_=struct.unpack('!HHHHHH',query[:12])
    if count!=1 or flags&0x8000:raise ValueError('single_dns_question_required')
    labels=[];position=12
    while True:
        length=query[position];position+=1
        if length==0:break
        if length>63 or position+length>len(query):raise ValueError('invalid_dns_name')
        labels.append(query[position:position+length].decode('ascii').lower());position+=length
    kind,klass=struct.unpack('!HH',query[position:position+4]);position+=4
    domain='.'.join(labels)
    address=ADDRESSES.get(domain)
    answer=b''
    if address and kind==1 and klass==1:
        answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(address)
    response_flags=0x8180 if address else 0x8183
    return struct.pack('!HHHHHH',identifier,response_flags,1,int(bool(answer)),0,0)+query[12:position]+answer


class Handler(http.server.BaseHTTPRequestHandler):
    def handle(self):
        if self.connection.selected_alpn_protocol() != 'h2':
            return super().handle()
        # Xray's DoH client uses HTTP/2 explicitly, including its wire framing.
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import RequestReceived, DataReceived, StreamEnded
        connection = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
        connection.initiate_connection()
        self.connection.sendall(connection.data_to_send())
        streams = {}
        self.connection.settimeout(30)
        try:
            while data := self.connection.recv(16384):
                for event in connection.receive_data(data):
                    if isinstance(event, RequestReceived):
                        if len(streams) >= 16:
                            connection.reset_stream(event.stream_id)
                            continue
                        streams[event.stream_id] = [dict(event.headers), bytearray()]
                    elif isinstance(event, DataReceived):
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        if event.stream_id in streams:
                            streams[event.stream_id][1].extend(event.data)
                            if len(streams[event.stream_id][1]) > 4096:
                                connection.reset_stream(event.stream_id)
                                del streams[event.stream_id]
                    elif isinstance(event, StreamEnded) and event.stream_id in streams:
                        headers, body = streams.pop(event.stream_id)
                        try:
                            if headers.get(':method') == 'GET':
                                value=urllib.parse.parse_qs(urllib.parse.urlsplit(headers[':path']).query)['dns'][0]
                                body=base64.urlsafe_b64decode(value+'='*((-len(value))%4))
                            result=reply(bytes(body)); status='200'
                        except (KeyError,ValueError,IndexError,UnicodeError,struct.error):
                            result=b''; status='400'
                        connection.send_headers(event.stream_id, [(':status',status),('content-type','application/dns-message'),('content-length',str(len(result)))])
                        connection.send_data(event.stream_id,result,end_stream=True)
                self.connection.sendall(connection.data_to_send())
        except (OSError, TimeoutError):
            return

    def log_message(self,*args):pass
    def answer(self,data):
        try:data=reply(data)
        except (ValueError,IndexError,UnicodeError,struct.error):self.send_error(400);return
        self.send_response(200);self.send_header('Content-Type','application/dns-message');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        size=int(self.headers.get('Content-Length','0'))
        if not 0<size<=4096:self.send_error(400);return
        self.answer(self.rfile.read(size))
    def do_GET(self):
        try:
            value=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)['dns'][0]
            self.answer(base64.urlsafe_b64decode(value+'='*((-len(value))%4)))
        except (KeyError,ValueError):self.send_error(400)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--cert');parser.add_argument('--key');parser.add_argument('--prepare-network',action='store_true');args=parser.parse_args()
    if args.prepare_network:
        prepare_network()
        raise SystemExit(0)
    if not args.cert or not args.key:parser.error('--cert and --key are required for serving')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(args.cert,args.key);context.set_alpn_protocols(['h2','http/1.1'])
    threads=[]
    for address in ('1.1.1.1','8.8.8.8'):
        server=http.server.ThreadingHTTPServer((address,18445),Handler);server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever);thread.start();threads.append(thread)
    for thread in threads:thread.join()
