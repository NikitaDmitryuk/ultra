#!/usr/bin/env python3
"""Synthetic TLS/payload/Telegram fixtures for the isolated acceptance topology."""
import argparse
import http.server
import json
import os
from pathlib import Path
import shlex
import re
import ssl
import subprocess
import threading
import time
from vm_topology import command, NODES, endpoint

MANAGED_ZONE = 'fixture.test'
MANAGED_DOMAINS = ('sync.fixture.test','exit.fixture.test','admin.fixture.test','api.vultr.com')
FIXTURE_PROVIDER_TOKEN = 'synthetic-no-provider-permission'


class ManagedDNSStore:
    """A deliberately bounded provider replacement; never forwards a request."""
    def __init__(self, path):
        self.path=Path(path);self.lock=threading.RLock()
        self.records=json.loads(self.path.read_text()) if self.path.exists() else []
        self.sequence=max([int(row['id'].split('-')[-1]) for row in self.records]+[0])

    def save(self):
        temporary=self.path.with_suffix('.next')
        with temporary.open('w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(self.records,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,self.path)
        fd=os.open(self.path.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)

    def request(self, method, path, token, body=None):
        from urllib.parse import urlsplit
        target=urlsplit(path);base='/v2/domains/'+MANAGED_ZONE+'/records'
        if token!='Bearer '+FIXTURE_PROVIDER_TOKEN:return 403,{'error':'fixture_credential_required'}
        # Static-only acceptance must never create/delete a VPS or firewall.
        if method=='GET' and target.path=='/v2/instances':return 200,{'instances':[],'meta':{'links':{'next':''}}}
        if target.path!=base and not re.fullmatch(re.escape(base)+r'/fixture-[0-9]+',target.path):
            return 404,{'error':'fixture_zone_or_resource_forbidden'}
        identifier=target.path[len(base)+1:] if target.path!=base else None
        with self.lock:
            if method=='GET' and identifier is None:return 200,{'records':list(self.records),'meta':{'links':{'next':''}}}
            existing=next((row for row in self.records if row['id']==identifier),None)
            if method=='DELETE':
                if not existing:return 404,{'error':'record_missing'}
                self.records.remove(existing);self.save();return 204,None
            if method not in ('POST','PATCH') or (method=='POST')!=(identifier is None):return 405,{'error':'method_forbidden'}
            if method=='PATCH' and not existing:return 404,{'error':'record_missing'}
            if not isinstance(body,dict) or set(body)!={'type','name','data','ttl'} or body['type']!='A' or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',str(body['name'])) or body['data'] not in {endpoint(i) for i in range(4)} or type(body['ttl']) is not int or not 120<=body['ttl']<=86400:
                return 400,{'error':'synthetic_A_record_required'}
            if method=='POST':
                self.sequence+=1;existing={'id':'fixture-'+str(self.sequence)};self.records.append(existing)
            existing.update(body);self.save();return (201 if method=='POST' else 200),{'record':dict(existing)}


# This exact program is installed only under /etc/ultra-fixture on marked guests
# or in the owned fixture container. Production dns.py is never rewritten.
MANAGED_DNS_PROGRAM = r'''import argparse,json,socket,socketserver,struct,threading,time,urllib.request
from pathlib import Path
ZONE='fixture.test'
TOKEN='synthetic-no-provider-permission'
FIXED={name:'8.8.4.4' for name in ('www.cloudflare.com','cloudflare.com','www.google.com','www.gstatic.com','www.microsoft.com','api.telegram.org','speed.cloudflare.com','httpbingo.org')}
# Ubuntu systemd-resolved owns both 127.0.0.53 and 127.0.0.54.
FIXED.update({'api.vultr.com':'8.8.4.4','ns1.vultr.com':'127.0.0.55','ns2.vultr.com':'127.0.0.55'})
cache_lock=threading.Lock();cache=(0,[])
def labels(name):return b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
def records():
 global cache
 with cache_lock:
  if time.monotonic()-cache[0]>0.25:
   request=urllib.request.Request('https://api.vultr.com/v2/domains/fixture.test/records',headers={'Authorization':'Bearer '+TOKEN})
   opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
   with opener.open(request,timeout=5) as response:value=json.loads(response.read(1048576))['records']
   cache=(time.monotonic(),value)
  return cache[1]
def answer(query,provider=records):
 if len(query)<12 or len(query)>4096:raise ValueError('bounded_question_required')
 identifier,flags,count,_,_,_=struct.unpack('!HHHHHH',query[:12])
 if count!=1 or flags&0x8000:raise ValueError('single_question_required')
 parts=[];position=12
 while True:
  length=query[position];position+=1
  if length==0:break
  if length>63 or position+length>len(query):raise ValueError('invalid_name')
  parts.append(query[position:position+length].decode('ascii').lower());position+=length
 kind,klass=struct.unpack('!HH',query[position:position+4]);position+=4
 name='.'.join(parts);found=name in FIXED;values=[]
 if klass==1 and name==ZONE and kind==2:values=[labels('ns1.vultr.com'),labels('ns2.vultr.com')];found=True
 elif klass==1:
  address=FIXED.get(name)
  if name.endswith('.'+ZONE):
   matching=[r for r in provider() if r['name']+'.'+ZONE==name];address=matching[0]['data'] if matching else None
  found=bool(address)
  if address and kind==1:values=[socket.inet_aton(address)]
 raw=b''.join(b'\xc0\x0c'+struct.pack('!HHIH',kind,1,0,len(value))+value for value in values)
 return struct.pack('!HHHHHH',identifier,0x8580 if found else 0x8583,1,len(values),0,0)+query[12:position]+raw
class UDP(socketserver.BaseRequestHandler):
 def handle(self):
  try:self.request[1].sendto(answer(self.request[0]),self.client_address)
  except (OSError,ValueError,IndexError,struct.error):pass
class TCP(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(5)
  def exact(size):
   value=b''
   while len(value)<size:
    chunk=self.request.recv(size-len(value))
    if not chunk:raise ValueError('short_query')
    value+=chunk
   return value
  try:
   size=struct.unpack('!H',exact(2))[0]
   if size>4096:return
   raw=answer(exact(size));self.request.sendall(struct.pack('!H',len(raw))+raw)
  except (OSError,ValueError,IndexError,struct.error):pass
class UDPServer(socketserver.ThreadingUDPServer):allow_reuse_address=True;daemon_threads=True
class TCPServer(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--synthetic-marker',required=True);args=p.parse_args()
 if not Path(args.synthetic_marker).is_file():raise ValueError('synthetic_marker_required')
 threads=[]
 for server in (UDPServer(('127.0.0.55',53),UDP),TCPServer(('127.0.0.55',53),TCP)):
  thread=threading.Thread(target=server.serve_forever);thread.start();threads.append(thread)
 for thread in threads:thread.join()
'''


def managed_dns_guests(directory):
    """Install an isolated local resolver and real fixture CA leaf, never ACME."""
    directory=Path(directory);saved=json.loads((directory/'topology.json').read_text())
    if not saved.get('synthetic_only') or saved['nodes']!={name:endpoint(i) for i,name in enumerate(NODES)}:
        raise ValueError('verified_synthetic_topology_required')
    prepare(directory)
    code=r'''import json,pathlib,subprocess,sys
v=json.load(sys.stdin);root=pathlib.Path('/etc/ultra-fixture');assert pathlib.Path('/etc/ultra-fixture-marker').is_file()
(root/'managed-dns.py').write_text(v['source']);(root/'managed-dns.py').chmod(0o600)
# Remove only managed fixture aliases inherited from the original topology.
p=pathlib.Path('/etc/hosts');lines=[]
for line in p.read_text().splitlines():
 tokens=line.split();remaining=[x for x in tokens[1:] if not x.endswith('.fixture.test') and x not in ('api.vultr.com','ns1.vultr.com','ns2.vultr.com')]
 if remaining:lines.append(tokens[0]+' '+' '.join(remaining))
lines+=['8.8.4.4 api.vultr.com','127.0.0.55 ns1.vultr.com ns2.vultr.com'];p.write_text('\n'.join(lines)+'\n')
with pathlib.Path('/etc/environment').open('a') as stream:stream.write('\nno_proxy=localhost,127.0.0.1,198.18.0.0/24,.fixture.test,api.vultr.com,ns1.vultr.com,ns2.vultr.com\nNO_PROXY=localhost,127.0.0.1,198.18.0.0/24,.fixture.test,api.vultr.com,ns1.vultr.com,ns2.vultr.com\n')
unit='[Unit]\nAfter=network-online.target ultra-fixture-doh.service\nRequires=ultra-fixture-doh.service\n[Service]\nExecStart=/usr/bin/python3 /etc/ultra-fixture/managed-dns.py --synthetic-marker /etc/ultra-fixture-marker\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n'
pathlib.Path('/etc/systemd/system/ultra-fixture-managed-dns.service').write_text(unit)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','ultra-fixture-managed-dns.service'],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['systemctl','restart','ultra-fixture-managed-dns.service'],check=True)
p=pathlib.Path('/etc/resolv.conf')
if p.is_symlink():p.unlink()
p.write_text('nameserver 127.0.0.55\noptions timeout:2 attempts:1\n')
for name in ('vpn.fixture.test','sync.fixture.test','admin.fixture.test','exit.fixture.test'):
 p=pathlib.Path('/etc/letsencrypt/live')/name;p.mkdir(parents=True,exist_ok=True)
 (p/'fullchain.pem').write_text(v['cert']);(p/'privkey.pem').write_text(v['key']);(p/'privkey.pem').chmod(0o600)
print(json.dumps({'managed_dns_local':True}))
'''
    payload=json.dumps({'source':MANAGED_DNS_PROGRAM,'cert':(directory/'fixture.crt').read_text(),
        'key':(directory/'fixture.key').read_text()}).encode()
    for address in saved['nodes'].values():ssh(saved,address,['python3','-c',code],payload)


DOMAINS = ('www.cloudflare.com', 'cloudflare.com', 'www.google.com', 'www.gstatic.com', 'www.microsoft.com', 'api.telegram.org', 'speed.cloudflare.com', 'httpbingo.org')


def ssh(saved, address, args, data=None, timeout=120):
    return command(['ssh','-F','/dev/null','-i',saved['identity'],'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                    '-o','UserKnownHostsFile='+saved['known_hosts'],'root@'+address,shlex.join(args)], data, timeout=timeout)


def ensure_certificate(directory):
    ca=directory/'fixture-ca.crt';key=directory/'fixture-ca.key';cert=directory/'fixture.crt';server_key=directory/'fixture.key'
    if not ca.exists():
        command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','3','-subj','/CN=Ultra synthetic acceptance CA','-keyout',str(key),'-out',str(ca)])
    required=(*DOMAINS,*MANAGED_DOMAINS) if (directory/'managed-dns-enabled.json').is_file() else DOMAINS
    domains=set(re.findall(r'DNS:([^,\s]+)',command(['openssl','x509','-in',str(cert),'-noout','-ext','subjectAltName']).decode())) if cert.exists() else set()
    if not set(('vpn.fixture.test',*required)) <= domains:
        key_args=['-key',str(server_key)] if server_key.exists() else ['-newkey','rsa:2048','-nodes','-keyout',str(server_key)]
        command(['openssl','req','-new',*key_args,'-subj','/CN=vpn.fixture.test','-out',str(directory/'fixture.csr')])
        (directory/'extensions').write_text('subjectAltName='+','.join('DNS:'+name for name in ('vpn.fixture.test',*required))+'\n')
        command(['openssl','x509','-req','-in',str(directory/'fixture.csr'),'-CA',str(ca),'-CAkey',str(key),'-CAcreateserial','-days','3','-extfile',str(directory/'extensions'),'-out',str(cert)])
    return ca,cert,server_key


def prepare(directory):
    os.umask(0o077)
    directory=Path(directory)
    saved=json.loads((directory/'topology.json').read_text())
    if not saved.get('synthetic_only') or not saved.get('isolation_verified_at'):
        raise ValueError('verified_synthetic_topology_required')
    ca,cert,server_key=ensure_certificate(directory)
    for name,address in saved['nodes'].items():
        payload={'ca':ca.read_text(),'cert':cert.read_text(),'key':server_key.read_text(),'domains':DOMAINS}
        code='''import json,pathlib,subprocess,sys
v=json.load(sys.stdin)
p=pathlib.Path('/usr/local/share/ca-certificates/ultra-fixture.crt');p.write_text(v['ca']);p.chmod(0o644)
p=pathlib.Path('/etc/letsencrypt/live/vpn.fixture.test');p.mkdir(parents=True,exist_ok=True)
(p/'fullchain.pem').write_text(v['cert']);(p/'privkey.pem').write_text(v['key']);(p/'privkey.pem').chmod(0o600)
with pathlib.Path('/etc/hosts').open('a') as f:f.write('\\n8.8.4.4 '+' '.join(v['domains'])+'\\n')
with pathlib.Path('/etc/environment').open('a') as f:f.write('\\nno_proxy=localhost,127.0.0.1,198.18.0.0/24,vpn.fixture.test,'+','.join(v['domains'])+'\\n')
subprocess.run(['update-ca-certificates'],check=True,stdout=subprocess.DEVNULL)
'''
        ssh(saved,address,['python3','-c',code],json.dumps(payload).encode())
    Path('/usr/local/share/ca-certificates/ultra-fixture.crt').write_bytes(ca.read_bytes())
    command(['update-ca-certificates'])
    with Path('/etc/hosts').open('a') as stream:stream.write('\n198.18.0.11 vpn.fixture.test\n')
    print(json.dumps({'fixture_ca_installed':True,'synthetic_only':True}))


def dependencies(directory):
    """Prepare guest-only test packages before measuring any restoration."""
    saved=json.loads((Path(directory)/'topology.json').read_text())
    if not saved.get('synthetic_only') or not saved.get('isolation_verified_at'):
        raise ValueError('verified_synthetic_topology_required')
    code = """import shutil,subprocess
if shutil.which('dig') and shutil.which('iptables') and subprocess.run(['python3','-c','import h2'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
 print('prepared')
else:
 state=subprocess.run(['systemctl','is-active','ultra-fixture-dependencies.service'],stdout=subprocess.PIPE).stdout.strip()
 if state not in (b'active',b'activating'):
  subprocess.run(['systemctl','reset-failed','ultra-fixture-dependencies.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['systemd-run','--no-block','--unit=ultra-fixture-dependencies','--property=Type=oneshot','--setenv=DEBIAN_FRONTEND=noninteractive','/bin/sh','-c','apt-get update && apt-get install -y iptables python3-h2 dnsutils'],check=True,stdout=subprocess.DEVNULL)
 print('pending')
"""
    pending=[]
    for name,address in saved['nodes'].items():
        if ssh(saved,address,['python3','-c',code]).strip()!=b'prepared':
            pending.append(name)
    print(json.dumps({'prepared':not pending,'pending':pending,'synthetic_only':True}))
    return not pending


def payload_targets(directory):
    directory=Path(directory)
    saved=json.loads((directory/'topology.json').read_text())
    if not saved.get('synthetic_only') or not saved.get('isolation_verified_at'):
        raise ValueError('verified_synthetic_topology_required')
    self_addresses(directory)
    cert=directory/'payload.crt';key=directory/'payload.key'
    if not cert.exists():
        command(['openssl','req','-newkey','rsa:2048','-nodes','-subj','/CN=8.8.8.8','-keyout',str(key),'-out',str(directory/'payload.csr')])
        (directory/'payload.extensions').write_text('subjectAltName=IP:8.8.8.8,IP:1.1.1.1,DNS:cloudflare-dns.com,DNS:dns.google\n')
        command(['openssl','x509','-req','-in',str(directory/'payload.csr'),'-CA',str(directory/'fixture-ca.crt'),'-CAkey',str(directory/'fixture-ca.key'),'-CAcreateserial','-days','3','-extfile',str(directory/'payload.extensions'),'-out',str(cert)])
    script=Path(__file__).with_name('vm_fixture.py').read_text()
    code = """import json,pathlib,subprocess,sys
v=json.load(sys.stdin);p=pathlib.Path('/etc/ultra-fixture');p.mkdir(mode=0o700,exist_ok=True)
import shutil
if not shutil.which('iptables') or subprocess.run(['python3','-c','import h2'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
 raise ValueError('fixture_dependencies_not_prepared')
for name,value in v.items():
 q=p/name;q.write_text(value);q.chmod(0o600)
pathlib.Path('/etc/ultra-fixture-marker').write_text('synthetic-only')
subprocess.run(['ip','address','replace','8.8.8.8/32','dev','lo'],check=True)
subprocess.run(['ip','address','replace','1.1.1.1/32','dev','lo'],check=True)
unit=pathlib.Path('/etc/systemd/system/ultra-fixture-payload.service')
unit.write_text(v['payload.service'])
pathlib.Path('/etc/systemd/system/ultra-fixture-doh.service').write_text(v['doh.service'])
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','ultra-fixture-payload','ultra-fixture-doh'],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['systemctl','restart','ultra-fixture-payload','ultra-fixture-doh'],check=True)
"""
    for address in saved['nodes'].values():
        ssh(saved,address,['python3','-c',code],json.dumps({'payload.py':script,'doh.py':Path(__file__).with_name('vm_doh.py').read_text(),'doh.service':'[Unit]\nBefore=nginx.service ultra-relay.service\n[Service]\nExecStartPre=/usr/bin/python3 /etc/ultra-fixture/doh.py --prepare-network\nExecStart=/usr/bin/python3 /etc/ultra-fixture/doh.py --cert /etc/ultra-fixture/cert.pem --key /etc/ultra-fixture/key.pem\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n','cert.pem':cert.read_text(),'key.pem':key.read_text(),'payload.service':'[Service]\nExecStart=/usr/bin/python3 /etc/ultra-fixture/payload.py --cert /etc/ultra-fixture/cert.pem --key /etc/ultra-fixture/key.pem\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n'}).encode())


def self_addresses(directory):
    """Give each isolated guest its own public address, including staging ports."""
    saved=json.loads((Path(directory)/'topology.json').read_text())
    if (not saved.get('synthetic_only') or not saved.get('isolation_verified_at')
            or saved.get('nodes') != {name:endpoint(i) for i,name in enumerate(NODES)}):
        raise ValueError('verified_synthetic_topology_required')
    for address in saved['nodes'].values():
        unit='[Unit]\nBefore=nginx.service ultra-relay.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/ip address replace '+address+'/32 dev lo\n[Install]\nWantedBy=multi-user.target\n'
        code="""import pathlib,subprocess,sys
p=pathlib.Path('/etc/systemd/system/ultra-fixture-address.service');p.write_text(sys.stdin.read());p.chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','ultra-fixture-address.service'],check=True,stdout=subprocess.DEVNULL)
"""
        ssh(saved,address,['python3','-c',code],unit.encode())



class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def answer(self):
        if self.path.startswith('/v2/'):
            return self.api_answer()
        length=int(self.headers.get('Content-Length','0'))
        if length:self.rfile.read(min(length,65536))
        if self.path.endswith('/getMe'):
            value={'ok':True,'result':{'id':123456,'is_bot':True,'first_name':'Synthetic','username':'ultra_fixture_bot'}}
        elif self.path.endswith('/getUpdates'):
            time.sleep(1);value={'ok':True,'result':[]}
        elif self.path.startswith('/bot'):
            value={'ok':True,'result':{'message_id':1,'date':int(time.time()),'chat':{'id':123456789,'type':'private'},'text':'synthetic'}}
        else:
            data=b'x'*65536 if self.path in ('/__down?bytes=65536','/bytes/65536') else ('fl=fixture\nip='+self.server.fixture_address+'\nloc=ZZ\n').encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
            if self.command!='HEAD':self.wfile.write(data)
            return
        data=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        if self.command!='HEAD':self.wfile.write(data)
    def api_answer(self):
        store=getattr(self.server,'fixture_dns_store',None)
        if store is None:self.send_error(404);return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<=size<=65536:self.send_error(413);return
            body=json.loads(self.rfile.read(size)) if size else None
            status,value=store.request(self.command,self.path,self.headers.get('Authorization',''),body)
        except (ValueError,KeyError,TypeError):status,value=400,{'error':'fixture_request_invalid'}
        raw=json.dumps(value).encode() if value is not None else b''
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers()
        if self.command!='HEAD':self.wfile.write(raw)
    do_HEAD=answer
    do_GET=answer
    do_POST=answer
    do_PATCH=answer
    do_DELETE=answer


def serve(directory):
    directory=Path(directory)
    threads=[]
    managed=(directory/'managed-dns-enabled.json').is_file()
    store=ManagedDNSStore(directory/'managed-dns-records.json') if managed else None
    for index,port in enumerate([18443+i for i in range(len(NODES))]+([443] if managed else [])):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler)
        server.fixture_dns_store=store
        server.fixture_address=endpoint(min(index,len(NODES)-1))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(directory/'fixture.crt',directory/'fixture.key')
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever);thread.start();threads.append(thread)
    for thread in threads:thread.join()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','serve','dependencies'));parser.add_argument('--workspace',required=True)
    args=parser.parse_args()
    action={'prepare':prepare,'serve':serve,'dependencies':dependencies}[args.action]
    result=action(args.workspace)
    if args.action=='dependencies' and result is False:
        raise SystemExit(2)
