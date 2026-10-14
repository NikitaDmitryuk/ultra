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

DOMAINS = ('www.cloudflare.com', 'cloudflare.com', 'www.google.com', 'www.gstatic.com', 'www.microsoft.com', 'api.telegram.org', 'speed.cloudflare.com', 'httpbingo.org')


def ssh(saved, address, args, data=None, timeout=120):
    return command(['ssh','-F','/dev/null','-i',saved['identity'],'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                    '-o','UserKnownHostsFile='+saved['known_hosts'],'root@'+address,shlex.join(args)], data, timeout=timeout)


def ensure_certificate(directory):
    ca=directory/'fixture-ca.crt';key=directory/'fixture-ca.key';cert=directory/'fixture.crt';server_key=directory/'fixture.key'
    if not ca.exists():
        command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','3','-subj','/CN=Ultra synthetic acceptance CA','-keyout',str(key),'-out',str(ca)])
    domains=set(re.findall(r'DNS:([^,\s]+)',command(['openssl','x509','-in',str(cert),'-noout','-ext','subjectAltName']).decode())) if cert.exists() else set()
    if not set(('vpn.fixture.test',*DOMAINS)) <= domains:
        key_args=['-key',str(server_key)] if server_key.exists() else ['-newkey','rsa:2048','-nodes','-keyout',str(server_key)]
        command(['openssl','req','-new',*key_args,'-subj','/CN=vpn.fixture.test','-out',str(directory/'fixture.csr')])
        (directory/'extensions').write_text('subjectAltName='+','.join('DNS:'+name for name in ('vpn.fixture.test',*DOMAINS))+'\n')
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
if shutil.which('iptables') and subprocess.run(['python3','-c','import h2'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
 print('prepared')
else:
 state=subprocess.run(['systemctl','is-active','ultra-fixture-dependencies.service'],stdout=subprocess.PIPE).stdout.strip()
 if state not in (b'active',b'activating'):
  subprocess.run(['systemctl','reset-failed','ultra-fixture-dependencies.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['systemd-run','--no-block','--unit=ultra-fixture-dependencies','--property=Type=oneshot','--setenv=DEBIAN_FRONTEND=noninteractive','/bin/sh','-c','apt-get update && apt-get install -y iptables python3-h2'],check=True,stdout=subprocess.DEVNULL)
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
    do_HEAD=answer
    do_GET=answer
    do_POST=answer


def serve(directory):
    directory=Path(directory)
    threads=[]
    for index in range(4):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',18443+index),Handler)
        server.fixture_address=endpoint(index)
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
