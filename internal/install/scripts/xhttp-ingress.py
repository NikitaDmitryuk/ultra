#!/usr/bin/env python3
"""Owned, repeatable bridge ingress changes. Configuration and keys stay on the host."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = Path('/var/lib/ultra-ingress')
SPEC = Path('/etc/ultra-relay/spec.json')
SITE = Path('/etc/nginx/conf.d/ultra-vpn.conf')
UNIT = Path('/etc/systemd/system/ultra-experimental.service')
MANIFEST = ROOT / 'managed.json'

def run(args, **kw):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)

def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.ultra-next')
    with open(tmp, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, mode)
    if path.exists():
        st = path.stat(); os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)
    sync_directory(path.parent)

def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def digest(data): return hashlib.sha256(data).hexdigest()

def recover_owned(manifest):
    journal=MANIFEST.with_name(MANIFEST.name+'.pending')
    if not journal.exists():return
    if journal.is_symlink():raise RuntimeError('managed journal is a symlink')
    operation=json.loads(journal.read_text())
    target=Path(operation['path'])
    if operation.get('version')!=1 or not target.is_absolute() or target.is_symlink():
        raise RuntimeError('invalid managed transaction')
    before,after=operation['before'],operation['after']
    current=digest(target.read_bytes()) if target.exists() else None
    persisted=json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    if current not in (before,after) or persisted.get(str(target)) not in (before,after):
        raise RuntimeError('managed transaction drift')
    # File before-image means the write did not happen (or an enclosing rollback
    # restored it). Target-image means finish its interrupted receipt update.
    if current is None:persisted.pop(str(target),None)
    else:persisted[str(target)]=current
    atomic(MANIFEST,json.dumps(persisted,sort_keys=True).encode())
    journal.unlink();sync_directory(journal.parent)
    manifest.clear();manifest.update(persisted)

def owned(path, content, manifest, mode=0o644):
    recover_owned(manifest)
    key = str(path)
    if path.is_symlink(): raise RuntimeError('managed path is a symlink')
    old = path.read_bytes() if path.exists() else None
    if old is not None and manifest.get(key) != digest(old):
        raise RuntimeError('refusing foreign or modified configuration: ' + key)
    if old == content: return False
    journal=MANIFEST.with_name(MANIFEST.name+'.pending')
    atomic(journal,json.dumps({'version':1,'path':str(path),'before':digest(old) if old is not None else None,'after':digest(content)},sort_keys=True).encode())
    atomic(path, content, mode); manifest[key] = digest(content)
    atomic(MANIFEST,json.dumps(manifest,sort_keys=True).encode())
    journal.unlink();sync_directory(journal.parent)
    return True

def endpoint(p, port, experimental=False):
    return {'port':port,'server_name':p['domain'],'path':p['path'],'mode':'stream-up',
            'fingerprint':p.get('experimental_fingerprint',p.get('fingerprint','chrome')) if experimental else p.get('fingerprint','chrome'),
            'xmux':{'maxConnections':'2','hMaxRequestTimes':'600-900','hMaxReusableSecs':'1800-3000'}}

def nginx(p, port):
    domain = p['domain']; path = p['path']
    return f'''# Managed by ultra-install ingress; edit the plan instead.
server {{
    listen 80;
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/ultra-acme; access_log off; }}
    location / {{ return 301 https://{domain}$request_uri; }}
}}
server {{
    listen {port} ssl http2;
    server_name {domain};
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:ultravpn:10m;
    ssl_session_timeout 1d;
    access_log off;
    error_log /var/log/nginx/ultra-vpn-error.log crit;
    root /var/www/ultra-site;
    location ^~ {path}/ {{
        grpc_pass grpc://127.0.0.1:{p['backend_port']};
        grpc_set_header Host $host;
        grpc_set_header X-Forwarded-For $remote_addr;
        grpc_set_header X-Ultra-Proxy 1;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header Forwarded "";
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
        grpc_socket_keepalive on;
        client_body_timeout 3600s;
        client_max_body_size 0;
    }}
    location = {path} {{
        grpc_pass grpc://127.0.0.1:{p['backend_port']};
        grpc_set_header X-Forwarded-For $remote_addr;
        grpc_set_header X-Ultra-Proxy 1;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header Forwarded "";
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
        client_body_timeout 3600s;
        client_max_body_size 0;
    }}
    location / {{ try_files $uri $uri/ =404; }}
}}
'''.encode()

def wait_relay():
    # Read credentials inside the checking process; never expose values or responses.
    values = {}
    for line in Path('/etc/ultra-relay/environment').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=',1); values[key] = value.strip().strip('"').strip("'")
    token = values.get('ULTRA_RELAY_ADMIN_TOKEN','')
    for _ in range(120):
        try:
            req = urllib.request.Request('http://127.0.0.1:8443/v1/hardening',headers={'Authorization':'Bearer '+token})
            with urllib.request.urlopen(req,timeout=2) as r: data=json.load(r)
            if data.get('reload',{}).get('count',0)>0 and not data.get('reload',{}).get('error'): return
        except Exception: pass
        time.sleep(1)
    raise RuntimeError('relay readiness timeout')

def wait_experiment(port):
    for _ in range(30):
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/ready',timeout=2) as r: data=json.load(r)
            if data.get('ready'): return
        except Exception: pass
        time.sleep(1)
    raise RuntimeError('experimental readiness timeout')

def prepare_certificate(p, manifest):
    run(['apt-get','update','-qq'])
    run(['apt-get','install','-y','-qq','nginx','certbot'])
    Path('/var/www/ultra-acme').mkdir(parents=True,exist_ok=True)
    Path('/var/www/ultra-site').mkdir(parents=True,exist_ok=True)
    atomic(Path('/var/www/ultra-site/index.html'),b'<!doctype html><meta charset="utf-8"><title>Cedar Leaf</title><h1>Cedar Leaf</h1><p>Welcome.</p>\n',0o644)
    cert = Path('/etc/letsencrypt/live')/p['domain']/'fullchain.pem'
    if cert.exists(): return
    if not p.get('email'):raise ValueError('existing certificate missing; supply ACME email before issuance')
    challenge=Path('/etc/nginx/conf.d/ultra-acme.conf')
    content=(f'server {{ listen 80; server_name {p["domain"]}; location ^~ /.well-known/acme-challenge/ {{ root /var/www/ultra-acme; access_log off; }} location / {{ return 404; }} }}\n').encode()
    owned(challenge,content,manifest)
    run(['nginx','-t']);run(['systemctl','reload','nginx'])
    run(['certbot','certonly','--webroot','-w','/var/www/ultra-acme','-d',p['domain'],'--non-interactive','--agree-tos','--email',p['email']])
    challenge.unlink();manifest.pop(str(challenge),None)
    atomic(MANIFEST,json.dumps(manifest,sort_keys=True).encode())

def configure_renewal(p, manifest):
    # Existing bot HTTP-01 forwarding still reaches bridge:80. Keep that path served.
    old=json.loads((ROOT/'spec.before.json').read_text())
    old_domain=old.get('public_xhttp_tls',{}).get('server_name','')
    if old_domain:
        acme=Path('/etc/nginx/conf.d/ultra-bot-acme.conf')
        if old_domain != p['domain']:
            owned(acme,(f'server {{ listen 80; server_name {old_domain}; location ^~ /.well-known/acme-challenge/ {{ root /var/www/ultra-acme; access_log off; }} location / {{ return 404; }} }}\n').encode(),manifest)
        renewal=Path('/etc/letsencrypt/renewal')/(old_domain+'.conf')
        if renewal.exists():
            raw=renewal.read_text()
            if 'authenticator = standalone' in raw:
                backup=ROOT/'bot-renewal.before.conf'
                if not backup.exists(): atomic(backup,raw.encode())
                raw=raw.replace('authenticator = standalone','authenticator = webroot')
                raw += '\nwebroot_path = /var/www/ultra-acme,\n[[webroot_map]]\n'+old_domain+' = /var/www/ultra-acme\n'
                atomic(renewal,raw.encode())
    hook=Path('/etc/letsencrypt/renewal-hooks/deploy/ultra-vpn')
    owned(hook,(f'#!/bin/sh\nset -eu\n[ "${{RENEWED_LINEAGE:-}}" = "/etc/letsencrypt/live/{p["domain"]}" ] || exit 0\nnginx -t\nsystemctl reload nginx\nif systemctl is-active --quiet ultra-experimental; then\n install -o ultra-experimental -g ultra-experimental -m 600 "$RENEWED_LINEAGE/fullchain.pem" /etc/ultra-experimental/fullchain.pem\n install -o ultra-experimental -g ultra-experimental -m 600 "$RENEWED_LINEAGE/privkey.pem" /etc/ultra-experimental/privkey.pem\n /opt/ultra-experimental/ultra-relay -transport-spec /etc/ultra-experimental/spec.json -check\n systemctl restart ultra-experimental\nfi\n').encode(),manifest,0o755)
    run(['systemctl','enable','--now','certbot.timer'])

def experiment(p, manifest):
    run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','ultra-experimental']) if subprocess.run(['id','ultra-experimental'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode else None
    directory=Path('/etc/ultra-experimental');directory.mkdir(exist_ok=True);os.chmod(directory,0o750)
    run(['chown','root:ultra-experimental',str(directory)])
    Path('/opt/ultra-experimental').mkdir(parents=True,exist_ok=True)
    binary=Path('/opt/ultra-experimental/ultra-relay')
    source=Path(p['binary'])
    old=binary.read_bytes() if binary.exists() else None
    binary_changed=old!=source.read_bytes()
    if binary_changed: atomic(binary,source.read_bytes(),0o755)
    for name in ['fullchain.pem','privkey.pem']:
        run(['install','-o','ultra-experimental','-g','ultra-experimental','-m','600',f'/etc/letsencrypt/live/{p["domain"]}/{name}',str(directory/name)])
    profile={'host':p.get('public_host',p['domain']),'endpoint':endpoint(p,p['experimental_port'],experimental=True),'status_port':p['status_port']}
    private=json.loads(json.dumps(profile))
    private['endpoint'].pop('fingerprint',None)  # Publication-only changes must not restart the gateway.
    private['endpoint'].update(certificate_file=str(directory/'fullchain.pem'),key_file=str(directory/'privkey.pem'))
    transport={'profile':private,'backend_port':p['gateway_port']}
    changed=owned(directory/'spec.json',json.dumps(transport,sort_keys=True).encode(),manifest,0o640)
    run(['chown','root:ultra-experimental',str(directory/'spec.json')])
    unit=b'''[Unit]\nDescription=Ultra isolated experimental transport\nAfter=network-online.target ultra-relay.service\n[Service]\nUser=ultra-experimental\nGroup=ultra-experimental\nExecStart=/opt/ultra-experimental/ultra-relay -transport-spec /etc/ultra-experimental/spec.json\nRestart=on-failure\nRestartSec=5\nMemoryMax=256M\nCPUQuota=50%\nTasksMax=64\nLimitNOFILE=8192\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n[Install]\nWantedBy=multi-user.target\n'''
    unit_changed=owned(UNIT,unit,manifest)
    run(['runuser','-u','ultra-experimental','--',str(binary),'-transport-spec',str(directory/'spec.json'),'-check'])
    if unit_changed:run(['systemctl','daemon-reload'])
    run(['systemctl','enable','ultra-experimental'])
    active=subprocess.run(['systemctl','is-active','--quiet','ultra-experimental']).returncode==0
    if changed or binary_changed or unit_changed or not active:run(['systemctl','restart','ultra-experimental'])
    wait_experiment(p['status_port'])
    raw=json.dumps(profile,sort_keys=True).encode()
    target=Path('/etc/ultra-relay/experimental-profile.json')
    owned(target,raw,manifest,0o644)
    print('experiment_ready=true')

def recovery_spec(current, saved, backend_port):
    spec=dict(current)
    primary=saved.get('primary_xhttp')
    if primary and primary.get('published',True):
        spec['primary_xhttp']=dict(primary)
        if saved.get('public_xhttp_tls'):spec['public_xhttp_tls']=saved['public_xhttp_tls']
        else:spec.pop('public_xhttp_tls',None)
    else:
        tls=saved['public_xhttp_tls']
        spec['public_xhttp_tls']=tls
        spec['primary_xhttp']={'host':spec['public_host'],'backend_port':backend_port,'published':True,**{k:v for k,v in tls.items() if k not in ['certificate_file','key_file']}}
    spec['legacy_public_enabled']=False
    return spec

def check_stage(spec, action):
    if action=='stage' and spec.get('primary_xhttp',{}).get('published',True) and spec.get('primary_xhttp'):
        raise ValueError('stage cannot replace a published primary; use the isolated experiment')

def apply(p, action):
    manifest=json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    if action=='notice':
        values={}
        for line in Path('/etc/ultra-relay/environment').read_text().splitlines():
            if '=' in line:
                k,v=line.split('=',1);values[k]=v.strip().strip(chr(34)).strip(chr(39))
        raw=json.dumps({'key':p['notice_key'],'text':p['notice_text']}).encode()
        req=urllib.request.Request('http://127.0.0.1:8443/v1/ingress/notice',data=raw,headers={'Authorization':'Bearer '+values.get('ULTRA_RELAY_ADMIN_TOKEN',''),'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=10) as response:print('notice_queued='+str(json.load(response)['queued']))
        return
    if action=='status':
        state={}
        for service in ['ultra-relay','ultra-bot','nginx','ultra-experimental']:
            state[service]=subprocess.run(['systemctl','is-active',service],capture_output=True,text=True).stdout.strip()
        print(json.dumps(state));return
    check_stage(json.loads(SPEC.read_text()),action)
    ROOT.mkdir(parents=True,exist_ok=True);os.chmod(ROOT,0o700)
    if not (ROOT/'spec.before.json').exists():
        atomic(ROOT/'spec.before.json',SPEC.read_bytes())
        atomic(ROOT/'relay.before',Path('/usr/local/bin/ultra-relay').read_bytes(),0o755)
        if Path('/usr/local/bin/ultra-bot').exists():atomic(ROOT/'bot.before',Path('/usr/local/bin/ultra-bot').read_bytes(),0o755)
    before=SPEC.read_bytes();old_site=SITE.read_bytes() if SITE.exists() else None
    old_site_owner=manifest.get(str(SITE))
    before_binary=Path('/usr/local/bin/ultra-relay').read_bytes()
    try:
        if action=='rollback':
            # Restore the known working TLS endpoint, not the failed REALITY-only subscription.
            spec=recovery_spec(json.loads(before),json.loads((ROOT/'spec.before.json').read_text()),p['backend_port'])
            atomic(SPEC,json.dumps(spec).encode())
            run([p['binary'],'-spec',str(SPEC),'-check'])
            # Keep the ACME webroot and independent experimental gateway available during recovery.
            run(['systemctl','restart','ultra-relay']);wait_relay()
            print('working_xhttp_recovery_restored=true')
        elif action=='experiment':
            experiment(p,manifest)
        else:
            if action=='stage':prepare_certificate(p,manifest)
            spec=json.loads(SPEC.read_text())
            public_port=p['staging_port'] if action=='stage' else 443
            primary={'host':p.get('public_host',p['domain']),'backend_port':p['backend_port'],'published':action=='activate',**endpoint(p,public_port)}
            spec['primary_xhttp']=primary
            spec['gateway_vless_port']=p['gateway_port']
            spec['experimental_profile_file']='/etc/ultra-relay/experimental-profile.json'
            if action=='activate':
                spec['legacy_public_enabled']=False
                spec.pop('public_xhttp_tls',None)
            raw=json.dumps(spec,sort_keys=True).encode()
            candidate=ROOT/'spec.next.json';atomic(candidate,raw)
            run([p['binary'],'-spec',str(candidate),'-check'])
            content=nginx(p,public_port)
            changed=owned(SITE,content,manifest)
            configure_renewal(p,manifest)
            run(['nginx','-t'])
            binary_changed=Path('/usr/local/bin/ultra-relay').read_bytes()!=Path(p['binary']).read_bytes()
            if binary_changed:atomic(Path('/usr/local/bin/ultra-relay'),Path(p['binary']).read_bytes(),0o755)
            spec_changed=before!=raw
            if spec_changed:atomic(SPEC,raw)
            if spec_changed or binary_changed:
                run(['systemctl','stop','ultra-bot'])
                run(['systemctl','restart','ultra-relay']);wait_relay()
                run(['systemctl','start','ultra-bot'])
            if changed:run(['systemctl','reload','nginx'])
            import socket,ssl
            context=ssl.create_default_context()
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            with socket.create_connection((p.get('public_host',p['domain']),public_port),timeout=5) as connection:
                with context.wrap_socket(connection,server_hostname=p['domain']):pass
            if action=='stage':
                candidate_profile={'host':p.get('public_host',p['domain']),'endpoint':endpoint(p,public_port),'status_port':p['status_port']}
                owned(Path('/etc/ultra-relay/experimental-profile.json'),json.dumps(candidate_profile,sort_keys=True).encode(),manifest,0o644)
            print('ingress_'+action+'_ready=true')
        atomic(MANIFEST,json.dumps(manifest,sort_keys=True).encode())
    except Exception:
        atomic(SPEC,before)
        atomic(Path('/usr/local/bin/ultra-relay'),before_binary,0o755)
        if old_site is None:
            if SITE.exists():SITE.unlink()
        else:atomic(SITE,old_site,0o644)
        # A failed apply must not claim ownership of a rejected foreign configuration.
        if old_site_owner is None:manifest.pop(str(SITE),None)
        else:manifest[str(SITE)]=old_site_owner
        atomic(MANIFEST,json.dumps(manifest,sort_keys=True).encode())
        if action not in ['experiment','status']:
            subprocess.run(['nginx','-t'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['systemctl','reload','nginx'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['systemctl','restart','ultra-relay'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['systemctl','start','ultra-bot'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise

def validate(p):
    for key in ['fingerprint','experimental_fingerprint']:
        if key in p and p[key] not in ['chrome','firefox']:raise ValueError('invalid TLS fingerprint')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',p['domain']) or '..' in p['domain']:raise ValueError('invalid domain')
    if not re.fullmatch(r'/[a-zA-Z0-9_-]+',p['path']):raise ValueError('invalid HTTP path')
    if p.get('email') and not re.fullmatch(r'[^\s@]+@[^\s@]+',p['email']):raise ValueError('invalid ACME email')
    if not re.fullmatch(r'[a-zA-Z0-9.:-]+',p.get('public_host',p['domain'])):raise ValueError('invalid public host')
    if not p['binary'].startswith('/') or '..' in Path(p['binary']).parts:raise ValueError('invalid binary path')
    ports=[p[k] for k in ['backend_port','gateway_port','status_port','experimental_port','staging_port']]
    if len(set(ports))!=len(ports) or any(not isinstance(n,int) or n<1024 or n>65535 for n in ports):raise ValueError('invalid ports')

def main():
    if len(sys.argv)==2 and sys.argv[1]=='--self-test':
        p=dict(domain='example.com',path='/connect',email='test@example.com',binary='/tmp/relay',backend_port=18080,gateway_port=18081,status_port=18082,experimental_port=5543,staging_port=18443)
        check_stage({},'stage')
        check_stage({'primary_xhttp':{'published':False}},'stage')
        check_stage({'primary_xhttp':{}},'activate')
        for published in [{'port':443},{'port':443,'published':True}]:
            try:check_stage({'primary_xhttp':published},'stage')
            except ValueError:pass
            else:raise AssertionError('published primary can be replaced by staging')
        validate(p);n=nginx(p,443).decode();assert 'grpc_pass grpc://127.0.0.1:18080' in n and 'X-Forwarded-For $remote_addr' in n and 'listen 443 ssl http2' in n
        assert endpoint(p,443)['fingerprint']=='chrome'
        fp={**p,'experimental_fingerprint':'firefox'};validate(fp)
        assert endpoint(fp,443)['fingerprint']=='chrome' and endpoint(fp,5543,experimental=True)['fingerprint']=='firefox'
        assert endpoint({**p,'fingerprint':'firefox'},443)['fingerprint']=='firefox'
        current={'public_host':'example.com','gateway_vless_port':18081,'experimental_profile_file':'/etc/ultra-relay/experiment.json'}
        saved={'public_xhttp_tls':{'port':5443,'server_name':'example.com','path':'/old','certificate_file':'/cert','key_file':'/key'}}
        restored=recovery_spec(current,saved,18080)
        assert restored['gateway_vless_port']==18081 and restored['experimental_profile_file']==current['experimental_profile_file']
        assert restored['primary_xhttp']['port']==5443 and 'key_file' not in restored['primary_xhttp']
        assert restored['public_xhttp_tls']==saved['public_xhttp_tls'] and restored['legacy_public_enabled'] is False
        assert 'primary_xhttp' not in current
        working={**saved,'primary_xhttp':{'host':'bridge.example','port':5543,'backend_port':18080,'published':True,'fingerprint':'firefox','server_name':'example.com','path':'/working'}}
        recovered=recovery_spec(current,working,18080)
        assert recovered['primary_xhttp']==working['primary_xhttp'] and recovered['primary_xhttp']['port']!=saved['public_xhttp_tls']['port']
        assert recovered['gateway_vless_port']==current['gateway_vless_port']
        for k,v in [('domain','x;evil'),('path','/x;evil'),('backend_port',443),('fingerprint','random'),('experimental_fingerprint','invalid')]:
            q={**p,k:v}
            try:validate(q)
            except ValueError:pass
            else:raise AssertionError('invalid input accepted')
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            global MANIFEST, ROOT, SPEC, SITE
            MANIFEST=Path(directory)/'manifest.json'
            target=Path(directory)/'owned.conf';manifest={}
            assert owned(target,b'one',manifest)
            stamp=target.stat().st_mtime_ns
            assert not owned(target,b'one',manifest) and target.stat().st_mtime_ns==stamp
            from unittest.mock import patch
            original_atomic=atomic
            for initial in (None,b'one'):
                crash_target=Path(directory)/('new.conf' if initial is None else 'existing.conf')
                state={}
                if initial is not None:
                    crash_target.write_bytes(initial);state[str(crash_target)]=digest(initial)
                atomic(MANIFEST,json.dumps(state).encode())
                def interrupted(path,*args,**kwargs):
                    original_atomic(path,*args,**kwargs)
                    if path==crash_target:raise SystemExit('simulated power loss')
                with patch.dict(globals(),atomic=interrupted):
                    try:owned(crash_target,b'two',state)
                    except SystemExit:pass
                    else:raise AssertionError('failure injection missed')
                state=json.loads(MANIFEST.read_text())
                owned(crash_target,b'two',state)
                assert state[str(crash_target)]==digest(b'two')
                assert not MANIFEST.with_name(MANIFEST.name+'.pending').exists()
            for crash_phase in ('journal','receipt'):
                crash_target=Path(directory)/(crash_phase+'.conf')
                state={};atomic(MANIFEST,b'{}')
                crash_at=MANIFEST if crash_phase=='receipt' else MANIFEST.with_name(MANIFEST.name+'.pending')
                def interrupted(path,*args,**kwargs):
                    original_atomic(path,*args,**kwargs)
                    if path==crash_at:raise SystemExit('simulated power loss')
                with patch.dict(globals(),atomic=interrupted):
                    try:owned(crash_target,b'two',state)
                    except SystemExit:pass
                state=json.loads(MANIFEST.read_text())
                owned(crash_target,b'two',state)
                assert crash_target.read_bytes()==b'two' and state[str(crash_target)]==digest(b'two')
                assert not MANIFEST.with_name(MANIFEST.name+'.pending').exists()
            # A pending operation must not adopt unrelated edits.
            atomic(MANIFEST,json.dumps({str(target):digest(b'one')}).encode())
            state=json.loads(MANIFEST.read_text())
            def interrupted(path,*args,**kwargs):
                original_atomic(path,*args,**kwargs)
                if path==target:raise SystemExit('simulated power loss')
            with patch.dict(globals(),atomic=interrupted):
                try:owned(target,b'two',state)
                except SystemExit:pass
            target.write_bytes(b'foreign')
            try:owned(target,b'two',json.loads(MANIFEST.read_text()))
            except RuntimeError:pass
            else:raise AssertionError('pending transaction adopted foreign file')
            MANIFEST.with_name(MANIFEST.name+'.pending').unlink(missing_ok=True)
            target.write_bytes(b'foreign')
            try:owned(target,b'two',manifest)
            except RuntimeError:pass
            else:raise AssertionError('foreign configuration overwritten')
            # Exercise failed activation: foreign files must remain foreign after rollback.
            from unittest.mock import patch
            ROOT=Path(directory)/'state';ROOT.mkdir()
            SPEC=Path(directory)/'spec.json';SPEC.write_text('{}')
            SITE=target
            (ROOT/'spec.before.json').write_text('{}')
            fake_binary=Path(directory)/'relay';fake_binary.write_bytes(b'binary')
            p['binary']=str(fake_binary)
            original_read=Path.read_bytes
            original_atomic=atomic
            def read_test(path):
                return b'binary' if str(path)=='/usr/local/bin/ultra-relay' else original_read(path)
            def atomic_test(path,*args,**kwargs):
                if str(path)!='/usr/local/bin/ultra-relay':original_atomic(path,*args,**kwargs)
            with patch.object(Path,'read_bytes',read_test), patch.dict(globals(),atomic=atomic_test,run=lambda *a,**k:None), patch.object(subprocess,'run'):
                try:apply(p,'activate')
                except RuntimeError:pass
                else:raise AssertionError('foreign site accepted during activation')
            assert SITE.read_bytes()==b'foreign'
            assert json.loads(MANIFEST.read_text()).get(str(SITE))!=digest(b'foreign')

        print('ingress renderer and ownership self-test: PASS');return
    action=sys.argv[1]
    if action not in ['stage','activate','experiment','rollback','status','notice']:raise ValueError('invalid action')
    p=json.loads(base64.b64decode(sys.argv[2]));validate(p);apply(p,action)

if __name__=='__main__':
    try:main()
    except Exception as e:
        # Subprocess output can include credentials; report only the failed operation.
        if isinstance(e,subprocess.CalledProcessError):print('ingress failed: '+str(e.cmd[0]),file=sys.stderr)
        else:print('ingress failed: '+str(e),file=sys.stderr)
        sys.exit(1)
