#!/usr/bin/env python3
"""Explicit alias-first domain publication. Existing listeners, users, and tokens are retained."""
import argparse
import base64
import copy
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import urllib.parse

from dns import execute as dns_execute, wait_ready, private, save


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=kwargs.pop('timeout', 60), **kwargs)
    if result.returncode:
        raise ValueError('cutover_command_failed')
    return result.stdout


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def candidate_spec(before, target):
    after = copy.deepcopy(before)
    old = before.get('primary_xhttp', {})
    if not old or old.get('published', True) is not True or old.get('port') != 443:
        raise ValueError('cutover_requires_published_primary')
    if old['path'] != target['path'] or old['backend_port'] != target['backend_port']:
        raise ValueError('cutover_cannot_change_transport')
    primary = after['primary_xhttp']
    primary['host'] = target['public_host']
    primary['server_name'] = target['domain']
    for descriptor in after.get('subscription_bridges', []):
        if descriptor.get('security') != 'tls':
            continue
        if (descriptor.get('host'), descriptor.get('server_name'), descriptor.get('port'), descriptor.get('path')) != (old['host'], old['server_name'], old['port'], old['path']):
            raise ValueError('cutover_unknown_tls_publication')
        descriptor['host'] = target['public_host']
        descriptor['server_name'] = target['domain']
    return after


def single_alias_probe(profile, old, target, bridge_ip):
    matches = []
    for outbound in profile.get('outbounds', []):
        stream = outbound.get('streamSettings', {})
        destinations = outbound.get('settings', {}).get('vnext', [])
        if (outbound.get('protocol') == 'vless' and stream.get('security') == 'tls'
                and stream.get('network') == 'xhttp' and stream.get('tlsSettings', {}).get('serverName') == old['server_name']
                and len(destinations) == 1 and destinations[0]['address'] == old['host'] and destinations[0]['port'] == 443):
            matches.append(copy.deepcopy(outbound))
    if not matches:
        raise ValueError('cutover_monitor_tls_route_missing')
    selected = matches[0]
    selected['tag'] = 'cutover-edge-only'
    selected['settings']['vnext'][0]['address'] = bridge_ip
    selected['streamSettings']['tlsSettings']['serverName'] = target['domain']
    selected['streamSettings']['tlsSettings'].pop('allowInsecure', None)
    if selected['streamSettings'].get('xhttpSettings', {}).get('downloadSettings'):
        raise ValueError('cutover_split_download_requires_explicit_plan')
    return {'outbounds': [selected]}


def subscription_shape(raw):
    try:
        document = json.loads(raw)
    except ValueError:
        try:
            text = base64.b64decode(raw + b'='*((-len(raw))%4), validate=True).decode()
        except (ValueError, UnicodeError):
            text = raw.decode()
        uris = [line for line in text.splitlines() if line.startswith('vless://')]
        if not uris:
            raise ValueError('cutover_subscription_invalid')
        credentials = sorted(urllib.parse.urlsplit(uri).username for uri in uris)
    else:
        if not isinstance(document, dict) or not isinstance(document.get('outbounds'), list):
            raise ValueError('cutover_subscription_invalid')
        credentials = sorted(user['id'] for row in document['outbounds'] if row.get('protocol') == 'vless'
                             for destination in row.get('settings', {}).get('vnext', []) for user in destination.get('users', []))
        if not credentials:
            raise ValueError('cutover_subscription_invalid')
    return {'credential_digest': digest(json.dumps(credentials).encode()), 'routes': len(credentials)}


def subscription_tls_endpoints(raw):
    try:
        doc=json.loads(raw)
    except ValueError:
        try:text=base64.b64decode(raw+b'='*((-len(raw))%4),validate=True).decode()
        except (ValueError,UnicodeError):text=raw.decode()
        endpoints=[]
        for line in text.splitlines():
            if not line.startswith('vless://'):continue
            parsed=urllib.parse.urlsplit(line);query=urllib.parse.parse_qs(parsed.query)
            if query.get('security')==['tls']:endpoints.append((parsed.hostname,query.get('sni',[''])[0]))
        return set(endpoints)
    endpoints=set()
    for outbound in doc.get('outbounds',[]):
        stream=outbound.get('streamSettings',{})
        if stream.get('security')!='tls':continue
        for destination in outbound.get('settings',{}).get('vnext',[]):
            endpoints.add((destination['address'],stream.get('tlsSettings',{}).get('serverName','')))
    return endpoints


def https(host, address, port, request_path):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((address, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.sendall(('GET ' + request_path + ' HTTP/1.1\r\nHost: ' + host + '\r\nUser-Agent: Happ/4.7.1/Android/cutover-check\r\nConnection: close\r\n\r\n').encode())
            response = http.client.HTTPResponse(connection)
            response.begin()
            data = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(data) > 1024 * 1024:
                raise ValueError('cutover_https_failed')
            return data


class Host:
    def __init__(self, plan, directory):
        self.plan = plan
        self.directory = directory
        self.subscription = load_module('bridge_subscription')
        self.ingress = load_module('xhttp_ingress')
        self.spec_path = Path('/etc/ultra-relay/spec.json')
        self.public_dropin = Path('/etc/systemd/system/ultra-bot.service.d/zz-domain-public-origin.conf')
        self.public_env = Path('/etc/ultra-relay/domain-public.env')

    def prepare(self):
        run(['python3', '/opt/ultra-recovery/recovery.py', 'capture', '--config', '/etc/ultra-recovery/backup.json'], timeout=175)
        backup = json.loads(private('/var/lib/ultra-recovery/last-success.json').read_text())
        if not 0 <= time.time() - backup['snapshot_at'] <= 180 or not backup.get('destinations'):
            raise ValueError('cutover_fresh_backup_required')
        imported = json.loads(private(self.plan['dns_receipt_source']).read_text())
        if imported.get('zone') != self.plan['dns']['zone'] or imported.get('pending') or set(imported.get('records', {})) != {'subscription','vpn'}:
            raise ValueError('cutover_owned_dns_receipt_required')
        receipt = Path('/etc/ultra-recovery/dns-receipt.json')
        if receipt.exists():
            existing = json.loads(private(receipt).read_text())
            if existing.get('zone') != imported['zone'] or {k:v['id'] for k,v in existing['records'].items()} != {k:v['id'] for k,v in imported['records'].items()}:
                raise ValueError('cutover_dns_ownership_drift')
        else:save(receipt, imported)
        self.subscription.atomic(Path(self.plan['dns']['api_key_file']),private(self.plan['dns_key_source']).read_bytes(),0o600)
        before = self.spec_path.read_bytes()
        old = json.loads(before)
        candidate = candidate_spec(old, self.plan['ingress'])
        environment = read_env('/etc/ultra-relay/environment')
        bot_domain = environment.get('ULTRA_BOT_DOMAIN', '')
        bot_port = int(environment.get('ULTRA_BOT_PORT', '8444'))
        self.subscription.validate({'domain':self.plan['subscription_domain'], 'upstream_domain':bot_domain, 'bot_port':bot_port})
        https(bot_domain, '127.0.0.1', bot_port, '/healthz')
        for name, data in [('before-spec.json', before), ('candidate-spec.json', json.dumps(candidate, sort_keys=True).encode())]:
            self.subscription.atomic(self.directory/name, data, 0o600)
        if self.public_dropin.exists() or self.public_env.exists():
            # Never adopt unrelated drop-ins or overwrite an operator's public-origin policy.
            raise ValueError('cutover_existing_public_origin_requires_review')
        save(self.directory/'metadata.json', {'bot_domain':bot_domain, 'bot_port':bot_port,
             'before_sha':digest(before), 'candidate_sha':digest((self.directory/'candidate-spec.json').read_bytes()),
             'relay_sha':digest(Path('/usr/local/bin/ultra-relay').read_bytes())})

    def check_spec(self, allowed):
        metadata = json.loads((self.directory/'metadata.json').read_text())
        for name in ('before', 'candidate'):
            if digest((self.directory/(name+'-spec.json')).read_bytes()) != metadata[name+'_sha']:
                raise ValueError('cutover_saved_spec_corrupted')
        if digest(Path('/usr/local/bin/ultra-relay').read_bytes()) != metadata['relay_sha']:
            raise ValueError('cutover_binary_changed')
        if digest(self.spec_path.read_bytes()) not in {metadata[key+'_sha'] for key in allowed}:
            raise ValueError('cutover_spec_drift')

    def aliases(self):
        self.check_spec(['before'])
        dns = self.plan['dns']
        desired = self.plan['desired']
        dns_execute(dns, desired, '/etc/ultra-recovery/dns-receipt.json')
        wait_ready(dns, desired)
        save('/etc/ultra-recovery/dns.json', {'config':dns,'desired':desired})
        manifest = json.loads(self.ingress.MANIFEST.read_text()) if self.ingress.MANIFEST.exists() else {}
        parameters = dict(self.plan['ingress'], binary='/usr/local/bin/ultra-relay')
        self.ingress.prepare_certificate(parameters, manifest)
        self.ingress.prepare_certificate(dict(parameters, domain=self.plan['subscription_domain']), manifest)
        # Preserve the old endpoint in a separate owned file; the standard site becomes
        # the new primary, so a later ordinary apply does not create duplicate vhosts.
        site = Path('/etc/nginx/conf.d/ultra-vpn.conf')
        legacy = Path('/etc/nginx/conf.d/ultra-vpn-legacy.conf')
        previous_site=site.read_bytes() if site.exists() else None
        previous_legacy=legacy.read_bytes() if legacy.exists() else None
        previous_manifest=self.ingress.MANIFEST.read_bytes()
        content=self.ingress.nginx(parameters,443)
        try:
            if previous_site is None:raise ValueError('cutover_primary_site_missing')
            if previous_site!=content:
                if manifest.get(str(site))!=digest(previous_site):raise ValueError('cutover_primary_site_drift')
                if previous_legacy is not None and previous_legacy!=previous_site:raise ValueError('cutover_legacy_site_conflict')
                self.ingress.owned(legacy,previous_site,manifest)
            elif previous_legacy is None:raise ValueError('cutover_legacy_site_missing')
            self.ingress.owned(site, content, manifest)
            metadata = json.loads((self.directory/'metadata.json').read_text())
            self.subscription.install({'domain':self.plan['subscription_domain'], 'upstream_domain':metadata['bot_domain'], 'bot_port':metadata['bot_port']})
        except Exception:
            for path,previous in ((site,previous_site),(legacy,previous_legacy)):
                if previous is None:path.unlink(missing_ok=True)
                else:self.subscription.atomic(path,previous,0o644)
            self.subscription.atomic(self.ingress.MANIFEST,previous_manifest,0o600)
            run(['nginx','-t']);run(['systemctl','reload','nginx'])
            raise
        run(['systemctl', 'enable', '--now', 'certbot.timer'])
        manifest=json.loads(self.ingress.MANIFEST.read_text())
        self.ingress.owned(Path('/etc/letsencrypt/renewal-hooks/deploy/ultra-domain-alias'),
            b'#!/bin/sh\nset -eu\nnginx -t\nsystemctl reload nginx\n', manifest, 0o755)

    def validate(self, published):
        self.check_spec(['candidate'] if published else ['before'])
        parsed = urllib.parse.urlsplit(private(self.plan['subscription_url_file']).read_text().strip())
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('cutover_private_subscription_url_invalid')
        if not parsed.path.startswith('/sub/') or any(c in parsed.path for c in '\r\n '):
            raise ValueError('cutover_private_subscription_path_invalid')
        # Fixed explicit formats override any preview or caller-controlled query.
        for fmt in ('happ', 'uri'):
            request_path = parsed.path + '?format=' + fmt
            old_shape = subscription_shape(https(parsed.hostname, parsed.hostname, parsed.port or 443, request_path))
            new_body=https(self.plan['subscription_domain'], self.plan['bridge_ipv4'], 443, request_path)
            new_shape = subscription_shape(new_body)
            if published and (self.plan['ingress']['public_host'],self.plan['ingress']['domain']) not in subscription_tls_endpoints(new_body):
                raise ValueError('cutover_publication_not_visible')
            if old_shape != new_shape:
                raise ValueError('cutover_subscription_identity_changed')
            baseline = self.directory/('subscription-'+fmt+'.json')
            if baseline.exists():
                if json.loads(baseline.read_text()) != new_shape:
                    raise ValueError('cutover_subscription_identity_changed')
            else:
                save(baseline, new_shape)
        before = json.loads((self.directory/'before-spec.json').read_text())
        profile = json.loads(private('/etc/ultra-recovery/probe.json').read_text())
        # Reconcile can refresh the profile after publication; accept either known old or new endpoint.
        old = before['primary_xhttp']
        if published:
            old = json.loads((self.directory/'candidate-spec.json').read_text())['primary_xhttp']
        try:
            profile = single_alias_probe(profile, old, self.plan['ingress'], self.plan['bridge_ipv4'])
        except ValueError:
            if not published: raise
            profile = single_alias_probe(json.loads(private('/etc/ultra-recovery/probe.json').read_text()), before['primary_xhttp'], self.plan['ingress'], self.plan['bridge_ipv4'])
        save(self.directory/'probe.json', profile)
        sockets = []
        for _ in range(2):
            sock = socket.socket();sock.bind(('127.0.0.1',0));sockets.append(sock)
        ports = [sock.getsockname()[1] for sock in sockets]
        for sock in sockets:sock.close()
        process = subprocess.Popen(['/usr/local/bin/ultra-client','-config',str(self.directory/'probe.json'),'-socks','127.0.0.1:'+str(ports[0]),'-http','127.0.0.1:'+str(ports[1])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic()+25
            while True:
                if process.poll() is not None:raise ValueError('cutover_probe_client_failed')
                try:
                    data = run(['curl','--silent','--fail','--max-time','8','--connect-timeout','3','--max-filesize','16384','--noproxy','','--proxy','socks5h://127.0.0.1:'+str(ports[0]),'https://www.cloudflare.com/cdn-cgi/trace'], timeout=10)
                    if re.search(rb'(?m)^ip=[0-9a-fA-F:.]+$',data):break
                    raise ValueError('cutover_payload_invalid')
                except ValueError:
                    if time.monotonic()>=deadline:raise ValueError('cutover_payload_unavailable') from None
                    time.sleep(.25)
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

    def restart(self):
        run(['systemctl','stop','ultra-bot'])
        run(['systemctl','restart','ultra-relay'])
        self.ingress.wait_relay()
        run(['systemctl','daemon-reload'])
        if self.public_dropin.exists():
            files = run(['systemctl','show','ultra-bot','--property=EnvironmentFiles','--value']).decode()
            order = re.findall(r'(\S+) \(ignore_errors=(?:yes|no)\)',files)
            if not order or order[-1]!=str(self.public_env):raise ValueError('cutover_public_origin_precedence_failed')
        run(['systemctl','start','ultra-bot'])
        metadata=json.loads((self.directory/'metadata.json').read_text())
        deadline=time.monotonic()+30
        while True:
            try:
                https(metadata['bot_domain'],'127.0.0.1',metadata['bot_port'],'/healthz')
                break
            except (OSError, ValueError, http.client.HTTPException):
                if time.monotonic()>=deadline:raise ValueError('cutover_bot_not_ready') from None
                time.sleep(.25)

    def public_files(self):
        return {self.public_dropin:('[Service]\nEnvironmentFile='+str(self.public_env)+'\n').encode(),
                self.public_env:('ULTRA_BOT_PUBLIC_URL=https://'+self.plan['subscription_domain']+'\n').encode()}

    def publish(self):
        self.check_spec(['before','candidate'])
        candidate = self.directory/'candidate-spec.json'
        run(['/usr/local/bin/ultra-relay','-spec',str(candidate),'-check'])
        for path,data in self.public_files().items():
            if path.exists() and path.read_bytes()!=data:raise ValueError('cutover_public_origin_drift')
        self.subscription.atomic(self.spec_path,candidate.read_bytes(),0o600)
        for path,data in self.public_files().items():
            self.subscription.atomic(path,data,0o600 if path==self.public_env else 0o644)
        self.restart()

    def finalize(self):
        # Retain old inventory and ingress. New aliases must survive disaster recovery too.
        backup_path=Path('/etc/ultra-recovery/backup.json')
        backup=json.loads(private(backup_path).read_text())
        inventory=set(backup['state_paths'])
        inventory.update(('/etc/ultra-recovery','/etc/ultra-relay',
                          '/etc/systemd/system/ultra-bot.service.d',str(self.ingress.MANIFEST)))
        manifest=json.loads(self.ingress.MANIFEST.read_text())
        for name,expected in manifest.items():
            if not name.startswith(('/etc/nginx/','/etc/letsencrypt/renewal-hooks/','/var/www/ultra-')):continue
            path=Path(name)
            if not path.is_file() or digest(path.read_bytes())!=expected:
                raise ValueError('cutover_ingress_inventory_drift')
            inventory.add(name)
        for domain in (self.plan['subscription_domain'],self.plan['ingress']['domain']):
            renewal=Path('/etc/letsencrypt/renewal')/(domain+'.conf')
            live=Path('/etc/letsencrypt/live')/domain
            if not renewal.is_file() or not live.is_dir():raise ValueError('cutover_certificate_inventory_missing')
            inventory.update((str(renewal),str(live)))
            account=re.search(r'^account\s*=\s*([a-f0-9]+)\s*$',renewal.read_text(),re.M)
            if account:
                matches=list(Path('/etc/letsencrypt/accounts').glob('*/directory/'+account.group(1)))
                if len(matches)!=1:raise ValueError('cutover_acme_account_missing')
                inventory.add(str(matches[0]))
        backup['state_paths']=sorted(inventory)
        save(backup_path,backup)
        for name in ('reconcile','deployment'):
            path=Path('/etc/ultra-recovery')/(name+'.json')
            value=json.loads(private(path).read_text())
            value['bridge_url']='https://'+self.plan['subscription_domain']+'/healthz'
            if name=='deployment':
                value['ingress']=dict(self.plan['ingress'])
                value['ingress_mode']='direct'
                value['subscription_domain']=self.plan['subscription_domain']
            save(path,value)
        run(['python3','/opt/ultra-recovery/recovery.py','capture','--config',str(backup_path)],timeout=175)

    def rollback(self):
        self.check_spec(['before','candidate'])
        for path,data in self.public_files().items():
            if path.exists() and path.read_bytes()!=data:raise ValueError('cutover_public_origin_drift')
        self.subscription.atomic(self.spec_path,(self.directory/'before-spec.json').read_bytes(),0o600)
        for path in self.public_files():
            path.unlink(missing_ok=True)
        self.restart()


def execute(plan, directory, host_factory=Host):
    directory = Path(directory)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    if directory.is_symlink():raise ValueError('cutover_work_symlink')
    os.chmod(directory,0o700)
    fd=os.open(directory/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        fingerprint = digest(json.dumps({key:plan[key] for key in ('bridge_ipv4','subscription_domain','ingress','desired')},sort_keys=True).encode())
        journal = directory/'journal.json'
        state = json.loads(private(journal).read_text()) if journal.exists() else {'version':1,'plan':fingerprint,'phase':'new'}
        if state.get('plan') != fingerprint:raise ValueError('cutover_plan_changed')
        host = host_factory(plan,directory)
        if state['phase']=='new':
            host.prepare();state['phase']='prepared';save(journal,state)
        if state['phase'] in ('prepared','rolled_back'):
            host.aliases();state['phase']='aliases';save(journal,state)
        if state['phase']=='aliases':
            host.validate(False);state['phase']='publishing';save(journal,state)
        was_complete=state['phase']=='complete'
        was_finalizing=state['phase']=='finalizing'
        if state['phase']=='publishing':
            try:
                host.publish();host.validate(True)
            except Exception:
                host.rollback();state['phase']='rolled_back';save(journal,state)
                raise ValueError('cutover_publication_failed_rolled_back') from None
            # Publication is verified. Recovery metadata/capture may now be partially
            # durable; resume this phase instead of reverting only the application.
            state['phase']='finalizing';save(journal,state)
        if state['phase']=='finalizing':
            if was_finalizing:host.validate(True)
            host.finalize()
            state['phase']='complete';save(journal,state)
        if state['phase']!='complete':raise ValueError('cutover_invalid_journal')
        if was_complete:host.validate(True)
        return {'cutover':'complete','old_ingress_preserved':True}


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    parser.add_argument('--work',default='/var/lib/ultra-domain-cutover/current')
    args=parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(execute(json.loads(private(args.config).read_text()),args.work)))
    except Exception:
        raise SystemExit('domain cutover failed; private details suppressed') from None
