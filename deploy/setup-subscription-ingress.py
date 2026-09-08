# Executed on bridge by scripts/setup-subscription-ingress.sh; settings is supplied over stdin.
import datetime
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import urllib.request

P = pathlib.Path

def environment():
    result = {}
    for line in P('/etc/ultra-relay/environment').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            result[key] = value.strip().strip('"\'')
    unit = subprocess.check_output(['systemctl', 'show', 'ultra-relay', '-p', 'Environment', '--value'], text=True)
    result.update(dict(item.split('=', 1) for item in shlex.split(unit) if '=' in item))
    return result


def run():
    env = environment()
    spec = json.loads(P('/etc/ultra-relay/spec.json').read_text())
    request = urllib.request.Request('http://' + spec.get('admin_listen', '127.0.0.1:8443') + '/v1/cloud/operations', headers={'Authorization': 'Bearer ' + env['ULTRA_RELAY_ADMIN_TOKEN']})
    operations = json.load(urllib.request.urlopen(request, timeout=20))
    key = P(env['ULTRA_VULTR_KEY_FILE']).read_text().strip()

    def vultr(path, body=None):
        req = urllib.request.Request('https://api.vultr.com/v2' + path,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}

    matches = []
    for candidate in operations:
        if candidate.get('instance_id') and candidate.get('charged'):
            if settings['instance'] and candidate['instance_id'] != settings['instance']:
                continue
            vm = vultr('/instances/' + candidate['instance_id'])['instance']
            if vm['main_ip'] == settings['ingress']:
                matches.append((candidate, vm))
    if len(matches) != 1:
        raise ValueError('managed_ingress_not_unique')
    op, vm = matches[0]
    if vm['firewall_group_id'] != op['firewall_id']:
        raise ValueError('unexpected_firewall')
    # Validate local ownership before touching the remote node or provider firewall.
    hook = P('/etc/letsencrypt/renewal-hooks/deploy/ultra-bot')
    if hook.exists() and hook.read_text() not in [settings['hook'], '#!/bin/sh\nset -eu\nsystemctl try-restart ultra-bot.service\n']:
        raise ValueError('foreign_certificate_hook')
    guard = P('/etc/systemd/system/ultra-relay.service.d/subscription-ingress.conf')
    text = '[Service]\nEnvironment=ULTRA_SUBSCRIPTION_INGRESS_INSTANCE_ID='+op['instance_id']+'\n'
    changed = not guard.exists() or guard.read_text()!=text
    if guard.exists() and changed:
        raise ValueError('move_existing_ingress_explicitly_before_replacing_guard')
    config = settings['config']
    remote = '''import pathlib,subprocess,hashlib,shutil,datetime
P=pathlib.Path
cfg=P('/etc/haproxy/haproxy.cfg');marker=P('/etc/haproxy/ultra-managed.sha256')
installed=subprocess.run(['dpkg-query','-W','-f=${Status}','haproxy'],capture_output=True,text=True).returncode==0
if installed and cfg.exists():
 digest=hashlib.sha256(cfg.read_bytes()).hexdigest()
 if cfg.read_text()!=config and (not marker.exists() or marker.read_text().strip()!=digest):
  raise ValueError('foreign_haproxy_configuration')
backup=P('/root/ultra-ingress-backups')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');backup.mkdir(parents=True,mode=0o700)
if cfg.exists():shutil.copy2(cfg,backup/'haproxy.cfg')
if not installed:
 for command in [['apt-get','update','-qq'],['apt-get','install','-y','haproxy']]:
  subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180)
changed=not cfg.exists() or cfg.read_text()!=config
tmp=P('/etc/haproxy/ultra-next.cfg');tmp.write_text(config)
subprocess.run(['haproxy','-c','-f',str(tmp)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if changed:tmp.replace(cfg)
else:tmp.unlink()
marker.write_text(hashlib.sha256(cfg.read_bytes()).hexdigest())
for port in ['80','443','8444']:
 subprocess.run(['ufw','allow','proto','tcp','from','0.0.0.0/0','to','any','port',port],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['systemctl','enable','--now','haproxy'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if changed:subprocess.run(['systemctl','reload','haproxy'],check=True)
subprocess.run(['systemctl','is-active','--quiet','haproxy'],check=True)
print('haproxy_ready=true config_changed='+str(changed))
'''
    state = env.get('ULTRA_VULTR_STATE_DIR', '/var/lib/ultra-relay/vultr')
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8',
            '-o', 'UserKnownHostsFile=' + state + '/' + op['id'] + '/known_hosts',
            '-i', env['ULTRA_VULTR_SSH_KEY_FILE'], 'root@' + settings['ingress'], 'python3 -']
    result = subprocess.run(args, input='config='+repr(config)+'\n'+remote, capture_output=True, text=True, timeout=420)
    if result.returncode:
        raise RuntimeError('ingress_setup_failed_check_existing_config_and_ports')
    print(result.stdout.strip())
    fid = op['firewall_id']
    rules = vultr('/firewalls/' + fid + '/rules')['firewall_rules']
    backup = P('/root/ultra-ingress-backups') / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup.mkdir(parents=True, mode=0o700)
    (backup/'firewall.json').write_text(json.dumps(rules))
    for port in ['80', '443', '8444']:
        if not any(r.get('ip_type')=='v4' and r.get('protocol')=='tcp' and r.get('subnet')=='0.0.0.0' and r.get('subnet_size')==0 and r.get('port')==port and r.get('action')=='accept' for r in rules):
            vultr('/firewalls/'+fid+'/rules', {'ip_type':'v4','protocol':'tcp','subnet':'0.0.0.0','subnet_size':0,'port':port,'notes':'Ultra HTTPS subscription ingress'})
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(settings['hook']); hook.chmod(0o755)
    guard.parent.mkdir(parents=True, exist_ok=True)
    guard.write_text(text)
    if changed:
        subprocess.run(['systemctl','daemon-reload'],check=True)
    print('firewall_ready=true guard_configured=true relay_restart_required='+str(changed))

try:
    run()
except Exception as error:
    print('ingress_setup_failed='+type(error).__name__, file=sys.stderr)
    sys.exit(1)
