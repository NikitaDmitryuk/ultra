#!/usr/bin/env python3
"""Install a verified Ultra automation release; never print configuration or child output."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
import shlex
import urllib.request
import datetime

ROOT = Path('/opt/ultra-recovery')
CONFIG = Path('/etc/ultra-recovery')
STATE = Path('/var/lib/ultra-automation')
UNITS = Path('/etc/systemd/system')
BIN = Path('/usr/local/bin')
REQUIRED = {'dns.py', 'recovery.py', 'reconcile.py', 'monitor.py', 'heartbeat.py',
            'ultra-recovery-backup.service', 'ultra-recovery-backup.timer',
            'ultra-recovery-reconcile.service', 'ultra-recovery-reconcile.timer',
            'ultra-recovery-prune.service', 'ultra-recovery-prune.timer',
            'ultra-monitor.service', 'ultra-monitor.timer', 'ultra-monitor-probe.service'}


def run(argv, timeout=120, input=None, env=None):
    result = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
    if result.returncode:
        raise ValueError('automation subprocess failed')
    return result.stdout


def stop_existing_unit(unit):
    # Fresh bootstrap has no automation units yet; all other systemd errors matter.
    state = run(['systemctl', 'show', '--property=LoadState', '--value', unit]).decode().strip()
    if state == 'not-found':
        return
    run(['systemctl', 'stop', unit], timeout=550)


def atomic(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('managed symlink refused')
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.next')
    if tmp.is_symlink():
        raise ValueError('staging symlink refused')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_json(path, value):
    atomic(path, json.dumps(value, sort_keys=True).encode())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_release(directory, version, architecture):
    directory = Path(directory)
    manifest = json.loads((directory / 'release-manifest.json').read_text())
    if 'service-access-v1' not in manifest.get('capabilities', []):
        raise ValueError('release lacks service access capability')
    if manifest.get('version') != version:
        raise ValueError('release version mismatch')
    assets = {item['name']: item for item in manifest['assets']}
    names = ['ultra-recovery.tar.gz', 'ultra-client-linux-' + architecture, 'ultra-relay-linux-amd64', 'ultra-relay-linux-arm64', 'ultra-bot-linux-' + architecture]
    for name in names:
        item = assets[name]
        file = directory / name
        if file.is_symlink() or file.stat().st_size != item['size'] or sha(file) != item['sha256']:
            raise ValueError('release checksum mismatch')
    with tarfile.open(directory / names[0], 'r:gz') as archive:
        members = archive.getmembers()
        nameset = set()
        for member in members:
            if not member.isfile() or '/' in member.name or member.name.startswith('.') or not re.fullmatch(r'[a-zA-Z0-9_.-]+', member.name):
                raise ValueError('unsafe recovery bundle member')
            if member.name in nameset or member.size > 4 * 1024 * 1024:
                raise ValueError('duplicate or oversized recovery bundle member')
            nameset.add(member.name)
        if not REQUIRED <= nameset:
            raise ValueError('incomplete recovery bundle')
        return {member.name: archive.extractfile(member).read() for member in members}


def read_env(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator and not key.startswith('#'):
            result[key.strip()] = value.strip().strip('\"\'')
    return result


def replicas_ready(database):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database): return False
    query = "SELECT count(*)>0 AND bool_and(COALESCE(r.state='streaming' AND r.checked_at>now()-interval '90 seconds',false)) FROM exit_nodes n LEFT JOIN node_replication r ON r.node_id=n.id WHERE n.enabled"
    return run(['runuser','-u','postgres','--','psql','-XAtq','-v','ON_ERROR_STOP=1','-d',database,'-c',query]).strip() == b't'


def status(not_before=None):
    reasons = []
    independent = False
    try:
        reconcile = json.loads(Path('/var/lib/ultra-relay/recovery-reconcile-status.json').read_text())
        backup = json.loads(Path('/var/lib/ultra-recovery/last-success.json').read_text())
        now = time.time()
        independent = reconcile.get('independent') is True
        if reconcile.get('state') != 'ready': reasons.append('controller_pending')
        if not independent: reasons.append('independent_destination_unavailable')
        if not 0 <= now - reconcile['updated_at'] <= 180: reasons.append('controller_status_stale')
        if not 0 <= now - backup['snapshot_at'] <= 300: reasons.append('backup_stale')
        if not_before is not None:
            if reconcile['updated_at'] <= not_before: reasons.append('controller_before_activation')
            if backup['snapshot_at'] <= not_before: reasons.append('backup_before_activation')
        database = json.loads((CONFIG / 'reconcile.json').read_text())['database']
        if not replicas_ready(database): reasons.append('replica_not_fresh_streaming')
        for unit in ('ultra-recovery-reconcile.timer', 'ultra-recovery-backup.timer'):
            if run(['systemctl', 'is-active', unit]).strip() != b'active': reasons.append('timer_inactive')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        reasons.append('readiness_evidence_unavailable')
    result = {'ready': not reasons, 'independent': independent, 'reasons': sorted(set(reasons))}
    try:
        failure = json.loads((STATE/'last-error.json').read_text())
        if failure.get('action') in ('bootstrap','upgrade') and failure.get('stage') in ERROR_STAGES and failure.get('code') == failure['stage']+'_failed':
            result['last_error'] = {key: failure[key] for key in ('action','stage','code','timestamp')}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return result


def static_nodes(config):
    # IDs come from actual persisted bootstrap, never from an operator-maintained UUID list.
    database = config['database']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
        raise ValueError('invalid database name')
    rows = json.loads(run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database,
                          '-c', "SELECT COALESCE(json_agg(json_build_object('id',id,'address',address)), '[]'::json) FROM exit_nodes WHERE enabled"]))
    nodes = []
    for item in config['static_nodes']:
        ipaddress.ip_address(item['address'])
        found = [row for row in rows if row['address'] == item['address']]
        if len(found) != 1:
            raise ValueError('static node not uniquely persisted and enabled')
        nodes.append(dict(item, id=found[0]['id'], known_hosts=str(CONFIG / 'known_hosts')))
    return nodes


def ensure_backup_repository(path):
    # Reuse recovery's strict marker/source/permission checks before any capture.
    script = ('import sys; from pathlib import Path; '
              'sys.path.insert(0,sys.argv[1]); from recovery import repository; '
              'p=Path(sys.argv[2]); '
              'repository(p,"bridge",initialize=not (p/".ultra-recovery-repository").exists())')
    run(['python3', '-c', script, str(ROOT), str(path)])


def configure(config):
    CONFIG.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONFIG, 0o700)
    # Preserve primary/SSH credentials generated by the ordinary installer.
    identity = '/var/lib/ultra-relay/automation/id_ed25519'
    if not Path(identity).is_file() or not Path(identity + '.pub').is_file():
        raise ValueError('replica automation identity missing')
    known = Path(config['known_hosts_file']).read_bytes()
    previous = CONFIG / 'known_hosts'
    if previous.exists() and previous.read_bytes() != known:
        raise ValueError('existing SSH pins differ; explicit pin rotation required')
    atomic(previous, known)
    cloud_source = config.get('cloud_key_file')
    if cloud_source:
        atomic(CONFIG / 'vultr-api-key', Path(cloud_source).read_bytes())
        run(['chown', 'ultra-relay:ultra-relay', str(CONFIG / 'vultr-api-key')])
        # Keep credential in the relay's existing private directory, not traverse root-only CONFIG.
        atomic('/var/lib/ultra-relay/automation/vultr-api-key', (CONFIG / 'vultr-api-key').read_bytes())
        run(['chown', 'ultra-relay:ultra-relay', '/var/lib/ultra-relay/automation/vultr-api-key'])
    if config.get('dns'):
        dns_policy = dict(config['dns'])
        key_path = CONFIG / 'dns-api-key'
        if dns_policy.get('api_key_file'):
            atomic(key_path, Path(dns_policy['api_key_file']).read_bytes())
        if not key_path.is_file(): raise ValueError('derived DNS key missing')
        dns_policy['api_key_file'] = str(key_path)
        desired = {role: {'name': dns_policy[field], 'data': config['bridge_ipv4']} for role, field in [('subscription','subscription_name'),('vpn','vpn_name')]}
        write_json(CONFIG / 'dns.json', {'config': dns_policy, 'desired': desired})
    cloud_path = '/var/lib/ultra-relay/automation/vultr-api-key'
    if not Path(cloud_path).exists():
        raise ValueError('cloud API key input required for complete automation')
    bridge_ip = str(ipaddress.IPv4Address(config['bridge_ipv4']))
    atomic(UNITS / 'ultra-relay.service.d/automation.conf',
           ('[Service]\nEnvironment=ULTRA_VULTR_KEY_FILE=' + cloud_path + '\nEnvironment=ULTRA_VULTR_BRIDGE_IP=' + bridge_ip + '\n').encode(), 0o644)
    token = read_env('/etc/ultra-relay/bot.env').get('TELEGRAM_BOT_TOKEN', '')
    if not token:
        raise ValueError('existing bot token unavailable')
    atomic(CONFIG / 'primary-bot-token', token.encode())
    nodes = static_nodes(config)
    for node in nodes:
        pinfile = Path('/var/lib/ultra-relay/vultr') / str(node['id']) / 'known_hosts'
        if pinfile.exists():
            def keys(file):
                text=run(['ssh-keygen','-F',node['address'],'-f',str(file)]).decode()
                return {tuple(line.split()[1:3]) for line in text.splitlines() if line and not line.startswith('#')}
            if not keys(pinfile) or keys(pinfile)!=keys(CONFIG/'known_hosts'):
                raise ValueError('existing operation pin differs from trusted installation pins')
            continue
        atomic(pinfile, known)
        run(['chown','-R','ultra-relay:ultra-relay',str(pinfile.parent)])
    # Static quota is explicit operator input; init-only command preserves all spend.
    write_json(CONFIG/'static-budgets.json', config['static_nodes'])
    run(['/usr/local/bin/ultra-relay', '-ensure-static-budgets', '-spec', config['spec'],
         '-static-budgets-file', str(CONFIG/'static-budgets.json')], timeout=60,
        env=dict(os.environ, **read_env('/etc/ultra-relay/environment')))
    # Supported command creates a dedicated service principal; it does not grant admin/user quota.
    run(['/usr/local/bin/ultra-relay', '-ensure-monitor-access', '-spec', config['spec'],
         '-monitor-profile-output', str(CONFIG / 'probe.json'), '-monitor-chat-output', str(CONFIG / 'admin-chat-id'),
         '-monitor-admin-telegram-id', str(config.get('admin_telegram_id', 0))], timeout=60, env=dict(os.environ, **read_env('/etc/ultra-relay/environment')))
    state_paths = ['/etc/ultra-relay', str(CONFIG), '/var/lib/ultra-relay/automation',
                   str(UNITS / 'ultra-relay.service'), str(UNITS / 'ultra-relay.service.d'), str(UNITS / 'ultra-bot.service')]
    state_paths.extend(config.get('state_paths', []))
    # Explicit discovery of certificate/account/geo paths; no blanket /etc or ACME directory.
    spec = json.loads(Path(config['spec']).read_text())
    heartbeat=Path('/var/lib/ultra-recovery-reconcile/heartbeat_ed25519')
    heartbeat.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not heartbeat.exists(): run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(heartbeat)],timeout=10)
    public=run(['ssh-keygen','-y','-f',str(heartbeat)],timeout=10)
    atomic(str(heartbeat)+'.pub',public,0o600)
    state_paths.extend([str(heartbeat),str(heartbeat)+'.pub'])
    for candidate in ('/etc/systemd/system/ultra-bot.service.d', '/var/lib/ultra-bot', '/etc/nginx/sites-available/ultra-bot', '/var/lib/ultra-ingress/managed.json'):
        if Path(candidate).exists(): state_paths.append(candidate)
    ingress_receipt=Path('/var/lib/ultra-ingress/managed.json')
    if ingress_receipt.exists():
        managed=json.loads(ingress_receipt.read_text())
        for name,digest in managed.items():
            if not name.startswith(('/etc/nginx/','/etc/letsencrypt/renewal-hooks/','/var/www/ultra-')): continue
            managed_path=Path(name)
            if managed_path.exists() and sha(managed_path)==digest: state_paths.append(name)
            else: raise ValueError('managed ingress artifact changed outside installer')
    domains={config['bridge_url'].split('/')[2].split(':')[0]}
    if config.get('ingress'): domains.add(config['ingress']['domain'])
    for domain in domains:
        live=Path('/etc/letsencrypt/live')/domain
        if live.exists(): state_paths.append(str(live))
    for cert in Path('/etc/letsencrypt/renewal').glob('*.conf'):
        # Only certificates for this configured bridge are included.
        domains={config['bridge_url'].split('/')[2].split(':')[0]}
        if config.get('ingress'): domains.add(config['ingress']['domain'])
        domain=cert.stem
        if domain not in domains: continue
        state_paths.extend([str(cert), '/etc/letsencrypt/live/' + domain])
        text = cert.read_text()
        account = re.search(r'^account\s*=\s*([a-f0-9]+)\s*$', text, re.M)
        if account:
            matches = list(Path('/etc/letsencrypt/accounts').glob('*/directory/' + account.group(1)))
            if len(matches) != 1: raise ValueError('ACME account not uniquely found')
            state_paths.append(str(matches[0]))
    artifact_paths = ['/usr/local/bin/ultra-relay', '/usr/local/bin/ultra-bot', '/usr/local/bin/ultra-client', '/usr/local/libexec/ultra-relay-emergency', '/usr/local/libexec/ultra-emergency-manifest.json']
    artifact_paths.extend(str(ROOT / name) for name in REQUIRED)
    artifact_paths.extend(config.get('artifact_paths', []))
    if spec.get('geo_assets_dir'): artifact_paths.append(spec['geo_assets_dir'])
    for candidate in ('/etc/nginx/conf.d/ultra-vpn.conf', '/var/www/ultra-site'):
        if Path(candidate).exists(): state_paths.append(candidate)
    # Include every active recovery tool in the immutable artifact, not historical releases.
    artifact_paths.extend(str(p) for p in ROOT.glob('*.py'))
    artifact_paths.append(str(ROOT / 'release-manifest.json'))
    for unit in ROOT.glob('*.service'): state_paths.append(str(UNITS / unit.name))
    for unit in ROOT.glob('*.timer'): state_paths.append(str(UNITS / unit.name))
    backup = {'source': 'bridge', 'repository': '/var/lib/ultra-recovery', 'database': config['database'],
              'recipient': config['age_recipient'], 'identity_file': identity, 'known_hosts': str(CONFIG / 'known_hosts'),
              'destinations': [{'id':n['id'],'name':n['name'],'host': 'root@'+n['address'], 'required': True} for n in nodes],
              'independent': any(n['provider'].lower()!=config['bridge_provider'].lower() for n in nodes),
              'state_paths': sorted(set(state_paths)), 'artifact_paths': sorted(set(artifact_paths)), 'diagnostic_status': True}
    reconcile = {'database': config['database'], 'bridge_provider': config['bridge_provider'],
                 'vultr_state_dir': '/var/lib/ultra-relay/vultr', 'ssh_identity_file': identity,
                 'vultr_api_key_file': cloud_path, 'api_key_owner': 'ultra-relay', 'ssh_identity_owner': 'ultra-relay',
                 'backup_config': str(CONFIG / 'backup.json'), 'state_dir': '/var/lib/ultra-recovery-reconcile',
                 'status_file': '/var/lib/ultra-relay/recovery-reconcile-status.json', 'status_group': 'ultra-relay',
                 'bundle_dir': str(ROOT), 'client_binary': '/usr/local/bin/ultra-client',
                 'bot_token_file': str(CONFIG / 'primary-bot-token'), 'chat_id_file': str(CONFIG / 'admin-chat-id'),
                 'probe_profile_file': str(CONFIG / 'probe.json'), 'bridge_url': config['bridge_url'],
                 'payload_url': 'https://www.cloudflare.com/cdn-cgi/trace', 'static_nodes': nodes, 'monitor_spec_file': config['spec']}
    if (CONFIG / 'backup.json').exists():
        existing = json.loads((CONFIG / 'backup.json').read_text())
        if existing['recipient'] != backup['recipient']: raise ValueError('age recipient rotation requires explicit recovery-key procedure')
        # Keep dynamic destinations; controller reconciles their readiness.
        backup['destinations'] = existing['destinations']
    write_json(CONFIG / 'backup.json', backup)
    write_json(CONFIG / 'reconcile.json', reconcile)
    deployment={key:config[key] for key in ('version','bridge_ipv4','bridge_provider','bridge_url','database') if key in config}
    deployment['ingress']=config.get('ingress')
    deployment['ssh_identity_file']=identity
    deployment['known_hosts_file']=str(CONFIG/'known_hosts')
    deployment['static_nodes']=nodes
    write_json(CONFIG/'deployment.json',deployment)
    ensure_backup_repository('/var/lib/ultra-recovery')


def compatible_fallback(previous, target):
    required = {'service-access-v1'}
    if 'provider-pool-quota-v1' in target.get('capabilities', []):
        required.add('provider-pool-quota-v1')
    return (required <= set(previous.get('capabilities', [])) and required <= set(target.get('capabilities', []))
            and target.get('database_schema_min', 10**9) <= target.get('database_schema_max', -1)
            and previous.get('database_schema_max', 0) >= target.get('database_schema_max', 10**9)
            and previous.get('database_schema_min', 10**9) <= target.get('database_schema_min', 0))



POOL_CAPABILITY = 'provider-pool-quota-v1'


def pool_transition(previous, target):
    return (POOL_CAPABILITY in target.get('capabilities', [])
            and POOL_CAPABILITY not in previous.get('capabilities', [])
            and 'service-access-v1' in previous.get('capabilities', [])
            and target.get('database_schema_min', 10**9) <= previous.get('database_schema_max', 0)
            and previous.get('database_schema_max', 10**9) <= target.get('database_schema_max', 0))


def pool_override():
    return UNITS/'ultra-relay.service.d'/'95-ultra-pool-emergency.conf'


def clear_pool_override():
    path = pool_override()
    if path.exists():
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        run(['systemctl', 'daemon-reload'])


def prepare_pool_emergency(binary, manifest, architecture, target_digest):
    metadata = json.loads(manifest)
    expected = asset_hash(metadata, 'ultra-relay-linux-'+architecture)
    if POOL_CAPABILITY not in metadata.get('capabilities', []) or hashlib.sha256(binary).hexdigest() != expected:
        raise ValueError('pool emergency checksum or capability mismatch')
    receipt = STATE/'pool-emergency.json'
    existing = json.loads(receipt.read_text()) if receipt.exists() else {}
    if existing and existing.get('target_digest') != target_digest and existing.get('stage') != 'complete':
        raise ValueError('unfinished pool transition belongs to another release')
    path = Path('/usr/local/libexec/ultra-relay-emergency')
    atomic(path, binary, 0o755)
    # A manifest claim alone is insufficient for the irreversible transition.
    capabilities = json.loads(run([str(path), '-capabilities'], timeout=15))
    if not isinstance(capabilities, list) or not {'service-access-v1', POOL_CAPABILITY} <= set(capabilities):
        raise ValueError('pool emergency capability probe failed')
    atomic(Path('/usr/local/libexec/ultra-emergency-manifest.json'), manifest, 0o644)
    if sha(path) != expected:
        raise ValueError('pool emergency changed during capability probe')
    stage = existing.get('stage', 'prepared') if existing.get('target_digest') == target_digest else 'prepared'
    if stage == 'complete': stage = 'prepared'
    write_json(receipt, {'target_digest':target_digest, 'sha256':expected, 'stage':stage})



def arm_pool_override():
    unit = (UNITS/'ultra-relay.service').read_text()
    commands = [line for line in unit.splitlines() if line.startswith('ExecStart=')]
    if len(commands) != 1 or not commands[0].startswith('ExecStart=/usr/local/bin/ultra-relay '):
        raise ValueError('managed relay unit required for pool emergency')
    command = commands[0]
    if '-require-provider-pool-quota' not in command.split():
        command += ' -require-provider-pool-quota'
    command = command.replace('ExecStart=/usr/local/bin/ultra-relay ',
                              'ExecStart=/usr/local/libexec/ultra-relay-emergency -cache-only ', 1)
    atomic(pool_override(), ('[Service]\nExecStart=\n'+command+'\n').encode(), 0o644)
    run(['systemctl', 'daemon-reload'])
    receipt_path = STATE/'pool-emergency.json'
    receipt = json.loads(receipt_path.read_text())
    receipt['stage'] = 'armed'; write_json(receipt_path, receipt)


def pool_cache_only(config, release, architecture, manifest, targets):
    # Never restore the pre-pool controller or emergency manifest after activation.
    # Stop writers even if failure occurred while readiness had already enabled them.
    for unit in ('ultra-recovery-reconcile.timer', 'ultra-recovery-backup.timer',
                 'ultra-recovery-reconcile.service', 'ultra-recovery-backup.service'):
        stop_existing_unit(unit)
    receipt_path = STATE/'pool-emergency.json'
    receipt = json.loads(receipt_path.read_text())
    expected = asset_hash(manifest, 'ultra-relay-linux-'+architecture)
    emergency = Path('/usr/local/libexec/ultra-relay-emergency')
    if receipt['sha256'] != expected or sha(emergency) != expected:
        raise ValueError('prepared pool emergency checksum mismatch')
    for path, (data, mode) in targets.items(): atomic(path, data, mode)
    journal_path = STATE/'upgrade.json'
    journal = json.loads(journal_path.read_text()) if journal_path.exists() else None
    for name in ('ultra-relay', 'ultra-bot'):
        binary = Path(release)/(name+'-linux-'+architecture)
        if sha(binary) != asset_hash(manifest, name+'-linux-'+architecture):
            raise ValueError('pool recovery binary checksum mismatch')
        if journal:
            journal['steps'].setdefault('bridge-'+name, {'state':'emergency-prepared',
                'old_sha':asset_hash(journal['previous'], name+'-linux-'+architecture),
                'new_sha':asset_hash(manifest, name+'-linux-'+architecture)})
            write_json(journal_path, journal)
        atomic(BIN/name, binary.read_bytes(), 0o755)
    arm_pool_override()
    ensure_pool_guard(manifest)
    receipt['stage'] = 'cache-only-prepared'; write_json(receipt_path, receipt)
    write_json(STATE/'release-manifest.json', manifest)
    write_json(STATE/'release.json', {'version':manifest['version'], 'ready':False})
    run(['systemctl', 'daemon-reload'])
    restart_bridge(config['spec'])
    receipt['stage'] = 'cache-only'; write_json(receipt_path, receipt)


def asset_hash(manifest, name):
    matches = [x['sha256'] for x in manifest['assets'] if x['name'] == name]
    if len(matches) != 1: raise ValueError('ambiguous release asset')
    return matches[0]


def remote(config, node, script, data=None):
    argv = ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile='+node['known_hosts'],'-o','ConnectTimeout=5',
            '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
            '-i',config['ssh_identity_file'],'root@'+str(ipaddress.ip_address(node['address'])),script]
    return run(argv, timeout=90, input=data)


def wait_exit(config, node, since):
    spec = json.loads(Path(config['spec']).read_text())
    address = spec.get('admin_listen', '127.0.0.1:8443')
    if not address.startswith('127.0.0.1:'): raise ValueError('loopback admin endpoint required')
    token = read_env('/etc/ultra-relay/environment')['ULTRA_RELAY_ADMIN_TOKEN']
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request('http://'+address+'/v1/health', headers={'Authorization':'Bearer '+token})
            with urllib.request.urlopen(request, timeout=8) as response: result = json.load(response)
            health = next(h for h in result['exits'] if h['id'] == node['id'])
            checked = datetime.datetime.fromisoformat(health['checked_at'].replace('Z','+00:00')).timestamp()
            if health['internet_ok'] and health['eligible'] and checked >= since: return
        except (OSError, ValueError, KeyError, StopIteration): pass
        time.sleep(3)
    raise ValueError('updated exit did not pass tunnel payload health')


def upgrade_fleet(config, release, architecture, target):
    journal_path=STATE/'upgrade.json'
    target_digest=hashlib.sha256(json.dumps(target,sort_keys=True).encode()).hexdigest()
    journal=json.loads(journal_path.read_text()) if journal_path.exists() else None
    resuming = journal is not None
    if journal:
        if journal.get('target_digest')!=target_digest or journal.get('version')!=config['version']:
            raise ValueError('unfinished upgrade belongs to another immutable version')
        previous=journal['previous']
    else:
        previous=json.loads((ROOT/'release-manifest.json').read_text())
    transition = pool_transition(previous, target)
    if not compatible_fallback(previous,target) and not transition: raise ValueError('compatible service-access fallback required')
    reconcile=json.loads((CONFIG/'reconcile.json').read_text())
    import sys
    sys.path.insert(0,str(ROOT))
    import reconcile as controller
    nodes,_=controller.desired_nodes(reconcile,controller.discover(reconcile))
    if not nodes: raise ValueError('no owned exits available for upgrade')
    if journal and journal['node_ids']!=[n['id'] for n in nodes]: raise ValueError('topology changed during interrupted upgrade')
    if not journal:
        run(['python3',str(ROOT/'recovery.py'),'capture','--config',str(CONFIG/'backup.json')],timeout=175)
        if not status()['ready']: raise ValueError('fresh independent backup and healthy fleet required before upgrade')
        journal={'version':config['version'],'target_digest':target_digest,'previous':previous,
                 'node_ids':[n['id'] for n in nodes],'steps':{},'created_at':int(time.time())}
        write_json(journal_path,journal)
    for unit in ('ultra-recovery-reconcile.timer','ultra-recovery-backup.timer','ultra-recovery-reconcile.service','ultra-recovery-backup.service'):
        run(['systemctl','stop',unit],timeout=550)
    if transition:
        receipt = json.loads((STATE/'pool-emergency.json').read_text())
        if receipt['target_digest'] != target_digest or receipt['sha256'] != asset_hash(target, 'ultra-relay-linux-'+architecture):
            raise ValueError('verified pool emergency required before activation')
        journal['pool_transition'] = True
        journal['pool_activation_started'] = True
        write_json(journal_path, journal)
        # Arm verified cache-only startup before changing the base unit or fleet.
        # The current process keeps running; any reboot uses the saved state.
        arm_pool_override()
        ensure_pool_guard(target)
    rollback=[]
    def activate_bridge():
        for name in ('ultra-relay','ultra-bot'):
            destination=BIN/name
            expected=asset_hash(previous,name+'-linux-'+architecture)
            target_sha=asset_hash(target,name+'-linux-'+architecture)
            step=journal['steps'].get('bridge-'+name)
            actual=sha(destination)
            if actual not in ({expected,target_sha} if step else {expected}): raise ValueError('bridge binary has no verified fallback')
            backup=BIN/(name+'.automation-previous')
            if not step:
                journal['steps']['bridge-'+name]={'state':'prepared','old_sha':expected,'new_sha':target_sha}
                write_json(journal_path,journal)
            elif step['old_sha']!=expected or step['new_sha']!=target_sha: raise ValueError('bridge journal hash mismatch')
            if actual==expected: atomic(backup,destination.read_bytes(),destination.stat().st_mode & 0o777)
            if not transition:
                if sha(backup)!=expected: raise ValueError('bridge fallback checksum mismatch')
                rollback.append(('local',(destination,backup.read_bytes(),backup.stat().st_mode & 0o777)))
            atomic(destination,(Path(release)/(name+'-linux-'+architecture)).read_bytes(),0o755)
            journal['steps']['bridge-'+name]['state']='applied';write_json(journal_path,journal)
        run([str(BIN/'ultra-relay'),'-check','-spec',config['spec']],timeout=30)
        ensure_pool_guard(target)
        if transition:
            receipt_path = STATE/'pool-emergency.json'
            receipt = json.loads(receipt_path.read_text())
            receipt['stage'] = 'normal-starting'; write_json(receipt_path, receipt)
        clear_pool_override()
        restart_bridge(config['spec'])
    try:
        if transition and resuming:
            # Cache-only /v1/health intentionally has no exits. Restore the
            # target control plane before waiting for its fresh tunnel probes.
            activate_bridge()
            # Keep the normal process running, but preserve cache-only startup
            # if the installer or host dies before fleet verification finishes.
            arm_pool_override()
        for node in nodes:
            arch=remote(reconcile,node,'dpkg --print-architecture').decode().strip()
            if arch not in ('amd64','arm64'): raise ValueError('unsupported exit architecture')
            expected=asset_hash(previous,'ultra-relay-linux-'+arch)
            target_sha=asset_hash(target,'ultra-relay-linux-'+arch)
            actual=remote(reconcile,node,'sha256sum /usr/local/bin/ultra-relay').decode().split()[0]
            step=journal['steps'].get(node['id'])
            if actual not in ({expected,target_sha} if step else {expected}): raise ValueError('exit binary has no verified compatible fallback')
            if not step:
                journal['steps'][node['id']]={'state':'prepared','old_sha':expected,'new_sha':target_sha}
                write_json(journal_path,journal)
            elif step['old_sha']!=expected or step['new_sha']!=target_sha: raise ValueError('upgrade journal hash mismatch')
            binary=Path(release)/('ultra-relay-linux-'+arch)
            remote(reconcile,node,'umask 077; cat > /usr/local/bin/ultra-relay.next',binary.read_bytes())
            # Re-entry may see the target active already. Never overwrite the verified old fallback.
            script=('set -eu; old='+shlex.quote(expected)+'; new='+shlex.quote(target_sha)+'; '
                    'hash() { sha256sum "$1" | cut -d " " -f1; }; '
                    'test "$(hash /usr/local/bin/ultra-relay.next)" = "$new"; '
                    'if test "$(hash /usr/local/bin/ultra-relay)" = "$old"; then '
                    'cp -p /usr/local/bin/ultra-relay /usr/local/bin/ultra-relay.automation-previous; '
                    'else test "$(hash /usr/local/bin/ultra-relay.automation-previous)" = "$old"; fi; '
                    'chmod 755 /usr/local/bin/ultra-relay.next; /usr/local/bin/ultra-relay.next -check -spec /etc/ultra-relay/spec.json >/dev/null 2>&1; '
                    'mv /usr/local/bin/ultra-relay.next /usr/local/bin/ultra-relay; systemctl restart ultra-relay; systemctl is-active --quiet ultra-relay')
            rollback.append(('exit',dict(node,old_sha=expected)))
            since=time.time()
            if transition:
                journal['pool_activation_started'] = True; write_json(journal_path, journal)
            remote(reconcile,node,script)
            journal['steps'][node['id']]['state']='applied';write_json(journal_path,journal)
            wait_exit(config,node,since)
            journal['steps'][node['id']]['state']='verified';write_json(journal_path,journal)
        if not (transition and resuming):
            activate_bridge()
        else:
            # The resumed normal controller has now verified every exit.
            clear_pool_override()
        journal['fleet_verified']=True;write_json(journal_path,journal)
        return rollback
    except Exception:
        if transition and journal.get('pool_activation_started'):
            journal['fallback_required'] = True; write_json(journal_path, journal)
            raise
        rollback=[]
        for node in nodes:
            if node['id'] in journal['steps']:
                rollback.append(('exit',dict(node,old_sha=journal['steps'][node['id']]['old_sha'])))
        for name in ('ultra-relay','ultra-bot'):
            step=journal['steps'].get('bridge-'+name)
            if not step: continue
            destination=BIN/name;backup=BIN/(name+'.automation-previous')
            if sha(destination)==step['old_sha']: continue
            if not backup.exists() or sha(backup)!=step['old_sha']: raise ValueError('interrupted bridge fallback unavailable')
            rollback.append(('local',(destination,backup.read_bytes(),backup.stat().st_mode & 0o777)))
        rollback_fleet(reconcile,rollback)
        journal_path.unlink(missing_ok=True)
        raise


def ensure_pool_guard(manifest):
    if 'provider-pool-quota-v1' not in manifest.get('capabilities', []):
        return
    unit = UNITS/'ultra-relay.service'
    text = unit.read_text()
    lines = [line for line in text.splitlines() if line.startswith('ExecStart=')]
    if len(lines) != 1 or not lines[0].startswith('ExecStart=/usr/local/bin/ultra-relay '):
        raise ValueError('managed relay unit required for pool activation')
    if '-require-provider-pool-quota' not in lines[0].split():
        guarded = lines[0].replace('ExecStart=/usr/local/bin/ultra-relay ',
                                  'ExecStart=/usr/local/bin/ultra-relay -require-provider-pool-quota ', 1)
        atomic(unit, text.replace(lines[0], guarded).encode(), 0o644)
    run(['systemctl', 'daemon-reload'])


def restart_bridge(spec_path):
    run(['systemctl','stop','ultra-bot'],timeout=30)
    run(['systemctl','restart','ultra-relay'],timeout=60)
    spec=json.loads(Path(spec_path).read_text())
    address=spec.get('admin_listen','127.0.0.1:8443')
    if not address.startswith('127.0.0.1:'): raise ValueError('loopback admin required')
    token=read_env('/etc/ultra-relay/environment')['ULTRA_RELAY_ADMIN_TOKEN']
    for _ in range(60):
        try:
            request=urllib.request.Request('http://'+address+'/v1/hardening',headers={'Authorization':'Bearer '+token})
            with urllib.request.urlopen(request,timeout=3) as response: evidence=json.load(response)
            if evidence.get('reload',{}).get('count',0)>0 and not evidence.get('reload',{}).get('error'):
                run(['systemctl','start','ultra-bot'],timeout=30)
                return
        except (OSError,ValueError,KeyError): pass
        time.sleep(1)
    raise ValueError('bridge reload readiness unavailable')


def rollback_fleet(reconcile, records):
    failed = False
    for kind, record in reversed(records):
        try:
            if kind == 'exit':
                remote(reconcile,record,'set -eu; if test "$(sha256sum /usr/local/bin/ultra-relay | cut -d \" \" -f1)" = '+shlex.quote(record['old_sha'])+'; then exit 0; fi; test "$(sha256sum /usr/local/bin/ultra-relay.automation-previous | cut -d \" \" -f1)" = '+shlex.quote(record['old_sha'])+'; mv /usr/local/bin/ultra-relay.automation-previous /usr/local/bin/ultra-relay; systemctl restart ultra-relay; systemctl is-active --quiet ultra-relay')
            else:
                destination,data,mode = record
                atomic(destination,data,mode)
        except (OSError, ValueError, subprocess.SubprocessError): failed = True
    if any(kind == 'local' for kind,_ in records):
        restart_bridge('/etc/ultra-relay/spec.json')
    if failed: raise ValueError('rollback incomplete; retained artifacts require operator recovery')


def saved_bundle_rollback(targets, digest):
    directory=STATE/'rollback'/digest
    index=directory/'index.json'
    if not index.exists():
        directory.mkdir(parents=True,mode=0o700,exist_ok=True)
        entries=[]
        for path in targets:
            if not path.exists(): entries.append({'path':str(path),'exists':False});continue
            key=hashlib.sha256(str(path).encode()).hexdigest()
            atomic(directory/key,path.read_bytes())
            entries.append({'path':str(path),'exists':True,'key':key,'sha256':sha(path),'mode':path.stat().st_mode & 0o777})
        write_json(index,entries)
    entries=json.loads(index.read_text())
    if {x['path'] for x in entries}!={str(path) for path in targets}: raise ValueError('upgrade rollback inventory mismatch')
    prior={}
    for item in entries:
        if not item['exists']: continue
        file=directory/item['key']
        if sha(file)!=item['sha256']: raise ValueError('rollback snapshot checksum mismatch')
        prior[Path(item['path'])]=(file.read_bytes(),item['mode'])
    return prior,directory


ERROR_STAGES = ('validate','dependencies','fleet','activate','configure','readiness')


def apply(config, release, action):
    progress = ['validate']
    try:
        _apply(config, release, action, progress)
    except Exception:
        # Never persist exception messages, command output, paths or credentials.
        write_json(STATE/'last-error.json', {'action': action, 'stage': progress[0],
                   'code': progress[0]+'_failed', 'timestamp': int(time.time())})
        raise
    (STATE/'last-error.json').unlink(missing_ok=True)


def emergency_pair(action, release, architecture):
    manifest = (ROOT/'release-manifest.json' if action=='upgrade' else Path(release)/'release-manifest.json').read_bytes()
    if action == 'upgrade' and (STATE/'upgrade.json').exists():
        manifest = json.dumps(json.loads((STATE/'upgrade.json').read_text())['previous'], sort_keys=True).encode()
    metadata = json.loads(manifest)
    target = json.loads((Path(release)/'release-manifest.json').read_text())
    transition = action == 'upgrade' and pool_transition(metadata, target)
    if transition:
        manifest = (Path(release)/'release-manifest.json').read_bytes()
        metadata = target
    elif POOL_CAPABILITY in target.get('capabilities', []) and not compatible_fallback(metadata, target):
        raise ValueError('provider pool compatible emergency required before activation')
    if 'service-access-v1' not in metadata.get('capabilities', []):
        raise ValueError('service-compatible emergency manifest required')
    expected = asset_hash(metadata, 'ultra-relay-linux-'+architecture)
    # Before bridge replacement the active binary is still the previous release.
    # After replacement only the journal-bound, checksum-verified backup is valid.
    source = Path(release)/('ultra-relay-linux-'+architecture) if transition else BIN/'ultra-relay'
    if sha(source) != expected and action == 'upgrade' and not transition:
        source = BIN/'ultra-relay.automation-previous'
    binary = source.read_bytes()
    if hashlib.sha256(binary).hexdigest() != expected:
        raise ValueError('emergency binary does not match compatible manifest')
    return binary, manifest


def _apply(config, release, action, progress):
    version = config['version']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', version) or version == 'latest':
        raise ValueError('explicit version required')
    architecture = run(['dpkg', '--print-architecture']).decode().strip()
    if architecture not in ('amd64', 'arm64'): raise ValueError('unsupported architecture')
    files = verify_release(release, version, architecture)
    manifest = json.loads((Path(release)/'release-manifest.json').read_text())
    fleet_rollback = []
    configured = False
    previous = None
    if action == 'upgrade':
        journal = STATE/'upgrade.json'
        if journal.exists():
            pending = json.loads(journal.read_text())
            if pending.get('target_digest') != hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest() or pending.get('version') != version:
                raise ValueError('unfinished upgrade belongs to another immutable version')
            previous = pending['previous']
        else:
            previous = json.loads((ROOT/'release-manifest.json').read_text())
    transition = (action == 'upgrade' and pool_transition(previous, manifest)) or (action == 'bootstrap' and POOL_CAPABILITY in manifest.get('capabilities', []))
    if action == 'bootstrap':
        for name in ('ultra-relay','ultra-bot'):
            if sha('/usr/local/bin/'+name) != asset_hash(manifest,name+'-linux-'+architecture):
                raise ValueError('installed bridge binaries must match the complete release')
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    ROOT.mkdir(parents=True, exist_ok=True)
    immutable = ROOT / 'releases' / version
    if immutable.exists():
        for name, data in files.items():
            if (immutable / name).read_bytes() != data: raise ValueError('immutable release changed')
    else:
        immutable.mkdir(parents=True, mode=0o700)
        for name, data in files.items(): atomic(immutable / name, data, 0o644)
    prior = {}
    targets = {ROOT / name: (data, 0o755 if name.endswith('.py') else 0o644) for name, data in files.items()}
    emergency_binary, emergency_manifest = emergency_pair(action, release, architecture)
    targets[Path('/usr/local/libexec/ultra-relay-emergency')] = (emergency_binary, 0o755)
    targets[Path('/usr/local/libexec/ultra-emergency-manifest.json')] = (emergency_manifest, 0o644)
    targets[ROOT / 'release-manifest.json'] = ((Path(release)/'release-manifest.json').read_bytes(), 0o644)
    targets.update({UNITS / name: (data, 0o644) for name, data in files.items() if name.endswith(('.service', '.timer'))})
    targets[Path('/usr/local/bin/ultra-client')] = ((Path(release) / ('ultra-client-linux-' + architecture)).read_bytes(), 0o755)
    for path in targets:
        if path.exists(): prior[path] = (path.read_bytes(), path.stat().st_mode & 0o777)
    rollback_directory=None
    if action=='upgrade':
        prior,rollback_directory=saved_bundle_rollback(targets,hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest())
    try:
        progress[0] = 'dependencies'
        run(['apt-get', 'update', '-qq'], timeout=180)
        run(['apt-get', 'install', '-y', '-qq', 'age', 'curl', 'python3'], timeout=240)
        progress[0] = 'fleet'
        if transition:
            prepare_pool_emergency(emergency_binary, emergency_manifest, architecture,
                                   hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest())
        if action == 'upgrade': fleet_rollback = upgrade_fleet(config, release, architecture, manifest)
        progress[0] = 'activate'
        # Stop automation writers during bundle activation.
        for unit in ('ultra-recovery-reconcile.timer', 'ultra-recovery-backup.timer',
                     'ultra-recovery-reconcile.service', 'ultra-recovery-backup.service'):
            stop_existing_unit(unit)
        for path, (data, mode) in targets.items(): atomic(path, data, mode)
        if action == 'bootstrap':
            if transition:
                receipt = json.loads((STATE/'pool-emergency.json').read_text())
                receipt['stage'] = 'activation-started'; write_json(STATE/'pool-emergency.json', receipt)
                arm_pool_override()
            ensure_pool_guard(manifest)
            write_json(STATE / 'release-manifest.json', manifest)
            write_json(STATE / 'release.json', {'version': version, 'ready': False})
            # Configuration may persist a service identity before a later check fails.
            # Keep its compatible emergency/code installed across any such failure.
            configured = True
            progress[0] = 'configure'
            configure(config)
        elif not (CONFIG / 'reconcile.json').exists(): raise ValueError('upgrade requires an installed automation configuration')
        run(['systemctl', 'daemon-reload'])
        if action == 'bootstrap':
            clear_pool_override()
            run(['systemctl', 'restart', 'ultra-relay'], timeout=60)
        activated_at = int(time.time())
        run(['systemctl', 'enable', '--now', 'ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer'])
        progress[0] = 'readiness'
        deadline = time.monotonic() + config.get('readiness_timeout_sec', 900)
        while time.monotonic() < deadline:
            # The service serializes with its timer and has bounded execution.
            try: run(['systemctl', 'start', 'ultra-recovery-reconcile.service'], timeout=max(1,min(550,deadline-time.monotonic())))
            except (ValueError, subprocess.SubprocessError): pass
            if status(not_before=activated_at)['ready']:
                write_json(STATE / 'release.json', {'version': version, 'ready_at': int(time.time())})
                write_json(STATE / 'release-manifest.json', manifest)
                if transition:
                    receipt = json.loads((STATE/'pool-emergency.json').read_text())
                    receipt['stage'] = 'complete'; write_json(STATE/'pool-emergency.json', receipt)
                (STATE/'upgrade.json').unlink(missing_ok=True)
                if rollback_directory: shutil.rmtree(rollback_directory)
                return
            time.sleep(5)
        raise ValueError('full automation readiness deadline exceeded')
    except Exception:
        journal = STATE/'upgrade.json'
        if transition and ((journal.exists() and json.loads(journal.read_text()).get('pool_activation_started')) or
                           (action == 'bootstrap' and (STATE/'pool-emergency.json').exists() and
                            json.loads((STATE/'pool-emergency.json').read_text()).get('stage') != 'prepared')):
            pool_cache_only(config, release, architecture, manifest, targets)
            raise
        if action == 'bootstrap' and configured:
            # Bootstrap may already have durable database/configuration side effects.
            # Preserve compatible code and readiness=false; a corrected rerun resumes.
            raise
        if fleet_rollback:
            rollback_fleet(json.loads((CONFIG/'reconcile.json').read_text()),fleet_rollback)
            (STATE/'upgrade.json').unlink(missing_ok=True)
        # Roll back managed code only. Do not rewind credentials, SQL or live topology.
        for path, (data, mode) in prior.items(): atomic(path, data, mode)
        for path in targets:
            if path not in prior: path.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'])
        if rollback_directory: shutil.rmtree(rollback_directory)
        if prior:
            subprocess.run(['systemctl', 'start', 'ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', choices=['bootstrap', 'upgrade', 'status'], required=True)
    parser.add_argument('--config')
    parser.add_argument('--release')
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'status':
        result = status(); print(json.dumps(result)); return 0 if result['ready'] else 1
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    with open(STATE / 'install.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = json.loads(Path(args.config).read_text())
        apply(config, args.release, args.action)
        receipt = STATE / 'receipts' / (args.action + '-' + config['version'] + '.json')
        write_json(receipt, {'action': args.action, 'version': config['version'],
                            'completed_at': int(time.time())})
    print(json.dumps({'ready': True, 'version': config['version']}))
    return 0

if __name__ == '__main__':
    try: raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError):
        raise SystemExit('automation failed; private diagnostics suppressed') from None
