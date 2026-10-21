#!/usr/bin/env python3
"""Run the shipped apply/key/restore CLI against a synthetic isolated topology.

Infrastructure/TLS fixture preparation is separate. The restore timer starts
before the real restore command and is never reset after a failure. Only newly
created synthetic credentials and this topology's owned VM processes are used.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import re
import subprocess
import time
from vm_topology_fixture import ssh, payload_targets


def run(args, log, timeout=3600, cwd=None):
    with log.open('ab') as output:
        result=subprocess.run(args,stdout=output,stderr=subprocess.STDOUT,timeout=timeout,cwd=cwd)
    if result.returncode:raise ValueError('acceptance_command_failed; inspect private synthetic log')


def running_process(pid, root=Path('/proc')):
    try:
        state=(root/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[0]
        return state not in ('Z','X')
    except FileNotFoundError:
        return False


def owned_vm_pids(disk, root=Path('/proc')):
    """Find only live QEMU processes owning this exact fixture disk."""
    result=[]
    for directory in Path(root).glob('[0-9]*'):
        try:
            args=(directory/'cmdline').read_bytes().split(b'\0')
            if Path(os.fsdecode(args[0])).name not in ('qemu-system-x86_64','qemu-system-aarch64'):
                continue
            drives=[args[i+1].split(b',') for i,arg in enumerate(args[:-1]) if arg==b'-drive']
            if any(b'file='+os.fsencode(disk) in drive for drive in drives) and running_process(int(directory.name),root):
                result.append(int(directory.name))
        except (FileNotFoundError,ProcessLookupError):
            continue
    return sorted(result)


def fence_owned_vm(disk):
    pids=owned_vm_pids(disk)
    if len(pids)>1:raise ValueError('multiple_synthetic_primary_processes')
    for pid in pids:
        # The fd binds the signal to this process even if the numeric PID is reused.
        try:fd=os.pidfd_open(pid)
        except ProcessLookupError:continue
        try:
            if pid not in owned_vm_pids(disk):
                raise ValueError('synthetic_vm_process_ownership_changed')
            signal.pidfd_send_signal(fd,signal.SIGTERM)
        finally:os.close(fd)
    deadline=time.monotonic()+30
    while owned_vm_pids(disk):
        if time.monotonic()>deadline:raise ValueError('synthetic_primary_not_offline')
        time.sleep(0.2)


def fetch_generation(topology, metadata, generation):
    address=topology['nodes']['us']
    if (not topology.get('synthetic_only') or address!='198.18.0.12'
            or 'root@'+address not in metadata.get('destinations', [])):
        raise ValueError('confirmed_independent_synthetic_receiver_required')
    pending=[]
    for kind,pattern in (('backup',r'backup-[0-9]+-[a-f0-9]{32}\.age'),('artifact',r'artifact-[a-f0-9]{64}\.age')):
        name=metadata[kind+'_name'];digest=metadata[kind+'_sha256']
        if not re.fullmatch(pattern,name) or not re.fullmatch(r'[a-f0-9]{64}',digest):
            raise ValueError('invalid_synthetic_generation_receipt')
        data=ssh(topology,address,['cat','/var/lib/ultra-recovery/'+name])
        if hashlib.sha256(data).hexdigest()!=digest:
            raise ValueError('synthetic_receiver_ciphertext_mismatch')
        pending.append((name,data))
    generation.mkdir(exist_ok=True,mode=0o700)
    for name,data in pending:
        path=generation/name;path.write_bytes(data);path.chmod(0o600)
    return generation/metadata['backup_name']


def fixture_helper_sources():
    base=Path(__file__).parent
    return {name:(base/source).read_bytes() for name,source in {
        'acceptance.py':'vm_payload.py', 'restore_host.py':'restore_host.py',
        'db_connection.py':'db_connection.py',
        'restore_common.py':'restore_common.py'}.items()}


def fixture_public_key(path):
    if not path:
        raise ValueError('synthetic_upgrade_trusted_public_key_file_required')
    lines=Path(path).read_text().splitlines()
    if lines and lines[0].startswith('untrusted comment:'):
        lines=lines[1:]
    if len(lines)!=1:
        raise ValueError('invalid_synthetic_upgrade_public_key')
    key=lines[0].strip()
    try:
        decoded=base64.b64decode(key,validate=True)
    except ValueError:
        raise ValueError('invalid_synthetic_upgrade_public_key') from None
    if len(decoded)!=42 or decoded[:2] not in (b'Ed',b'ED'):
        raise ValueError('invalid_synthetic_upgrade_public_key')
    return key


def synthetic_upgrade_config(plan, release, public_key):
    """Project the fixture's initial policy into the signed upgrade CLI contract.

    The canonical format has one bootstrap main exit; all installed exit policy
    (including independent budgets) lives in automation.static_nodes.
    """
    bridge=plan['bridge'];database=plan['database'];bot=plan['bot']
    automation=plan['automation'];ingress=automation['ingress'];ssh_config=plan['ssh']
    main_exit=plan['exits'][0]
    values={
        'INSTALL_SCHEMA_VERSION':'2',
        'ULTRA_RELEASE_MINISIGN_PUBLIC_KEY':public_key,
        'SSH_USER':ssh_config['user'],
        'ULTRA_INSTALL_SSH_STRICT_HOST_KEY':ssh_config['strict_host_key'],
        'BRIDGE_IP':bridge['address'],
        'BRIDGE_SSH_KEY':bridge.get('ssh_identity',ssh_config['identity']),
        'PUBLIC_HOST':bridge['public_host'],
        'REUSE_BRIDGE_SPEC':bridge.get('reuse_spec',False),
        'REALITY_DEST':bridge['reality_dest'],'REALITY_SNI':bridge['reality_sni'],
        'VLESS_PORT':bridge['vless_port'],
        'MAIN_EXIT_IP':main_exit['ssh_host'],
        'MAIN_EXIT_SSH_KEY':main_exit.get('ssh_identity',ssh_config['identity']),
        'DATABASE_IP':database['primary_host'],
        'DATABASE_SSH_KEY':database.get('ssh_identity',ssh_config['identity']),
        'DB_NAME':database['name'],'DB_USER':database['user'],
        'BOT_ENABLE':bot['enabled'],'BOT_DOMAIN':bot['domain'],'BOT_PORT':bot['port'],
        'SUBSCRIPTION_DOMAIN':bot.get('subscription_domain',bot['domain']),
        'VPN_DOMAIN':ingress['domain'],'ACME_EMAIL':ingress['email'],
        'PUBLIC_XHTTP_PATH':ingress['path'],
        'BOT_INGRESS_IP':ingress.get('forward_host',''),
        'ULTRA_AUTOMATION_VERSION':release['version'],
        'ULTRA_AUTOMATION_RELEASE_DIR':release['directory'],
        'ULTRA_AUTOMATION_AGE_RECIPIENT':automation['age_recipient'],
        'ULTRA_AUTOMATION_BRIDGE_PROVIDER':automation['bridge_provider'],
        'ULTRA_AUTOMATION_BRIDGE_URL':automation['bridge_url'],
        'ULTRA_AUTOMATION_KNOWN_HOSTS_FILE':automation['known_hosts_file'],
        'ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID':automation['admin_telegram_id'],
        'ULTRA_AUTOMATION_STATIC_NODES':json.dumps(automation['static_nodes']),
        'ULTRA_AUTOMATION_READINESS_TIMEOUT_SEC':automation['readiness_timeout_sec'],
    }
    if automation.get('dns'):
        dns=automation['dns']
        values.update(DNS_PROVIDER=dns['provider'],DNS_ZONE=dns['zone'],DNS_TTL=dns.get('ttl',300),
                      DNS_SUBSCRIPTION_NAME=dns['subscription_name'],DNS_VPN_NAME=dns['vpn_name'])
    for field in ('state_paths','artifact_paths'):
        if field in automation:
            values['ULTRA_AUTOMATION_'+field.upper()]=json.dumps(automation[field])
    for field in ('backend','gateway','status','experimental','staging'):
        if field+'_port' in ingress:
            values['ULTRA_INGRESS_'+field.upper()+'_PORT']=ingress[field+'_port']
    # JSON string quoting matches the canonical Go parser, including spaces,
    # quotes and backslashes in private fixture paths. No shell evaluates it.
    return ''.join(key+'='+json.dumps(str(value).lower() if isinstance(value,bool) else str(value))+'\n'
                   for key,value in values.items())


def require_synthetic_upgrade_dns_policy(plan):
    # The real forward-only VM fixture has no managed DNS provider. A canonical
    # direct-ingress plan can be exercised locally in preflight tests, but dummy
    # credentials do not make live provider mutation available to this harness.
    automation=plan.get('automation',{})
    if not automation.get('dns') or automation.get('ingress',{}).get('forward_host'):
        raise ValueError('synthetic_upgrade_managed_dns_fixture_required')


def serial_upgrade(directory, installer, upgrade_release, public_key_file):
    if not upgrade_release:
        raise ValueError('explicit_synthetic_upgrade_release_required')
    next_release=Path(upgrade_release).resolve()
    manifest=json.loads((next_release/'release-manifest.json').read_text())
    version=manifest.get('version','')
    if version=='latest' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}',version):
        raise ValueError('explicit_synthetic_upgrade_version_required')
    public_key=fixture_public_key(public_key_file)
    plan=json.loads((directory/'install-plan.json').read_text())
    require_synthetic_upgrade_dns_policy(plan)
    config=directory/'upgrade-install.config'
    config.write_text(synthetic_upgrade_config(plan,{'version':version,'directory':str(next_release)},public_key))
    config.chmod(0o600)
    # Resolve canonical .env only inside this private fixture workspace; never
    # persist a bootstrap plan's secret-file reference in the public policy.
    run([installer,'upgrade','--config',str(config),'--release-dir',str(next_release)],directory/'upgrade.log',cwd=directory)
    return version


def execute(args):
    os.umask(0o077)
    directory=Path(args.workspace).resolve();installer=str(Path(args.installer).resolve())
    if args.upgrade_release:
        fixture_public_key(getattr(args,'upgrade_public_key_file',None))
        # Fresh VM apply intentionally uses the supported external/forward
        # ingress path. It cannot also supply managed DNS for signed upgrade.
        if not getattr(args,'existing_deployment',False):
            raise ValueError('synthetic_upgrade_managed_dns_fixture_required')
        require_synthetic_upgrade_dns_policy(json.loads((directory/'install-plan.json').read_text()))
    topology=json.loads((directory/'topology.json').read_text())
    if not topology.get('synthetic_only') or not topology.get('isolation_verified_at'):
        raise ValueError('verified_synthetic_topology_required')
    vpn = {topology['nodes'][node] for node in ('bridge', 'nl', 'us', 'replacement')}
    databases = {topology['nodes'].get(node) for node in ('database', 'database_restore')}
    if None in databases or len(databases) != 2 or vpn & databases:
        raise ValueError('isolated_dedicated_database_vm_fixture_required')
    receipt_path=directory/'acceptance.json'
    receipt=json.loads(receipt_path.read_text()) if receipt_path.exists() else {'started_at':int(time.time()),'completed':[],'synthetic_only':True}
    def save():receipt_path.write_text(json.dumps(receipt));receipt_path.chmod(0o600)
    save()
    def phase(name,action):
        if name not in receipt['completed']:
            receipt['phase']=name;save();action();receipt['completed'].append(name);save()
    def init_key():
        run([installer,'recovery-key','init','--identity',str(directory/'identity.age'),'--recipient-output',str(directory/'recipient.txt')],directory/'key.log')
        shutil.copyfile(directory/'identity.age',directory/'extracted-identity.age');(directory/'extracted-identity.age').chmod(0o600)
    phase('operator_key',init_key)
    phase('isolated_payload_targets',lambda:payload_targets(directory))
    def apply():
        plan=json.loads((Path(__file__).parent.parent / 'install-plan-v2.example.json').read_text())
        plan['ssh']={'user':'root','identity':topology['identity'],'strict_host_key':True}
        plan['bridge'].update(address=topology['nodes']['bridge'], ssh_host=topology['nodes']['bridge'], public_host=topology['nodes']['bridge'], ssh_identity=topology['identity'])
        plan['database'].update(enabled=True, primary_host=topology['nodes']['database'], ssh_user='root', ssh_identity=topology['identity'])
        plan['exits']=[{'name':'NL','ssh_host':topology['nodes']['nl'],'priority':100},{'name':'US','ssh_host':topology['nodes']['us'],'priority':200}]
        plan['bot'].update(domain='vpn.fixture.test')
        env=directory/'.env';env.write_text('TELEGRAM_BOT_TOKEN=123456:synthetic_fixture_token_only\nULTRA_RELAY_ADMIN_TOKEN=synthetic_fixture_admin_token_only\n');env.chmod(0o600)
        cloud=directory/'synthetic-cloud-key';cloud.write_text('synthetic-no-provider-permission');cloud.chmod(0o600)
        plan['secrets']['env_file']=str(env)
        release=json.loads((Path(args.release_dir)/'release-manifest.json').read_text())
        automation=plan['automation'];automation.update(version=release['version'],release_dir=str(Path(args.release_dir).resolve()),age_recipient=(directory/'recipient.txt').read_text().strip(),bridge_ipv4=topology['nodes']['bridge'],bridge_provider='fixture-a',bridge_url='https://vpn.fixture.test/happ',cloud_key_file=str(cloud),known_hosts_file=topology['known_hosts'],admin_telegram_id=123456789)
        automation['static_nodes']=[{'name':'NL','address':topology['nodes']['nl'],'provider':'fixture-a','budget':{'monthly_bytes':107374182400,'is_fallback':True}},{'name':'US','address':topology['nodes']['us'],'provider':'fixture-b','budget':{'monthly_bytes':107374182400,'is_fallback':False}}]
        automation['ingress'].update(domain='vpn.fixture.test',forward_host=topology['nodes']['nl'],public_host=topology['nodes']['bridge'])
        (directory/'install-plan.json').write_text(json.dumps(plan))
        run([installer,'apply','--plan',str(directory/'install-plan.json'),'--format','jsonl'],directory/'apply.log')
    if getattr(args, 'existing_deployment', False):
        # Resume only a separately verified existing synthetic deployment. Do not
        # relabel a previously failed installation as a successful apply.
        phase('existing_deployment_preflight',lambda:run([installer,'status','--plan',str(directory/'install-plan.json')],directory/'existing-status.log'))
    else:
        phase('apply',apply)
    if args.upgrade_release:
        def upgrade():
            receipt['upgraded_version']=serial_upgrade(directory,installer,args.upgrade_release,args.upgrade_public_key_file);save()
        phase('serial_upgrade',upgrade)
    def install_payload_tools(address):
        files={**{'/opt/ultra-fixture/'+name:data for name,data in fixture_helper_sources().items()},
               '/usr/local/bin/ultra-acceptance-client':(Path(args.upgrade_release or args.release_dir)/'ultra-client-linux-amd64').read_bytes(),
               '/usr/local/bin/ultra-acceptance-state':Path(args.state_proof).read_bytes()}
        for destination,data in files.items():
            code="import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(sys.stdin.buffer.read());p.chmod(0o700)"
            ssh(topology,address,['python3','-c',code,destination],data)
    def seed_accounts():
        install_payload_tools(topology['nodes']['bridge'])
        proof=json.loads(ssh(topology,topology['nodes']['bridge'],['python3','/opt/ultra-fixture/acceptance.py','seed'],timeout=600))
        receipt['fixture_accounts']=proof;save()
    phase('five_fixture_accounts',seed_accounts)
    def capture():
        bridge=topology['nodes']['bridge']
        ssh(topology,bridge,['systemctl','start','ultra-recovery-backup.service'])
        metadata=json.loads(ssh(topology,bridge,['cat','/var/lib/ultra-recovery/last-success.json']))
        receipt['bundle']=str(fetch_generation(topology,metadata,directory/'generation'));receipt['snapshot_at']=metadata['snapshot_at'];save()
        run([installer,'recovery-key','verify','--identity',str(directory/'identity.age'),'--extracted-identity',str(directory/'extracted-identity.age'),'--bundle',receipt['bundle'],'--receipt',str(directory/'key-proof.json')],directory/'key.log')
    phase('encrypted_generation',capture)
    # Recheck real process ownership even when an earlier receipt says fenced.
    # Cached topology PIDs can become stale after fixture VM restarts.
    fence_owned_vm(directory/'bridge/disk.qcow2')
    phase('old_primary_fenced',lambda:None)
    fence={'source':'bridge','confirmed_offline':True,'confirmed_at':int(time.time()),'source_address':topology['nodes']['bridge'],'target_host':'root@'+topology['nodes']['replacement']}
    # Every retry rechecks that the old producer remains absent.
    if owned_vm_pids(directory/'bridge/disk.qcow2'):raise ValueError('old_primary_process_exists')
    (directory/'fence.json').write_text(json.dumps(fence))
    config={'format':1,'source':'bridge','bundle':receipt['bundle'],'identity':str(directory/'extracted-identity.age'),'fence_file':str(directory/'fence.json'),'state_dir':str(directory/'restore-runs'),
            'target':{'host':fence['target_host'],'identity':topology['identity'],'known_hosts':topology['known_hosts']},
            'database_host':topology['nodes']['database_restore'],
            'database_target':{'host':'root@'+topology['nodes']['database_restore'],'identity':topology['identity'],'known_hosts':topology['known_hosts']},
            'ingress':{'host':'root@'+topology['nodes']['nl'],'identity':topology['identity'],'known_hosts':topology['known_hosts']},
            'new_bridge_provider':'fixture-a','old_bridge_address':topology['nodes']['bridge'],'new_bridge_address':topology['nodes']['replacement'],'public_host':topology['nodes']['replacement'],'subscription_domain':'vpn.fixture.test','readiness_timeout':900,'isolated_peer_addresses':list(topology['nodes'].values())}
    (directory/'restore.json').write_text(json.dumps(config))
    if 'restore_started_at' not in receipt:receipt['restore_started_at']=int(time.time());save()
    phase('restore',lambda:run([installer,'restore','--config',str(directory/'restore.json')],directory/'restore.log'))
    # Run it again: the same command must verify and resume without reimporting DB.
    phase('idempotent_resume',lambda:run([installer,'restore','--config',str(directory/'restore.json')],directory/'resume.log'))
    def verify_payload():
        install_payload_tools(topology['nodes']['replacement'])
        proof=json.loads(ssh(topology,topology['nodes']['replacement'],['python3','/opt/ultra-fixture/acceptance.py','verify'],timeout=900))
        receipt['payload_proof']=proof;save()
    phase('five_account_payload_and_emergency',verify_payload)
    receipt['restore_elapsed_seconds']=int(time.time())-receipt['restore_started_at']
    receipt['within_one_hour']=receipt['restore_elapsed_seconds']<=3600
    receipt['completed_at']=int(time.time());save()
    print(json.dumps(receipt))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--workspace',required=True);parser.add_argument('--installer',required=True);parser.add_argument('--release-dir',required=True);parser.add_argument('--state-proof',required=True);parser.add_argument('--upgrade-release');parser.add_argument('--existing-deployment',action='store_true',help='verify installed automation, then restore without repeating apply')
    parser.add_argument('--upgrade-public-key-file',help='independently trusted synthetic fixture Minisign public key; required with --upgrade-release')
    execute(parser.parse_args())
