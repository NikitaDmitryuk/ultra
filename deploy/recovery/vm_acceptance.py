#!/usr/bin/env python3
"""Run the shipped apply/key/restore CLI against a synthetic isolated topology.

Infrastructure/TLS fixture preparation is separate. The restore timer starts
before the real restore command and is never reset after a failure. Only newly
created synthetic credentials and this topology's owned VM processes are used.
"""
import argparse
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


def run(args, log, timeout=3600):
    with log.open('ab') as output:
        result=subprocess.run(args,stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
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
        'restore_common.py':'restore_common.py'}.items()}


def execute(args):
    os.umask(0o077)
    directory=Path(args.workspace).resolve();installer=str(Path(args.installer).resolve())
    topology=json.loads((directory/'topology.json').read_text())
    if not topology.get('synthetic_only') or not topology.get('isolation_verified_at'):
        raise ValueError('verified_synthetic_topology_required')
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
        plan['bridge'].update(ssh_host=topology['nodes']['bridge'],public_host=topology['nodes']['bridge'])
        plan['exits']=[{'name':'NL','ssh_host':topology['nodes']['nl'],'priority':100},{'name':'US','ssh_host':topology['nodes']['us'],'priority':200}]
        plan['bot'].update(domain='vpn.fixture.test')
        env=directory/'synthetic-bot.env';env.write_text('TELEGRAM_BOT_TOKEN=123456:synthetic_fixture_token_only\nULTRA_RELAY_ADMIN_TOKEN=synthetic_fixture_admin_token_only\n');env.chmod(0o600)
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
            plan=json.loads((directory/'install-plan.json').read_text())
            next_release=Path(args.upgrade_release).resolve()
            manifest=json.loads((next_release/'release-manifest.json').read_text())
            plan['automation'].update(version=manifest['version'],release_dir=str(next_release))
            (directory/'upgrade-plan.json').write_text(json.dumps(plan))
            run([installer,'upgrade','--plan',str(directory/'upgrade-plan.json')],directory/'upgrade.log')
            receipt['upgraded_version']=manifest['version'];save()
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
            'ingress':{'host':'root@'+topology['nodes']['nl'],'identity':topology['identity'],'known_hosts':topology['known_hosts']},
            'new_bridge_provider':'fixture-a','old_bridge_address':topology['nodes']['bridge'],'new_bridge_address':topology['nodes']['replacement'],'public_host':topology['nodes']['replacement'],'subscription_domain':'vpn.fixture.test','readiness_timeout':900}
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
    execute(parser.parse_args())
