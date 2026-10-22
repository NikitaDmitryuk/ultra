#!/usr/bin/env python3
"""Retained-primary deployment repair on the owned, isolated six-QEMU fixture.

This driver never loads operator configuration/keys. Bootstrap is a separate
checkpoint: it does not claim recovery preparation or the later upgrade passed.
Every mutating child has a durable intent; an interrupted child is not replayed.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from vm_topology import NODES, endpoint
from vm_topology_fixture import dependencies, payload_targets, ssh
from vm_acceptance import synthetic_upgrade_config


def need(value, reason):
    if not value:
        raise ValueError(reason)


ORIGINAL_COMMIT='0210df891322b56ff747241bc43974677a786525'
FAILED_COMMIT='4c287fd4d4b44f019c40668ae51bd396ff0aaa20'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def publish(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    pending = path.with_name('.' + path.name + '.pending')
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        pending.unlink(missing_ok=True)


def checked_topology(directory):
    directory = Path(directory).resolve()
    value = json.loads((directory / 'topology.json').read_text())
    need(value.get('synthetic_only') is True and value.get('network_restrict') is True and
         value.get('isolation_verified_at') and value.get('nodes') == {name: endpoint(i) for i, name in enumerate(NODES)},
         'verified_isolated_six_vm_topology_required')
    for name, expected in [('identity', 'synthetic_operator_key'), ('known_hosts', 'known_hosts')]:
        path = Path(value[name])
        need(path == directory / expected and not path.is_symlink() and path.is_file(), 'fixture_transport_path_invalid')
        info = path.stat()
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'fixture_transport_permissions_invalid')
    # Public pins may be read; the private identity is passed only by path to SSH.
    value['fixture_binding'] = sha(json.dumps({'nodes':value['nodes'], 'base_image':value['base_image'],
        'pins_sha256':file_sha(value['known_hosts'])},sort_keys=True).encode())
    return value


def checked_release(directory):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / 'release-manifest.json').read_text())
    need(re.fullmatch('[a-f0-9]{40}', manifest.get('source_commit','')) and
         manifest.get('version') == 'v0.0.' + str(int(manifest['source_commit'],16)) and
         len(manifest.get('assets',[])) == 14, 'complete_commit_bound_baseline_release_required')
    names = set()
    for asset in manifest['assets']:
        name = asset['name']; path = directory / name
        need(Path(name).name == name and name not in names and not path.is_symlink() and path.is_file() and
             path.stat().st_size == asset['size'] and file_sha(path) == asset['sha256'], 'baseline_asset_changed')
        names.add(name)
    return manifest


def baseline_plan(topology, release, release_dir, recipient, credentials, cloud):
    plan = json.loads((Path(__file__).parent.parent / 'install-plan-v2.example.json').read_text())
    nodes = topology['nodes']; identity = topology['identity']
    plan['ssh'] = {'user':'root','identity':identity,'strict_host_key':True}
    plan['bridge'].update(address=nodes['bridge'],ssh_host=nodes['bridge'],public_host=nodes['bridge'],
        reality_dest='www.google.com:443',reality_sni='www.google.com',ssh_identity=identity)
    plan['database'].update(enabled=True,primary_host=nodes['database'],ssh_user='root',ssh_identity=identity)
    plan['exits'] = [{'name':'NL','ssh_host':nodes['nl'],'priority':100,'ssh_identity':identity}]
    plan['bot'].update(domain='vpn.fixture.test')
    plan['secrets']['env_file'] = str(credentials)
    automation = plan['automation']
    automation['dns']={'provider':'vultr','zone':'fixture.test','ttl':120,'subscription_name':'sync','vpn_name':'vpn'}
    plan['features']['main_exit_domain']='exit.fixture.test'
    plan['bot']['domain']='admin.fixture.test'
    plan['bot']['subscription_domain']='sync.fixture.test'
    automation.update(version=release['version'],release_dir=str(release_dir),age_recipient=recipient,
        bridge_ipv4=nodes['bridge'],bridge_provider='fixture-a',bridge_url='https://vpn.fixture.test/happ',
        cloud_key_file=str(cloud),known_hosts_file=topology['known_hosts'],admin_telegram_id=123456789,
        readiness_timeout_sec=180)
    automation['static_nodes'] = [{'name':'NL','address':nodes['nl'],'provider':'fixture-b',
        'budget':{'monthly_bytes':107374182400,'is_fallback':True}}]
    automation['ingress'].update(domain='vpn.fixture.test',public_host=nodes['bridge'])
    automation['ingress'].pop('forward_host',None)
    return plan


PRIMARY_QUERY = """BEGIN READ ONLY;
SELECT json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
 'database',current_database(),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'primary',NOT pg_is_in_recovery(),'migration_versions',(SELECT string_agg(version::text,',' ORDER BY version) FROM public.schema_migrations),
 'routes',(SELECT COALESCE(json_agg(json_build_object('name',name,'address',address,'port',port,'tunnel_uuid',tunnel_uuid,
 'pin',pinned_peer_cert_sha256,'priority',priority,'enabled',enabled) ORDER BY address,port),'[]'::json) FROM public.exit_nodes));
ROLLBACK;"""


def primary_identity(topology):
    output = ssh(topology, topology['nodes']['database'], ['runuser','-u','postgres','--','psql','-XAtq',
        '-v','ON_ERROR_STOP=1','-d','ultra_db','-c',PRIMARY_QUERY], timeout=30)
    identity = json.loads(output)
    need(identity.get('primary') is True and identity.get('system_identifier') and identity.get('migration_versions') and
         len(identity.get('routes',[])) == 1 and identity['routes'][0]['address'] == topology['nodes']['nl'] and
         identity['routes'][0]['tunnel_uuid'] and identity['routes'][0].get('pin') in ('',None), 'baseline_primary_identity_incomplete')
    return identity


class Driver:
    def __init__(self, workspace, topology_dir, release_dir, failed_release_dir=None):
        self.workspace = Path(workspace).resolve()
        self.topology_dir = Path(topology_dir).resolve()
        self.release_dir = Path(release_dir).resolve()
        need(self.workspace != self.topology_dir and not self.workspace.is_symlink(), 'separate_driver_workspace_required')
        self.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        need(stat.S_IMODE(self.workspace.stat().st_mode) == 0o700, 'private_driver_workspace_required')
        self.topology = checked_topology(self.topology_dir)
        self.release = checked_release(self.release_dir) if self.release_dir.exists() else None
        self.failed_release_dir=Path(failed_release_dir).resolve() if failed_release_dir else None
        self.failed_release=checked_release(self.failed_release_dir) if self.failed_release_dir else None
        if self.failed_release:need(self.failed_release['source_commit']==FAILED_COMMIT,'exact_failed_candidate_required')
        self.installer = self.release_dir / 'ultra-install-linux-amd64'
        self.binding = {'topology_sha256':self.topology['fixture_binding'],
            'original_baseline_directory':str(self.release_dir),
            'failed_candidate_manifest_sha256':file_sha(self.failed_release_dir/'release-manifest.json') if self.failed_release_dir else ''}
        self.state = self.workspace / 'acceptance.json'
        if self.state.exists():
            self.receipt = json.loads(self.state.read_text())
            need(self.receipt.get('binding') == self.binding, 'acceptance_binding_changed')
        else:
            self.receipt = {'schema':1,'synthetic_only':True,'binding':self.binding,'completed':[],'phase':'new'}
            publish(self.state,self.receipt)

    def phase(self,name,action,fixture_replay=False):
        if name in self.receipt['completed']:
            return
        started = self.workspace / (name + '.started.json')
        if started.exists():
            intent=json.loads(started.read_text())
            need(fixture_replay and name in ('fixture_payload','managed_dns_fixture','baseline_inputs') and intent.get('binding')==self.binding and
                 not (self.workspace/'baseline_apply.started.json').exists(), 'interrupted_phase_requires_observation:' + name)
        else:
            publish(started,{'binding':self.binding,'phase':name,'started_at':int(time.time())})
        self.receipt['phase'] = name; publish(self.state,self.receipt)
        action()
        self.receipt['completed'].append(name); publish(self.state,self.receipt)
        print(json.dumps({'checkpoint':name,'completed':True,'synthetic_only':True}),flush=True)

    def run(self,args,name,timeout=1800):
        with (self.workspace/(name+'.log')).open('ab') as output:
            result = subprocess.run([str(x) for x in args],cwd=self.workspace,stdout=output,stderr=subprocess.STDOUT,
                timeout=timeout,env=dict(os.environ,XDG_CACHE_HOME=str(self.workspace/'cache')))
        need(result.returncode == 0,'synthetic_child_failed:'+name+':'+str(result.returncode))

    def managed_dns(self):
        from vm_topology_fixture import (ensure_certificate, managed_dns_guests,
            MANAGED_DNS_PROGRAM, ManagedDNSStore, FIXTURE_PROVIDER_TOKEN)
        def action():
            # Fixture-only work may finish an interrupted setup. The application
            # apply phase has a separate non-replayable intent below.
            publish(self.topology_dir/'managed-dns-enabled.json',{'synthetic_only':True,'zone':'fixture.test'})
            ensure_certificate(self.topology_dir)
            script=Path(__file__).with_name('vm_topology_fixture.py').resolve()
            expected=[os.fsencode(os.sys.executable),os.fsencode(script),b'serve',b'--workspace',os.fsencode(self.topology_dir)]
            matches=[]
            for proc in Path('/proc').glob('[0-9]*'):
                try:
                    argv=(proc/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                    if argv==expected:matches.append(int(proc.name))
                except FileNotFoundError:pass
            need(len(matches)<=1,'ambiguous_owned_fixture_api_process')
            for pid in matches:
                import signal
                fd=os.pidfd_open(pid)
                try:
                    need((Path('/proc')/str(pid)/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')==expected,'fixture_process_identity_changed')
                    signal.pidfd_send_signal(fd,signal.SIGTERM)
                finally:os.close(fd)
                deadline=time.monotonic()+10
                while Path('/proc',str(pid),'cmdline').exists():
                    try:
                        status=Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[0]
                        if status=='Z':break
                    except FileNotFoundError:break
                    need(time.monotonic()<deadline,'fixture_api_stop_timeout');time.sleep(.1)
            with (self.workspace/'managed-api.log').open('ab') as log:
                child=subprocess.Popen([os.fsdecode(x) for x in expected],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            time.sleep(.5);need(child.poll() is None,'fixture_api_start_failed')
            publish(self.workspace/'managed-api-process.json',{'pid':child.pid,'argv':[os.fsdecode(x) for x in expected],
                'source_sha256':file_sha(script),'certificate_sha256':file_sha(self.topology_dir/'fixture.crt')})
            # Finish only idempotent fixture setup; no app/DB provisioning is
            # hidden in this observational DNS prerequisite.
            deadline=time.monotonic()+1200
            while not dependencies(self.topology_dir):
                need(time.monotonic()<deadline,'fixture_dependencies_timeout');time.sleep(5)
            payload_targets(self.topology_dir)
            managed_dns_guests(self.topology_dir)
            # DNS commands are run on the marked bridge using its actual local
            # resolver and the unchanged provider URL/TLS trust contract.
            remote=r'''import json,pathlib,sys,subprocess,socket,ssl,urllib.request
root=pathlib.Path('/etc/ultra-fixture/dns-proof');root.mkdir(mode=0o700,exist_ok=True)
(root/'dns.py').write_text(sys.stdin.read());sys.path.insert(0,str(root));import dns
key=root/'token';key.write_text('synthetic-no-provider-permission');key.chmod(0o600)
config={'provider':'vultr','zone':'fixture.test','ttl':120,'api_key_file':str(key)}
api=dns.API(config)
# Exercise real POST/PATCH/GET/DELETE plus system and authoritative dig.
target={'type':'A','name':'proof','data':'198.18.0.10','ttl':120}
for row in api.records():
 if row['name']=='proof':api.delete_owned(row)
api.write('POST',target);row=next(r for r in api.records() if r['name']=='proof')
dns.wait_ready(config,{'vpn':target},timeout=20)
assert socket.gethostbyname('proof.fixture.test')=='198.18.0.10'
target['data']='198.18.0.11';api.write('PATCH',target,row['id'])
dns.wait_ready(config,{'vpn':target},timeout=20)
assert socket.gethostbyname('proof.fixture.test')=='198.18.0.11'
row=next(r for r in api.records() if r['name']=='proof');api.delete_owned(row)
assert not any(r['name']=='proof' for r in api.records())
# Leave application names absent: only the installer may create them with its
# matching ownership receipt. Preseeding them makes a genuine bootstrap reject
# the fixture with dns_foreign_record.
print(json.dumps({'provider_crud':True,'resolver_and_authoritative_dig':True,'system_resolve':True,'https_provider_certificate_valid':True,'external_provider_calls':False}))
'''
            result=ssh(self.topology,self.topology['nodes']['bridge'],['python3','-c',remote],
                Path(__file__).with_name('dns.py').read_bytes(),timeout=180)
            proof=json.loads(result);need(all(proof[k] is True for k in ('provider_crud','resolver_and_authoritative_dig','system_resolve','https_provider_certificate_valid')),'fixture_dns_proof_failed')
            publish(self.workspace/'managed-dns-proof.json',proof)
        self.phase('managed_dns_fixture',action,fixture_replay=True)

    def bootstrap(self):
        need(self.release is not None and self.release['source_commit']==ORIGINAL_COMMIT,'exact_original_baseline_0210_required')
        original_sha=file_sha(self.release_dir/'release-manifest.json')
        need(self.receipt.get('original_baseline_manifest_sha256',original_sha)==original_sha,'original_baseline_changed')
        self.receipt['original_baseline_manifest_sha256']=original_sha;publish(self.state,self.receipt)
        self.managed_dns()
        def inputs():
            self.run([self.installer,'recovery-key','init','--identity',self.workspace/'fixture.age',
                '--recipient-output',self.workspace/'fixture-recipient.txt'],'fixture-key',timeout=30)
            credentials = self.workspace/'fixture-runtime.env'
            credentials.write_text('TELEGRAM_BOT_TOKEN=123456:synthetic_fixture_token_only\nULTRA_RELAY_ADMIN_TOKEN=synthetic_fixture_admin_token_only\nULTRA_VULTR_API_KEY=synthetic-no-provider-permission\n')
            credentials.chmod(0o600)
            cloud = self.workspace/'fixture-cloud-key'
            cloud.write_text('synthetic-no-provider-permission');cloud.chmod(0o600)
            saved_database=self.workspace/'fixture-database.json'
            publish(saved_database,{'database':{'dsn':'postgres://ultra:synthetic_fixture_database_only@127.0.0.1:25432/ultra_db?sslmode=disable'}})
            plan = baseline_plan(self.topology,self.release,self.release_dir,(self.workspace/'fixture-recipient.txt').read_text().strip(),credentials,cloud)
            plan['secrets']['database_credentials_file']=str(saved_database)
            publish(self.workspace/'baseline-plan.json',plan)
            # Public policy is separate from the newly created fixture-only
            # runtime credential. Never resolve or copy a user .env/key.
            config = synthetic_upgrade_config(plan,{'version':self.release['version'],'directory':str(self.release_dir)},'')
            config += 'MAIN_EXIT_DOMAIN="exit.fixture.test"\n'
            config += 'SECRETS_ENV_FILE='+json.dumps(str(credentials))+'\n'
            config += 'ULTRA_OPERATOR_AGE_IDENTITY_FILE='+json.dumps(str(self.workspace/'fixture.age'))+'\n'
            config += 'DB_CREDENTIALS_FILE='+json.dumps(str(saved_database))+'\n'
            target=self.workspace/'original.config';target.write_text(config);target.chmod(0o600)
        self.phase('baseline_inputs',inputs,fixture_replay=True)
        self.phase('baseline_apply',lambda:self.run([self.installer,'apply','--plan',self.workspace/'baseline-plan.json',
            '--format','jsonl'],'baseline-apply'))
        def observe():
            identity = primary_identity(self.topology)
            publish(self.workspace/'primary-before.json',identity)
            self.receipt['primary_sha256'] = sha(json.dumps(identity,sort_keys=True).encode())
        self.phase('baseline_primary_verified',observe)
        self.receipt['phase']='baseline_complete';publish(self.state,self.receipt)
        print(json.dumps({'baseline_complete':True,'recovery_acceptance_complete':False,
            'primary_sha256':self.receipt['primary_sha256'],'synthetic_only':True}),flush=True)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['bootstrap','managed-dns','inspect'])
    parser.add_argument('--workspace',default='/work/deployment-repair-0210')
    parser.add_argument('--topology',default='/work/topology')
    parser.add_argument('--baseline-release',default='/work/original-baseline-release')
    parser.add_argument('--failed-candidate-release',default='/work/baseline-release')
    args=parser.parse_args()
    driver=Driver(args.workspace,args.topology,args.baseline_release,args.failed_candidate_release)
    lock=os.open(driver.workspace/'driver.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='bootstrap':driver.bootstrap()
        elif args.action=='managed-dns':driver.managed_dns()
        else:print(json.dumps(driver.receipt,sort_keys=True))
    finally:os.close(lock)


if __name__=='__main__':
    main()
