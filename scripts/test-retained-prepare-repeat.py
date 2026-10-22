#!/usr/bin/env python3
"""Real retained prepare-only CLI twice, root SSH/PostgreSQL/age in one disposable VM.

Distinct loopback role addresses remain inside a network-less container. The
candidate contains checksum-bound synthetic application payloads, never runs.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('execution_fixture',ROOT/'scripts/test-execution-systemd.py')
F=importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

SETUP=r'''import hashlib,json,pathlib,shlex,subprocess,time
root=pathlib.Path('/fixture')
def run(*args):return subprocess.check_output(args,text=True).strip()
def private(path,value):
 p=pathlib.Path(path);p.write_text(value);p.chmod(0o600)
subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f','/fixture/identity'],check=True)
private('/root/.ssh/authorized_keys',(root/'identity.pub').read_text())
subprocess.run(['passwd','-d','root'],check=True,stdout=subprocess.DEVNULL)
public=pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
pins=''.join(host+' '+public[0]+' '+public[1]+'\n' for host in ('127.0.0.1','127.0.0.2','127.0.0.3'))
private('/fixture/pins',pins)
(root/'backup').mkdir(mode=0o700)
private('/fixture/backup/bootstrap-known_hosts',pins)
subprocess.run(['age-keygen','-o','/fixture/age-identity'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
recipient=run('age-keygen','-y','/fixture/age-identity')
private('/fixture/credentials.json',json.dumps({'database':{'dsn':'postgres://app:synthetic-only@127.0.0.1:25432/fixture_db?sslmode=disable'}}))
private('/fixture/secrets.env','TELEGRAM_BOT_TOKEN=123456:synthetic_only_fixture_token\nULTRA_VULTR_API_KEY=synthetic-never-used\n')
private('/fixture/original-journal.json','{"phase":"applying","synthetic":true}\n')
(root/'release').mkdir(mode=0o700)
assets=[]
for name in ('ultra-relay-linux-amd64','ultra-relay-linux-arm64','ultra-bot-linux-amd64','ultra-bot-linux-arm64','ultra-client-linux-amd64','ultra-client-linux-arm64','ultra-recovery.tar.gz'):
 data=('synthetic-unexecuted-'+name).encode();p=root/'release'/name;p.write_bytes(data);p.chmod(0o600)
 assets.append({'name':name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
private('/fixture/release/release-manifest.json',json.dumps({'version':'v1.0.0','capabilities':['service-access-v1'],'database_schema_max':1,'assets':assets}))
config={
 'SSH_USER':'root','BRIDGE_IP':'127.0.0.1','MAIN_EXIT_IP':'127.0.0.2','DATABASE_IP':'127.0.0.3',
 'BRIDGE_SSH_KEY':'/fixture/identity','MAIN_EXIT_SSH_KEY':'/fixture/identity','DATABASE_SSH_KEY':'/fixture/identity',
 'MAIN_EXIT_DOMAIN':'tunnel.example.com','TUNNEL_PORT':'24443','VLESS_PORT':'24443','REALITY_DEST':'origin.example.net:443','REALITY_SNI':'origin.example.net',
 'REUSE_BRIDGE_SPEC':'false','SKIP_GEO_DOWNLOAD':'true','BOT_ENABLE':'true','BOT_DOMAIN':'bot.example.com','SUBSCRIPTION_DOMAIN':'sync.example.com',
 'VPN_DOMAIN':'edge.example.com','PUBLIC_XHTTP_PATH':'/connect','ACME_EMAIL':'operator@example.com','DNS_PROVIDER':'vultr','DNS_ZONE':'example.com',
 'DB_NAME':'fixture_db','DB_USER':'app','DB_CREDENTIALS_FILE':'/fixture/credentials.json','DB_TUNNEL_PRIVATE_KEY_FILE':'/fixture/identity',
 'SECRETS_ENV_FILE':'/fixture/secrets.env','ULTRA_RELEASE_MINISIGN_PUBLIC_KEY':'RWQsynthetic-fixture-key',
 'ULTRA_OPERATOR_AGE_IDENTITY_FILE':'/fixture/age-identity','ULTRA_AUTOMATION_VERSION':'v1.0.0','ULTRA_AUTOMATION_RELEASE_DIR':'/fixture/release',
 'ULTRA_AUTOMATION_AGE_RECIPIENT':recipient,'ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID':'123456','ULTRA_AUTOMATION_BRIDGE_PROVIDER':'fixture',
 'ULTRA_AUTOMATION_BRIDGE_URL':'https://sync.example.com/healthz','ULTRA_AUTOMATION_KNOWN_HOSTS_FILE':'/fixture/pins',
 'ULTRA_AUTOMATION_STATIC_NODES':json.dumps([{'name':'primary','address':'127.0.0.2','provider':'fixture','budget':{'monthly_bytes':1000000,'is_fallback':True}}])}
private('/fixture/install.config',''.join(k+'='+shlex.quote(v)+'\n' for k,v in config.items()))
'''
SQL=r"""CREATE DATABASE fixture_db;
\connect fixture_db
CREATE TABLE schema_migrations(version bigint PRIMARY KEY);
INSERT INTO schema_migrations VALUES (1);
CREATE TABLE exit_nodes(name text, address text, port int, tunnel_uuid text, pinned_peer_cert_sha256 text, priority int, enabled bool);
INSERT INTO exit_nodes VALUES ('primary','127.0.0.2',24443,'11111111-2222-3333-4444-555555555555','',0,true);
"""


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime',type=Path,required=True)
    args=parser.parse_args()
    runtime=args.runtime.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='.retained-prepare-fixture-',dir=ROOT) as temporary:
        directory=Path(temporary)
        installer=directory/'ultra-install'
        F.run(['go','build','-o',str(installer),'./cmd/ultra-install'],cwd=ROOT,env={**os.environ,'CGO_ENABLED':'0'})
        (directory/'Dockerfile').write_text('FROM ubuntu:24.04\nENV container=docker\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus openssh-server openssh-client python3 python3-venv age postgresql postgresql-client && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /root/.ssh && ssh-keygen -A\nSTOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n')
        image='ultra-retained-prepare-fixture'
        F.run(['docker','build','-q','-t',image,str(directory)])
        name='ultra-retained-prepare-'+uuid.uuid4().hex[:12]
        F.run(['docker','run','-d','--name',name,'--network','none','--privileged','--cgroupns','private','--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp',image])
        def command(*argv,**kwargs):return F.run(['docker','exec','-i',name,*argv],**kwargs)
        try:
            F.wait(lambda:subprocess.run(['docker','exec',name,'systemctl','show','--property=Version','--value'],capture_output=True).returncode==0)
            command('mkdir','-m','700','/fixture')
            F.run(['docker','cp',str(installer),name+':/fixture/ultra-install'])
            F.run(['docker','cp',str(runtime),name+':/fixture/runtime.tar.gz'])
            command('mkdir','-p','/fixture/source/scripts','/fixture/source/deploy/recovery','/fixture/wheels')
            for source,target in [(ROOT/'scripts/operator-db-dump.py','scripts/operator-db-dump.py'),(ROOT/'deploy/recovery/ssh_policy.py','deploy/recovery/ssh_policy.py'),(ROOT/'deploy/recovery/ssh_policy.json','deploy/recovery/ssh_policy.json')]:
                F.run(['docker','cp',str(source),name+':/fixture/source/'+target])
            command('tar','-xzf','/fixture/runtime.tar.gz','-C','/fixture/wheels')
            command('python3','-m','venv','/opt/runtime')
            command('/opt/runtime/bin/pip','install','--no-index','--require-hashes','--find-links=/fixture/wheels/wheels','-r','/fixture/wheels/requirements.lock')
            command('python3','-c',SETUP)
            command('mkdir','-p','/run/sshd')
            command('python3','-c',"from pathlib import Path; Path('/etc/ssh/sshd_config.d/fixture.conf').write_text('PermitRootLogin yes\\nPasswordAuthentication no\\nUsePAM no\\n')")
            command('systemctl','restart','ssh.service')
            command('systemctl','start','postgresql@16-main.service')
            command('runuser','-u','postgres','--','psql','--no-psqlrc','-v','ON_ERROR_STOP=1',input=SQL)
            snapshot="SELECT json_build_object('versions',(SELECT json_agg(version) FROM schema_migrations),'routes',(SELECT json_agg(exit_nodes) FROM exit_nodes));"
            before=command('runuser','-u','postgres','--','psql','--no-psqlrc','-At','-d','fixture_db','-c',snapshot)
            command('python3','/fixture/source/scripts/operator-db-dump.py','--config','/fixture/install.config','--identity','/fixture/age-identity','--output-dir','/fixture/backup')
            backup=command('python3','-c',"import pathlib; p=list(pathlib.Path('/fixture/backup').glob('*.backup.tar.age')); assert len(p)==1; print(p[0])")
            digest=command('sha256sum',backup).split()[0]
            protected=command('stat','-c','%u:%g:%a:%s:%i',backup)
            prepared=[]
            for workspace in ('prepare-first','prepare-second'):
                state='/fixture/'+workspace
                if workspace=='prepare-first':command('mkdir','-m','700',state)
                output=command('/fixture/ultra-install','rebuild-retained-primary','--accept-reimaged-fleet','--prepare-only','--config','/fixture/install.config','--manifest','/fixture/release/release-manifest.json','--original-journal','/fixture/original-journal.json','--state-dir',state,'--backup',backup,'--backup-sha256',digest,'--python','/usr/bin/python3','--executable','/opt/runtime/bin/ansible-playbook',timeout=90)
                assert 'inputs validated; production unchanged' in output,output
                command('test','-f',state+'/prepared-input.json')
                saved=json.loads(command('cat',state+'/prepared-input.json'))
                assert saved['BackupSHA256']==digest
                prepared.append(saved)
                assert command('stat','-c','%u:%g:%a:%s:%i',backup)==protected
                assert command('sha256sum',backup).split()[0]==digest
                assert command('runuser','-u','postgres','--','psql','--no-psqlrc','-At','-d','fixture_db','-c',snapshot)==before
                command('test','!','-e','/var/lib/ultra-ansible/retained-primary-admission.json')
                command('test','!','-e','/var/lib/ultra-ansible/execution-fence.json')
                command('test','!','-e',state+'/execute')
                print(workspace+': actual CLI passed; backup unchanged; no execution or remote fence',flush=True)
            assert prepared[0]['BackupSnapshotUTC']==prepared[1]['BackupSnapshotUTC']
            assert prepared[0]['Primary']==prepared[1]['Primary']
        finally:F.run(['docker','rm','-f',name])


if __name__=='__main__':main()
