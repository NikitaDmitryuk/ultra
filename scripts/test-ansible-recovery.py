#!/usr/bin/env python3
"""Real SSH/Ansible recovery receiver application; systemd remains a fixture."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    result=subprocess.run(arguments,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)
    if result.returncode: result.check_returncode()
    return result.stdout.decode().strip()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--installer',required=True)
    parser.add_argument('--ansible-playbook',required=True)
    args=parser.parse_args()
    image='ultra-ansible-exit-fixture'
    run(['docker','build','-q','-t',image,str(ROOT/'deploy/ansible/tests')])
    with tempfile.TemporaryDirectory(prefix='ultra-recovery-roles-') as temp:
        directory=Path(temp)
        identity=directory/'identity'
        run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(identity)])
        container=run(['docker','run','-d','-p','127.0.0.1::22',image])
        try:
            run(['docker','cp',str(identity.with_suffix('.pub')),container+':/root/.ssh/authorized_keys'])
            run(['docker','exec',container,'chown','root:root','/root/.ssh/authorized_keys'])
            run(['docker','exec',container,'chmod','600','/root/.ssh/authorized_keys'])
            port=int(run(['docker','port',container,'22/tcp']).split(':')[-1])
            key=run(['docker','exec',container,'cat','/etc/ssh/ssh_host_ed25519_key.pub']).split()
            pins=directory/'pins';pins.write_text(f'[127.0.0.1]:{port} {key[0]} {key[1]}\n');pins.chmod(0o600)
            inventory={'all':{'children':{'recovery_nodes':{'hosts':{'receiver':{
                'ansible_host':'127.0.0.1','ansible_port':port,'ansible_user':'root','ansible_ssh_private_key_file':str(identity),
                'ansible_ssh_args':'-F /dev/null -o ControlMaster=no -o ControlPath=none',
                'ansible_ssh_common_args':'-o StrictHostKeyChecking=yes -o UserKnownHostsFile='+str(pins),
            }}}}}}
            files=[]
            for name in ['recovery.py','db_connection.py','monitor.py','heartbeat.py']:
                files.append({'source':str(ROOT/'deploy/recovery'/name),'destination':'/opt/ultra-recovery/'+name,'mode':'0755'})
            for name in ['ultra-recovery-prune.service','ultra-recovery-prune.timer']:
                files.append({'source':str(ROOT/'deploy/recovery'/name),'destination':'/etc/systemd/system/'+name,'mode':'0644'})
            variables={'ultra_recovery_files':files,'ultra_monitor_mode':'none'}
            for name,value in [('inventory',inventory),('variables',variables)]:
                path=directory/(name+'.json');path.write_text(json.dumps(value));path.chmod(0o600)
            ansible_error=directory/'ansible.stderr'
            wrapped_playbook=directory/'ansible-playbook'
            wrapped_playbook.write_text(
                '#!/usr/bin/env python3\n'
                'import pathlib,subprocess,sys\n'
                f"result=subprocess.run([{args.ansible_playbook!r},*sys.argv[1:]],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n"
                f"pathlib.Path({str(ansible_error)!r}).write_bytes(result.stderr[-4000:]) if result.returncode else None\n"
                'sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr);sys.exit(result.returncode)\n')
            wrapped_playbook.chmod(0o700)
            def apply(expect_success=True):
                job=directory/str(uuid.uuid4())
                command=[args.installer,'ansible-run','--operation','reconcile','--inventory',str(directory/'inventory.json'),
                         '--variables',str(directory/'variables.json'),'--state-dir',str(job),'--python','/usr/bin/python3',
                         '--executable',str(wrapped_playbook)]
                ansible_error.unlink(missing_ok=True)
                result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
                receipt_path=job/'receipt.json'
                if not receipt_path.is_file():
                    stderr=result.stderr.decode('utf-8','replace').strip()[-2000:]
                    playbook_stderr=ansible_error.read_text(errors='replace')[-4000:] if ansible_error.exists() else ''
                    raise ValueError(f"recovery receiver produced no receipt (exit {result.returncode}); {stderr}; ansible: {playbook_stderr}")
                receipt=json.loads(receipt_path.read_text())
                if expect_success and result.returncode:
                    stderr=result.stderr.decode('utf-8','replace').strip()[-2000:]
                    playbook_stderr=ansible_error.read_text(errors='replace')[-4000:] if ansible_error.exists() else ''
                    raise ValueError(f"recovery receiver failed (exit {result.returncode}): {receipt.get('code', 'unknown')} {receipt.get('diagnostic', {})}; {stderr}; ansible: {playbook_stderr}")
                assert (receipt['state']=='succeeded')==expect_success
            apply()
            before=run(['docker','exec',container,'stat','-c','%Y','/opt/ultra-recovery/recovery.py'])
            services=json.loads(run(['docker','exec',container,'cat','/var/lib/fixture-systemctl.json']))
            apply()
            after=run(['docker','exec',container,'stat','-c','%Y','/opt/ultra-recovery/recovery.py'])
            assert before==after,'identical receiver script was rewritten'
            assert services==json.loads(run(['docker','exec',container,'cat','/var/lib/fixture-systemctl.json'])),'identical receiver reactivated service'
            marker=json.loads(run(['docker','exec',container,'cat','/var/lib/ultra-recovery/.ultra-recovery-repository']))
            assert marker=={'source':'bridge','version':1}
            run(['docker','exec',container,'rm','/var/lib/ultra-recovery/.ultra-recovery-repository'])
            run(['docker','exec',container,'touch','/var/lib/ultra-recovery/foreign-generation'])
            apply(False)
            assert run(['docker','exec',container,'test','-f','/var/lib/ultra-recovery/foreign-generation'])==''
            print('Real SSH/Ansible recovery receiver apply/idempotence/foreign-repository rejection passed; full restore and real systemd not covered')
        finally:
            subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,check=False)


if __name__=='__main__':main()
