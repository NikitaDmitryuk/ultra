#!/usr/bin/env python3
"""Native forward role through SSH and real Nginx; generated service shim only."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError('fixture command failed: ' + result.stderr.decode(errors='replace')[-3000:])
    return result.stdout.decode().strip()


SERVICE = '''#!/usr/bin/python3
import json,subprocess,sys
from pathlib import Path
p=Path('/var/lib/forward-service.json');state=json.loads(p.read_text()) if p.exists() else {'active':False,'enabled':False,'reloads':0}
a=[v for v in sys.argv[1:] if not v.startswith('--')];action=a[0]
if action=='show': print('LoadState=loaded\\nActiveState='+('active' if state['active'] else 'inactive')+'\\nUnitFileState='+('enabled' if state['enabled'] else 'disabled')+'\\nCanReload=yes\\nNeedDaemonReload=no')
elif action=='is-enabled': print('enabled' if state['enabled'] else 'disabled');sys.exit(0 if state['enabled'] else 1)
elif action=='enable':state['enabled']=True
elif action in ('start','restart','reload'):
 if action=='reload' and Path('/tmp/fail-next-reload').exists():Path('/tmp/fail-next-reload').unlink();sys.exit(1)
 if action=='reload':subprocess.run(['/usr/sbin/nginx','-s','reload'],check=True);state['reloads']+=1
 elif not state['active']:subprocess.run(['/usr/sbin/nginx'],check=True)
 state['active']=True
elif action=='stop':
 if state['active']:subprocess.run(['/usr/sbin/nginx','-s','quit'],check=True)
 state['active']=False
elif action not in ('daemon-reload','reset-failed'):sys.exit(1)
p.write_text(json.dumps(state))
'''
NGINX = '''#!/bin/sh
if test "$1" = "-t" && test -f /tmp/fail-next-validation; then
 rm /tmp/fail-next-validation
 exit 1
fi
exec /usr/sbin/nginx "$@"
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ansible-playbook', required=True)
    args = parser.parse_args()
    run(['docker', 'build', '-q', '-t', 'ultra-ansible-exit-fixture', str(ROOT / 'deploy/ansible/tests')])
    with tempfile.TemporaryDirectory(prefix='ultra-forward-role-') as temporary:
        directory = Path(temporary)
        (directory / 'Dockerfile').write_text('FROM ultra-ansible-exit-fixture\nRUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx libnginx-mod-stream\n')
        run(['docker', 'build', '-q', '-t', 'ultra-ansible-forward-fixture', str(directory)])
        identity = directory / 'identity'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(identity)])
        container = run(['docker', 'run', '-d', '-p', '127.0.0.1::22', 'ultra-ansible-forward-fixture'])
        try:
            for name, content, destination in [('systemctl', SERVICE, '/usr/local/bin/systemctl'), ('nginx', NGINX, '/usr/local/bin/nginx')]:
                source = directory / name; source.write_text(content); source.chmod(0o755)
                run(['docker', 'cp', str(source), container + ':' + destination])
            run(['docker', 'cp', str(identity.with_suffix('.pub')), container + ':/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chown', 'root:root', '/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chmod', '600', '/root/.ssh/authorized_keys'])
            port = int(run(['docker', 'port', container, '22/tcp']).split(':')[-1])
            public = run(['docker', 'exec', container, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub']).split()
            pins = directory / 'pins'; pins.write_text(f'[127.0.0.1]:{port} {public[0]} {public[1]}\n')
            inventory = directory / 'inventory.json'
            inventory.write_text(json.dumps({'all': {'hosts': {'forward': {
                'ansible_host': '127.0.0.1', 'ansible_port': port, 'ansible_user': 'root',
                'ansible_ssh_private_key_file': str(identity), 'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
                'ansible_ssh_common_args': '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + str(pins),
            }}}}))
            playbook = directory / 'playbook.yml'
            playbook.write_text('---\n- name: Verify native forward ingress\n  hosts: all\n  gather_facts: false\n  roles: [forward_ingress]\n')
            variables = directory / 'variables.json'
            env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'deploy/ansible/ansible.cfg'))
            command = [args.ansible_playbook, '-i', str(inventory), str(playbook), '-e', '@' + str(variables)]
            def apply(bridge='192.0.2.1', fails=False):
                variables.write_text(json.dumps({'ultra_forward_bridge_ipv4': bridge, 'ultra_forward_domain': 'sync.example.com', 'ultra_forward_bot_port': 8444}))
                result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
                if (result.returncode != 0) != fails:
                    raise AssertionError(result.stdout.decode(errors='replace')[-5000:] + result.stderr.decode(errors='replace'))
            def digest():
                return run(['docker', 'exec', container, 'sha256sum', '/etc/nginx/nginx.conf', '/etc/nginx/stream.d/bot-proxy.conf', '/etc/nginx/conf.d/acme-proxy.conf'])
            apply(); original = digest()
            first = run(['docker', 'exec', container, 'cat', '/var/lib/forward-service.json'])
            apply(); assert digest() == original
            assert run(['docker', 'exec', container, 'cat', '/var/lib/forward-service.json']) == first, 'unchanged repeat reloaded service'
            for marker in ('fail-next-validation', 'fail-next-reload'):
                run(['docker', 'exec', container, 'touch', '/tmp/' + marker])
                apply('192.0.2.2', fails=True)
                assert digest() == original, 'failed activation lost working before-images'
            run(['docker', 'exec', container, 'python3', '-c', "from pathlib import Path;Path('/etc/nginx/stream.d/bot-proxy.conf').write_text('foreign')"])
            apply(fails=True)
            assert run(['docker', 'exec', container, 'cat', '/etc/nginx/stream.d/bot-proxy.conf']) == 'foreign'
            print('Native SSH forward role: Nginx validation/listeners, unchanged repeat, validation/reload rollback and foreign-file refusal passed; real systemd tested separately')
        finally:
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    main()
