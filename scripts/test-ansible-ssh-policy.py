"""Exercise the policy shipped inside a real Ansible module payload."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
subprocess.run(['python3', str(ROOT / 'scripts/generate-ansible-ssh-policy.py'), '--check'], check=True)
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    library = directory / 'library'
    library.mkdir()
    (library / 'ultra_policy_probe.py').write_text('''#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
def policy():
    from ansible.module_utils.ultra_ssh_policy import POLICY, ssh_options
    return POLICY['version'], ssh_options('probe'), ssh_options('mutate')
module = AnsibleModule(argument_spec={}, supports_check_mode=True)
version, probe, mutate = policy()
module.exit_json(changed=False, version=version, probe=probe, mutate=mutate)
''')
    environment = os.environ.copy()
    environment.update(ANSIBLE_LIBRARY=str(library),
                       ANSIBLE_MODULE_UTILS=str(ROOT / 'deploy/ansible/module_utils'),
                       ANSIBLE_LOCAL_TEMP=str(directory / 'local'),
                       ANSIBLE_REMOTE_TEMP=str(directory / 'remote'),
                       ANSIBLE_NOCOLOR='1', ANSIBLE_CONFIG=str(ROOT / 'deploy/ansible/ansible.cfg'))
    result = subprocess.run(['ansible', 'localhost', '-i', 'localhost,', '-c', 'local',
                             '-m', 'ultra_policy_probe', '--tree', str(directory / 'results')],
                            env=environment, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('Ansible bundled policy probe failed: ' + result.stderr)
    observed = json.loads((directory / 'results/localhost').read_text())
    assert not observed.get('failed'), observed
    assert observed['version'] == 1
    assert 'ConnectTimeout=15' in observed['probe']
    assert 'ConnectTimeout=30' in observed['mutate']
    for profile in ('probe', 'mutate'):
        for option in ('StrictHostKeyChecking=yes', 'UpdateHostKeys=no', 'ServerAliveInterval=5', 'ServerAliveCountMax=2'):
            assert option in observed[profile]
print('Ansible policy payload works without installed recovery helpers')
