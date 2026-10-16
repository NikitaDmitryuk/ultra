#!/usr/bin/env python3
"""Run the database tunnel authorization assertion with pinned Ansible."""
import base64
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'deploy/ansible/roles/db_tunnel/tasks/authorize.yml'
tasks = yaml.safe_load(source.read_text())
assertion = next(task for task in tasks if task.get('name') == 'Require authorization stage on database host')
fixture = base64.b64encode(b'ssh-ed25519 YWJj fixture').decode()
playbook = [{
    'name': 'Check database tunnel authorization precondition',
    'hosts': 'localhost',
    'connection': 'local',
    'gather_facts': False,
    'tasks': [
        {'ansible.builtin.set_fact': {'db_tunnel_bridge_public_key_slurp': {'content': fixture}}},
        assertion,
    ],
}]

with tempfile.TemporaryDirectory(prefix='ultra-ansible-db-tunnel-') as directory:
    path = Path(directory) / 'check.yml'
    path.write_text(yaml.safe_dump(playbook, sort_keys=False))
    environment = os.environ.copy()
    environment['ANSIBLE_CONFIG'] = str(ROOT / 'deploy/ansible/ansible.cfg')
    subprocess.run(
        ['ansible-playbook', '-i', 'localhost,', str(path)],
        cwd=ROOT,
        env=environment,
        check=True,
    )

print('Database tunnel authorization assertion passed with the pinned Ansible runtime')
