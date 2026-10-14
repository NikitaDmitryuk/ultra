#!/usr/bin/python
"""Bind a native broker deployment to its actual target machine privately."""
from ansible.module_utils.basic import AnsibleModule
from pathlib import Path
import hashlib
import ipaddress
import json
import os
import re
import tempfile


def main():
    module = AnsibleModule(argument_spec={'address': {'type': 'str', 'required': True}}, supports_check_mode=True)
    try:
        address = str(ipaddress.ip_address(module.params['address']))
        machine = Path('/etc/machine-id').read_text().strip()
        if not re.fullmatch(r'[a-f0-9]{32}', machine) or os.geteuid() != 0:
            raise ValueError('invalid_machine_identity')
        target = Path('/var/lib/ultra-ansible/deployment-identity.json')
        wanted = {'schema_version': 1, 'role': 'bridge', 'machine_sha256': hashlib.sha256(machine.encode()).hexdigest(), 'address': address}
        if target.exists():
            if target.is_symlink() or target.stat().st_uid != 0 or target.stat().st_mode & 0o077:
                raise ValueError('unknown_deployment_identity')
            previous = json.loads(target.read_text())
            if previous.get('schema_version') != 1 or not re.fullmatch(r'[a-f0-9]{64}', previous.get('machine_sha256', '')):
                raise ValueError('unknown_deployment_identity')
            ipaddress.ip_address(previous['address'])
            if previous == wanted:
                module.exit_json(changed=False)
        if not module.check_mode:
            with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
                temporary = stream.name
                stream.write(json.dumps(wanted).encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            directory = os.open(target.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        module.exit_json(changed=True)
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='deployment_identity_failed')


if __name__ == '__main__':
    main()
