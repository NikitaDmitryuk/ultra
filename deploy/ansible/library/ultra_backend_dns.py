#!/usr/bin/python
"""Extend the existing owned DNS policy without adopting or changing public records."""
import importlib.util
import json
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


def reconcile(application, domain, zone, address, root=Path('/etc/ultra-recovery')):
    policy_path = root / 'dns.json'
    policy = json.loads(application.private(policy_path).read_text())
    if policy['config']['zone'] != zone or not domain.endswith('.' + zone):
        raise ValueError('backend_dns_zone_mismatch')
    desired = policy['desired']
    if set(desired) not in ({'subscription', 'vpn'}, {'subscription', 'vpn', 'backend'}):
        raise ValueError('backend_dns_policy_mismatch')
    backend = {'name': domain[:-len(zone)-1], 'data': address}
    if 'backend' in desired and desired['backend'] != backend:
        raise ValueError('backend_dns_previous_operation_requires_review')
    receipt = json.loads(application.private(root / 'dns-receipt.json').read_text())
    for role in ('subscription', 'vpn'):
        target = dict(desired[role], type='A', ttl=policy['config'].get('ttl', 300))
        if not application.same(receipt['records'].get(role), target):
            raise ValueError('backend_public_dns_policy_drift')
    desired['backend'] = backend
    result = application.execute(policy['config'], desired, root / 'dns-receipt.json')
    application.wait_ready(policy['config'], desired)
    application.save(policy_path, policy)
    return result


def main():
    module = AnsibleModule(argument_spec={
        'domain': {'type': 'str', 'required': True},
        'zone': {'type': 'str', 'required': True},
        'address': {'type': 'str', 'required': True},
    }, supports_check_mode=False)
    try:
        source = Path('/opt/ultra-recovery/dns.py')
        if source.is_symlink() or source.stat().st_uid != 0 or source.stat().st_mode & 0o022:
            raise ValueError('untrusted_dns_application')
        spec = importlib.util.spec_from_file_location('backend_dns', source)
        application = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(application)
        reconcile(application, module.params['domain'], module.params['zone'], module.params['address'])
        module.exit_json(changed=True, ready=True)
    except Exception:
        module.fail_json(msg='backend_owned_dns_failed')


if __name__ == '__main__':
    main()
