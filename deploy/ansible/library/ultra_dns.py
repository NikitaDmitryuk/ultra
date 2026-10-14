#!/usr/bin/python
"""Owned DNS API reconciliation; host setup is managed by the DNS role."""
import importlib.util
import ipaddress
import re
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


def validate_backend_record(record):
    if (not isinstance(record, dict) or set(record) != {'id', 'type', 'name', 'data', 'ttl'}
            or record['type'] != 'A' or not re.fullmatch(r'[A-Za-z0-9-]+', str(record['id']))
            or not isinstance(record['name'], str)
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', record['name'])
            or type(record['ttl']) is not int or not 120 <= record['ttl'] <= 86400):
        raise ValueError('owned_backend_receipt_required')
    ipaddress.IPv4Address(record['data'])


def seed_receipt(application, receipt, seed, zone):
    public = {'subscription', 'vpn'}
    records = seed.get('records', {})
    if (seed.get('version') != 1 or seed.get('zone') != zone or seed.get('pending')
            or not isinstance(records, dict) or not public <= set(records) <= public | {'backend'}):
        raise ValueError('owned_dns_receipt_required')
    if 'backend' in records:
        validate_backend_record(records['backend'])
    if receipt.exists() or receipt.is_symlink():
        existing = application.json.loads(application.private(receipt).read_bytes())
        current = existing.get('records', {})
        if (existing.get('version') != 1 or existing.get('zone') != zone
                or not isinstance(current, dict) or not public <= set(current) <= public | {'backend'}
                or any(current[role]['id'] != records[role]['id'] for role in public)):
            raise ValueError('dns_ownership_drift')
        # A public-only historical seed cannot discard an owned backend. If a seed
        # claims that role too, require its complete identity to match, not just ID.
        if 'backend' in current:
            validate_backend_record(current['backend'])
        if 'backend' in records and current.get('backend') != records['backend']:
            raise ValueError('dns_backend_ownership_drift')
    else:
        application.save(receipt, seed)


def main():
    module = AnsibleModule(argument_spec={
        'config': {'type': 'dict', 'required': True, 'no_log': True},
        'desired': {'type': 'dict', 'required': True},
        'receipt': {'type': 'path', 'default': '/etc/ultra-recovery/dns-receipt.json'},
        'wait': {'type': 'bool', 'default': True},
        'receipt_seed': {'type': 'dict', 'no_log': True},
    }, supports_check_mode=False)
    try:
        source = Path('/opt/ultra-recovery/dns.py')
        if source.is_symlink() or source.stat().st_uid != 0 or source.stat().st_mode & 0o022:
            raise ValueError('untrusted_dns_application')
        specification = importlib.util.spec_from_file_location('ultra_dns_application', source)
        application = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(application)
        receipt = Path(module.params['receipt'])
        before = receipt.read_bytes() if receipt.exists() else None
        seed = module.params['receipt_seed']
        if seed:
            seed_receipt(application, receipt, seed, module.params['config']['zone'])
        result = application.execute(module.params['config'], module.params['desired'], str(receipt))
        if module.params['wait']:
            application.wait_ready(module.params['config'], module.params['desired'])
        module.exit_json(changed=before != receipt.read_bytes(), ready=result['ready'])
    except Exception:
        module.fail_json(msg='owned_dns_reconciliation_failed')


if __name__ == '__main__':
    main()
