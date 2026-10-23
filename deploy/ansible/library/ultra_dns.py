#!/usr/bin/python
"""Owned DNS API reconciliation; host setup is managed by the DNS role."""
import importlib.util
import ipaddress
import re
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


# Roles the ownership receipt may describe. A seed is an explicit operator
# attestation, so it may claim any owned role, including the exit tunnel.
PUBLIC = {'subscription', 'vpn'}
OWNED = PUBLIC | {'backend', 'tunnel'}

# Only bounded application codes reach the caller; raw provider payloads, request
# bodies and credentials never leave this process.
BOUNDED = re.compile(r'(?:dns|owned)_[a-z0-9_]{1,64}\Z')


def validate_owned_record(record, code):
    if (not isinstance(record, dict) or set(record) != {'id', 'type', 'name', 'data', 'ttl'}
            or record['type'] != 'A' or not re.fullmatch(r'[A-Za-z0-9-]+', str(record['id']))
            or not isinstance(record['name'], str)
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', record['name'])
            or type(record['ttl']) is not int or not 120 <= record['ttl'] <= 86400):
        raise ValueError(code)
    try:
        if str(ipaddress.IPv4Address(record['data'])) != record['data']:
            raise ValueError(code)
    except (TypeError, ValueError):
        raise ValueError(code) from None


def validate_backend_record(record):
    validate_owned_record(record, 'owned_backend_receipt_required')


def seed_receipt(application, receipt, seed, zone):
    records = seed.get('records', {})
    if (seed.get('version') != 1 or seed.get('zone') != zone or seed.get('pending')
            or not isinstance(records, dict) or not PUBLIC <= set(records) <= OWNED):
        raise ValueError('owned_dns_receipt_required')
    # A seeded role becomes owned, so every seeded row needs a complete identity
    # before the application may adopt it instead of refusing it as foreign.
    for role, record in records.items():
        validate_owned_record(record, 'owned_dns_receipt_required')
    if receipt.exists() or receipt.is_symlink():
        existing = application.json.loads(application.private(receipt).read_bytes())
        current = existing.get('records', {})
        if (existing.get('version') != 1 or existing.get('zone') != zone
                or not isinstance(current, dict) or not PUBLIC <= set(current) <= OWNED
                or any(current[role]['id'] != records[role]['id'] for role in PUBLIC)):
            raise ValueError('dns_ownership_drift')
        # A public-only historical seed cannot discard an owned backend or tunnel.
        # If a seed claims those roles too, require their complete identity to match.
        for role in OWNED - PUBLIC:
            if role in current:
                validate_owned_record(current[role], 'owned_backend_receipt_required')
            if role in records and current.get(role) != records[role]:
                raise ValueError('dns_backend_ownership_drift')
    else:
        application.save(receipt, seed)


def bounded_code(error):
    message = str(error)
    return message if BOUNDED.fullmatch(message) else 'owned_dns_reconciliation_failed'


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
    except Exception as error:
        module.fail_json(msg=bounded_code(error))


if __name__ == '__main__':
    main()
