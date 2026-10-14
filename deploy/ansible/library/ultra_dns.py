#!/usr/bin/python
"""Owned DNS API reconciliation; host setup is managed by the DNS role."""
import importlib.util
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


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
            if seed.get('zone') != module.params['config']['zone'] or seed.get('pending') or set(seed.get('records', {})) != {'subscription', 'vpn'}:
                raise ValueError('owned_dns_receipt_required')
            if before is not None:
                existing = application.json.loads(before)
                if existing.get('zone') != seed['zone'] or {key: value['id'] for key, value in existing['records'].items()} != {key: value['id'] for key, value in seed['records'].items()}:
                    raise ValueError('dns_ownership_drift')
            else:
                application.save(receipt, seed)
        result = application.execute(module.params['config'], module.params['desired'], str(receipt))
        if module.params['wait']:
            application.wait_ready(module.params['config'], module.params['desired'])
        module.exit_json(changed=before != receipt.read_bytes(), ready=result['ready'])
    except Exception:
        module.fail_json(msg='owned_dns_reconciliation_failed')


if __name__ == '__main__':
    main()
