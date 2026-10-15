#!/usr/bin/python
"""Retain published aliases in recovery inventory; services are managed by roles."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from ansible.module_utils.basic import AnsibleModule


def persisted_ingress(value):
    allowed = ('domain', 'email', 'path', 'forward_host', 'public_host', 'backend_port',
               'gateway_port', 'status_port', 'experimental_port', 'staging_port')
    if not isinstance(value, dict):
        raise ValueError('invalid_ingress_metadata')
    strings = ('domain', 'email', 'path', 'public_host')
    if any(key not in value or not isinstance(value[key], str) or not value[key].strip()
           for key in strings):
        raise ValueError('invalid_ingress_metadata')
    if 'forward_host' in value and not isinstance(value['forward_host'], str):
        raise ValueError('invalid_ingress_metadata')
    ports = ('backend_port', 'gateway_port', 'status_port', 'experimental_port', 'staging_port')
    if any(key not in value or type(value[key]) is not int or not 1024 <= value[key] <= 65535
           for key in ports):
        raise ValueError('invalid_ingress_metadata')
    if len({value[key] for key in ports}) != len(ports):
        raise ValueError('invalid_ingress_metadata')
    result = {key: value[key] for key in allowed if key in value}
    result.setdefault('forward_host', '')
    return result


def merge_backup_paths(existing, requested):
    if (not isinstance(existing, list) or not isinstance(requested, list)
            or any(not isinstance(path, str) or not Path(path).is_absolute() or Path(path) == Path('/')
                   for path in existing + requested)):
        raise ValueError('invalid_backup_paths')
    return sorted(set(existing) | set(requested))


def apply_backup_paths(backup, state_paths, artifact_paths):
    backup['state_paths'] = merge_backup_paths(backup.get('state_paths', []), state_paths)
    backup['artifact_paths'] = merge_backup_paths(backup.get('artifact_paths', []), artifact_paths)
    return set(backup['state_paths'])


def main():
    module = AnsibleModule(argument_spec={
        'subscription_domain': {'type': 'str', 'required': True},
        'ingress': {'type': 'dict', 'required': True},
        'backend_domain': {'type': 'str', 'default': ''},
        'bridge_url': {'type': 'str', 'default': ''},
        'state_paths': {'type': 'list', 'elements': 'str', 'default': []},
        'artifact_paths': {'type': 'list', 'elements': 'str', 'default': []},
    }, supports_check_mode=False)
    try:
        source = Path('/opt/ultra-recovery/dns.py')
        specification = importlib.util.spec_from_file_location('ultra_dns_application', source)
        application = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(application)
        changed = False
        backup_path = Path('/etc/ultra-recovery/backup.json')
        original = backup_path.read_bytes()
        backup = json.loads(original)
        inventory = apply_backup_paths(backup, module.params['state_paths'], module.params['artifact_paths'])
        inventory.update(('/etc/ultra-recovery', '/etc/ultra-relay', '/etc/systemd/system/ultra-bot.service.d',
                          '/var/lib/ultra-ingress/managed.json'))
        manifest = json.loads(Path('/var/lib/ultra-ingress/managed.json').read_text())
        for name, expected in manifest.items():
            if not name.startswith(('/etc/nginx/', '/etc/letsencrypt/renewal-hooks/', '/var/www/ultra-')):
                continue
            path = Path(name)
            if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError('owned_ingress_inventory_drift')
            inventory.add(name)
        domains = [module.params['subscription_domain'], module.params['ingress']['domain']]
        if module.params['backend_domain']:
            domains.append(module.params['backend_domain'])
        for domain in domains:
            renewal = Path('/etc/letsencrypt/renewal') / (domain + '.conf')
            live = Path('/etc/letsencrypt/live') / domain
            if not renewal.is_file() or not live.is_dir():
                raise ValueError('certificate_inventory_missing')
            inventory.update((str(renewal), str(live)))
            account = re.search(r'^account\s*=\s*([a-f0-9]+)\s*$', renewal.read_text(), re.M)
            if account:
                accounts = list(Path('/etc/letsencrypt/accounts').glob('*/directory/' + account.group(1)))
                if len(accounts) != 1:
                    raise ValueError('acme_account_missing')
                inventory.add(str(accounts[0]))
        backup['state_paths'] = sorted(inventory)
        if json.loads(original) != backup:
            application.save(backup_path, backup)
            changed = True
        for name in ('reconcile', 'deployment'):
            path = Path('/etc/ultra-recovery') / (name + '.json')
            prior = json.loads(application.private(path).read_text())
            target = dict(prior)
            target['bridge_url'] = module.params['bridge_url'] or ('https://' + module.params['subscription_domain'] + '/healthz')
            if name == 'deployment':
                target['ingress'] = persisted_ingress(module.params['ingress'])
                target['ingress_mode'] = 'direct'
                target['subscription_domain'] = module.params['subscription_domain']
            if target != prior:
                application.save(path, target)
                changed = True
        module.exit_json(changed=changed)
    except (OSError, KeyError, ValueError, TypeError):
        module.fail_json(msg='cutover_recovery_inventory_failed')


if __name__ == '__main__':
    main()
