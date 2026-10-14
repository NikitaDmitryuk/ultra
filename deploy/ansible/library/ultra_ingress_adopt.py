#!/usr/bin/python
"""Read-only ownership and exact publication checks for preserved ingress."""
import hashlib
import json
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


def verify(root, receipt, expected):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError('ingress_root_invalid')
    receipt = root / receipt.lstrip('/')
    if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_uid != 0 or receipt.stat().st_mode & 0o022:
        raise ValueError('ingress_ownership_receipt_required')
    if receipt.with_name(receipt.name + '.pending').exists() or receipt.with_name(receipt.name + '.pending').is_symlink():
        raise ValueError('ingress_ownership_transaction_pending')
    manifest = json.loads(receipt.read_text())
    if not isinstance(manifest, dict) or not expected:
        raise ValueError('ingress_ownership_receipt_invalid')
    for name, digest in manifest.items():
        if not isinstance(name, str) or not Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('ingress_owned_path_invalid')
        path = root / name.lstrip('/')
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise ValueError('ingress_owned_file_required')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('ingress_owned_file_changed')

    def matches(choice):
        if not isinstance(choice, dict) or not isinstance(choice.get('path'), str) or not isinstance(choice.get('content'), str):
            raise ValueError('ingress_publication_requirement_invalid')
        requirements = choice.get('requires', [])
        if not isinstance(requirements, list) or any(
                not isinstance(required, dict) or set(required) != {'path', 'content'}
                or not isinstance(required['path'], str) or not isinstance(required['content'], str)
                for required in requirements):
            raise ValueError('ingress_publication_requirement_invalid')
        for required in [choice, *requirements]:
            if not Path(required['path']).is_absolute() or '..' in Path(required['path']).parts:
                raise ValueError('ingress_publication_requirement_invalid')
        lineage = choice.get('lineage')
        if lineage is not None:
            if (not isinstance(lineage, str) or not lineage.startswith('/etc/letsencrypt/live/')
                    or len(Path(lineage).parts) != 5 or '..' in Path(lineage).parts):
                raise ValueError('ingress_publication_requirement_invalid')
        owned = all(required['path'] in manifest and
                    (root / required['path'].lstrip('/')).read_text() == required['content']
                    for required in [choice, *requirements])
        if lineage is not None:
            certificate = root / lineage.lstrip('/')
            owned = owned and certificate.is_dir() and all(
                (certificate / name).is_file() for name in ('fullchain.pem', 'privkey.pem'))
        return owned

    for item in expected:
        choices = item.get('alternatives', [item])
        # Evaluate every alternative so malformed requirements cannot hide behind
        # an earlier matching hook. Receipt validation above remains unconditional.
        if not any([matches(choice) for choice in choices]):
            raise ValueError('ingress_publication_configuration_mismatch')
    return {'changed': False, 'verified': True}


def main():
    module = AnsibleModule(argument_spec={
        'root': {'type': 'path', 'default': '/'},
        'receipt': {'type': 'path', 'default': '/var/lib/ultra-ingress/managed.json'},
        'expected': {'type': 'list', 'elements': 'dict', 'required': True, 'no_log': True},
    }, supports_check_mode=True)
    try:
        module.exit_json(**verify(module.params['root'], module.params['receipt'], module.params['expected']))
    except (OSError, ValueError, KeyError, TypeError):
        module.fail_json(msg='ingress_adoption_verification_failed')


if __name__ == '__main__':
    main()
