#!/usr/bin/python
"""Read-only comparison of managed configuration before adoption."""
import hashlib
import json
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


def environment(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if separator and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def main():
    module = AnsibleModule(argument_spec={
        'specification': {'type': 'dict', 'required': True, 'no_log': True},
        'environment': {'type': 'str', 'required': True, 'no_log': True},
        'unit_sha256': {'type': 'str', 'required': True},
        'binary_sha256': {'type': 'str', 'required': True},
    }, supports_check_mode=True)
    try:
        specification = Path('/etc/ultra-relay/spec.json')
        unit = Path('/etc/systemd/system/ultra-relay.service')
        binary = Path('/usr/local/bin/ultra-relay')
        if any(path.is_symlink() or not path.is_file() for path in (specification, unit, binary)):
            raise ValueError('managed_paths_required')
        actual = json.loads(specification.read_text())
        if actual != module.params['specification']:
            raise ValueError('specification_drift')
        if environment(Path('/etc/ultra-relay/environment').read_text()) != environment(module.params['environment']):
            raise ValueError('environment_drift')
        if hashlib.sha256(unit.read_bytes()).hexdigest() != module.params['unit_sha256']:
            raise ValueError('service_definition_drift')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != module.params['binary_sha256']:
            raise ValueError('installed_artifact_drift')
        module.exit_json(changed=False, verified=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        known = {'managed_paths_required', 'specification_drift', 'environment_drift', 'service_definition_drift', 'installed_artifact_drift'}
        code = str(error) if str(error) in known else 'inspection_failed'
        module.fail_json(msg='adoption_' + code)


if __name__ == '__main__':
    main()
