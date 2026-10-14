#!/usr/bin/python
"""Read-only comparison of managed configuration before adoption."""
import hashlib
import json
import re
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule


def environment(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if separator and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def installed_baseline(manifest, architecture, binary):
    """An adopted artifact must match its installed release, not the candidate."""
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('installed_artifact_drift')
    if not {'service-access-v1', 'provider-pool-quota-v1'} <= set(manifest.get('capabilities', [])):
        raise ValueError('installed_artifact_drift')
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', manifest.get('version', '')):
        raise ValueError('installed_artifact_drift')
    assets = [asset for asset in manifest['assets'] if asset.get('name') == 'ultra-relay-linux-' + architecture]
    if len(assets) != 1 or assets[0].get('size') != len(binary) or assets[0].get('sha256') != hashlib.sha256(binary).hexdigest():
        raise ValueError('installed_artifact_drift')


def main():
    module = AnsibleModule(argument_spec={
        'preserve_runtime': {'type': 'bool', 'default': False},
        'installed_manifest': {'type': 'dict', 'default': {}, 'no_log': True},
        'previous_unit_sha256': {'type': 'str', 'default': ''},
        'verified_rollback_sha256': {'type': 'str', 'default': ''},
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
        if hashlib.sha256(unit.read_bytes()).hexdigest() not in (module.params['unit_sha256'], module.params['previous_unit_sha256'] if module.params['preserve_runtime'] else ''):
            raise ValueError('service_definition_drift')
        actual_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        permitted = [module.params['binary_sha256']]
        if module.params['preserve_runtime']:
            rollback_sha = module.params['verified_rollback_sha256']
            if rollback_sha:
                if not re.fullmatch(r'[a-f0-9]{64}', rollback_sha):
                    raise ValueError('installed_artifact_drift')
                permitted.append(rollback_sha)
        if actual_sha not in permitted:
            if not module.params['preserve_runtime']:
                raise ValueError('installed_artifact_drift')
            selected = module.params['installed_manifest']
            if not selected:
                manifest = Path('/opt/ultra-recovery/release-manifest.json')
                metadata = manifest.lstat()
                if manifest.is_symlink() or not manifest.is_file() or metadata.st_uid != 0 or metadata.st_mode & 0o022 or metadata.st_size > 1048576:
                    raise ValueError('installed_artifact_drift')
                selected = json.loads(manifest.read_text())
            code, architecture, _ = module.run_command(['dpkg', '--print-architecture'])
            if code:
                raise ValueError('installed_artifact_drift')
            installed_baseline(selected, architecture.strip(), binary.read_bytes())
        module.exit_json(changed=False, verified=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        known = {'managed_paths_required', 'specification_drift', 'environment_drift', 'service_definition_drift', 'installed_artifact_drift'}
        code = str(error) if str(error) in known else 'inspection_failed'
        module.fail_json(msg='adoption_' + code, exception='')


if __name__ == '__main__':
    main()
