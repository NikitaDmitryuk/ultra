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
    if (architecture not in ('amd64', 'arm64') or not isinstance(manifest, dict)
            or not isinstance(manifest.get('capabilities'), list)
            or any(not isinstance(item, str) for item in manifest['capabilities'])
            or not isinstance(manifest.get('assets'), list)
            or any(not isinstance(item, dict) for item in manifest['assets'])):
        raise ValueError('installed_artifact_drift')
    if not {'service-access-v1', 'provider-pool-quota-v1'} <= set(manifest.get('capabilities', [])):
        raise ValueError('installed_artifact_drift')
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', manifest.get('version', '')):
        raise ValueError('installed_artifact_drift')
    assets = [asset for asset in manifest['assets'] if asset.get('name') == 'ultra-relay-linux-' + architecture]
    if len(assets) != 1 or assets[0].get('size') != len(binary) or assets[0].get('sha256') != hashlib.sha256(binary).hexdigest():
        raise ValueError('installed_artifact_drift')


def owned_baseline_file(name, bounded=False):
    path = Path(name)
    metadata = path.lstat()
    if (path.is_symlink() or not path.is_file() or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or (bounded and metadata.st_size > 1048576)):
        raise ValueError('installed_artifact_drift')
    return path


def local_installed_manifest():
    """A previously activated exit may have a different release than bridge."""
    return json.loads(owned_baseline_file('/opt/ultra-recovery/release-manifest.json', bounded=True).read_text())


def emergency_baseline(module, specification, architecture, binary):
    """Use the same fixed emergency identity/schema contract as adoption_guard.

    Compatible rollback may leave this artifact running after its old operation
    has completed. A new bridge adoption must verify it afresh, without trusting
    an observed checksum or borrowing another operation's retry checkpoint.
    """
    if specification.get('role') != 'bridge':
        raise ValueError('installed_artifact_drift')
    manifest = json.loads(owned_baseline_file('/usr/local/libexec/ultra-emergency-manifest.json', bounded=True).read_text())
    emergency = owned_baseline_file('/usr/local/libexec/ultra-relay-emergency')
    owned_baseline_file('/usr/local/bin/ultra-relay')
    installed_baseline(manifest, architecture, binary)
    installed_baseline(manifest, architecture, emergency.read_bytes())
    minimum, maximum = manifest['database_schema_min'], manifest['database_schema_max']
    if type(minimum) is not int or type(maximum) is not int or not 0 < minimum <= maximum:
        raise ValueError('installed_artifact_drift')
    config = json.loads(owned_baseline_file('/etc/ultra-recovery/reconcile.json', bounded=True).read_text())
    database = config['database']
    if not isinstance(database, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', database):
        raise ValueError('installed_artifact_drift')
    code, schema, _ = module.run_command(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database,
                                        '-c', "SELECT COALESCE(max(version),0)::text || ':' || count(*)::text FROM schema_migrations"])
    current, count = map(int, schema.strip().split(':'))
    if code or count != current or not minimum <= current <= maximum:
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
        if module.params['preserve_runtime']:
            code, _, _ = module.run_command(['runuser', '-u', 'ultra-relay', '--', 'test', '-r', '/etc/ultra-relay/spec.json'])
            if code:
                raise ValueError('specification_unreadable')
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
            code, architecture, _ = module.run_command(['dpkg', '--print-architecture'])
            if code:
                raise ValueError('installed_artifact_drift')
            try:
                selected = module.params['installed_manifest']
                if not selected:
                    selected = local_installed_manifest()
                installed_baseline(selected, architecture.strip(), binary.read_bytes())
            except ValueError:
                try:
                    installed_baseline(local_installed_manifest(), architecture.strip(), binary.read_bytes())
                except (OSError, ValueError, KeyError, TypeError):
                    emergency_baseline(module, actual, architecture.strip(), binary.read_bytes())
        module.exit_json(changed=False, verified=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        known = {'managed_paths_required', 'specification_drift', 'specification_unreadable', 'environment_drift', 'service_definition_drift', 'installed_artifact_drift'}
        code = str(error) if str(error) in known else 'inspection_failed'
        module.fail_json(msg='adoption_' + code, exception='')


if __name__ == '__main__':
    main()
