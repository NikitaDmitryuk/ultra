#!/usr/bin/env python3
"""Installed release identity is independent of the incoming adoption artifact."""
import hashlib
import importlib.util
from pathlib import Path
from copy import deepcopy

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_adopt_probe.py'
spec = importlib.util.spec_from_file_location('adopt_probe', source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
installed = b'previous compatible release'
candidate = b'incoming Ansible release'
manifest = {'version': 'v2.4.6', 'capabilities': ['service-access-v1', 'provider-pool-quota-v1'],
            'assets': [{'name': 'ultra-relay-linux-amd64', 'size': len(installed),
                        'sha256': hashlib.sha256(installed).hexdigest()}]}
probe.installed_baseline(manifest, 'amd64', installed)
for name, mutation, binary, architecture in [
    ('candidate cannot attest previous', lambda m: None, candidate, 'amd64'),
    ('wrong architecture', lambda m: None, installed, 'arm64'),
    ('unsupported architecture', lambda m: None, installed, 'x86'),
    ('missing accounting contract', lambda m: m.update(capabilities=[]), installed, 'amd64'),
    ('wrong size', lambda m: m['assets'][0].update(size=1), installed, 'amd64'),
    ('wrong checksum', lambda m: m['assets'][0].update(sha256='0'*64), installed, 'amd64'),
    ('ambiguous asset', lambda m: m['assets'].append(dict(m['assets'][0])), installed, 'amd64'),
    ('invalid version', lambda m: m.update(version='latest'), installed, 'amd64'),
]:
    modified = deepcopy(manifest)
    mutation(modified)
    try:
        probe.installed_baseline(modified, architecture, binary)
    except ValueError as failure:
        assert str(failure) == 'installed_artifact_drift'
    else:
        raise AssertionError(name)
print('Adoption installed baseline: valid previous release accepted; 8 invalid identities rejected')

# A new operation after compatible rollback has no checkpoint-bound retry hash.
# Its only alternative trust anchor is the fixed, root-owned emergency artifact.
import json
import os
import tempfile
from unittest.mock import patch


class Done(Exception):
    def __init__(self, result):
        self.result = result


class FakeModule:
    def __init__(self):
        self.params = {'preserve_runtime': True, 'installed_manifest': manifest,
                       'previous_unit_sha256': '', 'verified_rollback_sha256': '',
                       'specification': {'role': 'bridge'}, 'environment': 'TOKEN=fixture\n',
                       'unit_sha256': hashlib.sha256(b'unit').hexdigest(),
                       'binary_sha256': hashlib.sha256(candidate).hexdigest()}
        self.schema = '24:24'
        self.schema_code = 0
        self.spec_readable = True
        self.commands = []
    def run_command(self, args):
        self.commands.append(args)
        if args == ['runuser', '-u', 'ultra-relay', '--', 'test', '-r', '/etc/ultra-relay/spec.json']:
            return (0 if self.spec_readable else 1), '', ''
        if args == ['dpkg', '--print-architecture']:
            return 0, 'amd64\n', ''
        assert args[:11] == ['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', 'fixture', '-c'], args
        return self.schema_code, self.schema, ''
    def exit_json(self, **values):
        raise Done(values)
    def fail_json(self, **values):
        raise Done(dict(values, failed=True))


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    owners = {}
    class RootPath(type(Path())):
        def stat(self, **kwargs):
            values = list(super().stat(**kwargs))
            values[4] = owners.get(str(self), 0)
            return os.stat_result(values)
        def lstat(self):
            return self.stat(follow_symlinks=False)
    def mapped(path):
        candidate_path = Path(path)
        return RootPath(candidate_path if str(candidate_path).startswith(str(root)) or not candidate_path.is_absolute()
                        else root / str(candidate_path).lstrip('/'))
    def write(path, data):
        target = mapped(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
        target.chmod(0o600)
        return target
    emergency = b'previously verified compatible emergency'
    emergency_manifest = deepcopy(manifest)
    emergency_manifest.update(database_schema_min=23, database_schema_max=24)
    emergency_manifest['assets'][0].update(size=len(emergency), sha256=hashlib.sha256(emergency).hexdigest())
    emergency_path = '/usr/local/libexec/ultra-relay-emergency'
    manifest_path = '/usr/local/libexec/ultra-emergency-manifest.json'
    config_path = '/etc/ultra-recovery/reconcile.json'
    write('/etc/ultra-relay/spec.json', {'role': 'bridge'})
    write('/etc/ultra-relay/environment', b'TOKEN=fixture\n')
    write('/etc/systemd/system/ultra-relay.service', b'unit')
    write('/usr/local/bin/ultra-relay', emergency)
    write(emergency_path, emergency)
    write(manifest_path, emergency_manifest)
    write(config_path, {'database': 'fixture'})
    def invoke(module):
        with patch.object(probe, 'Path', mapped), patch.object(probe, 'AnsibleModule', return_value=module):
            try:
                probe.main()
            except Done as result:
                return result.result
        raise AssertionError('missing result')
    for ordinary in [installed, candidate]:
        write('/usr/local/bin/ultra-relay', ordinary)
        module = FakeModule()
        assert invoke(module).get('verified') is True, 'existing installed/candidate identity'
        assert not any(args[:3] == ['runuser', '-u', 'postgres'] for args in module.commands)
    # A prior partial rolling update can leave one exit on a newer verified
    # release than bridge. Its protected local manifest must attest that binary.
    exit_manifest = deepcopy(manifest)
    exit_manifest['version'] = 'v2.4.8'
    exit_manifest['assets'][0].update(size=len(candidate), sha256=hashlib.sha256(candidate).hexdigest())
    local_manifest_path = '/opt/ultra-recovery/release-manifest.json'
    write(local_manifest_path, exit_manifest)
    write('/usr/local/bin/ultra-relay', candidate)
    module = FakeModule()
    module.params['binary_sha256'] = hashlib.sha256(b'new candidate').hexdigest()
    module.params['specification'] = {'role': 'exit'}
    write('/etc/ultra-relay/spec.json', {'role': 'exit'})
    assert invoke(module).get('verified') is True, 'exit release newer than bridge'
    write('/usr/local/bin/ultra-relay', b'unknown binary')
    assert invoke(module).get('failed') is True, 'unknown exit binary refused'
    write('/usr/local/bin/ultra-relay', candidate)
    owners[str(mapped(local_manifest_path))] = 1000
    assert invoke(module).get('failed') is True, 'unowned exit manifest refused'
    owners.clear()
    mapped(local_manifest_path).chmod(0o622)
    assert invoke(module).get('failed') is True, 'writable exit manifest refused'
    mapped(local_manifest_path).chmod(0o600)
    write(local_manifest_path, b'{invalid json')
    assert invoke(module).get('failed') is True, 'malformed exit manifest refused'
    mapped(local_manifest_path).unlink()
    target = write('/exit-manifest-target', exit_manifest)
    mapped(local_manifest_path).symlink_to(target)
    assert invoke(module).get('failed') is True, 'symlinked exit manifest refused'
    mapped(local_manifest_path).unlink()
    write('/etc/ultra-relay/spec.json', {'role': 'bridge'})
    unreadable = FakeModule()
    unreadable.spec_readable = False
    assert invoke(unreadable).get('msg') == 'adoption_specification_unreadable'
    write('/usr/local/bin/ultra-relay', emergency)
    result = invoke(FakeModule())
    assert result.get('verified') is True, ('new operation after compatible rollback', result)
    for name, mutation in [
        ('missing capabilities', lambda m: m.update(capabilities=[])),
        ('changed digest', lambda m: m['assets'][0].update(sha256='0'*64)),
        ('changed size', lambda m: m['assets'][0].update(size=1)),
        ('duplicate asset', lambda m: m['assets'].append(dict(m['assets'][0]))),
        ('wrong architecture', lambda m: m['assets'][0].update(name='ultra-relay-linux-arm64')),
        ('schema too old', lambda m: m.update(database_schema_max=23)),
        ('schema too new', lambda m: m.update(database_schema_min=25)),
        ('schema missing', lambda m: m.pop('database_schema_min')),
        ('schema type', lambda m: m.update(database_schema_min='23')),
    ]:
        modified = deepcopy(emergency_manifest)
        mutation(modified)
        write(manifest_path, modified)
        assert invoke(FakeModule()).get('failed') is True, name
    for malformed in [[], None, {}, {'capabilities': [[]]}, dict(emergency_manifest, assets=[1])]:
        write(manifest_path, malformed)
        assert invoke(FakeModule()).get('failed') is True, ('malformed manifest', malformed)
    write(manifest_path, b'{invalid json')
    assert invoke(FakeModule()).get('failed') is True, 'invalid manifest JSON'
    write(manifest_path, emergency_manifest)
    for path in [emergency_path, manifest_path, config_path]:
        owners[str(mapped(path))] = 1000
        assert invoke(FakeModule()).get('failed') is True, ('unowned', path)
        owners.clear()
        mapped(path).chmod(0o622)
        assert invoke(FakeModule()).get('failed') is True, ('writable', path)
        mapped(path).chmod(0o600)
        saved = mapped(path).read_bytes()
        mapped(path).unlink()
        assert invoke(FakeModule()).get('failed') is True, ('absent', path)
        target = write('/fixture-target', saved)
        mapped(path).symlink_to(target)
        assert invoke(FakeModule()).get('failed') is True, ('symlink', path)
        mapped(path).unlink()
        write(path, saved)
    for schema in ['25:25', '22:22', '24:23', '0:0', 'invalid']:
        module = FakeModule()
        module.schema = schema
        assert invoke(module).get('failed') is True, ('schema', schema)
    module = FakeModule()
    module.schema_code = 1
    assert invoke(module).get('failed') is True, 'schema command failure'
    write(config_path, {'database': 'fixture; SELECT 1'})
    assert invoke(FakeModule()).get('failed') is True, 'database argument injection'
    write(config_path, {'database': 'fixture'})
    write(emergency_path, b'arbitrary unverified bytes')
    assert invoke(FakeModule()).get('failed') is True, 'emergency artifact changed'
    write(emergency_path, emergency)
    write('/usr/local/bin/ultra-relay', b'arbitrary unverified bytes')
    assert invoke(FakeModule()).get('failed') is True, 'installed artifact changed'
    write('/usr/local/bin/ultra-relay', emergency)
    for role in ['exit', '', None]:
        module = FakeModule()
        module.params['specification'] = {} if role is None else {'role': role}
        write('/etc/ultra-relay/spec.json', module.params['specification'])
        assert invoke(module).get('failed') is True, ('role', role)
        assert not any(args[:3] == ['runuser', '-u', 'postgres'] for args in module.commands)
    write('/etc/ultra-relay/spec.json', {'role': 'bridge'})
    module = FakeModule()
    module.params['preserve_runtime'] = False
    assert invoke(module).get('failed') is True, 'ordinary adoption remains pinned'
print('Adoption emergency baseline: new bridge operation accepted; identity, ownership, schema and exit guards passed')
