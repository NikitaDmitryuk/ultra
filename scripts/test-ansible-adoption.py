"""Legacy adoption checks use isolated files and a fake application runner."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_adoption_guard.py'
spec = importlib.util.spec_from_file_location('adoption', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Done(Exception):
    def __init__(self, result):
        self.result = result


class FakeModule:
    check_mode = False
    params = {'id': '11111111-2222-3333-4444-555555555555', 'action': 'checkpoint'}
    def exit_json(self, **values):
        raise Done(values)
    def fail_json(self, **values):
        raise Done(dict(values, failed=True))
    def run_command(self, args):
        if args[-1] == '--capabilities':
            return 0, '["service-access-v1","provider-pool-quota-v1"]', ''
        if args[0] == 'dpkg':
            return 0, 'amd64', ''
        if args[:2] == ['systemctl', 'is-active']:
            return 3, 'inactive', ''
        if args[:2] == ['systemctl', 'show']:
            return 0, '0', ''
        if args[0] == 'runuser':
            return 0, '24:24', ''
        raise AssertionError(args)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    def mapped(path):
        candidate = Path(path)
        return candidate if str(candidate).startswith(str(root)) or not candidate.is_absolute() else root / str(candidate).lstrip('/')
    def write(path, data):
        target = mapped(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
        target.chmod(0o600)
    for path in module.FILES:
        write(path, b'old-managed-bytes')
    write('/usr/local/libexec/ultra-relay-emergency', b'compatible-emergency')
    write('/var/lib/ultra-recovery/generation.age', b'encrypted-generation')
    write('/var/lib/ultra-recovery/artifact.age', b'encrypted-artifacts')
    with patch.object(module, 'Path', mapped), patch.object(module.os, 'geteuid', return_value=0), patch.object(module, 'AnsibleModule', return_value=FakeModule()):
        def manifest(binary):
            return {'capabilities': ['service-access-v1', 'provider-pool-quota-v1'], 'database_schema_min': 23, 'database_schema_max': 24,
                    'assets': [{'name': 'ultra-relay-linux-amd64', 'sha256': module.digest(binary), 'size': mapped(binary).stat().st_size}]}
        write('/opt/ultra-recovery/release-manifest.json', manifest(module.FILES[0]))
        write('/usr/local/libexec/ultra-emergency-manifest.json', manifest('/usr/local/libexec/ultra-relay-emergency'))
        write('/etc/ultra-recovery/reconcile.json', {'database': 'fixture', 'bridge_provider': 'provider-a', 'state_dir': '/var/lib/ultra-recovery-reconcile'}
        )
        write('/var/lib/ultra-recovery-reconcile/state.json', {'primary': 'independent-id', 'updated_at': int(time.time()), 'node_metadata': [{'id': 'independent-id', 'host': 'root@192.0.2.2', 'provider': 'provider-b'}]})
        write('/etc/ultra-recovery/backup.json', {'independent': True, 'repository': '/var/lib/ultra-recovery', 'destinations': [{'host': 'root@192.0.2.2', 'required': True}]})
        backup = {'snapshot_at': int(time.time()), 'destinations': ['root@192.0.2.2'], 'backup_name': 'generation.age', 'artifact_name': 'artifact.age',
                  'backup_sha256': module.digest('/var/lib/ultra-recovery/generation.age'), 'artifact_sha256': module.digest('/var/lib/ultra-recovery/artifact.age')}
        backup.update(source='bridge', delivered_target_ids=['independent-id'])
        contract='/var/lib/ultra-ansible/adoption/'+FakeModule.params['id']+'/recovery_status.py'
        write(contract, (source.parents[2]/'recovery/recovery_status.py').read_bytes())
        FakeModule.params['contract_sha256']=module.digest(contract)
        write('/var/lib/ultra-recovery/last-success.json', backup)
        write('/var/lib/ultra-relay/recovery-reconcile-status.json', {'state': 'ready', 'primary': 'independent-id', 'independent': True, 'updated_at': int(time.time())})
        def invoke(action):
            FakeModule.params['action'] = action
            try:
                module.main()
            except Done as result:
                return result.result
            raise AssertionError('missing result')
        assert invoke('checkpoint').get('verified') is True
        assert invoke('resume-check').get('verified') is True
        assert invoke('rollback-check').get('verified') is True
        # A rollback emergency deliberately differs from the original worker.
        # Retry validates the saved checkpoint, never the target release manifest.
        original_binary = mapped(module.FILES[0]).read_bytes()
        checkpoint_path = '/var/lib/ultra-ansible/adoption/' + FakeModule.params['id'] + '/checkpoint.json'
        checkpoint_bytes = mapped(checkpoint_path).read_bytes()
        write(module.FILES[0], mapped('/usr/local/libexec/ultra-relay-emergency').read_bytes())
        with patch.object(module, 'check_private_checkpoint', return_value=None):
            assert invoke('retry-check').get('verified') is True
            write(module.FILES[1], b'changed-restored-config')
            assert invoke('retry-check').get('failed') is True
            saved = json.loads(checkpoint_bytes)
            write(module.FILES[1], mapped(saved['restore_files'][0]['source']).read_bytes())
            write(module.FILES[0], b'unknown-worker')
            assert invoke('retry-check').get('failed') is True
        assert mapped(checkpoint_path).read_bytes() == checkpoint_bytes
        write(module.FILES[0], original_binary)

        assert invoke('prepare-gate').get('verified') is True
        journal = json.loads(mapped('/var/lib/ultra-ansible/lifecycle.json').read_text())
        assert journal == {'id': FakeModule.params['id'], 'phase': 'applying'}
        gate = '/var/lib/ultra-ansible/lifecycle.json'
        write(gate, {'id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'phase': 'checking'})
        # The initial inspection must reject a foreign reservation before any
        # role can stop the broker, even when no application exists yet.
        saved_binary = mapped(module.FILES[0]).read_bytes()
        saved_spec = mapped(module.FILES[1]).read_bytes()
        mapped(module.FILES[0]).unlink()
        mapped(module.FILES[1]).unlink()
        result = invoke('inspect')
        assert result.get('failed') and result.get('msg') == 'adoption_guard_failed', result
        write(module.FILES[0], saved_binary)
        write(module.FILES[1], saved_spec)
        write(gate, journal)
        playbook = (source.parents[1] / 'playbooks/prepare-controller.yml').read_text()
        assert playbook.index('ultra_adoption_guard:') < playbook.index('ansible.builtin.user:') < playbook.index('Stop the previous broker')

        backup['delivered_target_ids'] = ['local-only-id']
        write('/var/lib/ultra-recovery/last-success.json', backup)
        assert invoke('checkpoint').get('failed') is True, 'fresh local-only generation accepted as independent'
        backup['delivered_target_ids'] = ['independent-id']
        write('/var/lib/ultra-recovery/last-success.json', backup)
        write(module.FILES[1], b'changed-after-checkpoint')
        assert invoke('resume-check').get('failed') is True
        write(module.FILES[1], b'old-managed-bytes')
        backup['snapshot_at'] -= 301
        write('/var/lib/ultra-recovery/last-success.json', backup)
        assert invoke('checkpoint').get('failed') is True
print('legacy adoption identity, freshness, emergency and pre-base recovery guards passed')
