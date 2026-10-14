"""Legacy adoption checks use isolated files and a fake application runner."""
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import subprocess
import argparse
import stat
import time
from unittest.mock import patch

import yaml

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
    owners = {}
    directory_modes = {}
    class RootPath(type(Path())):
        def stat(self, **kwargs):
            values = list(super().stat(**kwargs))
            values[4] = owners.get(str(self), 0)
            return os.stat_result(values)
        def lstat(self):
            values = list(super().lstat())
            values[4] = owners.get(str(self), 0)
            if stat.S_ISDIR(values[0]):
                values[0] = directory_modes.get(str(self), values[0] & ~0o022)
            return os.stat_result(values)
    def mapped(path):
        candidate = Path(path)
        return RootPath(candidate if str(candidate).startswith(str(root)) or not candidate.is_absolute() else root / str(candidate).lstrip('/'))
    def write(path, data):
        target = mapped(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
        target.chmod(0o600)
    for path in module.FILES:
        write(path, b'old-managed-bytes')
    write('/usr/local/libexec/ultra-relay-emergency', b'compatible-emergency')
    snapshot = int(time.time())
    backup_name = 'backup-' + str(snapshot) + '-' + 'a'*32 + '.age'
    artifact_name = 'artifact-' + 'b'*64 + '.age'
    write('/var/lib/ultra-recovery/' + backup_name, b'encrypted-generation')
    write('/var/lib/ultra-recovery/' + artifact_name, b'encrypted-artifacts')
    identity = '/etc/ultra-recovery/ssh-key'
    pins = '/var/lib/ultra-relay/vultr/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/known_hosts'
    write(identity, b'fixture-key')
    write(pins, b'fixture-pins')
    with patch.object(module, 'Path', mapped), patch.object(module.os, 'geteuid', return_value=0), patch.object(module, 'AnsibleModule', return_value=FakeModule()), patch.object(module.pwd, 'getpwnam', return_value=argparse.Namespace(pw_uid=1001)):
        def manifest(binary):
            return {'capabilities': ['service-access-v1', 'provider-pool-quota-v1'], 'database_schema_min': 23, 'database_schema_max': 24,
                    'assets': [{'name': 'ultra-relay-linux-amd64', 'sha256': module.digest(binary), 'size': mapped(binary).stat().st_size}]}
        write('/opt/ultra-recovery/release-manifest.json', manifest(module.FILES[0]))
        write('/usr/local/libexec/ultra-emergency-manifest.json', manifest('/usr/local/libexec/ultra-relay-emergency'))
        write('/etc/ultra-recovery/reconcile.json', {'database': 'fixture', 'bridge_provider': 'provider-a', 'state_dir': '/var/lib/ultra-recovery-reconcile', 'ssh_identity_file': identity, 'ssh_identity_owner': 'root', 'vultr_state_dir': '/var/lib/ultra-relay/vultr'}
        )
        write('/var/lib/ultra-recovery-reconcile/state.json', {'primary': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'updated_at': int(time.time()), 'node_metadata': [{'id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'host': 'root@192.0.2.2', 'provider': 'provider-b', 'known_hosts': pins, 'managed': True, 'address': '192.0.2.2'}]})
        write('/etc/ultra-recovery/backup.json', {'independent': True, 'repository': '/var/lib/ultra-recovery', 'destinations': [{'id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'host': 'root@192.0.2.2', 'required': True, 'identity_file': identity, 'known_hosts': pins}]})
        backup = {'snapshot_at': int(time.time()), 'destinations': ['root@192.0.2.2'], 'backup_name': backup_name, 'artifact_name': artifact_name,
                  'backup_sha256': module.digest('/var/lib/ultra-recovery/' + backup_name), 'artifact_sha256': module.digest('/var/lib/ultra-recovery/' + artifact_name)}
        backup.update(source='bridge', delivered_target_ids=['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'])
        contract='/var/lib/ultra-ansible/adoption/'+FakeModule.params['id']+'/recovery_status.py'
        write(contract, (source.parents[2]/'recovery/recovery_status.py').read_bytes())
        FakeModule.params['contract_sha256']=module.digest(contract)
        write('/var/lib/ultra-recovery/last-success.json', backup)
        write('/var/lib/ultra-relay/recovery-reconcile-status.json', {'state': 'ready', 'primary': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'independent': True, 'updated_at': int(time.time())})
        def invoke(action):
            FakeModule.params['action'] = action
            try:
                module.main()
            except Done as result:
                return result.result
            raise AssertionError('missing result')
        for path in [pins, '/var/lib/ultra-relay', '/var/lib/ultra-relay/vultr', '/var/lib/ultra-relay/vultr/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee']:
            owners[str(mapped(path))] = 1001  # managed receiver subtree belongs to ultra-relay
        # Production capture deliberately removes its local backup workdir.
        mapped('/var/lib/ultra-recovery/' + backup_name).unlink()
        remote_output = (backup['backup_sha256'] + '  /var/lib/ultra-recovery/' + backup_name + '\n'
                         + backup['artifact_sha256'] + '  /var/lib/ultra-recovery/' + artifact_name + '\n').encode()
        remote_result = argparse.Namespace(returncode=0, stdout=remote_output)
        remote = patch.object(module.subprocess, 'run', return_value=remote_result)
        with remote as ssh:
            checkpoint_path = '/var/lib/ultra-ansible/adoption/' + FakeModule.params['id'] + '/checkpoint.json'
            FakeModule.check_mode = True
            assert invoke('checkpoint').get('verified') is True
            assert not mapped(checkpoint_path).exists()
            FakeModule.check_mode = False
            assert invoke('checkpoint').get('verified') is True
            argv = ssh.call_args.args[0]
            assert argv[0] == 'ssh' and argv[-2] == 'root@192.0.2.2'
            assert 'StrictHostKeyChecking=yes' in argv and 'BatchMode=yes' in argv and 'IdentitiesOnly=yes' in argv
            assert 'UserKnownHostsFile=' + pins in argv and identity in argv
            assert ssh.call_args.kwargs['timeout'] == 15 and ssh.call_args.kwargs['stderr'] == subprocess.DEVNULL
        parent = str(mapped('/var/lib/ultra-relay/vultr'))
        directory_modes[parent] = stat.S_IFDIR | 0o777
        with patch.object(module.subprocess, 'run', return_value=remote_result) as ssh:
            assert invoke('checkpoint').get('failed') is True
            ssh.assert_not_called()
        directory_modes.pop(parent)
        owners[str(mapped(pins))] = 1002
        with patch.object(module.subprocess, 'run', return_value=remote_result) as ssh:
            assert invoke('checkpoint').get('failed') is True
            ssh.assert_not_called()
        owners[str(mapped(pins))] = 1001
        with patch.object(module.subprocess, 'run', return_value=argparse.Namespace(returncode=1, stdout=b'')) as ssh:
            assert invoke('checkpoint').get('failed') is True
            assert ssh.call_count == 1 and ssh.call_args.args[0][0] == 'ssh-keygen'
        # A local cipher, if present, never substitutes for remote integrity.
        write('/var/lib/ultra-recovery/' + backup_name, b'encrypted-generation')
        def remote_failure(value):
            return lambda args, **kwargs: argparse.Namespace(returncode=0) if args[0] == 'ssh-keygen' else value
        for invalid in [argparse.Namespace(returncode=1, stdout=b''),
                        argparse.Namespace(returncode=0, stdout=remote_output.replace(backup['backup_sha256'].encode(), b'0'*64)),
                        argparse.Namespace(returncode=0, stdout=remote_output.replace(backup['artifact_sha256'].encode(), b'0'*64)),
                        argparse.Namespace(returncode=0, stdout=remote_output.splitlines()[0] + b'\n'),
                        argparse.Namespace(returncode=0, stdout=remote_output.replace(backup_name.encode(), b'wrong-file.age')),
                        argparse.Namespace(returncode=0, stdout=b'\n')]:
            with patch.object(module.subprocess, 'run', side_effect=remote_failure(invalid)):
                assert invoke('checkpoint').get('failed') is True
        def timeout(args, **kwargs):
            if args[0] == 'ssh-keygen':
                return argparse.Namespace(returncode=0)
            raise subprocess.TimeoutExpired('ssh', 15)
        with patch.object(module.subprocess, 'run', side_effect=timeout):
            assert invoke('checkpoint').get('failed') is True
        config_path = '/etc/ultra-recovery/backup.json'
        config = module.read(config_path)
        for field, value in [('id', 'wrong-primary'), ('host', 'root@192.0.2.3'), ('required', False),
                             ('identity_file', '/wrong-key'), ('known_hosts', '/wrong-pins')]:
            altered = json.loads(json.dumps(config))
            altered['destinations'][0][field] = value
            write(config_path, altered)
            with patch.object(module.subprocess, 'run', return_value=remote_result) as ssh:
                assert invoke('checkpoint').get('failed') is True
                ssh.assert_not_called()
        write(config_path, config)
        for field, value in [('backup_name', '../generation.age'), ('artifact_name', '../artifact.age'),
                             ('backup_name', 'backup-' + str(snapshot-1) + '-' + 'a'*32 + '.age'),
                             ('source', 'exit'), ('snapshot_at', snapshot-301)]:
            altered = dict(backup, **{field: value})
            write('/var/lib/ultra-recovery/last-success.json', altered)
            with patch.object(module.subprocess, 'run', return_value=remote_result) as ssh:
                assert invoke('checkpoint').get('failed') is True
                ssh.assert_not_called()
        write('/var/lib/ultra-recovery/last-success.json', backup)
        # Verify private key/host pins ownership modes and symlink rejection.
        for path in [identity, pins]:
            mapped(path).chmod(0o666)
            with patch.object(module.subprocess, 'run', return_value=remote_result) as ssh:
                assert invoke('checkpoint').get('failed') is True
                ssh.assert_not_called()
            mapped(path).chmod(0o600)
            saved = mapped(path).read_bytes()
            mapped(path).unlink()
            mapped(path).symlink_to(mapped('/var/lib/ultra-recovery/' + artifact_name))
            with patch.object(module.subprocess, 'run', return_value=remote_result) as ssh:
                assert invoke('checkpoint').get('failed') is True
                ssh.assert_not_called()
            mapped(path).unlink()
            write(path, saved)
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
        backup['delivered_target_ids'] = ['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee']
        write('/var/lib/ultra-recovery/last-success.json', backup)
        write(module.FILES[1], b'changed-after-checkpoint')
        assert invoke('resume-check').get('failed') is True
        write(module.FILES[1], b'old-managed-bytes')
        backup['snapshot_at'] -= 301
        write('/var/lib/ultra-recovery/last-success.json', backup)
        assert invoke('checkpoint').get('failed') is True

# Type=oneshot workers report activating while is-active returns 3. Check the
# actual module through its Ansible entrypoint; all commands remain fake.
idle_source = source.with_name('ultra_recovery_idle.py')
idle_spec = importlib.util.spec_from_file_location('recovery_idle', idle_source)
idle_module = importlib.util.module_from_spec(idle_spec)
idle_spec.loader.exec_module(idle_module)


class IdleModule(FakeModule):
    params = {'service': 'ultra-recovery-backup.service'}
    def __init__(self, output, rc):
        self.output, self.rc = output, rc
    def run_command(self, args):
        assert args == ['systemctl', 'show', '--property=LoadState', '--property=ActiveState',
                        '--property=MainPID', '--property=ControlPID', self.params['service']]
        return self.rc, self.output, ''


def idle_result(state='inactive', main='0', control='0', load='loaded', rc=0, output=None):
    if output is None:
        # Order is deliberately different from the requested properties.
        output = f'ControlPID={control}\nActiveState={state}\nMainPID={main}\nLoadState={load}\n'
    with patch.object(idle_module, 'AnsibleModule', return_value=IdleModule(output, rc)):
        try:
            idle_module.main()
        except Done as result:
            return result.result
    raise AssertionError('missing idle result')


for state, main, control in [('activating', '1234', '0'), ('activating', '0', '1234'),
                             ('active', '1234', '0'), ('deactivating', '0', '0'),
                             ('inactive', '1234', '0'), ('failed', '0', '1234')]:
    assert idle_result(state, main, control) == {'changed': False, 'idle': False}
for state in ('inactive', 'failed'):
    assert idle_result(state) == {'changed': False, 'idle': True}
assert idle_result(load='not-found') == {'changed': False, 'idle': True}
for kwargs in [{'state': 'unknown'}, {'load': 'error'}, {'load': 'masked'},
               {'main': 'unknown'}, {'control': '-1'}, {'rc': 1},
               {'output': 'ActiveState=inactive\nMainPID=0\n'},
               {'output': 'LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\nMainPID=0\n'},
               {'load': 'not-found', 'main': '1234'}, {'load': 'not-found', 'state': 'failed'}]:
    assert idle_result(**kwargs).get('failed') is True, kwargs

# Every wait after pausing timers must use the same predicate and retain its
# bounded retry policy. No wait is allowed to stop a recovery service.
ansible_root = source.parents[1]
for name, register in [('playbooks/prepare-controller.yml', 'adoption_cycle'),
                       ('playbooks/upgrade.yml', 'release_cycle'),
                       ('playbooks/reserve-rolledback-bootstrap.yml', 'adoption_retry_cycle'),
                       ('roles/recovery_primary/tasks/main.yml', 'recovery_primary_copy_active')]:
    tasks = yaml.safe_load((ansible_root / name).read_text())
    if name.startswith('playbooks/'):
        tasks = tasks[0]['tasks']
    expanded = [child for task in tasks for child in task.get('block', [task])]
    wait = next(task for task in expanded if task.get('register') == register)
    service = 'ultra-recovery-backup.service' if name.startswith('roles/') else '{{ item }}'
    assert wait['ultra_recovery_idle'] == {'service': service}, name
    assert wait['until'] == register+'.idle | default(false) | bool', name
    assert (wait['retries'], wait['delay']) == (110, 5), name
    assert 'ansible.builtin.command' not in wait and 'failed_when' not in wait, name
    if not name.startswith('roles/'):
        assert wait['loop'] == ['ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'], name
print('legacy adoption identity, freshness, emergency, pre-base recovery and oneshot drain guards passed')
