"""Operator-local Ansible adapter; data proofs and fencing stay in restore_host."""
import gzip
import tarfile
import io
import re
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import uuid
from recovery import atomic_json
from restore_common import APP_UNITS, AUTOMATION_UNITS


def prepare_runtime(config, directory):
    """Bootstrap pinned dependencies from authenticated artifact members, never /opt."""
    from restore_common import stage_manifests,sha
    stage=directory/'stage'; _,artifacts=stage_manifests(stage)
    arguments=[os.environ.get('ULTRA_INSTALL_BINARY','/usr/local/bin/ultra-install'),
               'prepare-recovery-runtime','--state-dir',str(directory/'operator-runtime')]
    if config.get('release_dir'):
        if not Path(config['release_dir']).is_absolute():raise ValueError('absolute_runtime_release_required')
        arguments+=['--release-dir',config['release_dir']]
    else:
        deployment=json.loads((stage/'state/etc/ultra-recovery/deployment.json').read_text())
        root=deployment.get('controller_directory','')
        if not re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}',root):
            raise ValueError('authenticated_offline_runtime_missing')
        prefix=root.lstrip('/')+'/runtime/'
        selected={name[len(prefix):]:row for name,row in artifacts['files'].items() if name.startswith(prefix)}
        if 'requirements.lock' not in selected or not any(name.startswith('wheels/pip-25.3-') for name in selected):
            raise ValueError('authenticated_offline_runtime_missing')
        if len(selected)>64 or sum(row.get('bytes',0) for row in selected.values())>128*1024*1024:
            raise ValueError('authenticated_offline_runtime_exceeds_bounds')
        for name,row in selected.items():
            if row.get('bytes',0)<=0 or row['bytes']>64*1024*1024:
                raise ValueError('authenticated_offline_runtime_exceeds_bounds')
            if name!='requirements.lock' and not re.fullmatch(r'wheels/[A-Za-z0-9_.+-]+\.whl',name):
                raise ValueError('authenticated_offline_runtime_member_invalid')
        archive=directory/'operator-runtime.tar.gz';pending=archive.with_suffix('.pending')
        with pending.open('wb') as output,gzip.GzipFile(fileobj=output,mode='wb',mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as bundle:
            for name,row in sorted(selected.items()):
                source=stage/'artifacts'/prefix/name
                if source.is_symlink() or sha(source)!=row['sha256']:raise ValueError('authenticated_offline_runtime_changed')
                payload=source.read_bytes();header=tarfile.TarInfo(name);header.size=len(payload);header.mode=0o600
                bundle.addfile(header,io.BytesIO(payload))
        pending.chmod(0o600);pending.replace(archive)
        arguments+=['--runtime-archive',str(archive),'--sha256',sha(archive)]
    result=subprocess.run(arguments,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=660)
    if result.returncode:raise ValueError('offline_recovery_runtime_failed')
    response=json.loads(result.stdout)
    executable=response.get('executable')
    if not isinstance(executable,str) or not Path(executable).is_absolute():raise ValueError('offline_recovery_runtime_invalid')
    config['ansible_executable']=executable
    return executable


def runtime_arguments(config):
    executable=config.get('ansible_executable')
    if not isinstance(executable,str) or not Path(executable).is_absolute():
        raise ValueError('offline_recovery_runtime_not_prepared')
    return ['--executable',executable]


def phase(config, directory, plan, action, archive):
    endpoint = config['target']
    user, address = endpoint['host'].split('@', 1)
    attempt = directory / ('ansible-' + action + '-' + str(uuid.uuid4()))
    attempt.mkdir(mode=0o700)
    inventory = {'all': {'children': {'restore_targets': {'hosts': {'target': {
        'ansible_host': address, 'ansible_user': user, 'ansible_port': endpoint.get('port', 22),
        'ansible_ssh_private_key_file': endpoint['identity'],
        'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
        'ansible_ssh_common_args': '-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o UserKnownHostsFile=' + shlex.quote(endpoint['known_hosts']),
    }}}}}}
    variables = {'ultra_restore_phase': action, 'ultra_restore_id': plan['restore_id'],
                 'ultra_restore_directory': '/var/lib/ultra-restore/' + plan['restore_id'],
                 'ultra_restore_plan': plan, 'ultra_restore_script_directory': str(Path(__file__).parent),
                 'ultra_restore_stage_archive': str(archive), 'ultra_restore_app_units': APP_UNITS,
                 'ultra_restore_automation_units': AUTOMATION_UNITS}
    atomic_json(attempt / 'inventory.json', inventory)
    atomic_json(attempt / 'variables.json', variables)
    operation = attempt / 'operation'
    started = time.monotonic()
    deadline = started + plan.get('readiness_timeout', 900)
    while True:
        operation = attempt / ('observation-' + str(uuid.uuid4())) if action == 'ready' else attempt / 'operation'
        result = subprocess.run([os.environ.get('ULTRA_INSTALL_BINARY', '/usr/local/bin/ultra-install'),
                                 'ansible-run', '--operation', 'restore',
                                 '--inventory', str(attempt / 'inventory.json'),
                                 '--variables', str(attempt / 'variables.json'),
                                 '--state-dir', str(operation), *runtime_arguments(config)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1900)
        if result.returncode == 0:
            return json.loads((operation / 'result.json').read_text())
        if action != 'ready' or time.monotonic() >= deadline:
            raise ValueError('pinned_remote_action_failed')
        time.sleep(5)


def peer_inputs(config, endpoint, plan):
    """Operator-owned peer task; restored credentials projected from checked stage."""
    allowed = config.get('isolated_peer_addresses')
    destination = endpoint['host'].split('@')[-1]
    if allowed is not None and destination not in allowed:
        raise ValueError('isolated_restore_production_peer_forbidden')
    user, separator, address = endpoint['host'].partition('@')
    if not separator:
        user, address = 'root', user
    inventory = {'all': {'children': {'restore_peers': {'hosts': {'peer': {
        'ansible_host': address, 'ansible_user': user, 'ansible_port': endpoint.get('port', 22),
        'ansible_ssh_private_key_file': endpoint['identity'],
        'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
        'ansible_ssh_common_args': '-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o UserKnownHostsFile=' + shlex.quote(endpoint['known_hosts']),
    }}}}}}
    variables = {'ultra_peer_plan': plan, 'ultra_peer_script_directory': str(Path(__file__).parent)}
    return {'inventory': inventory, 'variables': variables}


def peer(config, directory, endpoint, plan):
    inputs = peer_inputs(config, endpoint, plan)
    attempt = directory / ('peer-' + str(uuid.uuid4()))
    attempt.mkdir(mode=0o700)
    atomic_json(attempt / 'inventory.json', inputs['inventory'])
    atomic_json(attempt / 'variables.json', inputs['variables'])
    result = subprocess.run([os.environ.get('ULTRA_INSTALL_BINARY', '/usr/local/bin/ultra-install'),
                             'ansible-run', '--operation', 'restore-peer',
                             '--inventory', str(attempt / 'inventory.json'),
                             '--variables', str(attempt / 'variables.json'),
                             '--state-dir', str(attempt / 'operation'), *runtime_arguments(config)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1900)
    if result.returncode:
        raise ValueError('pinned_remote_action_failed')


def project_peer_inputs(config, directory, nodes):
    from restore_common import stage_manifests, sha
    state, _ = stage_manifests(directory / 'stage')
    result = []
    for node in nodes:
        endpoints = {}
        for name in ('identity', 'known_hosts'):
            relative = 'state/' + node[name].lstrip('/')
            if '..' in Path(relative).parts or relative not in state['files']:
                raise ValueError('restored_peer_credential_missing')
            source = directory / 'stage' / relative
            if source.is_symlink() or sha(source) != state['files'][relative]['sha256']:
                raise ValueError('restored_peer_credential_changed')
            endpoints[name] = str(source)
        endpoints['host'] = 'root@' + node['address']
        result.append(peer_inputs(config, endpoints, node['plan']))
    return result


def reseed_peers(config, directory, nodes):
    inputs = project_peer_inputs(config, directory, nodes)
    for value in inputs:
        attempt = directory / ('peer-' + str(uuid.uuid4()))
        attempt.mkdir(mode=0o700)
        atomic_json(attempt / 'inventory.json', value['inventory'])
        atomic_json(attempt / 'variables.json', value['variables'])
        completed = subprocess.run([os.environ.get('ULTRA_INSTALL_BINARY', '/usr/local/bin/ultra-install'),
                                    'ansible-run', '--operation', 'restore-peer',
                                    '--inventory', str(attempt / 'inventory.json'),
                                    '--variables', str(attempt / 'variables.json'),
                                    '--state-dir', str(attempt / 'operation'), *runtime_arguments(config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1900)
        if completed.returncode:
            raise ValueError('pinned_remote_action_failed')
