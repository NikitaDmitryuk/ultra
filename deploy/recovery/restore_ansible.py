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
from recovery import private
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
                 'ultra_restore_automation_units': AUTOMATION_UNITS,
                 'ultra_db_tunnel_host': plan['database_host'],
                 'ultra_db_tunnel_known_hosts_source': config['database_target']['known_hosts']}
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


def database(config, directory, plan, archive):
    """Restore PostgreSQL through operator-pinned SSH directly to its dedicated host."""
    endpoint = config['database_target']
    private(endpoint['identity'])
    pins = Path(endpoint['known_hosts'])
    if pins.is_symlink() or not pins.is_file() or pins.stat().st_mode & 0o022 or not pins.read_bytes():
        raise ValueError('trusted_known_hosts_required')
    user, address = endpoint['host'].split('@', 1)
    if address != plan.get('database_host'):
        raise ValueError('restore_database_target_mismatch')
    from restore_common import stage_manifests, sha
    state, _ = stage_manifests(directory / 'stage')
    public_key_name = 'state/etc/ultra-db-tunnel/id_ed25519.pub'
    public_key = directory / 'stage' / public_key_name
    row = state['files'].get(public_key_name)
    if not row or public_key.is_symlink() or not public_key.is_file() or sha(public_key) != row['sha256']:
        raise ValueError('restored_database_tunnel_key_missing')
    public_key_text = public_key.read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: .*)?', public_key_text):
        raise ValueError('restored_database_tunnel_key_invalid')
    from restore_host import database_spec
    spec = json.loads((directory / 'stage/state/etc/ultra-relay/spec.json').read_text())
    database_name, database_user, database_password = database_spec(spec)
    if (database_name, database_user) != (plan['database']['name'], plan['database']['user']):
        raise ValueError('restore_database_credentials_mismatch')
    attempt = directory / ('ansible-database-' + plan['restore_id'] + '-' + str(uuid.uuid4()))
    attempt.mkdir(mode=0o700)
    inventory = {'all': {'hosts': {'bridge': {
        'ansible_host': config['target']['host'].split('@', 1)[1],
        'ansible_user': config['target']['host'].split('@', 1)[0],
        'ansible_port': config['target'].get('port', 22),
        'ansible_ssh_private_key_file': config['target']['identity'],
        'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
        'ansible_ssh_common_args': '-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o UserKnownHostsFile=' + shlex.quote(config['target']['known_hosts']),
        'db_tunnel_ultra_public_key': public_key_text,
    }}, 'children': {'restore_databases': {'hosts': {'database': {
        'ansible_host': address, 'ansible_user': user, 'ansible_port': endpoint.get('port', 22),
        'ansible_ssh_private_key_file': endpoint['identity'],
        'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
        'ansible_ssh_common_args': '-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o UserKnownHostsFile=' + shlex.quote(endpoint['known_hosts']),
    }}}}}}
    variables = {'ultra_restore_database_plan': plan,
                 'ultra_postgres': {'name': database_name, 'user': database_user, 'password': database_password},
                 'ultra_db_tunnel_host': plan['database_host'],
                 'ultra_restore_stage_archive': str(archive),
                 'ultra_restore_script_directory': str(Path(__file__).parent)}
    atomic_json(attempt / 'inventory.json', inventory)
    atomic_json(attempt / 'variables.json', variables)
    result = subprocess.run([os.environ.get('ULTRA_INSTALL_BINARY', '/usr/local/bin/ultra-install'),
                             'ansible-run', '--operation', 'restore-database',
                             '--inventory', str(attempt / 'inventory.json'),
                             '--variables', str(attempt / 'variables.json'),
                             '--state-dir', str(attempt / 'operation'), *runtime_arguments(config)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1900)
    if result.returncode:
        raise ValueError('pinned_remote_action_failed')
    response = json.loads((attempt / 'operation/result.json').read_text())
    if response.get('verified') is not True:
        raise ValueError('dedicated_database_restore_unverified')
    return response


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
