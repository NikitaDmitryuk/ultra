#!/usr/bin/env python3
"""Restore a verified encrypted bridge generation onto a prepared, fenced VM."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import time
from types import SimpleNamespace
import urllib.request

from recovery import atomic_json, private, restore
import restore_ansible
from restore_common import configuration, fence, plan_id, read_private, sha, stage_manifests, safe_error_code, SAFE_ERROR_CODES


def ssh_arguments(endpoint):
    private(endpoint['identity'])
    pins = Path(endpoint['known_hosts'])
    if pins.is_symlink() or not pins.is_file() or pins.stat().st_mode & 0o022:
        raise ValueError('trusted_known_hosts_required')
    return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
            '-o', 'UserKnownHostsFile=' + str(pins), '-i', endpoint['identity'],
            '-p', str(endpoint.get('port', 22)), endpoint['host']]


def remote(endpoint, arguments, data, timeout=1900):
    result = subprocess.run(ssh_arguments(endpoint) + [shlex.join(arguments)], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        if len(result.stderr) <= 1024:
            try:
                failure = json.loads(result.stderr)
                if (set(failure) == {'restore_error_code'}
                        and failure['restore_error_code'] in SAFE_ERROR_CODES):
                    raise ValueError(failure['restore_error_code'])
            except (json.JSONDecodeError, TypeError):
                pass
        raise ValueError('pinned_remote_action_failed')
    return result.stdout


def current_fence(config):
    return fence(read_private(config['fence_file']), 'bridge', config['target']['host'], config['old_bridge_address'], migration=config.get('migration_identity'))


def seed_original_artifact(config, state, destination):
    # Re-verify ciphertext even on resume; the age identity remains on the operator.
    verified = restore(SimpleNamespace(command='verify', identity=config['identity'], bundle=config['bundle'],
                                       target=str(Path(config['state_dir']) / 'verify-only')))
    if verified != state:
        raise ValueError('staged_manifest_mismatch')
    artifact = Path(config['bundle']).parent / state['artifact']
    private(artifact)
    script = "import sys,json;sys.path.insert(0,sys.argv[1]);from restore_host import seed_artifact_cache;" + \
             "c=json.load(open('/etc/ultra-recovery/backup.json'));" + \
             "assert c['repository']=='/var/lib/ultra-recovery' and c['source']=='bridge';" + \
             "seed_artifact_cache(c['repository'],sys.argv[2],sys.argv[3],sys.stdin.buffer)"
    remote(config['target'], ['python3', '-c', script, destination, artifact.name, sha(artifact)], artifact.read_bytes())


def stage_generation(config, directory):
    stage = directory / 'stage'
    if not stage.exists():
        pending = directory / 'stage.pending'
        if pending.exists():
            shutil.rmtree(pending)
        restore(SimpleNamespace(command='restore', identity=config['identity'], bundle=config['bundle'],
                                target=str(pending), fence_file=config['fence_file']))
        stage_manifests(pending)
        pending.rename(stage)
    state, artifacts = stage_manifests(stage)
    archive = directory / 'stage.tar.gz'
    if not archive.exists():
        pending = directory / 'stage.tar.gz.pending'
        with tarfile.open(pending, 'w:gz') as output:
            for path in sorted(stage.rglob('*')):
                if path.is_symlink():
                    raise ValueError('stage_symlink_rejected')
                if path.is_file():
                    output.add(path, arcname=str(path.relative_to(stage)), recursive=False)
        pending.chmod(0o600)
        pending.rename(archive)
    return state, artifacts, archive


class RestoreFailure(ValueError):
    def __init__(self, value):
        self.diagnostic = value
        super().__init__('restore_failed')


class Diagnostics:
    def __init__(self):
        self.stage = 'validate'
        self.directory = None
    def failed(self, error):
        value = {'stage': self.stage, 'code': safe_error_code(error), 'at': int(time.time())}
        if self.directory is not None:
            try:
                atomic_json(self.directory / 'last-error.json', value)
            except OSError:
                pass
        return value
    def success(self):
        if self.directory is not None:
            (self.directory / 'last-error.json').unlink(missing_ok=True)


def execute(config):
    diagnostic = Diagnostics()
    try:
        value = _execute(config, diagnostic)
        diagnostic.success()
        return value
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise RestoreFailure(diagnostic.failed(error)) from None


def _execute(config, diagnostic):
    os.umask(0o077)
    config = configuration(config)
    private(config['identity']); private(config['bundle'])
    current_fence(config)
    run_id = plan_id(config, sha(config['bundle']))
    base = Path(config['state_dir'])
    if base.is_symlink():
        raise ValueError('private_state_directory_required')
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if base.stat().st_mode & 0o077:
        raise ValueError('private_state_directory_required')
    directory = base / run_id
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError('private_state_directory_required')
    diagnostic.directory = directory
    with (directory / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started_at = int(time.time())
        diagnostic.stage = 'decrypt'
        state, artifacts, archive = stage_generation(config, directory)
        diagnostic.stage = 'operator_runtime'
        restore_ansible.prepare_runtime(config,directory)
        destination = '/var/lib/ultra-restore/' + run_id
        plan = {key: config[key] for key in ('old_bridge_address', 'new_bridge_address', 'public_host', 'subscription_domain', 'new_bridge_provider')}
        plan['ingress_mode'] = config['ingress_mode']
        binary = (directory / 'stage/artifacts/usr/local/bin/ultra-relay').read_bytes()[:20]
        if binary[:4] != b'\x7fELF' or binary[5] != 1 or int.from_bytes(binary[18:20], 'little') not in (62, 183):
            raise ValueError('supported_linux_release_required')
        architecture = {62: 'x86_64', 183: 'aarch64'}[int.from_bytes(binary[18:20], 'little')]
        if config.get('migration_identity') is not None:
            plan['migration_identity'] = config['migration_identity']
        plan.update(architecture=architecture, restore_id=run_id, target_host=config['target']['host'], readiness_timeout=config.get('readiness_timeout', 900), stage_sha256=sha(archive))
        receipt = {'restore_id': run_id, 'snapshot_at': state['snapshot_at'], 'completed': [], 'started_at': started_at}
        receipt_path = directory / 'receipt.json'
        if receipt_path.exists():
            receipt = read_private(receipt_path)
            if receipt.get('restore_id') != run_id:
                raise ValueError('restore_receipt_conflict')
        def host(phase):
            diagnostic.stage = phase
            plan['fence'] = current_fence(config)
            result = restore_ansible.phase(config, directory, plan, phase, archive)
            if phase == 'peer_reseed':
                restore_ansible.reseed_peers(config, directory, result.get('reseed_nodes', []))
            receipt.update({key: value for key, value in result.items() if key != 'reseed_nodes'})
            atomic_json(receipt_path, receipt)
            print(json.dumps({'phase': phase, 'complete': True}), flush=True)
        host('prepare')
        for phase in ('install', 'database', 'peer_reseed', 'activate'):
            host(phase)
        if config['ingress_mode'] == 'forward':
            plan['fence'] = current_fence(config)
            peer_plan = dict(plan, action='forward')
            diagnostic.stage = 'forward'
            restore_ansible.peer(config, directory, config['ingress'], peer_plan)
        else:
            host('ingress')
        # Validate the unchanged public DNS/TLS path before automatic services start.
        diagnostic.stage = 'public_https'
        with urllib.request.urlopen('https://' + config['subscription_domain'] + '/healthz', timeout=30) as response:
            if response.status != 200:
                raise ValueError('public_ingress_not_ready')
        plan['ingress_confirmed'] = True
        if config['ingress_mode'] == 'forward':
            host('ingress')
        diagnostic.stage = 'artifact_cache'
        current_fence(config)
        seed_original_artifact(config, state, destination)
        host('automation'); host('ready')
        receipt['finished_at'] = int(time.time())
        receipt['elapsed_seconds'] = receipt['finished_at'] - receipt['started_at']
        atomic_json(receipt_path, receipt)
        return receipt


def check(config):
    config = configuration(config)
    private(config['identity'])
    try:
        current_fence(config)
        fenced = True
    except (OSError, ValueError, KeyError, TypeError):
        fenced = False
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ultra-restore-check-') as temporary:
        stage = Path(temporary) / 'stage'
        restore(SimpleNamespace(command='verify', identity=config['identity'], bundle=config['bundle'], target=str(stage), test_stage=True))
        state, _ = stage_manifests(stage)
    code = "import json,os,pathlib,platform; print(json.dumps({'root':os.geteuid()==0,'architecture':platform.machine(),'os_release':dict(x.split('=',1) for x in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in x),'contains_ultra':pathlib.Path('/etc/ultra-relay/spec.json').exists()}))"
    target = json.loads(remote(config['target'], ['python3', '-c', code], b''))
    ingress = json.loads(remote(config['ingress'], ['python3', '-c', code], b'')) if config['ingress_mode'] == 'forward' else {'mode': 'direct'}
    return {'generation_verified': True, 'snapshot_at': state['snapshot_at'], 'target': target, 'ingress': ingress,
            'fence_valid': fenced, 'changed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='Private JSON restore plan; see restore.example.json')
    parser.add_argument('--release-dir',help='Optional complete verified release for operator offline dependencies')
    parser.add_argument('--check', action='store_true', help='Verify generation and pinned SSH prerequisites without installation')
    args = parser.parse_args()
    config=read_private(args.config)
    if args.release_dir:config['release_dir']=str(Path(args.release_dir).resolve())
    result = (check if args.check else execute)(config)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except RestoreFailure as error:
        raise SystemExit(json.dumps({'restore_failed': error.diagnostic}, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(json.dumps({'restore_failed': {'stage': 'validate', 'code': safe_error_code(error)}}, sort_keys=True))
