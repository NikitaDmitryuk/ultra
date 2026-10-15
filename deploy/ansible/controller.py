#!/usr/bin/env python3
"""Small durable job supervisor. Infrastructure changes belong to Ansible roles."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

LOCAL_OPERATIONS = {'bootstrap-forward-broker', 'contain-upgrade', 'drain-upgrade-workers', 'retain-artifacts', 'resume-schedules', 'rollback-adoption', 'reserve-rolledback-bootstrap', 'resume-adoption', 'lifecycle', 'prepare-controller', 'inspect-upgrade', 'preflight-retry', 'status-automation', 'inspect-release-hosts', 'resume-automation', 'configure-bot', 'configure-exit-operator', 'inspect-bootstrap', 'bootstrap', 'bootstrap-postgres', 'bootstrap-exit', 'bootstrap-bridge', 'bootstrap-automation', 'verify-bootstrap-automation', 'adopt', 'adopt-topology', 'adopt-replica-tunnels', 'upgrade', 'rollback', 'verify-release', 'commit-release', 'publish-release', 'ingress', 'reconcile', 'restore', 'restore-peer', 'replica', 'domain-cutover', 'backend-domain', 'bridge-migrate', 'bridge-migrate-inspect', 'bridge-migrate-fence', 'bridge-migrate-probe', 'bridge-migrate-rollback-peers', 'upgrade-dns-migration', 'inspect-upgrade-runtime', 'inspect-upgrade-maintenance', 'upgrade-runtime', 'inspect-upgrade-domains', 'upgrade-domain'}
OPERATIONS = {'configure-exit', 'configure-replica', 'stop-replica'} | LOCAL_OPERATIONS

# Operation identities and authorization stay distinct even when implementation
# is shared. Never derive a playbook path from caller-provided input.
PLAYBOOKS = {operation: operation for operation in OPERATIONS}
PLAYBOOKS.update({'configure-replica': 'replica',
                 'configure-exit-operator': 'configure-exit',
                 'domain-cutover': 'ingress'})


def operation_playbook(operation):
    try:
        return PLAYBOOKS[operation] + '.yml'
    except KeyError:
        raise ValueError('unsupported_operation') from None


def atomic(path, data):
    if path.is_symlink():
        raise ValueError('symlinked_receipt_forbidden')
    temporary = path.with_suffix('.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def unsafe_yaml(value, unsafe_keys=True):
    # Mark the container, not scalar leaves: Ansible 2.20's !unsafe scalar
    # constructor performs implicit type resolution even for quoted values.
    # Container tagging recursively blocks Jinja without changing JSON types.
    if not isinstance(value, (dict, list)):
        raise ValueError('unsafe_container_required')
    return '!unsafe ' + json.dumps(value, ensure_ascii=False)


def write_unsafe_variables(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(unsafe_yaml(value, unsafe_keys=False) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def load_private(path, raw=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        stat = os.fstat(stream.fileno())
        if stat.st_mode & 0o077 or stat.st_uid != os.geteuid() or stat.st_size > 1024 * 1024:
            raise ValueError('private_job_required')
        data = stream.read()
        return data.encode() if raw else json.loads(data)


def validate(job):
    if job.get('schema_version') != 1 or job.get('operation') not in OPERATIONS:
        raise ValueError('unsupported_operation')
    if not re.fullmatch(r'[a-f0-9]{64}', job.get('request_sha256', '')):
        raise ValueError('invalid_request_identity')
    if not re.fullmatch(r'[a-f0-9]{64}', job.get('binary_sha256', '')):
        raise ValueError('invalid_binary_identity')
    return job


def run_playbook(arguments, bundle, environment, timeout=900):
    # SSH workers must stop before a terminal receipt releases the fleet lease.
    # A separate session lets cleanup cover descendants even if the leader exits.
    process = subprocess.Popen(arguments, cwd=bundle, env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def execute(directory, executable, bundle):
    directory = Path(directory)
    if directory.is_symlink() or directory.stat().st_mode & 0o077 or directory.stat().st_uid != os.geteuid():
        raise ValueError('private_job_required')
    job = validate(load_private(directory / 'job.json'))
    raw = load_private(directory / 'request.json', raw=True)
    request = json.loads(raw)
    if hashlib.sha256(raw).hexdigest() != job['request_sha256']:
        raise ValueError('request_changed')
    if job['operation'] in LOCAL_OPERATIONS:
        inventory = request['inventory']
        variables = request['variables']
        variables['ultra_result_file'] = str(directory / 'result.json')
        atomic(directory / 'inventory.json', inventory)
        atomic(directory / 'variables.json', variables)
        write_unsafe_variables(directory / 'variables.yml', variables)
    elif job['operation'] in ('configure-replica', 'stop-replica'):
        import ipaddress
        import shlex
        if not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', request.get('id', '')):
            raise ValueError('invalid_replica_identity')
        slot = 'ultra_' + request['id'].replace('-', '')
        inventory = {'all': {'children': {'bridges': {'hosts': {'bridge': {'ansible_connection': 'local'}}}}}}
        variables = {'ultra_replica_slot': slot, 'ultra_result_file': str(directory / 'result.json')}
        if job['operation'] == 'configure-replica':
            ipaddress.ip_address(request['host'])
            if not re.fullmatch(r'[a-z_][a-z0-9_]*', request['user']) or not re.fullmatch(r'[a-f0-9]{48,128}', request['password']):
                raise ValueError('invalid_replica_credentials')
            if request['architecture'] not in ('x86_64', 'aarch64') or not 1 <= request['primary_port'] <= 65535:
                raise ValueError('invalid_replica_layout')
            for name in ('identity', 'known_hosts'):
                if hashlib.sha256(load_private(directory / name, raw=True)).hexdigest() != job[name + '_sha256']:
                    raise ValueError('ssh_identity_changed')
            inventory['all']['children']['replicas'] = {'hosts': {'replica': {
                'ansible_host': request['host'], 'ansible_user': 'root',
                'ansible_ssh_private_key_file': str(directory / 'identity'),
                'ansible_ssh_args': '-F /dev/null -o ControlMaster=no -o ControlPath=none',
                'ansible_ssh_common_args': '-o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile=' + shlex.quote(str(directory / 'known_hosts')),
            }}}
            for key in ('user', 'password', 'primary_port', 'architecture', 'connections', 'workers', 'prepared', 'locks', 'senders'):
                variables['ultra_replica_' + key] = request[key]
            variables['ultra_replica_required_bytes'] = request['required_bytes']
            variables['ultra_replica_address'] = request['host']
            variables['ultra_replica_identity_source'] = str(directory / 'identity')
            variables['ultra_replica_known_hosts_source'] = str(directory / 'known_hosts')
        atomic(directory / 'inventory.json', inventory)
        atomic(directory / 'variables.json', variables)
        write_unsafe_variables(directory / 'variables.yml', variables)
    else:
        if request['spec']['role'] != 'exit':
            raise ValueError('exit_spec_required')
        import ipaddress
        import shlex
        ipaddress.ip_address(request['host'])
        ipaddress.IPv4Address(request['bridge_ipv4'])
        if not re.fullmatch(r'[a-z_][a-z0-9_-]*', request['user']):
            raise ValueError('invalid_ssh_user')
        for key in ('identity', 'known_hosts'):
            if not Path(request[key]).is_absolute():
                raise ValueError('absolute_ssh_paths_required')
        for filename in ('identity', 'known_hosts'):
            if hashlib.sha256(load_private(directory / filename, raw=True)).hexdigest() != job[filename + '_sha256']:
                raise ValueError('ssh_identity_changed')
        inventory = {'all': {'children': {'exits': {'hosts': {'exit': {
            'ansible_host': request['host'], 'ansible_port': request.get('port', 22) or 22, 'ansible_user': request['user'],
            'ansible_ssh_private_key_file': str(directory / 'identity'),
            'ansible_ssh_args': '-F /dev/null -C -o ControlMaster=no -o ControlPath=none',
            'ansible_ssh_common_args': '-o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile=' + shlex.quote(str(directory / 'known_hosts')),
        }}}}}}
        variables = {'ultra_spec': request['spec'], 'ultra_bridge_ipv4': request['bridge_ipv4'],
                     'ultra_relay_source': str(directory / 'ultra-relay'),
                     'ultra_relay_sha256': job['binary_sha256'], 'ultra_result_file': str(directory / 'result.json')}
        atomic(directory / 'inventory.json', inventory)
        atomic(directory / 'variables.json', variables)
        write_unsafe_variables(directory / 'variables.yml', variables)
        binary = directory / 'ultra-relay'
        if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != job['binary_sha256']:
            raise ValueError('binary_changed')
    write_unsafe_variables(directory / 'inventory.yml', inventory)
    receipt = directory / 'receipt.json'
    if receipt.exists():
        saved = load_private(receipt)
        if saved.get('request_sha256') != job['request_sha256'] or saved.get('binary_sha256') != job['binary_sha256']:
            raise ValueError('receipt_conflict')
        if saved.get('state') == 'succeeded':
            return saved
        if saved.get('state') == 'failed':
            return saved  # Explicit retry creates a new attempt, never treats a failure as success.
    result_path = directory / 'result.json'
    result_path.unlink(missing_ok=True)
    state = {**job, 'state': 'running', 'started_at': int(time.time())}
    atomic(receipt, state)
    environment = {
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': str(directory),
        'ANSIBLE_CONFIG': str(Path(bundle) / 'ansible.cfg'),
        'ANSIBLE_LOCAL_TEMP': str(directory / 'ansible-tmp'),
        'ANSIBLE_NOCOLOR': '1',
        'PYTHONDONTWRITEBYTECODE': '1',
        'ULTRA_ANSIBLE_DIAGNOSTIC_FILE': str(directory / 'diagnostic.json'),
    }
    try:
        exit_code = run_playbook([
            str(executable), '-i', str(directory / 'inventory.yml'),
            str(Path(bundle) / 'playbooks' / operation_playbook(job['operation'])),
            '--extra-vars', '@' + str(directory / 'variables.yml'),
        ], bundle, environment)
        if exit_code:
            if (directory / 'diagnostic.json').exists():
                state['diagnostic'] = load_private(directory / 'diagnostic.json')
            state.update(state='failed', code='ansible_failed', exit_code=exit_code)
        else:
            result = load_private(result_path)
            if job['operation'] in ('configure-exit', 'bootstrap-exit') and not re.fullmatch(r'[a-f0-9]{64}', result.get('cert_pin', '')):
                raise ValueError('invalid_certificate_pin')
            if job['operation'] in ('bootstrap-postgres', 'bootstrap-exit', 'bootstrap-bridge', 'adopt-replica-tunnels') and result.get('verified') is not True:
                raise ValueError('invalid_bootstrap_component_acknowledgement')
            if job['operation'] == 'bootstrap-exit' and result.get('exit_host') != variables.get('ultra_bootstrap_exit_host'):
                raise ValueError('invalid_bootstrap_exit_identity')
            if job['operation'] in ('configure-replica', 'stop-replica') and result.get('verified') is not True:
                raise ValueError('invalid_replica_acknowledgement')
            state.update(state='succeeded', result=result)
    except InterruptedError:
        # Operator/service cancellation is resumable, unlike a terminal timeout.
        # The process group is already gone before this nonterminal receipt.
        state.update(state='running', code='interrupted')
    except (OSError, ValueError, subprocess.SubprocessError):
        state.update(state='failed', code='execution_failed')
    if state['state'] != 'running':
        state['finished_at'] = int(time.time())
    atomic(receipt, state)
    return state


def main():
    def interrupted(_signum, _frame):
        raise InterruptedError('controller_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser()
    parser.add_argument('--job', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--executable', required=True)
    args = parser.parse_args()
    directory = Path(args.job)
    fd = os.open(directory / 'execution.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            value = execute(directory, args.executable, args.bundle)
        except (ValueError, OSError, KeyError, TypeError):
            raise SystemExit('invalid_job') from None
    raise SystemExit(0 if value['state'] == 'succeeded' else 1)


if __name__ == '__main__':
    main()
