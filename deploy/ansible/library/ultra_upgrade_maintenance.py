#!/usr/bin/python
"""Private same-operation legacy maintenance barrier."""
import hashlib
import base64
import json
import os
from pathlib import Path
import pwd
import re
import stat
import uuid
import tempfile
import time
from ansible.module_utils.basic import AnsibleModule

SERVICES = ('ultra-bot.service', 'ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer')
FILES = ('/etc/ultra-relay/spec.json', '/etc/ultra-relay/environment', '/etc/systemd/system/ultra-relay.service')
PROPERTIES = ('LoadState', 'ActiveState', 'MainPID', 'ControlPID')


def private(path, evidence=False):
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_uid != 0 or metadata.st_mode & (0o022 if evidence else 0o077) or metadata.st_size > 1048576:
        raise ValueError('maintenance_checkpoint_invalid')
    return json.loads(path.read_text())


def service(module, unit):
    code, output, _ = module.run_command(['systemctl', 'show'] + ['--property=' + key for key in PROPERTIES] + [unit])
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition('=')
        if not sep or key not in PROPERTIES or key in values:
            raise ValueError('maintenance_service_unavailable')
        values[key] = value
    if code or set(values) != set(PROPERTIES) or values['LoadState'] != 'loaded':
        raise ValueError('maintenance_service_unavailable')
    if values['ActiveState'] not in ('active', 'inactive') or any(not re.fullmatch('[0-9]+', values[key]) for key in ('MainPID', 'ControlPID')):
        raise ValueError('maintenance_service_ambiguous')
    return values


def hashes():
    result = {}
    for name in FILES:
        path = Path(name)
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_mode & 0o022 or metadata.st_size > 1048576:
            raise ValueError('maintenance_configuration_invalid')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def accepted_configuration(checkpoint, contract, operation, root=Path('/'), compensation=False):
    """Prove the exact candidate chain, never bless arbitrary live bytes."""
    request_raw = contract['runtime_request_json']
    request = json.loads(request_raw)
    generation = contract['generation']
    transaction = operation + '-runtime-' + str(generation)
    if type(generation) is not int or not 1 <= generation <= 1000 or request['request']['transaction'] != transaction or request['request']['role'] != 'bridge':
        raise ValueError('maintenance_candidate_generation_invalid')
    binding = hashlib.sha256(request_raw.encode()).hexdigest()
    runtime = root / 'etc/ultra-recovery/runtime-transactions' / transaction
    journal = private(runtime.with_suffix('.json'))
    transport = private(runtime.with_suffix('.transport.json'))
    effects = private(runtime.with_suffix('.effects.json'))
    enabled = request['request']['bot_enabled']
    if (type(enabled) is not bool or journal.get('Version') != 1 or journal.get('Transaction') != transaction
            or journal.get('State') not in (('prepared', 'applied', 'rolled_back') if compensation else ('applied',))
            or transport.get('digest') != binding
            or effects.get('version') != 1 or effects.get('binding_sha256') != binding
            or effects.get('state') not in (('prepared', 'applying', 'applied', 'rolling_back', 'rolled_back') if compensation else ('applied',))
            or effects.get('plan') != transport.get('effects_plan')
            or effects['plan'].get('bot_service') is not True or effects['plan'].get('bot_enabled') != enabled):
        raise ValueError('maintenance_candidate_binding_invalid')
    before, candidate = journal['Before'], journal['Candidate']
    if len(before) != 2 or len(candidate) != 2:
        raise ValueError('maintenance_candidate_images_invalid')
    expected, permitted = {}, {}
    for index, name in enumerate(FILES[:2]):
        if before[index]['Exists'] is not True or candidate[index]['Exists'] is not True:
            raise ValueError('maintenance_candidate_images_invalid')
        original = base64.b64decode(before[index]['Data'], validate=True)
        if hashlib.sha256(original).hexdigest() != checkpoint['configuration'][name]:
            raise ValueError('maintenance_candidate_baseline_invalid')
        expected[name] = base64.b64decode(candidate[index]['Data'], validate=True)
        permitted[name] = [(original, before[index]), (expected[name], candidate[index])]
    domain = contract.get('domain')
    if domain:
        attempt = domain['attempt']
        if type(attempt) is not int or not 1 <= attempt <= 1000 or request.get('domain_transaction') != domain['binding']:
            raise ValueError('maintenance_domain_binding_invalid')
        identifier = operation + '-domain-' + str(generation) + '-attempt-' + str(attempt)
        suffix = hashlib.sha256(identifier.encode()).hexdigest()
        ingress = root / ('var/lib/ultra-ingress/ansible-' + suffix)
        try:
            state = private(ingress / 'state.json')
        except FileNotFoundError:
            if not compensation:
                raise
            state = None
        if state is not None:
            before_spec = private_bytes(ingress / 'before.json')
            target = private_bytes(ingress / 'candidate.json')
            plan_hash = hashlib.sha256(json.dumps({'plan': domain['plan'], 'action': 'cutover'}, sort_keys=True).encode()).hexdigest()
            if (state.get('request_sha') != plan_hash or before_spec != expected[FILES[0]]
                    or state.get('before_sha') != hashlib.sha256(before_spec).hexdigest()
                    or state.get('candidate_sha') != hashlib.sha256(target).hexdigest()):
                raise ValueError('maintenance_ingress_candidate_invalid')
            expected[FILES[0]] = target
            ingress_image = dict(candidate[0], Mode=0o600)
            permitted[FILES[0]].extend(((before_spec, ingress_image), (target, ingress_image)))
        if domain.get('backend_policy'):
            try:
                backend = private(root / ('var/lib/ultra-ingress/backend-' + suffix) / 'state.json')
            except FileNotFoundError:
                if not compensation:
                    raise
                backend = None
            if backend is not None:
                images = [item for item in backend['files'] if item['path'] == FILES[1]]
                phases = ('prepared', 'applying', 'applied', 'verified', 'rolled_back') if compensation else ('applied', 'verified')
                if (backend.get('version') != 1 or backend.get('phase') not in phases
                        or backend.get('policy') != domain['backend_policy'] or len(images) != 1
                        or base64.b64decode(images[0]['before'], validate=True) != expected[FILES[1]]):
                    raise ValueError('maintenance_backend_candidate_invalid')
                expected[FILES[1]] = base64.b64decode(images[0]['after'], validate=True)
                backend_image = {'Mode': images[0]['mode'], 'UID': images[0]['uid'], 'GID': images[0]['gid']}
                permitted[FILES[1]].extend(((base64.b64decode(images[0]['before'], validate=True), backend_image), (expected[FILES[1]], backend_image)))
    elif request.get('domain_transaction'):
        raise ValueError('maintenance_domain_candidate_missing')
    live = hashes()
    for index, name in enumerate(FILES[:2]):
        path = root / name.lstrip('/')
        metadata = path.lstat()
        options = permitted[name] if compensation else [permitted[name][-1]]
        if not any(live[name] == hashlib.sha256(raw).hexdigest()
                   and stat.S_IMODE(metadata.st_mode) == image['Mode']
                   and metadata.st_uid == image['UID'] and metadata.st_gid == image['GID']
                   for raw, image in options):
            raise ValueError('maintenance_live_candidate_changed')
    if live[FILES[2]] != checkpoint['configuration'][FILES[2]]:
        raise ValueError('maintenance_relay_unit_changed')
    return enabled


def retry_relay_identity(module, checkpoint, contract, sha, root=Path('/')):
    """Candidate execution needs the manifest-bound fallback activation journal."""
    target, version = contract['target_sha256'], contract['release_version']
    if not re.fullmatch(r'[a-f0-9]{64}', target) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('maintenance_retry_release_invalid')
    relay = service(module, 'ultra-relay.service')
    if relay['ControlPID'] != '0':
        raise ValueError('maintenance_retry_identity_unverified')
    binary = root / 'usr/local/bin/ultra-relay'
    metadata = binary.lstat()
    if binary.is_symlink() or not binary.is_file() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError('maintenance_retry_identity_unverified')
    running = hashlib.sha256(binary.read_bytes()).hexdigest()
    if relay['ActiveState'] == 'inactive':
        if contract['mode'] == 'committed' or relay['MainPID'] != '0':
            raise ValueError('maintenance_retry_identity_unverified')
    else:
        pid = relay['MainPID']
        executable = root / 'proc' / pid / 'exe'
        if (pid == '0' or os.readlink(executable) != '/usr/local/bin/ultra-relay'
                or hashlib.sha256(executable.read_bytes()).hexdigest() != running):
            raise ValueError('maintenance_retry_identity_unverified')
    if running == sha and contract['mode'] != 'committed':
        return
    if running != target:
        raise ValueError('maintenance_retry_identity_unverified')
    fallback = root / 'var/lib/ultra-ansible/releases' / version / 'ultra-relay.previous'
    for path in (fallback, *fallback.parents):
        metadata = path.lstat()
        if path.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('maintenance_retry_fallback_invalid')
        if path == root:
            break
    metadata = fallback.lstat()
    if not fallback.is_file() or metadata.st_size > 256 * 1024 * 1024 or hashlib.sha256(fallback.read_bytes()).hexdigest() != sha:
        raise ValueError('maintenance_retry_fallback_invalid')


def untouched_runtime(request_raw, operation, root=Path('/')):
    """Missing maintenance never authorizes skipping a partially applied image."""
    request = json.loads(request_raw)
    transaction = request['request']['transaction']
    if (not re.fullmatch(re.escape(operation) + r'-runtime-[1-9][0-9]{0,3}', transaction)
            or request['request']['role'] != 'bridge'):
        raise ValueError('maintenance_initial_transaction_invalid')
    runtime = root / 'etc/ultra-recovery/runtime-transactions' / transaction
    journal = private(runtime.with_suffix('.json'))
    transport = private(runtime.with_suffix('.transport.json'))
    effects = private(runtime.with_suffix('.effects.json'))
    binding = hashlib.sha256(request_raw.encode()).hexdigest()
    if (journal.get('Version') != 1 or journal.get('Transaction') != transaction
            or journal.get('State') not in ('prepared', 'rolled_back')
            or transport.get('digest') != binding or effects.get('version') != 1
            or effects.get('binding_sha256') != binding
            or effects.get('state') not in ('prepared', 'rolled_back')
            or effects.get('plan') != transport.get('effects_plan')
            or len(journal['Before']) != 2):
        raise ValueError('maintenance_initial_transaction_changed')
    bot = effects.get('bot')
    if not isinstance(bot, dict) or bot.get('active') not in ('active', 'inactive'):
        raise ValueError('maintenance_initial_bot_state_invalid')
    live = hashes()
    for name, image in zip(FILES[:2], journal['Before']):
        metadata = (root / name.lstrip('/')).lstat()
        original = base64.b64decode(image['Data'], validate=True)
        if (image['Exists'] is not True or live[name] != hashlib.sha256(original).hexdigest()
                or stat.S_IMODE(metadata.st_mode) != image['Mode']
                or metadata.st_uid != image['UID'] or metadata.st_gid != image['GID']):
            raise ValueError('maintenance_initial_configuration_changed')
    return bot['active']


def private_bytes(path):
    metadata = path.lstat()
    if (path.is_symlink() or not path.is_file() or metadata.st_uid != 0
            or metadata.st_mode & 0o077 or metadata.st_nlink != 1 or metadata.st_size > 1048576):
        raise ValueError('maintenance_candidate_file_invalid')
    return path.read_bytes()


def recovery_file(name, allowed_uids, private_file=False, managed_pin=False, relay_prefix=Path('/var/lib/ultra-relay'), root_uid=0, trusted_root=Path('/')):
    path = Path(name)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('maintenance_recovery_path_invalid')
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError('maintenance_recovery_file_invalid')
    if (metadata.st_uid not in allowed_uids
            or (private_file and stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600))
            or (not private_file and metadata.st_mode & 0o022)):
        raise ValueError('maintenance_recovery_file_owner_invalid')
    if metadata.st_size <= 0 or metadata.st_size > 65536:
        raise ValueError('maintenance_recovery_file_size_invalid')
    if not private_file:
        prefix = relay_prefix
        relay_uid = pwd.getpwnam('ultra-relay').pw_uid
        for parent in (path, *path.parents):
            owner = parent.lstat()
            relay_owned = (managed_pin and (parent == prefix or prefix in parent.parents)
                           and owner.st_uid == relay_uid)
            if stat.S_ISLNK(owner.st_mode) or owner.st_mode & 0o022 or (owner.st_uid != root_uid and not relay_owned):
                raise ValueError('maintenance_recovery_pin_owner_invalid')
            if parent == trusted_root:
                break
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_recovery_tool(expected, tool=Path('/opt/ultra-recovery/recovery.py'), owner_uid=0):
    if not expected or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in expected):
        raise ValueError('maintenance_recovery_tool_hash_invalid')
    metadata = tool.lstat()
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid or metadata.st_mode & 0o022 or metadata.st_size > 4 * 1024 * 1024):
        raise ValueError('maintenance_recovery_tool_changed')
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    if digest not in expected:
        raise ValueError('maintenance_recovery_tool_changed')
    return digest



def validate_managed_pin(node, config):
    identifier = str(uuid.UUID(node['id']))
    pin = node['known_hosts']
    if (identifier != node['id'] or config.get('vultr_state_dir') != '/var/lib/ultra-relay/vultr'
            or pin != '/var/lib/ultra-relay/vultr/' + identifier + '/known_hosts'
            or node['host'] != 'root@' + node['address']):
        raise ValueError('maintenance_recovery_managed_pin_invalid')
    return pin


def validate_primary_destination(identity, topology, backup):
    primary = topology['primary']
    selected = [node for node in topology['node_metadata'] if node['id'] == primary]
    required = [item for item in backup.get('destinations', [])
                if item.get('id') == primary and item.get('required') is True]
    if (len(selected) != 1 or len(required) != 1 or required[0].get('identity_file') != identity
            or required[0].get('known_hosts') != selected[0]['known_hosts']
            or required[0].get('host') != selected[0]['host']):
        raise ValueError('maintenance_recovery_primary_identity_invalid')

def recovery_provenance():
    result, configs = {}, {}
    for name in ('/etc/ultra-recovery/reconcile.json', '/etc/ultra-recovery/backup.json',
                 '/var/lib/ultra-recovery-reconcile/state.json', '/var/lib/ultra-relay/recovery-reconcile-status.json'):
        value = private(Path(name), evidence=True)
        configs[name] = value
        normalized = dict(value)
        normalized.pop('updated_at', None)
        result[name] = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()

    config = configs['/etc/ultra-recovery/reconcile.json']
    backup = configs['/etc/ultra-recovery/backup.json']
    topology = configs['/var/lib/ultra-recovery-reconcile/state.json']
    identity = config['ssh_identity_file']
    owner_policy = config.get('ssh_identity_owner', 'ultra-relay')
    if owner_policy not in ('root', 'ultra-relay'):
        raise ValueError('maintenance_recovery_identity_policy_invalid')
    relay_uid = pwd.getpwnam('ultra-relay').pw_uid
    identity_uids = {0}
    if owner_policy == 'ultra-relay':
        identity_uids.add(relay_uid)
    result[identity] = recovery_file(identity, identity_uids, private_file=True)

    for node in topology.get('node_metadata', []):
        pin = node['known_hosts']
        allowed = {0}
        managed = node.get('managed') is True
        if managed:
            validate_managed_pin(node, config)
            allowed.add(relay_uid)
        result[pin] = recovery_file(pin, allowed, managed_pin=managed)

    destinations = backup.get('destinations', [])
    validate_primary_destination(identity, topology, backup)

    for value in [config, backup] + destinations:
        candidate = value.get('ssh_identity_file') or value.get('identity_file')
        if candidate:
            approved_uids = identity_uids if candidate == identity else {0}
            result[candidate] = recovery_file(candidate, approved_uids, private_file=True)
    for value in [config, backup] + destinations:
        pin = value.get('known_hosts')
        if pin and pin not in result:
            result[pin] = recovery_file(pin, {0})
    return result


def idle(module, units):
    for unit in units:
        values = service(module, unit)
        if values['ActiveState'] != 'inactive' or values['MainPID'] != '0' or values['ControlPID'] != '0':
            raise ValueError('maintenance_worker_not_stopped')


def atomic(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_uid != 0 or path.parent.stat().st_mode & 0o077:
        raise ValueError('maintenance_directory_invalid')
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.maintenance-')
    try:
        with os.fdopen(fd, 'w') as target:
            json.dump(value, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    module = AnsibleModule(argument_spec={
        'id': {'type': 'str', 'required': True},
        'legacy_sha256': {'type': 'str', 'required': True},
        'phase': {'type': 'str', 'required': True, 'choices': ['checkpoint', 'capture-checkpoint', 'retry-checkpoint', 'capture-tool-check', 'recovery-ready', 'stopped', 'restore-bot', 'restore-services', 'restore-accepted', 'rollback-check']},
        'accepted': {'type': 'dict', 'default': {}, 'no_log': True},
        'retry': {'type': 'dict', 'default': {}, 'no_log': True},
        'initial_runtime_request_json': {'type': 'str', 'default': '', 'no_log': True},
        'recovery_tool_hashes': {'type': 'list', 'elements': 'str', 'default': []},
    }, supports_check_mode=True)
    try:
        operation, sha = module.params['id'], module.params['legacy_sha256']
        if os.geteuid() != 0 or not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', operation) or not re.fullmatch(r'[a-f0-9]{64}', sha):
            raise ValueError('maintenance_identity_invalid')
        gate = private(Path('/var/lib/ultra-ansible/lifecycle.json'))
        phases = ('applying', 'checking') if module.params['phase'] in ('restore-services', 'restore-accepted', 'rollback-check') else ('applying',)
        if gate.get('id') != operation or gate.get('phase') not in phases:
            raise ValueError('maintenance_reservation_not_owned')
        path = Path('/var/lib/ultra-ansible/upgrade') / operation / 'maintenance.json'
        if module.params['phase'] in ('retry-checkpoint', 'rollback-check') and not path.exists() and not path.is_symlink():
            # No producer was stopped before a checkpoint existed. Retain the
            # ordinary fresh preflight only for the exact running legacy bridge.
            runtime = service(module, 'ultra-relay.service')
            pid = runtime['MainPID']
            binary = Path('/usr/local/bin/ultra-relay')
            metadata = binary.lstat()
            executable = Path('/proc') / pid / 'exe'
            if (gate.get('phase') != 'applying' or not binary.is_file()
                    or metadata.st_uid != 0 or metadata.st_mode & 0o022
                    or hashlib.sha256(binary.read_bytes()).hexdigest() != sha
                    or runtime['ActiveState'] != 'active' or pid == '0' or runtime['ControlPID'] != '0'
                    or binary.is_symlink() or os.readlink(executable) != str(binary)
                    or hashlib.sha256(executable.read_bytes()).hexdigest() != sha
                    or any(service(module, unit)['ActiveState'] != 'active' or service(module, unit)['ControlPID'] != '0' for unit in SERVICES[1:])
                    or json.loads(Path('/etc/ultra-relay/spec.json').read_text()).get('role') != 'bridge'):
                raise ValueError('maintenance_initial_retry_unverified')
            initial_request = module.params.get('initial_runtime_request_json') or module.params.get('retry', {}).get('runtime_request_json')
            if initial_request:
                bot_before = untouched_runtime(initial_request, operation)
                bot = service(module, 'ultra-bot.service')
                if bot['ActiveState'] != bot_before or bot['ControlPID'] != '0':
                    raise ValueError('maintenance_initial_bot_state_changed')
            elif module.params['phase'] == 'rollback-check':
                raise ValueError('maintenance_initial_transaction_missing')
            hashes()  # Reject unsafe configuration files even without a checkpoint.
            module.exit_json(changed=False, verified=True, held=False, untouched=True)
        if module.params['phase'] == 'capture-tool-check' and not path.exists():
            raise ValueError('maintenance_checkpoint_missing')
        if module.params['phase'] == 'checkpoint' and not path.exists():
            binary = Path('/usr/local/bin/ultra-relay')
            if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != sha:
                raise ValueError('maintenance_legacy_identity_changed')
            runtime = service(module, 'ultra-relay.service')
            pid = runtime['MainPID']
            executable = Path('/proc') / pid / 'exe'
            if (runtime['ActiveState'] != 'active' or pid == '0' or runtime['ControlPID'] != '0'
                    or os.readlink(executable) != str(binary) or hashlib.sha256(executable.read_bytes()).hexdigest() != sha
                    or json.loads(Path('/etc/ultra-relay/spec.json').read_text()).get('role') != 'bridge'):
                raise ValueError('maintenance_running_identity_unverified')
            code, _, _ = module.run_command(['runuser', '-u', 'ultra-relay', '--', 'test', '-r', '/etc/ultra-relay/spec.json'])
            if code:
                raise ValueError('maintenance_spec_unreadable')
            states = {unit: service(module, unit)['ActiveState'] for unit in SERVICES}
            checkpoint = {'id': operation, 'legacy_sha256': sha, 'services': states, 'configuration': hashes(), 'created_at': int(time.time())}
            if not module.check_mode:
                atomic(path, checkpoint)
        else:
            checkpoint = private(path)
        retry = module.params.get('retry', {})
        retry_phase = module.params['phase'] in ('retry-checkpoint', 'capture-tool-check', 'recovery-ready') and bool(retry)
        if retry_phase and retry.get('mode') not in ('compensation', 'committed'):
            raise ValueError('maintenance_retry_mode_invalid')
        if (checkpoint.get('id') != operation or checkpoint.get('legacy_sha256') != sha
                or (module.params['phase'] not in ('restore-accepted', 'rollback-check') and not retry_phase and checkpoint.get('configuration') != hashes()) or set(checkpoint.get('services', {})) != set(SERVICES)
                or any(value not in ('active', 'inactive') for value in checkpoint['services'].values())):
            raise ValueError('maintenance_checkpoint_changed')
        if module.params['phase'] == 'rollback-check':
            module.exit_json(changed=False, verified=True, held=True, untouched=False)
        if retry_phase:
            accepted_configuration(checkpoint, retry, operation, compensation=retry['mode'] == 'compensation')
            if module.params['phase'] == 'retry-checkpoint':
                retry_relay_identity(module, checkpoint, retry, sha)
            if retry['mode'] == 'committed':
                module.exit_json(changed=False, verified=True, held=False, continuation=True)
            if module.params['phase'] == 'retry-checkpoint':
                if not module.check_mode:
                    for unit in SERVICES + ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service', 'ultra-relay.service'):
                        code, _, _ = module.run_command(['systemctl', 'stop', unit])
                        if code:
                            raise ValueError('maintenance_retry_stop_failed')
        desired_services = dict(checkpoint['services'])
        if module.params['phase'] == 'restore-accepted':
            enabled = accepted_configuration(checkpoint, module.params['accepted'], operation)
            desired_services['ultra-bot.service'] = 'active' if enabled else 'inactive'
        if module.params['phase'] == 'capture-tool-check':
            checked_recovery_tool(module.params['recovery_tool_hashes'])
            module.exit_json(changed=False, verified=True)
        if module.params['phase'] == 'retry-checkpoint' and not retry_phase:
            states = {unit: service(module, unit)['ActiveState'] for unit in SERVICES}
            relay = service(module, 'ultra-relay.service')
            if states == checkpoint['services'] and relay['ActiveState'] == 'active':
                pid = relay['MainPID']
                binary = Path('/usr/local/bin/ultra-relay')
                executable = Path('/proc') / pid / 'exe'
                if (pid == '0' or relay['ControlPID'] != '0' or binary.is_symlink()
                        or os.readlink(executable) != str(binary) or hashlib.sha256(executable.read_bytes()).hexdigest() != sha):
                    raise ValueError('maintenance_restored_identity_unverified')
                module.exit_json(changed=False, verified=True, held=False)
        if module.params['phase'] in ('capture-checkpoint', 'retry-checkpoint', 'recovery-ready'):
            units = SERVICES + ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service')
            if module.params['phase'] == 'retry-checkpoint':
                units += ('ultra-relay.service',)
            idle(module, units)
            current_provenance = recovery_provenance()
            if module.params['phase'] == 'capture-checkpoint':
                if checkpoint.get('recovery_provenance') is None:
                    checkpoint['recovery_provenance'] = current_provenance
                elif checkpoint['recovery_provenance'] != current_provenance:
                    raise ValueError('maintenance_recovery_provenance_changed')
            elif checkpoint.get('recovery_provenance') != current_provenance:
                raise ValueError('maintenance_recovery_provenance_changed')
            if module.params['phase'] != 'recovery-ready':
                checkpoint['capture_after'] = int(time.time())
                checkpoint['previous_delivery'] = private(Path('/var/lib/ultra-recovery/last-success.json'), evidence=True)
                if not module.check_mode:
                    atomic(path, checkpoint)
                    # Capture timestamps have second precision. Cross the durable
                    # watermark before allowing the synchronous capture to start.
                    time.sleep(max(0, checkpoint['capture_after'] + 1 - time.time()))
        if module.params['phase'] == 'recovery-ready':
            # Capture is synchronous and verifies receiver delivery before writing
            # last-success. Bind that new generation to the independent primary.
            config = private(Path('/etc/ultra-recovery/reconcile.json'), evidence=True)
            backup_config = private(Path('/etc/ultra-recovery/backup.json'), evidence=True)
            topology = private(Path('/var/lib/ultra-recovery-reconcile/state.json'), evidence=True)
            status = private(Path('/var/lib/ultra-relay/recovery-reconcile-status.json'), evidence=True)
            backup = private(Path('/var/lib/ultra-recovery/last-success.json'), evidence=True)
            primary = topology['primary']
            selected = [node for node in topology['node_metadata'] if node['id'] == primary]
            targets = [target for target in backup_config['destinations'] if target.get('id') == primary and target.get('required') is True]
            now = time.time()
            if (len(selected) != 1 or len(targets) != 1 or selected[0]['provider'].lower() == config['bridge_provider'].lower()
                    or targets[0]['host'] != selected[0]['host'] or selected[0]['host'] not in backup['destinations']
                    or primary not in backup['delivered_target_ids'] or backup_config.get('independent') is not True
                    or backup.get('source') != 'bridge' or status.get('state') != 'ready' or status.get('independent') is not True
                    or status.get('primary') != primary or not 0 <= now - backup['snapshot_at'] <= 300
                    or backup['snapshot_at'] <= checkpoint.get('capture_after', now + 1)
                    or backup == checkpoint.get('previous_delivery') or not re.fullmatch(r'[a-f0-9]{64}', backup.get('backup_sha256', ''))
                    or not re.fullmatch(r'[a-f0-9]{64}', backup.get('artifact_sha256', ''))):
                raise ValueError('maintenance_independent_generation_unavailable')
            for unit in ('ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'):
                values = service(module, unit)
                if values['ActiveState'] != 'inactive' or values['MainPID'] != '0' or values['ControlPID'] != '0':
                    raise ValueError('maintenance_recovery_not_idle')
        if module.params['phase'] == 'stopped':
            for unit in SERVICES + ('ultra-relay.service',):
                values = service(module, unit)
                if values['ActiveState'] != 'inactive' or values['MainPID'] != '0' or values['ControlPID'] != '0':
                    raise ValueError('maintenance_worker_not_stopped')
        if module.params['phase'] in ('restore-bot', 'restore-services', 'restore-accepted') and not module.check_mode:
            units = SERVICES if module.params['phase'] in ('restore-services', 'restore-accepted', 'rollback-check') else ('ultra-bot.service',)
            for unit in units:
                action = 'start' if desired_services[unit] == 'active' else 'stop'
                code, _, _ = module.run_command(['systemctl', action, unit])
                if code or service(module, unit)['ActiveState'] != desired_services[unit]:
                    raise ValueError('maintenance_services_restore_failed')
        module.exit_json(changed=False, verified=True, held=True, bot_active=checkpoint['services']['ultra-bot.service'] == 'active')
    except (OSError, ValueError, KeyError, TypeError):
        message = 'legacy_maintenance_retry_recovery_required' if module.params.get('retry') else 'legacy_maintenance_barrier_failed'
        module.fail_json(msg=message)


if __name__ == '__main__':
    main()
