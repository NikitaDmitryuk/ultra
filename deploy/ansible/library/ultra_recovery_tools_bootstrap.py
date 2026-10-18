#!/usr/bin/python
"""Narrow, root-only recovery tool repair. Never writes readiness evidence."""
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/var/lib/ultra-ansible')
ACTIVE = Path('/opt/ultra-recovery')
MARKER = ROOT / 'recovery-tools-bootstrap.incomplete'
JOURNAL = ROOT / 'recovery-tools-bootstrap.json'
DROPIN = '90-ultra-recovery-tools-bootstrap.conf'
SYSTEMD = Path('/etc/systemd/system')
TOOLS = ('recovery.py', 'restore_host.py', 'restore_database.py')
SHA = re.compile(r'[a-f0-9]{64}')
VERSION = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?')


def private_bytes(path, maximum=4 * 1024 * 1024, executable=False, *, _owners=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        owners = {os.geteuid()} if _owners is None else _owners
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_size > maximum
                or info.st_mode & (0o022 if executable else 0o077)):
            raise ValueError('bootstrap_private_file_required')
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('bootstrap_file_too_large')
        return data


def ssh_bytes(path, identity=False):
    # Only the protected reconcile configuration selects these paths. Runtime
    # fleet keys and per-operation pins are legitimately owned by ultra-relay.
    account = pwd.getpwnam('ultra-relay')
    if account.pw_name != 'ultra-relay' or account.pw_uid <= 0:
        raise ValueError('bootstrap_relay_owner_invalid')
    return private_bytes(path, 65536, executable=not identity, _owners={0, account.pw_uid})


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def directory(path):
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('bootstrap_symlink_rejected')
    if path.exists():
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('bootstrap_directory_unsafe')
        return
    directory(path.parent)
    path.mkdir(mode=0o700)
    sync_directory(path.parent)


def durable(path, data, mode=0o600):
    path = Path(path)
    directory(path.parent)
    if path.is_symlink():
        raise ValueError('bootstrap_symlink_rejected')
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temporary = Path(name)
    os.fchmod(fd, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def save(value):
    durable(JOURNAL, (json.dumps(value, sort_keys=True) + '\n').encode())


def systemctl(*args):
    result = subprocess.run(['systemctl', *args], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20, check=True)
    return result.stdout.decode()


def units(bridge):
    bases = ['ultra-recovery-prune', 'ultra-monitor']
    if bridge:
        bases += ['ultra-recovery-backup', 'ultra-recovery-reconcile']
    return [base + suffix for base in bases for suffix in ('.timer', '.service')]


def unit_state(unit):
    properties = ['--property=LoadState', '--property=ActiveState']
    if unit.endswith('.service'):
        properties += ['--property=MainPID', '--property=ControlPID']
    output = systemctl('show', unit, *properties)
    result = dict(line.split('=', 1) for line in output.splitlines())
    if unit.endswith('.timer'):
        result.update(MainPID='0', ControlPID='0')
    if (set(result) != {'LoadState', 'ActiveState', 'MainPID', 'ControlPID'}
            or result['LoadState'] not in ('loaded', 'not-found')
            or result['ActiveState'] not in ('active', 'inactive', 'failed', 'activating', 'deactivating')
            or any(not result[key].isdigit() for key in ('MainPID', 'ControlPID'))):
        raise ValueError('bootstrap_unit_state_invalid')
    return result


def consumers_idle(proc=Path('/proc')):
    # Trusted operators exclude manual root restore/import launches for the
    # entire operation. The census detects already running standalone readers.
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            command = (entry / 'cmdline').read_bytes().split(b'\0')
        except FileNotFoundError:
            continue
        except PermissionError:
            raise ValueError('bootstrap_consumer_census_unavailable') from None
        names = {os.path.basename(os.fsdecode(arg)) for arg in command}
        if names.intersection((*TOOLS, 'reconcile.py', 'monitor.py', 'heartbeat.py', 'pg_restore')):
            raise ValueError('bootstrap_consumer_busy')


def inventory():
    manifest_bytes = private_bytes(ACTIVE / 'release-manifest.json')
    manifest = json.loads(manifest_bytes)
    version = manifest['version']
    if not VERSION.fullmatch(version):
        raise ValueError('bootstrap_installed_version_invalid')
    generation = ACTIVE / 'releases' / version
    info = generation.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('bootstrap_old_generation_unsafe')
    # Installed recovery tools are executables (0755); reject writes by group/world.
    old = {name: digest(private_bytes(generation / name, executable=True)) for name in TOOLS}
    sys.path.insert(0, str(ACTIVE))
    import reconcile
    config = json.loads(private_bytes('/etc/ultra-recovery/reconcile.json'))
    if Path(config['bundle_dir']) != ACTIVE:
        raise ValueError('bootstrap_reconcile_source_unsupported')
    nodes, _ = reconcile.desired_nodes(config, reconcile.discover(config))
    topology = [{'id': n['id'], 'address': n['address'], 'known_hosts': n['known_hosts']} for n in nodes]
    for node in nodes:
        node['pins'] = ssh_bytes(node['known_hosts']).decode()
    identity = ssh_bytes(config['ssh_identity_file'], identity=True).decode()
    return {'nodes': nodes, 'identity': identity, 'observed_at': int(time.time()),
            'topology_sha256': digest(json.dumps(topology, sort_keys=True, separators=(',', ':')).encode()),
            'previous_manifest_sha256': digest(manifest_bytes), 'previous_manifest': manifest,
            'tool_hashes': old, 'generation': str(generation)}


def validate_tools(tools, bridge):
    expected = set(TOOLS if bridge else ('recovery.py',))
    if len(tools) != len(expected) or {Path(t['destination']).name for t in tools} != expected:
        raise ValueError('bootstrap_incoherent_tools')
    for tool in tools:
        if (tool['destination'] != str(ACTIVE / Path(tool['destination']).name)
                or tool['backup_name'] != digest(tool['destination'].encode())
                or not SHA.fullmatch(tool['sha256']) or not SHA.fullmatch(tool['previous_sha256'])):
            raise ValueError('bootstrap_tool_contract_invalid')


def transition(phase, spec):
    bridge = spec['bridge']
    tools = spec['tools']
    validate_tools(tools, bridge)
    for key in ('baseline', 'topology', 'candidate'):
        if not SHA.fullmatch(spec[key]):
            raise ValueError('bootstrap_digest_invalid')
    if not VERSION.fullmatch(spec['version']):
        raise ValueError('bootstrap_version_invalid')
    baseline = {t['destination']: t['previous_sha256'] for t in tools}
    target = {t['destination']: t['sha256'] for t in tools}
    exists = JOURNAL.exists()
    journal = json.loads(private_bytes(JOURNAL)) if exists else None
    identity = {'baseline': spec['baseline'], 'topology': spec['topology'], 'bridge': bridge, 'old': baseline}
    if journal is not None and journal['identity'] != identity:
        raise ValueError('bootstrap_checkpoint_identity_changed')
    if bridge:
        actual = inventory()
        if actual['previous_manifest']['version'] == spec['version']:
            raise ValueError('bootstrap_installed_generation_is_immutable')
        if actual['previous_manifest_sha256'] != spec['baseline'] or actual['topology_sha256'] != spec['topology']:
            raise ValueError('bootstrap_baseline_or_topology_changed')
        if any(actual['tool_hashes'][Path(path).name] != old for path, old in baseline.items()):
            raise ValueError('bootstrap_old_generation_changed')
    if phase == 'fence':
        if journal is None:
            if MARKER.exists():
                raise ValueError('bootstrap_orphan_fence')
            states = {unit: unit_state(unit) for unit in units(bridge)}
            journal = {'identity': identity, 'units': states, 'history': [], 'stage': 'checkpoint'}
            # Checkpoint precedes every service change and marker publication.
            save(journal)
        elif journal['stage'] == 'complete':
            if MARKER.exists():
                raise ValueError('bootstrap_orphan_fence')
            journal['units'] = {unit: unit_state(unit) for unit in units(bridge)}
            journal['stage'] = 'checkpoint'
            save(journal)
        durable(MARKER, (spec['baseline'] + '\n').encode())
        for unit in journal['units']:
            drop = SYSTEMD / (unit + '.d') / DROPIN
            content = ('[Unit]\nConditionPathExists=!' + str(MARKER) + '\n').encode()
            if drop.exists() and private_bytes(drop) != content:
                raise ValueError('bootstrap_dropin_conflict')
            durable(drop, content)
        systemctl('daemon-reload')
        for unit, state in journal['units'].items():
            if unit.endswith('.timer') and state['LoadState'] == 'loaded':
                systemctl('stop', unit)
        deadline = time.monotonic() + 600
        while True:
            states = [unit_state(unit) for unit in journal['units']]
            if all(s['ActiveState'] in ('inactive', 'failed') and s['MainPID'] == s['ControlPID'] == '0' for s in states):
                break
            if time.monotonic() >= deadline:
                raise ValueError('bootstrap_consumer_busy')
            time.sleep(2)
        consumers_idle()
        # Only bytes previously authenticated by this durable journal may be
        # rebound to a later candidate after an unrelated normal-upgrade error.
        allowed = [baseline] + [item['tools'] for item in journal['history']]
        for tool in tools:
            active = digest(private_bytes(tool['destination'], executable=True))
            if not any(previous.get(tool['destination']) == active for previous in allowed):
                raise ValueError('bootstrap_active_tool_drift')
        if not any(item['candidate'] == spec['candidate'] and item['tools'] == target for item in journal['history']):
            journal['history'].append({'candidate': spec['candidate'], 'version': spec['version'], 'tools': target})
        journal['stage'] = 'fenced'
        save(journal)
    else:
        if journal is None or not journal['history'] or journal['history'][-1] != {'candidate': spec['candidate'], 'version': spec['version'], 'tools': target}:
            raise ValueError('bootstrap_checkpoint_required')
        if phase not in ('resume', 'proof') and not MARKER.exists():
            raise ValueError('bootstrap_fence_required')
        if MARKER.exists() and private_bytes(MARKER) != (spec['baseline'] + '\n').encode():
            raise ValueError('bootstrap_fence_identity_changed')
        if phase in ('seed', 'normalize'):
            consumers_idle()
            allowed = [baseline] + [item['tools'] for item in journal['history']]
            originals, actives = {}, {}
            # Validate the entire selected set before the first fallback or
            # active-file write. Unknown drift never authorizes partial work.
            for tool in tools:
                old = private_bytes(tool['baseline_source'])
                if digest(old) != tool['previous_sha256']:
                    raise ValueError('bootstrap_baseline_source_changed')
                originals[tool['destination']] = old
                fallback = ROOT / 'releases' / spec['version'] / 'tools-previous' / tool['backup_name']
                if fallback.exists():
                    if digest(private_bytes(fallback, executable=True)) != tool['previous_sha256']:
                        raise ValueError('bootstrap_fallback_changed')
                if phase == 'normalize':
                    active = digest(private_bytes(tool['destination'], executable=True))
                    if not any(previous.get(tool['destination']) == active for previous in allowed):
                        raise ValueError('bootstrap_active_tool_drift')
                    actives[tool['destination']] = active
            for tool in tools:
                fallback = ROOT / 'releases' / spec['version'] / 'tools-previous' / tool['backup_name']
                if not fallback.exists():
                    durable(fallback, originals[tool['destination']], 0o755)
            if phase == 'normalize':
                for tool in tools:
                    active = actives[tool['destination']]
                    if active not in (tool['previous_sha256'], tool['sha256']):
                        # Preserve tools.yml's strict original-or-target guard.
                        # A prior candidate is returned to authenticated O only
                        # while all consumers remain durably fenced. Its exact
                        # O fallback is already synced and never overwritten.
                        durable(tool['destination'], originals[tool['destination']], 0o755)
            journal['stage'] = 'normalized' if phase == 'normalize' else 'seeded'
            save(journal)
        elif phase in ('verify', 'resume', 'proof'):
            for tool in tools:
                if digest(private_bytes(tool['destination'], executable=True)) != tool['sha256']:
                    raise ValueError('bootstrap_target_incomplete')
                fallback = ROOT / 'releases' / spec['version'] / 'tools-previous' / tool['backup_name']
                if digest(private_bytes(fallback, executable=True)) != tool['previous_sha256']:
                    raise ValueError('bootstrap_fallback_changed')
            if phase == 'proof':
                if journal['stage'] != 'complete' or MARKER.exists():
                    raise ValueError('bootstrap_completion_required')
                for unit, state in journal['units'].items():
                    if unit.endswith('.timer') and state['LoadState'] == 'loaded':
                        expected = 'active' if state['ActiveState'] == 'active' else 'inactive'
                        if unit_state(unit)['ActiveState'] != expected:
                            raise ValueError('bootstrap_schedule_restore_incomplete')
            elif phase == 'verify':
                consumers_idle()
                journal['stage'] = 'verified'
                save(journal)
            else:
                if journal['stage'] not in ('verified', 'resuming', 'complete'):
                    raise ValueError('bootstrap_verification_required')
                journal['stage'] = 'resuming'
                save(journal)
                MARKER.unlink(missing_ok=True)
                sync_directory(MARKER.parent)
                for unit, state in journal['units'].items():
                    if unit.endswith('.timer') and state['LoadState'] == 'loaded':
                        systemctl('start' if state['ActiveState'] == 'active' else 'stop', unit)
                journal['stage'] = 'complete'
                save(journal)
        else:
            raise ValueError('bootstrap_phase_invalid')
    return {'verified': True, 'stage': journal['stage']}


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={'phase': {'type': 'str', 'required': True,
                           'choices': ['inventory', 'fence', 'seed', 'normalize', 'verify', 'resume', 'proof']},
                           'spec': {'type': 'dict', 'default': {}}}, supports_check_mode=False)
    if os.geteuid() != 0:
        module.fail_json(msg='bootstrap_root_bridge_required')
    try:
        if module.params['phase'] == 'inventory':
            module.exit_json(changed=False, inventory=inventory())
        result = transition(module.params['phase'], module.params['spec'])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
        reason = str(failure)
        module.fail_json(msg=reason if isinstance(failure, ValueError) and re.fullmatch(r'bootstrap_[a-z_]+', reason)
                         else 'recovery_tools_bootstrap_failed')
    module.exit_json(changed=True, **result)


if __name__ == '__main__':
    main()
