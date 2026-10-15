#!/usr/bin/env python3
"""Explicit operator deployment from clean, committed HEAD; never a scheduler."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from urllib.parse import urlsplit


class DeployError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise DeployError(code)


def require_manual_quiescence(record):
    """Legacy dispatch has no authoritative worker-drain receipt.

    A flock, terminal CLI status, signed release baseline, or operator-supplied
    JSON field cannot prove that an old SSH module stopped mutating. There is
    deliberately no bypass until a migration command can fence every dispatch
    origin and obtain host-bound drain evidence from the frozen target set.
    """
    require(isinstance(record, dict), 'manual_operation_journal_invalid')
    require(record.get('mutator_dispatched', False) is False and
            record.get('stage') not in ('adoption_apply', 'upgrade', 'status', 'completed'),
            'manual_operation_quiescence_migration_required')


def run(command, cwd, stage, capture=False, env=None):
    # Installer and build tools may include private input values in their errors.
    # Expose only this wrapper's fixed stage and exit code, never their output.
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, env=env)
    require(result.returncode == 0, stage + '_failed_exit_' + str(result.returncode))
    return result.stdout.decode().strip() if capture else None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600, 'canonical_config_requires_owned_regular_0600')
    return path.read_bytes()


def private_input(path, modes=(0o600,)):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'upgrade_baseline_path_invalid')
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'upgrade_baseline_symlink_forbidden')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) in modes and info.st_size <= 4 * 1024 * 1024,
            'upgrade_baseline_input_not_private')
    return path.read_bytes()


def canonical_file(path):
    """Read the non-secret canonical deployment config in either supported mode."""
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) in (0o600, 0o644), 'canonical_config_requires_owned_regular_readable_file')
    return path.read_bytes()


def subscription_probe_input(path, limit=4096):
    """Read only the operator's explicit private credential file."""
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'subscription_probe_private_file_required')
    for parent in path.parents:
        require(not parent.is_symlink(), 'subscription_probe_private_file_required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                0 < info.st_size <= limit, 'subscription_probe_private_file_required')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(0 < len(raw) <= limit, 'subscription_probe_private_file_required')
        return raw
    finally:
        os.close(descriptor)


def subscription_probe_from_env(path, optional=False):
    """Parse only one allowlisted literal; never source or expand the env file."""
    try:
        raw = subscription_probe_input(path, 1024 * 1024)
    except FileNotFoundError:
        if optional:
            return None
        raise DeployError('subscription_probe_env_file_missing') from None
    selected = []
    for line in raw.splitlines():
        key, separator, value = line.partition(b'=')
        if key.strip() == b'ULTRA_SUBSCRIPTION_PROBE_URL':
            require(bool(separator), 'subscription_probe_env_invalid')
            selected.append(value)
        elif line.strip().startswith(b'export ULTRA_SUBSCRIPTION_PROBE_URL') or line.strip() == b'ULTRA_SUBSCRIPTION_PROBE_URL':
            raise DeployError('subscription_probe_env_invalid')
    require(len(selected) <= 1, 'subscription_probe_env_invalid')
    require(optional or selected, 'subscription_probe_env_key_missing')
    if not selected:
        return None
    try:
        words = shlex.split(selected[0].decode('utf-8'), comments=False)
        require(words and (len(words) == 1 or words[1].startswith('#')), 'subscription_probe_env_invalid')
        value = words[0]
        parsed = urlsplit(value)
        require(len(value.encode()) <= 4096 and parsed.scheme == 'https' and parsed.hostname and
                parsed.netloc == parsed.hostname and not parsed.query and not parsed.fragment and
                re.fullmatch(r'/sub/[A-Za-z0-9_-]{1,1024}', parsed.path) and
                not re.search(r'[\s\x00]', value), 'subscription_probe_env_invalid')
    except (ValueError, UnicodeError):
        raise DeployError('subscription_probe_env_invalid') from None
    return value.encode()


def atomic_write(path, raw, preserve_mode=False):
    mode = 0o600
    if preserve_mode:
        try:
            info = path.lstat()
        except FileNotFoundError:
            pass
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                    stat.S_IMODE(info.st_mode) in (0o600, 0o644), 'canonical_config_mode_invalid')
            mode = stat.S_IMODE(info.st_mode)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600, 'manual_lock_not_private')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeployError('manual_deploy_already_running') from None
        yield
    finally:
        os.close(descriptor)


def canonical_config_lock(path):
    resolved = Path(path).resolve(strict=True)
    return resolved.with_name('.' + resolved.name + '.manual-deploy.lock')


def config_candidate(raw, version, release, baseline=None):
    replacements = {'ULTRA_AUTOMATION_VERSION': version, 'ULTRA_AUTOMATION_RELEASE_DIR': str(release)}
    if baseline is not None:
        replacements['ULTRA_UPGRADE_BASELINE_FILE'] = str(baseline)
    seen = set()
    lines = []
    for line in raw.decode().splitlines(keepends=True):
        match = re.match(r'^\s*(ULTRA_AUTOMATION_(?:VERSION|RELEASE_DIR)|ULTRA_UPGRADE_BASELINE_FILE)\s*=', line)
        if match:
            key = match[1]
            if key not in replacements:
                lines.append(line)
                continue
            require(key not in seen, 'duplicate_canonical_release_key')
            seen.add(key)
            line = key + '=' + json.dumps(replacements[key], ensure_ascii=True) + '\n'
        lines.append(line)
    text = ''.join(lines)
    if text and not text.endswith('\n'):
        text += '\n'
    for key in replacements:
        if key == 'ULTRA_UPGRADE_BASELINE_FILE' and baseline is None:
            continue
        if key in seen:
            continue
        text += key + '=' + json.dumps(replacements[key], ensure_ascii=True) + '\n'
    return text.encode()


def remove_config_key(raw, key):
    require(key in ('ULTRA_UPGRADE_BASELINE_FILE',), 'canonical_config_key_invalid')
    lines = []
    found = False
    for line in raw.decode().splitlines(keepends=True):
        match = re.match(r'^\s*' + re.escape(key) + r'\s*=', line)
        if match:
            require(not found, 'duplicate_canonical_release_key')
            found = True
            continue
        lines.append(line)
    return ''.join(lines).encode()


def remote_attempt(config, version):
    # Normalize derived release fields to avoid hashing a path that contains
    # this very hash. Corrections to any other canonical input get a new kit.
    value = config_values(config).get('ULTRA_UPGRADE_BASELINE_FILE')
    normalized_baseline = '/operator-baseline' if value else None
    return sha(config_candidate(config, version, '/manual-release', normalized_baseline))


def stage_upgrade_baseline(config, version, remote_root):
    """Prepare the optional, one-time baseline proof for remote staging.

    The old signed release is already retained on the bridge under the path
    pinned by the prior operation journal. Only the private journal is copied;
    the verifier on the bridge rechecks that entire retained release bundle.
    """
    values = config_values(config)
    source = values.get('ULTRA_UPGRADE_BASELINE_FILE', '')
    if not source:
        return config_candidate(config, version, remote_root / 'release'), {}
    descriptor_path = Path(source)
    raw = private_input(descriptor_path)
    try:
        descriptor = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise DeployError('upgrade_baseline_descriptor_invalid') from None
    require(isinstance(descriptor, dict) and descriptor.get('schema') == 1, 'upgrade_baseline_descriptor_invalid')
    journal_path = Path(descriptor.get('journal', ''))
    journal_raw = private_input(journal_path)
    try:
        journal = json.loads(journal_raw)
        manifest_path = Path(descriptor['manifest'])
    except (ValueError, KeyError, TypeError):
        raise DeployError('upgrade_baseline_descriptor_invalid') from None
    manifest_raw = private_input(manifest_path, (0o400, 0o600))
    require(sha(journal_raw) == descriptor.get('journal_sha256') and
            sha(manifest_raw) == descriptor.get('manifest_sha256'), 'upgrade_baseline_local_pin_changed')
    require(journal.get('schema') == 1 and journal.get('mutator_dispatched') is True and
            re.fullmatch('[a-f0-9]{40}', journal.get('commit', '')) and
            re.fullmatch('[a-f0-9]{16,64}', journal.get('remote_attempt', '')) and
            journal.get('manifest_sha256') == descriptor.get('manifest_sha256'),
            'upgrade_baseline_journal_invalid')
    require_manual_quiescence(journal)
    try:
        manifest = json.loads(manifest_raw)
    except (ValueError, UnicodeDecodeError):
        raise DeployError('upgrade_baseline_manifest_invalid') from None
    require(manifest.get('source_commit') == journal['commit'] and manifest.get('version') == journal.get('version') and
            isinstance(manifest.get('assets'), list) and len(manifest['assets']) == 14,
            'upgrade_baseline_manifest_unbound')
    old_release = Path('/var/lib/ultra-ansible/operator-inputs') / (
        'manual-' + journal['commit'] + '-' + journal['remote_attempt']) / 'release'
    staged_journal = remote_root / 'baseline' / 'operator-journal.json'
    staged_descriptor = remote_root / 'baseline' / 'descriptor.json'
    descriptor['journal'] = str(staged_journal)
    descriptor['manifest'] = str(old_release / 'release-manifest.json')
    staged_raw = (json.dumps(descriptor, sort_keys=True, separators=(',', ':')) + '\n').encode()
    remote_config = config_candidate(config, version, remote_root / 'release', staged_descriptor)
    return remote_config, {'baseline/descriptor.json': staged_raw,
                           'baseline/operator-journal.json': journal_raw}


def completed_baseline_replay(root, config, version, commit):
    """Recover the exact staged bytes for a completed same-commit retry.

    The one-time baseline setting is removed from the canonical config after
    success, but the remote immutable root still pins the staged config that
    contained it. Rebuild that config from the private pre-deploy backup and
    reuse it only when removing the one-time setting reproduces today's
    candidate byte-for-byte.
    """
    values = config_values(config)
    if values.get('ULTRA_UPGRADE_BASELINE_FILE'):
        return None
    match = re.fullmatch(r'v0\.0\.(0|[1-9][0-9]*)', version)
    if not match or values.get('ULTRA_AUTOMATION_VERSION') != version:
        return None
    try:
        target_commit = f'{int(match[1]):040x}'
    except ValueError:
        return None
    release = values.get('ULTRA_AUTOMATION_RELEASE_DIR', '')
    release_match = re.fullmatch(r'/var/lib/ultra-ansible/operator-inputs/manual-([a-f0-9]{40})-([a-f0-9]{64})/release', release)
    if not release_match or release_match[1] != target_commit or release_match[1] != commit:
        return None
    attempt = release_match[2]
    remote_root = Path(release).parent
    expected = config_candidate(config, version, remote_root / 'release')
    backup_pattern = 'install.config.before-' + version + '-*'
    for backup in sorted(root.glob(backup_pattern)):
        if not re.fullmatch(r'install\.config\.before-' + re.escape(version) + r'-[0-9]+', backup.name):
            continue
        original = private_file(backup)
        if not config_values(original).get('ULTRA_UPGRADE_BASELINE_FILE'):
            continue
        if remote_attempt(original, version) != attempt:
            continue
        staged, files = stage_upgrade_baseline(original, version, remote_root)
        if remove_config_key(staged, 'ULTRA_UPGRADE_BASELINE_FILE') == expected:
            return attempt, staged, files
    return None


def validate_config_policy(raw):
    # Match installplan.DisallowedDeploymentSecret before creating any backup,
    # temporary input, or remote copy. The exact built Go parser runs below too.
    forbidden = {'TELEGRAM_BOT_TOKEN', 'ULTRA_VULTR_API_KEY', 'ULTRA_VULTR_DNS_API_KEY',
                 'ULTRA_CUTOVER_SUBSCRIPTION_URL', 'ULTRA_SUBSCRIPTION_PROBE_URL', 'ULTRA_RELAY_ADMIN_TOKEN', 'ULTRA_DB_DSN'}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key = line.split('=', 1)[0].strip().upper()
        signing = any(word in key for word in ['MINISIGN', 'SIGNING'])
        private = any(word in key for word in ['SECRET', 'PRIVATE', 'PASSWORD', 'PASSPHRASE'])
        require(key not in forbidden and not (signing and private), 'canonical_config_contains_forbidden_secret')
        require(not key.startswith('ULTRA_AUTO_UPGRADE_'), 'canonical_config_contains_removed_policy')


def verify_bundle(source, bundle, commit, version):
    require(not bundle.is_symlink() and bundle.is_dir(), 'candidate_not_regular_directory')
    manifest_path = bundle / 'release-manifest.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'candidate_manifest_not_regular')
    manifest = json.loads(manifest_path.read_bytes())
    require(manifest.get('source_commit') == commit and manifest.get('version') == version,
            'candidate_identity_mismatch')
    rows = manifest.get('assets', [])
    require(len(rows) == 14 and len({row['name'] for row in rows}) == 14,
            'candidate_requires_14_assets')
    require({path.name for path in bundle.iterdir()} <= {row['name'] for row in rows} |
            {'release-manifest.json', 'candidate.json'}, 'candidate_unexpected_inventory')
    for row in rows:
        name = row['name']
        require(isinstance(name, str) and Path(name).name == name, 'candidate_asset_name_invalid')
        path = bundle / name
        require(not path.is_symlink() and path.is_file(), 'candidate_asset_not_regular')
    # Reuse the release contract from the exact source commit: ELF architectures,
    # full source archives, all 14 manifest hashes, checksum inventory, and locked
    # offline wheels for both architectures and Python 3.12/3.13/3.14.
    spec = importlib.util.spec_from_file_location('release_contract', source / 'scripts/test-release-assets.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate_bundle(bundle, (source / '.github/workflows/release.yml').read_text())


def prepare_runtime_environment(repo, source):
    environment = os.environ.copy()
    # Never inherit an unchecked runtime override into a candidate build.
    environment.pop('ULTRA_VERIFIED_RUNTIME_DIR', None)
    cached = repo / 'dist'
    if (cached / 'release-manifest.json').is_file():
        spec = importlib.util.spec_from_file_location('manual_runtime', source / 'scripts/manual-deploy-runtime.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_pair(cached, source / 'deploy/ansible/requirements.txt')
        frozen = source / '.manual-runtime-inputs'
        frozen.mkdir(mode=0o700)
        for name in ['release-manifest.json', 'checksums.txt', 'ultra-ansible-runtime-linux-amd64.tar.gz', 'ultra-ansible-runtime-linux-arm64.tar.gz']:
            shutil.copyfile(cached / name, frozen / name)
        module.validate_pair(frozen, source / 'deploy/ansible/requirements.txt')
        environment['ULTRA_VERIFIED_RUNTIME_DIR'] = str(frozen)
    else:
        run([sys.executable, '-m', 'pip', '--version'], repo, 'pip_prerequisite')
    return environment


def build_candidate(repo, root, commit, version):
    bundle = root / version
    with tempfile.TemporaryDirectory(prefix='.source-', dir=root) as temporary:
        source = Path(temporary) / 'source'
        run(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(repo), str(source)], repo, 'source_clone')
        run(['git', 'checkout', '--quiet', '--detach', commit], source, 'source_checkout')
        if bundle.exists() or bundle.is_symlink():
            identity_path = bundle / 'candidate.json'
            require(identity_path.is_file() and not identity_path.is_symlink(), 'candidate_identity_missing')
            identity = json.loads(identity_path.read_bytes())
            require(identity == {'schema': 1, 'commit': commit, 'version': version,
                    'manifest_sha256': sha((bundle / 'release-manifest.json').read_bytes())}, 'candidate_identity_mismatch')
            verify_bundle(source, bundle, commit, version)
            return bundle
        environment = prepare_runtime_environment(repo, source)
        run(['make', 'release-dist'], source, 'release_build', env=environment)
        run(['bash', 'scripts/build-release-manifest.sh', 'dist', version], source, 'manifest_build')
        verify_bundle(source, source / 'dist', commit, version)
        pending = Path(tempfile.mkdtemp(prefix='.candidate-', dir=root))
        try:
            shutil.copytree(source / 'dist', pending, dirs_exist_ok=True)
            verify_bundle(source, pending, commit, version)
            (pending / 'candidate.json').write_text(json.dumps({'schema': 1, 'commit': commit, 'version': version,
                'manifest_sha256': sha((pending / 'release-manifest.json').read_bytes())}))
            for path in pending.iterdir():
                require(path.is_file() and not path.is_symlink(), 'candidate_unexpected_file')
                path.chmod(0o500 if path.name.startswith('ultra-') and '-linux-' in path.name and not path.name.endswith('.gz') else 0o400)
            pending.chmod(0o500)
            os.rename(pending, bundle)
        finally:
            if pending.exists():
                pending.chmod(0o700)
                shutil.rmtree(pending)
    return bundle


def config_values(raw):
    # Parse literals only; never source the deployment file or interpolate it.
    values = {}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        tokens = shlex.split(value, comments=True)
        require(len(tokens) <= 1 and key.strip() not in values, 'operator_config_literal_required')
        values[key.strip()] = tokens[0] if tokens else ''
    return values


def operator_transport(path, config):
    values = config_values(config)
    bridge_address = values.get('BRIDGE_SSH_HOST') or values.get('BRIDGE') or values.get('FRONT')
    static = json.loads(values.get('ULTRA_AUTOMATION_STATIC_NODES', '[]'))
    local_identity = os.environ.get('ULTRA_OPERATOR_IDENTITY')
    local_pins = os.environ.get('ULTRA_OPERATOR_KNOWN_HOSTS')
    if path:
        require(not local_identity and not local_pins, 'operator_transport_sources_conflict')
        path = Path(path)
        require(path.is_absolute() and path.name == 'inventory.json' and path.parent.name == 'compare'
                and path.parent.parent.name.startswith('adopt-'), 'operator_generated_inventory_required')
        raw = private_file(path)
        request = private_file(path.with_name('request.json'))
        job = json.loads(private_file(path.with_name('job.json')))
        inventory = json.loads(raw)
        require(json.loads(request).get('inventory') == inventory and job.get('operation') == 'adopt'
                and job.get('request_sha256') == sha(request), 'operator_inventory_provenance_invalid')
        all_hosts = inventory['all']
        common = all_hosts['vars']
        bridge = all_hosts['children']['bridge']['hosts']['bridge']
        exits = all_hosts['children']['exits']['hosts']
        source_binding = sha(raw)
    else:
        require(local_identity and local_pins, 'operator_identity_and_pins_required')
        require(static, 'operator_static_jump_required')
        # Local credential references supplement the single canonical topology;
        # they are never written to install.config or sent to the bridge.
        common = {'ansible_user': 'root', 'ansible_ssh_private_key_file': local_identity,
                  'ansible_ssh_common_args': shlex.join(['-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
                                                       '-o', 'UserKnownHostsFile=' + local_pins])}
        bridge = {'ansible_host': bridge_address}
        exits = {'exit_' + str(index): {'ansible_host': node['address']} for index, node in enumerate(static)}
        source_binding = sha(json.dumps({'bridge': bridge_address, 'static': [n['address'] for n in static]}, sort_keys=True).encode())
    require(bridge.get('ansible_host') == bridge_address and bridge_address == values.get('BRIDGE')
            and static and {n['address'] for n in static} == {n['ansible_host'] for n in exits.values()}
            and 'exit_0' in exits, 'operator_inventory_topology_changed')

    def endpoint(host):
        settings = dict(common, **host)
        address = settings['ansible_host']
        ipaddress.ip_address(address)  # aliases cannot import local SSH configuration
        require(settings.get('ansible_user') == 'root', 'operator_root_transport_required')
        identity = Path(settings['ansible_ssh_private_key_file'])
        require(identity.is_absolute(), 'operator_identity_absolute_required')
        # Inspect identity ownership/mode only. SSH opens the private key itself.
        info = identity.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'operator_identity_private_required')
        identity_binding = [str(identity), info.st_ino, info.st_size, info.st_mtime_ns]
        options = shlex.split(settings.get('ansible_ssh_args', '') + ' ' + settings['ansible_ssh_common_args'])
        pins = [token.split('=', 1)[1] for token in options if token.startswith('UserKnownHostsFile=')]
        require('StrictHostKeyChecking=yes' in options and 'IdentitiesOnly=yes' in options
                and len(pins) == 1, 'operator_explicit_pins_required')
        pin_path = Path(pins[0])
        require(pin_path.is_absolute(), 'operator_pins_absolute_required')
        pins_sha = sha(private_file(pin_path))
        probe = subprocess.run(['ssh-keygen', '-F', address, '-f', str(pin_path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        require(probe.returncode == 0, 'operator_endpoint_pin_missing')
        argv = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ProxyJump=none',
                '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                '-o', 'UserKnownHostsFile=' + str(pin_path),
                '-i', str(identity), '-p', '22']
        return argv, 'root@' + address, {'host': address, 'identity_file': identity_binding,
                                       'pins_file': str(pin_path), 'pins_sha256': pins_sha}

    target, destination, target_identity = endpoint(bridge)
    jump, jump_destination, jump_identity = endpoint(exits['exit_0'])
    target += ['-o', 'ProxyCommand=' + shlex.join(jump + ['-W', '%h:%p', jump_destination]), destination]
    binding = sha(json.dumps({'source_sha256': source_binding, 'target': target_identity,
                             'jump': jump_identity}, sort_keys=True).encode())
    return target, binding


def operator_requested():
    return any(os.environ.get(key) for key in ['ULTRA_OPERATOR_INVENTORY', 'ULTRA_OPERATOR_IDENTITY',
                                              'ULTRA_OPERATOR_KNOWN_HOSTS'])


# Executed only through pinned SSH. This helper never reads secret environment files.
# Stage into a fresh private sibling and rename only after every byte is checked.
REMOTE_PROGRAM = r'''
import fcntl,hashlib,json,os,platform,re,shutil,stat,sys,tarfile,tempfile,uuid
from pathlib import Path
def need(ok, code='remote_input_invalid'):
    if not ok: raise ValueError(code)
def digest(data): return hashlib.sha256(data).hexdigest()
mode,commit,version,manifest_sha,config_sha,attempt=sys.argv[1:7]
probe_sha=(sys.argv[11] if len(sys.argv)>11 else '') if mode=='run' else (sys.argv[7] if len(sys.argv)>7 else '')
forward_journal_sha=(sys.argv[12] if mode=='run' and len(sys.argv)>12 else
                     (sys.argv[8] if mode in ['stage','cleanup','continue'] and len(sys.argv)>8 else ''))
prior_journal_sha=(sys.argv[16] if mode=='run' and len(sys.argv)>16 else
                   (sys.argv[9] if mode in ['stage','cleanup','continue'] and len(sys.argv)>9 else ''))
need(probe_sha=='' or re.fullmatch('[a-f0-9]{64}',probe_sha))
need(forward_journal_sha=='' or re.fullmatch('[a-f0-9]{64}',forward_journal_sha))
need(prior_journal_sha=='' or re.fullmatch('[a-f0-9]{64}',prior_journal_sha))
need(re.fullmatch('[a-f0-9]{40}',commit) and version=='v0.0.'+str(int(commit,16)))
need(all(re.fullmatch('[a-f0-9]{64}',x) for x in [manifest_sha,config_sha,attempt]))
need(os.geteuid()==0)
parent=Path('/var/lib/ultra-ansible/operator-inputs')
for directory in [parent.parent,parent]:
    if mode=='continue': need(directory.exists(), 'manual_forward_continuation_inputs_missing')
    if not directory.exists(): directory.mkdir(mode=0o700)
    info=directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077)
root=parent/('manual-'+commit+'-'+attempt)
lock=os.open(parent/'manual-deploy.lock',os.O_WRONLY|os.O_NOFOLLOW|(0 if mode=='continue' else os.O_CREAT),0o600)
info=os.fstat(lock);need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600)
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
def read(path):
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077)
    return path.read_bytes()
def verify_private_tree(directory):
    """Require private root-owned regular files/directories in retained job trees."""
    count=0;total=0
    for base,dirs,files in os.walk(directory,followlinks=False):
        base=Path(base);info=base.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077,
             'manual_forward_continuation_evidence_invalid')
        for name in dirs+files:
            item=base/name;info=item.lstat();count+=1
            need(count<=20000 and info.st_uid==0 and not stat.S_ISLNK(info.st_mode),
                 'manual_forward_continuation_evidence_invalid')
            if name in dirs:
                need(stat.S_ISDIR(info.st_mode) and not info.st_mode&0o077,
                     'manual_forward_continuation_evidence_invalid')
            else:
                need(stat.S_ISREG(info.st_mode) and not info.st_mode&0o077 and info.st_size<=2147483648,
                     'manual_forward_continuation_evidence_invalid')
                total+=info.st_size
                need(total<=4294967296,'manual_forward_continuation_evidence_invalid')
def verify_controller_artifacts(stage):
    # Retained artifacts do not prove quiescence; keep the lease/census gates.
    workspace=stage/'.ansible'
    if workspace.exists() or workspace.is_symlink():
        info=workspace.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077,
             'manual_forward_continuation_handoff_evidence_invalid')
        verify_private_tree(workspace)
    execution_lock=stage/'execution.lock'
    if execution_lock.exists() or execution_lock.is_symlink():
        info=execution_lock.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and
             info.st_size<=1048576, 'manual_forward_continuation_handoff_evidence_invalid')
def lifecycle_ledger(raw):
    ledger=json.loads(raw)
    need(isinstance(ledger,dict) and not (set(ledger)-{'version','ids','handoff'}) and
         ledger.get('version')==1 and isinstance(ledger.get('ids'),list) and
         len(ledger['ids'])==len(set(ledger['ids'])) and all(isinstance(value,str) and re.fullmatch(
             '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',value)
             for value in ledger['ids']), 'manual_forward_continuation_retirement_changed')
    handoff=ledger.get('handoff')
    need(isinstance(handoff,dict) and not (set(handoff)-{'old_id','new_id'}) and
         all(isinstance(handoff.get(key),str) and re.fullmatch(
             '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',handoff[key])
             for key in ('old_id','new_id')) and handoff['old_id']!=handoff['new_id'] and
         handoff['old_id'] in ledger['ids'], 'manual_forward_continuation_retirement_changed')
    return ledger
def forward_operation_fingerprint(directory):
    # Producer receipts and archive-bound bundles are rechecked by the Go
    # installer before it attaches A's lifecycle lease. This pins all durable
    # A evidence across a lost response and retry.
    verify_private_tree(directory)
    files={}
    for base,dirs,names in os.walk(directory,followlinks=False):
        base=Path(base);relative=base.relative_to(directory).parts
        if len(relative)==2 and base.name in ('bundle','.ansible','ansible-tmp'):
            dirs.clear();continue
        for name in names:
            path=base/name
            files[path.relative_to(directory).as_posix()]=digest(read(path))
    return digest(json.dumps(files,sort_keys=True,separators=(',',':')).encode())
def verify_chain_prior_tree(prior_operation, old_id, prior_id, proof_sha):
    names={p.name for p in prior_operation.iterdir()}
    fixed={'operator-plan.json','execution-mode.json','forward-handoff.json','inspect','hosts',
           'domain-inspect','architectures','recovery-bundle','identity','inventory.frozen.json'}
    allowed=fixed|{'runtime-use.json'}
    maintenance={name for name in names if name.startswith('forward-maintenance-')}
    drains={name for name in names if name.startswith('handoff-drain-')}
    bootstraps={name for name in names if name.startswith('broker-bootstrap-')}
    pins={name for name in names if re.fullmatch(r'exit_[a-f0-9]{32}\.pins',name)}
    allowed|=maintenance|drains|bootstraps|pins
    need(fixed<=names and names<=allowed and maintenance and drains and
         'activate' not in names and 'baseline' not in names,
         'manual_forward_continuation_handoff_inventory_invalid')
    verify_private_tree(prior_operation)
    # These direct directories are immutable inspection/output stages. Go does
    # the request, receipt, plan, and signed archive checks before mutation.
    for name in ['inspect','hosts','domain-inspect','architectures','recovery-bundle']+list(maintenance|drains|bootstraps):
        path=prior_operation/name
        info=path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,
             'manual_forward_continuation_handoff_evidence_invalid')
        if name in ('inspect','hosts','domain-inspect') or name.startswith(
                ('forward-maintenance-','handoff-drain-','broker-bootstrap-')):
            stage_names={p.name for p in path.iterdir()}
            stage_allowed={'request.json','job.json','receipt.json','result.json','inventory.json','inventory.yml',
                           'variables.json','variables.yml','bundle.retention.json','diagnostic.json',
                           'execution.lock','bundle','ansible-tmp','.ansible'}
            need({'request.json','job.json','receipt.json'}<=stage_names and stage_names<=stage_allowed and
                 ('result.json' in stage_names or name=='domain-inspect'),
                 'manual_forward_continuation_handoff_evidence_invalid')
        elif name=='architectures':
            architecture_files={p.name for p in path.iterdir()}
            need('bridge.json' in architecture_files and all(
                filename=='bridge.json' or re.fullmatch(r'exit_[a-f0-9]{32}\.json',filename)
                for filename in architecture_files), 'manual_forward_continuation_handoff_evidence_invalid')
    for name in ['operator-plan.json','execution-mode.json','forward-handoff.json','identity','inventory.frozen.json']+list(pins):
        info=(prior_operation/name).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,
             'manual_forward_continuation_handoff_evidence_invalid')
    intent=json.loads(read(prior_operation/'forward-handoff.json'))
    need(intent.get('schema')==1 and intent.get('proof_sha256')==proof_sha and
         intent.get('old_id')==old_id and intent.get('new_id')==prior_id and
         isinstance(intent.get('drain_directory'),str) and
         Path(intent['drain_directory']).parent==prior_operation and
         Path(intent['drain_directory']).name in drains,
         'manual_forward_continuation_handoff_evidence_invalid')
    return forward_operation_fingerprint(prior_operation)
def operation_id(path):
    return str(uuid.UUID(bytes=hashlib.sha256(str(path).encode()).digest()[:16],version=4))
def verify_chain_intent(directory, state, proof_sha, old_id, new_id, original_inventory):
    path=directory/'forward-handoff.json'
    raw=read(path);intent=json.loads(raw)
    need(set(intent)=={'schema','proof_sha256','old_id','new_id','drain_directory','request_sha256',
                       'job_sha256','receipt_sha256','result_sha256'} and intent.get('schema')==1 and
         intent.get('proof_sha256')==proof_sha and intent.get('old_id')==old_id and
         intent.get('new_id')==new_id, 'manual_forward_continuation_handoff_evidence_invalid')
    stage=Path(intent.get('drain_directory',''))
    need(stage.parent==directory and stage.name.startswith('handoff-drain-'),
         'manual_forward_continuation_handoff_evidence_invalid')
    names={p.name for p in stage.iterdir()}
    need({'request.json','job.json','receipt.json','result.json'}<=names and
         names<={'request.json','job.json','receipt.json','result.json','inventory.json','inventory.yml',
                 'variables.json','variables.yml','bundle','ansible-tmp','bundle.retention.json',
                 'diagnostic.json','.ansible','execution.lock'},
         'manual_forward_continuation_handoff_evidence_invalid')
    evidence={name:read(stage/name) for name in ('request.json','job.json','receipt.json','result.json')}
    reqsha=digest(evidence['request.json'])
    expected_request=json.dumps({'inventory':original_inventory,'variables':{
        'ultra_lock_directory':str(state),'ultra_forward_old_id':old_id,'ultra_lifecycle_id':new_id}},
        sort_keys=True,separators=(',',':')).encode()
    request=json.loads(evidence['request.json']);job=json.loads(evidence['job.json'])
    receipt=json.loads(evidence['receipt.json']);result=json.loads(evidence['result.json'])
    expected_result={'verified':True,'old_id':old_id,'new_id':new_id}
    need(evidence['request.json']==expected_request and
         all(item.get('schema_version')==1 and item.get('operation')=='drain-upgrade-workers' and
             item.get('request_sha256')==reqsha and item.get('binary_sha256')==reqsha
             for item in (job,receipt)) and receipt.get('state')=='succeeded' and
         receipt.get('code','')=='' and receipt.get('result')==expected_result and result==expected_result and
         all(intent.get(key)==digest(evidence[file]) for key,file in (
             ('request_sha256','request.json'),('job_sha256','job.json'),
             ('receipt_sha256','receipt.json'),('result_sha256','result.json'))),
         'manual_forward_continuation_handoff_evidence_invalid')
    return intent
def verify_chain_continuation(chain_offset=10):
    verify(root)
    need(bool(forward_journal_sha) and len(sys.argv)>=chain_offset+11,
         'manual_forward_continuation_chain_required')
    target_commit,target_version,target_manifest,target_config,target_attempt,prior_commit,prior_version,prior_attempt,prior_manifest,prior_config,chain_prior_sha=sys.argv[chain_offset:chain_offset+11]
    need(re.fullmatch('[a-f0-9]{40}',target_commit) and target_version=='v0.0.'+str(int(target_commit,16)) and
         re.fullmatch('[a-f0-9]{64}',target_manifest) and re.fullmatch('[a-f0-9]{64}',target_config) and
         re.fullmatch('[a-f0-9]{64}',target_attempt) and re.fullmatch('[a-f0-9]{40}',prior_commit) and
         prior_version=='v0.0.'+str(int(prior_commit,16)) and re.fullmatch('[a-f0-9]{64}',prior_attempt) and
         re.fullmatch('[a-f0-9]{64}',prior_manifest) and re.fullmatch('[a-f0-9]{64}',prior_config) and
         re.fullmatch('[a-f0-9]{64}',chain_prior_sha) and target_commit!=prior_commit,
         'manual_forward_continuation_chain_invalid')
    need((mode!='run' or (target_commit,target_version,target_manifest,target_config,target_attempt)==
          (commit,version,manifest_sha,config_sha,attempt)) and
         ((commit,version,manifest_sha,config_sha,attempt)==
          (target_commit,target_version,target_manifest,target_config,target_attempt) or
          (commit,version,manifest_sha,config_sha,attempt)==
          (prior_commit,prior_version,prior_manifest,prior_config,prior_attempt)),
         'manual_forward_continuation_chain_invalid')
    need(not prior_journal_sha or prior_journal_sha==chain_prior_sha,
         'manual_forward_continuation_predecessor_invalid')
    proof=json.loads(read(root/'forward-operation.json'))
    old_commit=proof.get('commit','');old_version=proof.get('version','')
    need(proof.get('schema')==1 and proof.get('stage')=='upgrade' and proof.get('mutator_dispatched') is True and
         re.fullmatch('[a-f0-9]{40}',old_commit) and old_version=='v0.0.'+str(int(old_commit,16)) and
         all(re.fullmatch('[a-f0-9]{64}',proof.get(key,'')) for key in
             ('remote_attempt','manifest_sha256','staged_config_sha256')),
         'manual_forward_continuation_predecessor_invalid')
    state=parent.parent
    old_id=operation_id(state/('upgrade-'+old_version))
    prior_operation=state/('upgrade-'+prior_version)
    target_operation=state/('upgrade-'+target_version)
    prior_id=operation_id(prior_operation);new_id=operation_id(target_operation)
    prior_inputs=parent/('manual-'+prior_commit+'-'+prior_attempt)
    need(prior_version==prior_operation.name.removeprefix('upgrade-') and
         stat.S_ISDIR(prior_inputs.lstat().st_mode) and
         digest(read(prior_inputs/'release/release-manifest.json'))==prior_manifest and
         digest(read(prior_inputs/'install.config'))==prior_config,
         'manual_forward_continuation_predecessor_invalid')
    if prior_journal_sha:
        saved_prior=read(root/'forward-prior-operation.json')
        saved_journal=json.loads(saved_prior)
        need(digest(saved_prior)==chain_prior_sha and saved_journal.get('commit')==prior_commit and
             saved_journal.get('version')==prior_version and saved_journal.get('remote_attempt')==prior_attempt and
             saved_journal.get('manifest_sha256')==prior_manifest and
             saved_journal.get('staged_config_sha256')==prior_config and
             saved_journal.get('forward_journal_sha256')==forward_journal_sha,
             'manual_forward_continuation_predecessor_invalid')
    original_inputs=parent/('manual-'+old_commit+'-'+proof['remote_attempt'])
    need(stat.S_ISDIR(original_inputs.lstat().st_mode) and
         digest(read(original_inputs/'release/release-manifest.json'))==proof['manifest_sha256'] and
         digest(read(original_inputs/'install.config'))==proof['staged_config_sha256'],
         'manual_forward_continuation_predecessor_invalid')
    original_operation=state/('upgrade-'+old_version)
    original_request=json.loads(read(original_operation/'activate/request.json'))
    original_inventory=original_request.get('inventory')
    need(isinstance(original_inventory,dict) and
         original_request.get('variables',{}).get('ultra_lifecycle_id')==old_id,
         'manual_forward_continuation_predecessor_invalid')
    fingerprint=verify_chain_prior_tree(prior_operation,old_id,prior_id,forward_journal_sha)
    handoff_raw=read(prior_operation/'forward-handoff.json')
    original_handoff_sha=digest(handoff_raw)
    original_evidence_sha=digest(json.dumps({'journal':forward_journal_sha,
        'activate/request.json':digest(read(original_operation/'activate/request.json')),
        'activate/job.json':digest(read(original_operation/'activate/job.json')),
        'activate/receipt.json':digest(read(original_operation/'activate/receipt.json')),
        'operator-plan.json':digest(read(original_operation/'operator-plan.json'))},
        sort_keys=True,separators=(',',':')).encode())
    ledger_path=state/'lifecycle-retired.json';current_ledger_raw=read(ledger_path)
    current_ledger=lifecycle_ledger(current_ledger_raw)
    lifecycle=json.loads(read(state/'lifecycle.json'))
    need(set(lifecycle)=={'id','phase'} and lifecycle.get('phase')=='applying',
         'manual_forward_continuation_lifecycle_changed')
    b_names=set()
    if target_operation.exists() or target_operation.is_symlink():
        info=target_operation.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,
             'manual_forward_continuation_handoff_inventory_invalid')
        b_names={p.name for p in target_operation.iterdir()}
        b_allowed={'operator-plan.json','execution-mode.json','runtime-use.json','forward-chain.json','forward-handoff.json'}
        b_drains={name for name in b_names if name.startswith('handoff-drain-')}
        need(b_names<=b_allowed|b_drains and
             all(not name.startswith(('domain-mutation-','runtime-mutation-','upgrade-domain-','upgrade-runtime-'))
                 for name in b_names), 'manual_forward_continuation_handoff_inventory_invalid')
        verify_private_tree(target_operation)
    chain_path=target_operation/'forward-chain.json'
    intent_path=target_operation/'forward-handoff.json'
    chain_present=chain_path.exists() or chain_path.is_symlink()
    intent_present=intent_path.exists() or intent_path.is_symlink()
    need(not intent_present or chain_present, 'manual_forward_continuation_handoff_evidence_invalid')
    expected_original={}
    if chain_present:
        chain_raw=read(chain_path);chain=json.loads(chain_raw)
        chain_keys={'schema','proof_sha256','prior_journal_sha256','original_id','prior_id','new_id',
                    'prior_evidence_sha256','original_handoff_sha256','original_evidence_sha256','original_retirement_json',
                    'original_retirement_sha256'}
        need(set(chain)==chain_keys and chain.get('schema')==1 and
             chain.get('proof_sha256')==forward_journal_sha and
             chain.get('prior_journal_sha256')==chain_prior_sha and
             chain.get('original_id')==old_id and chain.get('prior_id')==prior_id and
             chain.get('new_id')==new_id and chain.get('prior_evidence_sha256')==fingerprint and
             chain.get('original_handoff_sha256')==original_handoff_sha and
             chain.get('original_evidence_sha256')==original_evidence_sha and
             isinstance(chain.get('original_retirement_json'),str) and
             digest(chain['original_retirement_json'].encode())==chain.get('original_retirement_sha256'),
             'manual_forward_continuation_chain_changed')
        original_raw=chain['original_retirement_json'].encode()
        expected_original=lifecycle_ledger(original_raw)
        need(expected_original['handoff']=={'old_id':old_id,'new_id':prior_id} and
             old_id in expected_original['ids'] and prior_id not in expected_original['ids'] and
             new_id not in expected_original['ids'], 'manual_forward_continuation_chain_changed')
    else:
        original_raw=current_ledger_raw
        expected_original=current_ledger
        need(current_ledger['handoff']=={'old_id':old_id,'new_id':prior_id} and
             old_id in current_ledger['ids'] and prior_id not in current_ledger['ids'] and
             new_id not in current_ledger['ids'], 'manual_forward_continuation_retirement_changed')
    if lifecycle['id']==prior_id:
        need(current_ledger_raw==original_raw and not (intent_present and not chain_present),
             'manual_forward_continuation_retirement_changed')
        phase='start'
    elif lifecycle['id']==new_id:
        need(chain_present and intent_present and
             current_ledger['handoff']=={'old_id':prior_id,'new_id':new_id} and
             set(current_ledger['ids'])==set(expected_original['ids'])|{prior_id} and
             len(current_ledger['ids'])==len(set(expected_original['ids'])|{prior_id}),
             'manual_forward_continuation_retirement_changed')
        phase='restart'
    else:
        raise ValueError('manual_forward_continuation_lifecycle_changed')
    b_intent=None
    if intent_present:
        b_intent=verify_chain_intent(target_operation,state,forward_journal_sha,prior_id,new_id,original_inventory)
    else:
        # A crash may leave the durable chain intent before the drain handoff
        # intent is published. Accept only this validated prefix while A still
        # owns the exact original ledger; Go will rerun the fresh census before
        # it publishes the handoff or supersedes A.
        need(not intent_present and (not chain_present or phase=='start'),
             'manual_forward_continuation_handoff_evidence_invalid')
    chain_attestation={'phase':phase,'proof_sha256':forward_journal_sha,
        'prior_journal_sha256':chain_prior_sha,'original_id':old_id,'prior_id':prior_id,'new_id':new_id,
        'prior_evidence_sha256':fingerprint,'original_handoff_sha256':original_handoff_sha,
        'original_evidence_sha256':original_evidence_sha,'original_retirement_sha256':digest(original_raw)}
    architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    need(architecture in ['amd64','arm64'])
    candidate_receipt=({'commit':commit,'version':version,'remote_attempt':attempt,
        'manifest_sha256':manifest_sha,'staged_config_sha256':config_sha,
        'forward_journal_sha256':forward_journal_sha} if commit==target_commit else
        {'commit':prior_commit,'version':prior_version,'remote_attempt':prior_attempt,
         'manifest_sha256':prior_manifest,'staged_config_sha256':prior_config,
         'forward_journal_sha256':forward_journal_sha})
    return {'architecture':architecture,'manifest_sha256':manifest_sha,'config_sha256':config_sha,
        'attempt':attempt,'forward_journal_sha256':forward_journal_sha,'lifecycle_id':old_id,
        'prior_candidate':candidate_receipt,'chain_attestation':chain_attestation}
def verify(directory):
    info=directory.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
    info=(directory/'release').lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
    raw=read(directory/'release/release-manifest.json');need(digest(raw)==manifest_sha)
    m=json.loads(raw);need(m['source_commit']==commit and m['version']==version and len(m['assets'])==14)
    names=set()
    for row in m['assets']:
        name=row['name'];need(re.fullmatch('[A-Za-z0-9_.-]+',name) and name not in ['.','..','release-manifest.json'] and name not in names)
        names.add(name);data=read(directory/'release'/name)
        need(len(data)==row['size'] and digest(data)==row['sha256'])
    need({x.name for x in (directory/'release').iterdir()}==names|{'release-manifest.json'})
    top={x.name for x in directory.iterdir()}
    need(top - {'baseline','subscription-probe-url','subscription-probe.sha256','forward-operation.json','forward-prior-operation.json'} == {'release','install.config'})
    need(('subscription-probe.sha256' in top)==bool(probe_sha))
    if probe_sha:
        need(read(directory/'subscription-probe.sha256')==probe_sha.encode())
        if 'subscription-probe-url' in top:
            info=(directory/'subscription-probe-url').lstat()
            need(stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=4096)
            need(digest(read(directory/'subscription-probe-url'))==probe_sha)
    else: need('subscription-probe-url' not in top)
    need(('forward-operation.json' in top)==bool(forward_journal_sha))
    if forward_journal_sha:
        info=(directory/'forward-operation.json').lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600)
        need(digest(read(directory/'forward-operation.json'))==forward_journal_sha)
    need(('forward-prior-operation.json' in top)==bool(prior_journal_sha))
    if prior_journal_sha:
        info=(directory/'forward-prior-operation.json').lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600)
        need(digest(read(directory/'forward-prior-operation.json'))==prior_journal_sha)
    if 'baseline' in top:
        baseline=directory/'baseline';info=baseline.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
        need({x.name for x in baseline.iterdir()}=={'descriptor.json','operator-journal.json'})
        for name in ['descriptor.json','operator-journal.json']:
            info=(baseline/name).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600)
        descriptor_raw=read(baseline/'descriptor.json');journal_raw=read(baseline/'operator-journal.json')
        descriptor=json.loads(descriptor_raw);journal=json.loads(journal_raw)
        need(journal.get('mutator_dispatched') is not True,
             'manual_operation_quiescence_migration_required')
        need(descriptor.get('schema')==1 and digest(journal_raw)==descriptor.get('journal_sha256'))
        need(descriptor.get('journal')==str(root/'baseline/operator-journal.json'))
        old_release=Path('/var/lib/ultra-ansible/operator-inputs')/('manual-'+journal.get('commit','')+'-'+journal.get('remote_attempt',''))/'release'
        need(descriptor.get('manifest')==str(old_release/'release-manifest.json'))
        need(journal.get('manifest_sha256')==descriptor.get('manifest_sha256') and
             journal.get('mutator_dispatched') is True and
             re.fullmatch('[a-f0-9]{40}',journal.get('commit','')) and
             re.fullmatch('[a-f0-9]{16,64}',journal.get('remote_attempt','')))
    need(digest(read(directory/'install.config'))==config_sha)
    return m
def verify_continuation(chain_offset=None):
    if chain_offset is None and mode=='continue' and len(sys.argv)>=21:
        chain_offset=10
    if chain_offset is not None:
        # Select from live ownership, then fully verify the selected protocol.
        # O-owned failures retain the existing pre-handoff recovery path even
        # when a new candidate was requested. Never fall back after a failed
        # chain verification.
        verify(root)
        proof=json.loads(read(root/'forward-operation.json'))
        original_version=proof.get('version','')
        need(re.fullmatch('[a-f0-9]{40}',proof.get('commit','')) and
             original_version=='v0.0.'+str(int(proof['commit'],16)),
             'manual_forward_continuation_predecessor_invalid')
        lifecycle=json.loads(read(parent.parent/'lifecycle.json'))
        if lifecycle.get('id')!=operation_id(parent.parent/('upgrade-'+original_version)):
            return verify_chain_continuation(chain_offset)
    # Only the failed pre-handoff case is supported. The installer rechecks the
    # frozen plan, predecessor proof and live lifecycle under its operator lock.
    verify(root)
    need(not probe_sha or (root/'subscription-probe-url').exists(), 'manual_operation_probe_changed')
    need(bool(forward_journal_sha), 'manual_forward_continuation_proof_required')
    proof=json.loads(read(root/'forward-operation.json'))
    old_commit=proof.get('commit','');old_version=proof.get('version','')
    need(re.fullmatch('[a-f0-9]{40}',old_commit) and old_commit!=commit and
         old_version=='v0.0.'+str(int(old_commit,16)), 'manual_forward_continuation_predecessor_invalid')
    state=parent.parent
    operation=state/('upgrade-'+version)
    try:
        info=operation.lstat()
    except FileNotFoundError:
        # The exclusive manual-deploy lock is held through attestation and exec.
        # An absent operation has no handoff evidence to promote to a prior
        # candidate; retry the same signed inputs and let Go recheck the fleet.
        need(proof.get('schema')==1 and proof.get('stage')=='upgrade' and proof.get('mutator_dispatched') is True and
             all(re.fullmatch('[a-f0-9]{64}',proof.get(key,'')) for key in
                 ('remote_attempt','manifest_sha256','staged_config_sha256')),
             'manual_forward_continuation_predecessor_invalid')
        old_inputs=parent/('manual-'+old_commit+'-'+proof['remote_attempt'])
        old_info=old_inputs.lstat()
        need(stat.S_ISDIR(old_info.st_mode) and old_info.st_uid==0 and stat.S_IMODE(old_info.st_mode)==0o700 and
             digest(read(old_inputs/'release/release-manifest.json'))==proof['manifest_sha256'] and
             digest(read(old_inputs/'install.config'))==proof['staged_config_sha256'],
             'manual_forward_continuation_predecessor_invalid')
        old_id=str(uuid.UUID(bytes=hashlib.sha256(str(state/('upgrade-'+old_version)).encode()).digest()[:16],version=4))
        lifecycle=json.loads(read(state/'lifecycle.json'))
        need(lifecycle.get('id')==old_id and lifecycle.get('phase')=='applying',
             'manual_forward_continuation_lifecycle_changed')
        architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
        need(architecture in ['amd64','arm64'])
        return {'architecture':architecture,'manifest_sha256':manifest_sha,'config_sha256':config_sha,
                'attempt':attempt,'forward_journal_sha256':forward_journal_sha,'lifecycle_id':old_id,
                'prior_candidate':{},'operation_absent':True}
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
    operation_names={p.name for p in operation.iterdir()}
    fixed_names={'execution-mode.json','operator-plan.json','forward-handoff.json','runtime-use.json'}
    stage_names={name for name in operation_names if name.startswith(('handoff-drain-','broker-bootstrap-'))}
    expected_old_id=str(uuid.UUID(bytes=hashlib.sha256(str(state/('upgrade-'+old_version)).encode()).digest()[:16],version=4))
    expected_new_id=str(uuid.UUID(bytes=hashlib.sha256(str(operation).encode()).digest()[:16],version=4))
    prior_candidate=None
    need(operation_names==(fixed_names & operation_names)|stage_names and
         {'execution-mode.json','operator-plan.json'}<=operation_names,
         'manual_forward_continuation_handoff_inventory_invalid')
    if not stage_names and 'forward-handoff.json' not in operation_names:
        for name in ['execution-mode.json','operator-plan.json']:
            info=(operation/name).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,
                 'manual_forward_continuation_requires_pre_handoff')
            read(operation/name)
    elif stage_names and 'forward-handoff.json' not in operation_names:
        # A replacement with no saved handoff must census before broker
        # bootstrap. Retained census/bootstrap evidence is rechecked by Go
        # against the prior operation before any fleet mutation.
        need(bool(prior_journal_sha), 'manual_forward_continuation_handoff_evidence_invalid')
        drains=[p for p in operation.iterdir() if p.name.startswith('handoff-drain-')]
        bootstraps=[p for p in operation.iterdir() if p.name.startswith('broker-bootstrap-')]
        for stage in drains+bootstraps:
            verify_private_tree(stage)
            verify_controller_artifacts(stage)
            names={p.name for p in stage.iterdir()}
            need({'request.json','job.json','receipt.json'}<=names and
                 names<={'request.json','job.json','receipt.json','result.json','inventory.json','inventory.yml',
                         'variables.json','variables.yml','bundle','ansible-tmp','bundle.retention.json','diagnostic.json',
                         '.ansible','execution.lock'},
                 'manual_forward_continuation_handoff_evidence_invalid')
            request_raw=read(stage/'request.json');job_raw=read(stage/'job.json')
            receipt_raw=read(stage/'receipt.json')
            request=json.loads(request_raw);job=json.loads(job_raw);receipt=json.loads(receipt_raw)
            result=json.loads(read(stage/'result.json')) if 'result.json' in names else None
            reqsha=digest(request_raw)
            if stage in drains:
                expected_result={'verified':True,'old_id':expected_old_id,'new_id':expected_new_id}
                need(request.get('variables',{}).get('ultra_lock_directory')==str(state) and
                     request.get('variables',{}).get('ultra_forward_old_id')==expected_old_id and
                     request.get('variables',{}).get('ultra_lifecycle_id')==expected_new_id and
                     all(item.get('schema_version')==1 and item.get('operation')=='drain-upgrade-workers' and
                         item.get('request_sha256')==reqsha and item.get('binary_sha256')==reqsha
                         for item in (job,receipt)) and receipt.get('state')=='succeeded' and receipt.get('code','')=='' and
                     result==expected_result and result==receipt.get('result'),
                     'manual_forward_continuation_handoff_evidence_invalid')
            elif stage in bootstraps and receipt.get('state')=='failed':
                # The first task is a read-only guard; a failure here precedes
                # include_role, notifications and restart. The callback records
                # task identity, not the module's private failure reason.
                diagnostic={'stage':'Verify frozen broker identity and predecessor gate before replacement',
                            'node':'bridge','code':'task_failed'}
                variables=request.get('variables',{})
                need('result.json' not in names and 'result' not in receipt and
                     'diagnostic.json' in names and receipt.get('code')=='ansible_failed' and
                     type(receipt.get('exit_code')) is int and receipt['exit_code']==2 and
                     receipt.get('diagnostic')==diagnostic and json.loads(read(stage/'diagnostic.json'))==diagnostic and
                     variables.get('ultra_lock_directory')==str(state) and
                     variables.get('ultra_forward_old_id')==expected_old_id and
                     variables.get('ultra_forward_candidate_id')==expected_new_id and
                     variables.get('ultra_controller_directory')=='/opt/ultra-ansible/releases/managed-'+version and
                     all(item.get('schema_version')==1 and item.get('operation')=='bootstrap-forward-broker' and
                         item.get('request_sha256')==reqsha and item.get('binary_sha256')==reqsha for item in (job,receipt)),
                     'manual_forward_continuation_handoff_evidence_invalid')
                # Bind the frozen fleet and old broker identity to the original
                # activation request. Go also rechecks the complete bootstrap
                # request, signed bundle, lease and live broker before mutation.
                old_operation=state/('upgrade-'+old_version)
                verify_private_tree(old_operation)
                old_request_raw=read(old_operation/'activate/request.json')
                old_request=json.loads(old_request_raw)
                need(old_request.get('variables',{}).get('ultra_lifecycle_id')==expected_old_id and
                     isinstance(request.get('inventory'),dict) and request['inventory']==old_request.get('inventory'),
                     'manual_forward_continuation_handoff_evidence_invalid')
                for name in ['job.json','receipt.json']:
                    item=json.loads(read(old_operation/'activate'/name))
                    need(item.get('schema_version')==1 and item.get('operation')=='upgrade' and
                         item.get('request_sha256')==digest(old_request_raw) and item.get('binary_sha256')==digest(old_request_raw),
                         'manual_forward_continuation_handoff_evidence_invalid')
                bridge=request['inventory'].get('all',{}).get('children',{}).get('bridge',{}).get('hosts',{})
                need(set(bridge)=={'bridge'},'manual_forward_continuation_handoff_evidence_invalid')
                frozen=bridge['bridge']
                old_identity={'directory':frozen.get('ultra_controller_directory'),
                    'installer_sha256':frozen.get('ultra_install_sha256'),
                    'runtime_sha256':frozen.get('ultra_controller_runtime_sha256'),
                    'unit_sha256':frozen.get('ultra_target_controller_unit_sha256')}
                need(old_identity['directory']=='/opt/ultra-ansible/releases/managed-'+old_version and
                     all(isinstance(old_identity[key],str) and re.fullmatch('[a-f0-9]{64}',old_identity[key])
                         for key in ['installer_sha256','runtime_sha256','unit_sha256']) and
                     isinstance(variables.get('ultra_forward_expected_brokers'),list) and
                     old_identity in variables['ultra_forward_expected_brokers'],
                     'manual_forward_continuation_handoff_evidence_invalid')
            else:
                need(isinstance(result,dict) and request.get('variables',{}).get('ultra_lock_directory')==str(state) and
                     request.get('variables',{}).get('ultra_forward_old_id')==expected_old_id and
                     all(item.get('schema_version')==1 and item.get('operation')=='bootstrap-forward-broker' and
                         item.get('request_sha256')==reqsha and item.get('binary_sha256')==reqsha
                         for item in (job,receipt)) and receipt.get('state')=='succeeded' and receipt.get('code','')=='' and
                     result==receipt.get('result') and result.get('verified') is True and
                     result.get('old_id')==expected_old_id and
                     result.get('controller_directory')=='/opt/ultra-ansible/releases/managed-'+version,
                     'manual_forward_continuation_handoff_evidence_invalid')
        prior_candidate={'commit':commit,'version':version,'remote_attempt':attempt,
            'manifest_sha256':manifest_sha,'staged_config_sha256':config_sha,
            'forward_journal_sha256':forward_journal_sha}
    else:
        drains=[p for p in operation.iterdir() if p.name.startswith('handoff-drain-')]
        bootstraps=[p for p in operation.iterdir() if p.name.startswith('broker-bootstrap-')]
        need(bool(drains) and 'forward-handoff.json' in operation_names,
             'manual_forward_continuation_handoff_inventory_invalid')
        for name in ['execution-mode.json','operator-plan.json','forward-handoff.json']:
            info=(operation/name).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,
                 'manual_forward_continuation_handoff_evidence_invalid')
        intent=json.loads(read(operation/'forward-handoff.json'))
        for stage in drains+bootstraps:
            verify_private_tree(stage)
            verify_controller_artifacts(stage)
            names={p.name for p in stage.iterdir()}
            need({'request.json','job.json','receipt.json','result.json'}<=names and
                 names<={'request.json','job.json','receipt.json','result.json','inventory.json','inventory.yml',
                         'variables.json','variables.yml','bundle','ansible-tmp','bundle.retention.json','diagnostic.json',
                         '.ansible','execution.lock'},
                 'manual_forward_continuation_handoff_evidence_invalid')
        stage=Path(intent.get('drain_directory',''))
        need(stage in drains and intent.get('schema')==1 and intent.get('proof_sha256')==forward_journal_sha,
             'manual_forward_continuation_handoff_evidence_invalid')
        evidence={name:read(stage/name) for name in ['request.json','job.json','receipt.json','result.json']}
        need(proof.get('schema')==1 and proof.get('stage')=='upgrade' and proof.get('mutator_dispatched') is True and
             proof.get('commit')==old_commit and proof.get('version')==old_version and
             all(re.fullmatch('[a-f0-9]{64}',proof.get(key,'')) for key in
                 ('remote_attempt','manifest_sha256','staged_config_sha256')),
             'manual_forward_continuation_predecessor_invalid')
        old_inputs=parent/('manual-'+old_commit+'-'+proof['remote_attempt'])
        info=old_inputs.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,
             'manual_forward_continuation_predecessor_invalid')
        old_manifest=read(old_inputs/'release/release-manifest.json')
        old_config=read(old_inputs/'install.config')
        need(digest(old_manifest)==proof['manifest_sha256'] and digest(old_config)==proof['staged_config_sha256'],
             'manual_forward_continuation_predecessor_invalid')
        old_operation=state/('upgrade-'+old_version)
        old_names={p.name for p in old_operation.iterdir()}
        need({'execution-mode.json','operator-plan.json','activate'}<=old_names,
             'manual_forward_continuation_predecessor_invalid')
        verify_private_tree(old_operation)
        info=(old_operation/'activate').lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700 and
             {'request.json','job.json','receipt.json'}<={p.name for p in (old_operation/'activate').iterdir()},
             'manual_forward_continuation_predecessor_invalid')
        prior_request_raw=read(old_operation/'activate/request.json')
        prior_request=json.loads(prior_request_raw)
        prior_inventory=prior_request.get('inventory')
        need(prior_inventory is not None and prior_request.get('variables',{}).get('ultra_lifecycle_id')==expected_old_id,
             'manual_forward_continuation_predecessor_invalid')
        for name in ['execution-mode.json','operator-plan.json','activate/request.json','activate/job.json','activate/receipt.json']:
            path=old_operation/name
            info=path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,
                 'manual_forward_continuation_predecessor_invalid')
        for name in ['job.json','receipt.json']:
            item=json.loads(read(old_operation/'activate'/name))
            need(item.get('schema_version')==1 and item.get('operation')=='upgrade' and
                 item.get('request_sha256')==digest(prior_request_raw) and item.get('binary_sha256')==digest(prior_request_raw),
                 'manual_forward_continuation_predecessor_invalid')
        request=json.loads(evidence['request.json']); job=json.loads(evidence['job.json'])
        receipt=json.loads(evidence['receipt.json']); result=json.loads(evidence['result.json'])
        reqsha=digest(evidence['request.json'])
        variables=request.get('variables',{})
        expected_request=json.dumps({'inventory':prior_inventory,'variables':{'ultra_lock_directory':str(state),
            'ultra_forward_old_id':expected_old_id,'ultra_lifecycle_id':expected_new_id}},sort_keys=True,separators=(',',':')).encode()
        need(evidence['request.json']==expected_request and variables.get('ultra_lock_directory')==str(state) and
             variables.get('ultra_forward_old_id')==expected_old_id and variables.get('ultra_lifecycle_id')==expected_new_id and
             all(item.get('schema_version')==1 and item.get('operation')=='drain-upgrade-workers' and
                 item.get('request_sha256')==reqsha and item.get('binary_sha256')==reqsha for item in (job,receipt)) and
             receipt.get('state')=='succeeded' and receipt.get('code','')=='' and
             receipt.get('result')=={'verified':True,'old_id':expected_old_id,'new_id':expected_new_id} and
             result==receipt.get('result'), 'manual_forward_continuation_handoff_evidence_invalid')
        need(intent.get('schema')==1 and intent.get('proof_sha256')==forward_journal_sha and
             intent.get('old_id')==expected_old_id and intent.get('new_id')==expected_new_id and
             intent.get('drain_directory')==str(stage) and intent.get('request_sha256')==reqsha and
             intent.get('job_sha256')==digest(evidence['job.json']) and
             intent.get('receipt_sha256')==digest(evidence['receipt.json']) and
             intent.get('result_sha256')==digest(evidence['result.json']),
             'manual_forward_continuation_handoff_evidence_invalid')
        prior_candidate={'commit':commit,'version':version,'remote_attempt':attempt,
            'manifest_sha256':manifest_sha,'staged_config_sha256':config_sha,
            'forward_journal_sha256':forward_journal_sha}
    lifecycle=json.loads(read(state/'lifecycle.json'))
    old_id=str(uuid.UUID(bytes=hashlib.sha256(str(state/('upgrade-'+old_version)).encode()).digest()[:16],version=4))
    need(lifecycle.get('id')==old_id and lifecycle.get('phase')=='applying',
         'manual_forward_continuation_lifecycle_changed')
    architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    need(architecture in ['amd64','arm64'])
    lifecycle_retired=state/'lifecycle-retired.json'
    if prior_candidate and (lifecycle_retired.exists() or lifecycle_retired.is_symlink()):
        ledger=json.loads(read(lifecycle_retired))
        handoff=ledger.get('handoff',{})
        ids=ledger.get('ids',[])
        need(not (set(ledger)-{'version','ids','handoff'}) and ledger.get('version')==1 and isinstance(ids,list) and
             len(ids)==len(set(ids)) and all(re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',value) for value in ids) and
             expected_new_id not in ids and
             not (handoff.get('old_id')==expected_old_id and handoff.get('new_id')==expected_new_id),
             'manual_forward_continuation_retirement_changed')
    return {'architecture':architecture,'manifest_sha256':manifest_sha,'config_sha256':config_sha,
            'attempt':attempt,'forward_journal_sha256':forward_journal_sha,'lifecycle_id':old_id,
            'prior_candidate':prior_candidate}
if mode=='continue':
    print(json.dumps(verify_continuation()))
elif mode=='stage':
    pending=Path(tempfile.mkdtemp(prefix='.manual-'+commit+'-',dir=parent))
    try:
        (pending/'release').mkdir(mode=0o700)
        seen=set();rows=None;total=0
        with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
            for member in archive:
                name=member.name
                need(member.isfile() and name not in seen)
                if name=='release/release-manifest.json':
                    need(not seen and member.size<=1048576)
                    raw=archive.extractfile(member).read();need(digest(raw)==manifest_sha)
                    m=json.loads(raw);need(m['source_commit']==commit and m['version']==version and len(m['assets'])==14)
                    rows={}
                    for row in m['assets']:
                        n=row['name'];need(re.fullmatch('[A-Za-z0-9_.-]+',n) and n not in ['.','..','release-manifest.json'] and n not in rows)
                        rows[n]=row
                elif name in ('subscription-probe-url','subscription-probe.sha256'):
                    need(bool(probe_sha) and member.size<=4096)
                    raw=None
                elif name=='forward-operation.json':
                    need(bool(forward_journal_sha) and member.size<=1048576)
                    raw=None
                elif name=='forward-prior-operation.json':
                    need(bool(prior_journal_sha) and member.size<=1048576)
                    raw=None
                elif name in ('baseline/descriptor.json','baseline/operator-journal.json'):
                    need(name not in seen and member.size<=4194304)
                    if not (pending/'baseline').exists():
                        (pending/'baseline').mkdir(mode=0o700)
                    raw=None
                else:
                    need(rows is not None)
                    if name=='install.config': need(member.size<=1048576)
                    else:
                        need(name.startswith('release/') and name[8:] in rows)
                        need(member.size==rows[name[8:]]['size'])
                    total+=member.size;need(total<=2147483648)
                    raw=None
                destination=pending/name
                fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as output:
                    if raw is not None: output.write(raw)
                    else:
                        source=archive.extractfile(member)
                        shutil.copyfileobj(source,output,1048576)
                    output.flush();os.fsync(output.fileno())
                seen.add(name)
        expected={'release/release-manifest.json','install.config'}|{'release/'+n for n in rows}
        if any(name.startswith('baseline/') for name in seen):
            need({'baseline/descriptor.json','baseline/operator-journal.json'} <= seen)
            expected |= {'baseline/descriptor.json','baseline/operator-journal.json'}
        if probe_sha: expected |= {'subscription-probe-url','subscription-probe.sha256'}
        if forward_journal_sha: expected.add('forward-operation.json')
        if prior_journal_sha: expected.add('forward-prior-operation.json')
        need(rows is not None and seen==expected)
        verify(pending)
        for directory in [pending/'release',pending]:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        if root.exists() or root.is_symlink():
            requested_forward_sha=forward_journal_sha
            if requested_forward_sha and not (root/'forward-operation.json').exists():
                forward_journal_sha=''
                verify(root)
                forward_journal_sha=requested_forward_sha
                os.rename(pending/'forward-operation.json',root/'forward-operation.json')
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
            else:
                verify(root)
            if probe_sha and not (root/'subscription-probe-url').exists():
                os.rename(pending/'subscription-probe-url',root/'subscription-probe-url')
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        else:
            os.rename(pending,root)
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine());need(platform.system()=='Linux' and architecture)
        print(json.dumps({'architecture':architecture,'manifest_sha256':manifest_sha,'config_sha256':config_sha,'attempt':attempt,
                          'forward_prior_journal_sha256':prior_journal_sha}))
    finally:
        if pending.exists(): shutil.rmtree(pending)
elif mode=='run':
    verify(root)
    architecture=sys.argv[7];need(architecture in ['amd64','arm64'])
    need(architecture=={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine()))
    action=sys.argv[8];need(action in ['doctor','adoption_check','adoption_apply','upgrade','operator-upgrade','status'])
    retry_failed=len(sys.argv)>9 and sys.argv[9]=='1'
    forward_only=len(sys.argv)>10 and sys.argv[10]=='1'
    continuation=len(sys.argv)>13 and sys.argv[13]=='1'
    need((len(sys.argv)<=14 or (len(sys.argv) in [17,28] and bool(prior_journal_sha))) and
         (len(sys.argv)<=13 or sys.argv[13] in ['0','1']) and
         (not continuation or (forward_only and action=='upgrade' and
          ((bool(prior_journal_sha) and len(sys.argv) in [17,28]) or (not prior_journal_sha and len(sys.argv)==14)))) and
         (len(sys.argv)<=9 or sys.argv[9] in ['0','1']) and
         (len(sys.argv)<=10 or sys.argv[10] in ['0','1']) and
         (not forward_only or (action=='upgrade' and not retry_failed and bool(forward_journal_sha))) and
         (not prior_journal_sha or (action in ['doctor','upgrade','status'] and len(sys.argv) in [17,28] and
          sys.argv[14]==str(parent.parent/('upgrade-'+json.loads(read(root/'forward-prior-operation.json')).get('version',''))) and
          sys.argv[15]==str(root/'forward-prior-operation.json'))),
         'manual_forward_only_invalid')
    if continuation: verify_continuation(17 if len(sys.argv)==28 else None)
    binary=root/'release'/('ultra-install-linux-'+architecture)
    binary.chmod(0o700)
    args={'doctor':['doctor'],'adoption_check':['adopt','--adopt-runtime','--bridge-native','--check','--release-dir',str(root/'release')],
          'adoption_apply':['apply','--adopt-runtime','--bridge-native'],
          'upgrade':['operator-upgrade','--release-dir',str(root/'release'),
              '--source-commit',commit,'--version',version,'--manifest-sha256',manifest_sha,
              '--config-sha256',config_sha] + (['--retry-failed'] if retry_failed else []),
          'status':['status']}[action]
    if action=='upgrade' and forward_only:
        args += ['--job-dir', '/var/lib/ultra-ansible/upgrade-'+version,
                 '--forward-only', '--forward-journal-file', str(root/'forward-operation.json'),
                 '--forward-journal-sha256', forward_journal_sha]
    if action=='upgrade' and prior_journal_sha:
        need(len(sys.argv)>15 and sys.argv[15]==str(root/'forward-prior-operation.json'))
        prior=json.loads(read(root/'forward-prior-operation.json'))
        prior_version=prior.get('version','')
        need(re.fullmatch('[a-f0-9]{40}',prior.get('commit','')) and
             prior_version=='v0.0.'+str(int(prior['commit'],16)) and
             prior.get('remote_attempt') and sys.argv[14]==str(parent.parent/('upgrade-'+prior_version)))
        args += ['--forward-prior-candidate',sys.argv[14],
                 '--forward-prior-journal-file',str(root/'forward-prior-operation.json'),
                 '--forward-prior-journal-sha256',prior_journal_sha]
    if action=='upgrade' and probe_sha:
        need((root/'subscription-probe-url').exists())
        args += ['--subscription-probe-url-file',str(root/'subscription-probe-url')]
    os.chdir(root)
    # Keep the remote lock across exec and strip unchecked installer overrides.
    os.set_inheritable(lock,True)
    environment={k:v for k,v in os.environ.items() if not k.startswith('ULTRA_') and k not in ['DATABASE_URL','PYTHONPATH','PYTHONHOME','ANSIBLE_CONFIG']}
    os.execve(binary,[str(binary)]+args+['--config',str(root/'install.config')],environment)
elif mode=='cleanup':
    verify(root)
    if probe_sha:
        (root/'subscription-probe-url').unlink(missing_ok=True)
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    if forward_journal_sha:
        (root/'forward-operation.json').unlink()
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
else: raise ValueError('remote_action_invalid')
'''


def remote_command(transport, commit, version, manifest_sha, config_sha, attempt, mode, *arguments):
    return transport + [shlex.join(['python3', '-I', '-c', REMOTE_PROGRAM, mode, commit,
                                  version, manifest_sha, config_sha, attempt, *arguments])]


def stage_remote(repo, root, bundle, config, transport, commit, version, manifest_sha, extra_files=None):
    # A bounded on-disk stream avoids keeping release binaries in memory.
    with tempfile.TemporaryFile(dir=root) as stream:
        with tarfile.open(fileobj=stream, mode='w|') as archive:
            manifest = (bundle / 'release-manifest.json').read_bytes()
            require(sha(manifest) == manifest_sha, 'candidate_manifest_changed')
            for name in ['release-manifest.json'] + [row['name'] for row in json.loads(manifest)['assets']]:
                require(Path(name).name == name and not (bundle / name).is_symlink(), 'candidate_asset_name_invalid')
                archive.add(bundle / name, arcname='release/' + name, recursive=False)
            entry = tarfile.TarInfo('install.config')
            entry.size = len(config)
            archive.addfile(entry, io.BytesIO(config))
            for name, data in sorted((extra_files or {}).items()):
                require(name in ('baseline/descriptor.json', 'baseline/operator-journal.json', 'subscription-probe-url', 'subscription-probe.sha256', 'forward-operation.json', 'forward-prior-operation.json'), 'private_archive_path_invalid')
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        stream.seek(0)
        attempt = remote_attempt(config, version)
        result = subprocess.run(remote_command(transport, commit, version, manifest_sha, sha(config), attempt, 'stage',
                                              (extra_files or {}).get('subscription-probe.sha256', b'').decode(),
                                              sha((extra_files or {}).get('forward-operation.json', b'')) if (extra_files or {}).get('forward-operation.json') else '',
                                              sha((extra_files or {}).get('forward-prior-operation.json', b'')) if (extra_files or {}).get('forward-prior-operation.json') else ''),
                                cwd=repo, stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    require(result.returncode == 0, 'bridge_staging_failed')
    receipt = json.loads(result.stdout)
    require(receipt.get('architecture') in ['amd64', 'arm64'] and receipt.get('manifest_sha256') == manifest_sha
            and receipt.get('config_sha256') == sha(config) and receipt.get('attempt') == attempt and
            receipt.get('forward_prior_journal_sha256', '') == (sha(extra_files['forward-prior-operation.json']) if 'forward-prior-operation.json' in (extra_files or {}) else ''),
            'bridge_staging_receipt_invalid')
    return receipt


# Read-only compatibility attestation recovers only a missing input digest.
# The installer still revalidates the frozen plan and exact operation, then
# obtains the broker lease and fleet drain evidence before authorizing mutation.
REMOTE_LEGACY_ATTEST = r'''
import fcntl,hashlib,json,os,re,stat,sys,uuid
from pathlib import Path
def need(ok):
    if not ok: raise ValueError('manual_legacy_operation_unverified')
def digest(raw): return hashlib.sha256(raw).hexdigest()
def private(path, directory=False):
    for ancestor in (path,*path.parents):
        need(not stat.S_ISLNK(ancestor.lstat().st_mode))
    info=path.lstat()
    need(info.st_uid==0 and stat.S_IMODE(info.st_mode)==(0o700 if directory else 0o600))
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
def read(path):
    private(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=4194304)
        raw=stream.read(4194305);need(len(raw)<=4194304)
        return raw
commit,version,attempt,manifest_sha,config_sha_expected=sys.argv[1:]
need(os.geteuid()==0 and re.fullmatch('[a-f0-9]{40}',commit))
need(version=='v0.0.'+str(int(commit,16)))
need(all(re.fullmatch('[a-f0-9]{64}',x) for x in [attempt,manifest_sha,config_sha_expected]))
state=Path('/var/lib/ultra-ansible')
parent=state/'operator-inputs'
private(state,True);private(parent,True)
lock_path=parent/'manual-deploy.lock';private(lock_path)
lock=os.open(lock_path,os.O_RDONLY|os.O_NOFOLLOW)
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
root=parent/('manual-'+commit+'-'+attempt)
private(root,True);private(root/'release',True)
config_sha=digest(read(root/'install.config'));need(config_sha==config_sha_expected)
manifest_raw=read(root/'release/release-manifest.json')
need(digest(manifest_raw)==manifest_sha)
manifest=json.loads(manifest_raw)
need(manifest.get('source_commit')==commit and manifest.get('version')==version)
directory=state/('upgrade-'+version)
private(directory,True);private(directory/'activate',True)
request_raw=read(directory/'activate/request.json');request=json.loads(request_raw)
variables=request['variables']
operation_id=str(uuid.UUID(bytes=hashlib.sha256(str(directory).encode()).digest()[:16],version=4))
need(variables.get('ultra_lifecycle_id')==operation_id and variables.get('ultra_release_manifest_sha256')==manifest_sha)
need(variables.get('ultra_release_manifest')==manifest)
children=request['inventory']['all']['children']
need(len(children['bridge']['hosts'])==1 and len(children['exits']['hosts'])>0)
for name in ['job.json','receipt.json']:
    evidence=json.loads(read(directory/'activate'/name))
    need(evidence.get('schema_version')==1 and evidence.get('operation')=='upgrade' and evidence.get('request_sha256')==digest(request_raw))
print(json.dumps({'schema':1,'commit':commit,'version':version,'remote_attempt':attempt,
                  'manifest_sha256':manifest_sha,'staged_config_sha256':config_sha}))
'''


def attest_legacy_manual_operation(repo, record, transport, binding, current):
    require(transport and record.get('transport_binding') == binding and
            record.get('config_sha256') == sha(current) and
            record.get('remote_attempt') == remote_attempt(current, record['version']),
            'manual_legacy_operation_binding_changed')
    old_root = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + record['commit'] + '-' + record['remote_attempt'])
    values = config_values(current)
    require(values.get('ULTRA_AUTOMATION_VERSION') == record['version'] and
            values.get('ULTRA_AUTOMATION_RELEASE_DIR') == str(old_root / 'release'),
            'manual_legacy_operation_binding_changed')
    # Reproduce the sole staging transformation without opening a local
    # baseline descriptor/journal or inventing a claim about the old workers.
    baseline = old_root / 'baseline/descriptor.json' if values.get('ULTRA_UPGRADE_BASELINE_FILE') else None
    expected_sha = sha(config_candidate(current, record['version'], old_root / 'release', baseline))
    command = transport + [shlex.join(['python3', '-I', '-c', REMOTE_LEGACY_ATTEST,
        record['commit'], record['version'], record['remote_attempt'], record['manifest_sha256'], expected_sha])]
    raw = run(command, repo, 'legacy_operation_attestation', capture=True)
    try:
        receipt = json.loads(raw)
        require(isinstance(receipt, dict) and receipt.get('schema') == 1 and
                all(receipt.get(key) == record[key] for key in ('commit', 'version', 'remote_attempt', 'manifest_sha256')) and
                receipt.get('staged_config_sha256') == expected_sha and
                isinstance(receipt.get('staged_config_sha256'), str) and
                re.fullmatch('[a-f0-9]{64}', receipt['staged_config_sha256']),
                'manual_legacy_operation_receipt_invalid')
    except (TypeError, ValueError):
        raise DeployError('manual_legacy_operation_receipt_invalid') from None
    migrated = dict(record, staged_config_sha256=receipt['staged_config_sha256'])
    validate_dispatched_manual_operation(migrated)
    return migrated


def validate_dispatched_manual_operation(record, allow_legacy=False):
    require(isinstance(record, dict) and record.get('schema') == 1 and
            record.get('mutator_dispatched') is True and record.get('stage') == 'upgrade' and
            re.fullmatch('[a-f0-9]{40}', record.get('commit', '')) and
            re.fullmatch(r'v0\.0\.(0|[1-9][0-9]*)', record.get('version', '')) and
            record.get('version') == 'v0.0.' + str(int(record['commit'], 16)) and
            all(re.fullmatch('[a-f0-9]{64}', record.get(key, '')) for key in
                (('remote_attempt', 'manifest_sha256') if allow_legacy and 'staged_config_sha256' not in record else
                 ('remote_attempt', 'manifest_sha256', 'staged_config_sha256'))),
            'manual_forward_only_requires_dispatched_upgrade')


def valid_completed_remote_cleanup(record, commit, version, adopt):
    """Recognize a completed remote deployment journal that only needs cleanup."""
    if not (isinstance(record, dict) and record.get('schema') == 1 and
            record.get('stage') == 'completed' and record.get('mutator_dispatched') is True and
            record.get('commit') == commit and record.get('version') == version and
            record.get('adopt') is adopt):
        return False
    digests = ('remote_attempt', 'manifest_sha256', 'staged_config_sha256',
               'config_sha256', 'previous_sha256', 'final_config_sha256')
    if not all(isinstance(record.get(key), str) and
               re.fullmatch('[a-f0-9]{64}', record[key]) for key in digests):
        return False
    probe_sha = record.get('probe_sha256', '')
    return isinstance(probe_sha, str) and (probe_sha == '' or re.fullmatch('[a-f0-9]{64}', probe_sha) is not None)


def abandon_dispatched_manual_operation(root, journal, record):
    """Retain one explicitly abandoned failed upgrade without resuming it."""
    validate_dispatched_manual_operation(record)
    archived = root / ('operation.forward-only-abandoned-' + str(time.time_ns()) + '.json')
    atomic_write(archived, json.dumps(record, sort_keys=True).encode())
    journal.unlink()
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return archived


def restore_forward_preflight(root, journal, record, config):
    """Recover a local continuation transition that never dispatched a mutator.

    The new journal is the write-ahead recovery record. Its history and backup
    are durable before it replaces the old journal; canonical config is written
    last. Recovery accepts either side of that config replacement, and can
    itself be interrupted between config restoration and journal restoration.
    """
    require(record.get('schema') == 1 and record.get('forward_only') is True and
            record.get('mutator_dispatched') is False and
            record.get('stage') in ('prepared', 'bridge_staging', 'doctor', 'forward_continuation_preflight'),
            'manual_forward_preflight_recovery_invalid')
    history_name = record.get('forward_retry_history', '')
    require(isinstance(history_name, str) and re.fullmatch(r'operation\.forward-only-retry-[0-9]+\.json', history_name),
            'manual_forward_preflight_recovery_invalid')
    raw = private_file(root / history_name)
    require(sha(raw) == record.get('forward_retry_history_sha256'), 'manual_forward_preflight_history_changed')
    old = json.loads(raw)
    validate_dispatched_manual_operation(old)
    require(old.get('forward_only') is True and old.get('config_sha256') == record.get('previous_sha256') and
            old.get('forward_journal_sha256') == record.get('forward_journal_sha256') and
            old.get('transport_binding') == record.get('transport_binding') and
            old.get('probe_sha256', '') == record.get('probe_sha256', ''), 'manual_forward_preflight_history_changed')
    backup_name = record.get('backup', '')
    require(isinstance(backup_name, str) and re.fullmatch(r'install\.config\.before-' + re.escape(record.get('version', '')) + r'-[0-9]+', backup_name),
            'manual_backup_identity_invalid')
    previous = private_file(root / backup_name)
    require(sha(previous) == record.get('previous_sha256'), 'canonical_backup_changed')
    current = canonical_file(config)
    require(sha(current) in (record.get('previous_sha256'), record.get('config_sha256')),
            'canonical_config_changed_during_operation')
    if current != previous:
        atomic_write(config, previous, preserve_mode=True)
    atomic_write(journal, raw)
    return old


def rollout(repo, root, bundle, commit, version, adopt, config_path=None, retry_failed=False, probe_env_file=None, forward_only=False, continue_forward_only=False):
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(platform.system() == 'Linux' and architecture, 'operator_requires_linux_amd64_or_arm64')
    journal = root / 'operation.json'
    existing_record = json.loads(private_file(journal)) if journal.exists() or journal.is_symlink() else {}
    abandoned_record = None
    config = Path(config_path) if config_path else repo / 'install.config'
    if continue_forward_only:
        require(not adopt and not retry_failed and not forward_only and probe_env_file is None,
                'manual_forward_continuation_arguments_invalid')
    if continue_forward_only and existing_record.get('forward_only') is True and existing_record.get('mutator_dispatched') is False:
        existing_record = restore_forward_preflight(root, journal, existing_record, config)
    if continue_forward_only:
        require(not adopt and not retry_failed and not forward_only and probe_env_file is None,
                'manual_forward_continuation_arguments_invalid')
        validate_dispatched_manual_operation(existing_record)
        require(existing_record.get('forward_only') is True, 'manual_forward_continuation_requires_forward_operation')
        forward_only = True
    elif forward_only:
        require(not adopt and not retry_failed, 'manual_forward_only_upgrade_only')
        require(existing_record.get('forward_only') is not True, 'manual_forward_operation_requires_explicit_continuation')
        validate_dispatched_manual_operation(existing_record, allow_legacy=True)
        abandoned_record = existing_record
        existing_record = {}
    else:
        # Completed journals are recovery metadata, not a request to redispatch
        # the old mutator. Validate and clean them in the recovery block below
        # before applying the active-operation quiescence gate.
        if not valid_completed_remote_cleanup(existing_record, commit, version, adopt):
            require(existing_record.get('forward_only') is not True,
                    'manual_forward_operation_requires_explicit_continuation')
            require_manual_quiescence(existing_record)
    current = canonical_file(config)
    validate_config_policy(current)
    operator_inventory = os.environ.get('ULTRA_OPERATOR_INVENTORY')
    transport, transport_binding = operator_transport(operator_inventory, current) if operator_requested() else (None, None)
    if abandoned_record is not None and 'staged_config_sha256' not in abandoned_record:
        abandoned_record = attest_legacy_manual_operation(repo, abandoned_record, transport, transport_binding, current)
    continuation_proof = None
    continuation_prior_history = None
    continuation_record = dict(existing_record) if continue_forward_only else None
    continuation_journal_raw = private_file(journal) if continue_forward_only else None
    same_candidate = continue_forward_only and existing_record.get('commit') == commit
    if continue_forward_only:
        require(transport and existing_record.get('remote_architecture') in ('amd64', 'arm64') and
                existing_record.get('version') == 'v0.0.' + str(int(existing_record['commit'], 16)) and
                existing_record.get('adopt') is False and existing_record.get('transport_binding') == transport_binding and
                existing_record.get('manifest_sha256') == sha((root / existing_record['version'] / 'release-manifest.json').read_bytes()) and
                existing_record.get('config_sha256') == sha(current) and
                existing_record.get('staged_config_sha256') == sha(current) and
                existing_record.get('remote_attempt') == remote_attempt(current, existing_record['version']),
                'manual_forward_continuation_inputs_changed')
        digest = existing_record.get('forward_journal_sha256', '')
        require(isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest),
                'manual_forward_continuation_proof_changed')
        proofs = [private_file(path) for path in root.glob('operation.forward-only-abandoned-*.json')]
        matches = [raw for raw in proofs if sha(raw) == digest]
        require(len(matches) == 1, 'manual_forward_continuation_proof_changed')
        continuation_proof = matches[0]
        predecessor = json.loads(continuation_proof)
        validate_dispatched_manual_operation(predecessor)
        require(predecessor['commit'] != commit, 'manual_forward_continuation_proof_changed')
        backup_name = existing_record.get('backup', '')
        require(re.fullmatch(r'install\.config\.before-' + re.escape(existing_record['version']) + r'-[0-9]+', backup_name),
                'manual_backup_identity_invalid')
        require(sha(private_file(root / backup_name)) == existing_record.get('previous_sha256'), 'canonical_backup_changed')
        if same_candidate and existing_record.get('forward_prior_journal_sha256'):
            history_name=existing_record.get('forward_retry_history','')
            require(isinstance(history_name,str) and re.fullmatch(r'operation\.forward-only-retry-[0-9]+\.json',history_name),
                    'manual_forward_preflight_history_changed')
            history_raw=private_file(root/history_name)
            require(sha(history_raw)==existing_record.get('forward_retry_history_sha256')==
                    existing_record.get('forward_prior_journal_sha256'),
                    'manual_forward_preflight_history_changed')
            continuation_prior_history=json.loads(history_raw)
            validate_dispatched_manual_operation(continuation_prior_history)
            require(continuation_prior_history.get('forward_only') is True and
                    continuation_prior_history.get('version')!='' and
                    continuation_prior_history.get('forward_journal_sha256')==existing_record.get('forward_journal_sha256'),
                    'manual_forward_preflight_history_changed')
    if transport:
        # plan only parses/validates policy; unlike doctor it never opens the
        # secrets file. Suppress its output because the plan contains inputs.
        run([str(bundle / ('ultra-install-linux-' + architecture)), 'plan', '--config', str(config), '--format', 'json'],
            repo, 'canonical_policy')
    replay = completed_baseline_replay(root, current, version, commit) if transport and not forward_only else None
    if transport:
        if replay:
            attempt = replay[0]
        elif forward_only:
            attempt = remote_attempt(config_candidate(current, version, '/manual-release'), version)
        else:
            attempt = remote_attempt(current, version)
    else:
        attempt = None
    remote_release = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + commit + '-' + (attempt or '')) / 'release'
    manifest_sha = sha((bundle / 'release-manifest.json').read_bytes()) if transport else None
    backup = root / ('install.config.before-' + version + '-' + str(time.time_ns()))
    new = config_candidate(current, version, remote_release if transport else bundle)
    staged_config = new
    if same_candidate:
        require(new == current, 'manual_forward_continuation_inputs_changed')
    baseline_files = {}
    if transport and replay:
        staged_config, baseline_files = replay[1], replay[2]
    elif transport and not forward_only:
        staged_config, baseline_files = stage_upgrade_baseline(current, version, remote_release.parent)
    probe_snapshot = root / 'subscription-probe-url'
    binding = root / ('probe-binding-' + commit + '-' + (attempt or sha(new)))

    def cleanup_probe(record):
        forward_sha = record.get('forward_journal_sha256', '')
        if transport and (record.get('probe_sha256') or forward_sha):
            run(remote_command(transport, commit, version, manifest_sha, record['staged_config_sha256'],
                               record['remote_attempt'], 'cleanup', record.get('probe_sha256', ''),
                               forward_sha, record.get('forward_prior_journal_sha256', '')), repo, 'probe_cleanup')
        probe_snapshot.unlink(missing_ok=True)

    if journal.exists() and not forward_only:
        record = existing_record
        if record.get('stage') == 'completed':
            require(record.get('schema') == 1 and record.get('commit') == commit and
                    record.get('version') == version and record.get('adopt') == adopt and
                    record.get('transport_binding') == transport_binding and
                    record.get('manifest_sha256') == manifest_sha and
                    record.get('mutator_dispatched') is True, 'conflicting_unfinished_manual_operation')
            final_sha = record.get('final_config_sha256', '')
            require(re.fullmatch('[a-f0-9]{64}', final_sha) and
                    sha(current) in (record.get('config_sha256'), final_sha), 'canonical_config_changed_during_operation')
            completed = remove_config_key(current, 'ULTRA_UPGRADE_BASELINE_FILE') if sha(current) != final_sha else current
            require(sha(completed) == final_sha, 'manual_completion_config_changed')
            if completed != current:
                atomic_write(config, completed, preserve_mode=True)
            cleanup_probe(record)
            journal.unlink()
            return

    probe_raw = None
    if not adopt:
        # Retry the frozen credential without reopening .env. Explicit input
        # requires the same bytes and cannot replace a dispatched credential.
        if continue_forward_only and not existing_record.get('probe_sha256'):
            probe_raw = None
        elif existing_record.get('probe_sha256') and probe_env_file is None:
            probe_raw = subscription_probe_input(probe_snapshot)
        else:
            probe_raw = subscription_probe_from_env(Path(probe_env_file) if probe_env_file else config.parent / '.env',
                                                    optional=probe_env_file is None)
    require(not adopt or probe_env_file is None, 'subscription_probe_requires_upgrade')
    probe_sha = sha(probe_raw) if probe_raw is not None else ''
    if binding.exists():
        require(private_file(binding) == probe_sha.encode(), 'manual_operation_probe_changed')
    if existing_record:
        require(existing_record.get('probe_sha256', '') == probe_sha, 'manual_operation_probe_changed')

    def attest_continuation():
        failed = continuation_record
        chain_requested=not same_candidate or bool(failed.get('forward_prior_journal_sha256'))
        chain_args=[]
        prior_journal=None
        prior_journal_sha=''
        if chain_requested:
            if continuation_prior_history is not None:
                history_name=failed.get('forward_retry_history','')
                history_raw=private_file(root/history_name)
            else:
                history_raw=continuation_journal_raw
            prior_journal=json.loads(history_raw)
            prior_journal_sha=sha(history_raw)
            chain_args=[commit,version,manifest_sha,sha(staged_config),attempt,
                        prior_journal['commit'],prior_journal['version'],prior_journal['remote_attempt'],
                        prior_journal['manifest_sha256'],prior_journal['staged_config_sha256'],prior_journal_sha]
        receipt = json.loads(run(remote_command(transport, failed['commit'], failed['version'], failed['manifest_sha256'],
            failed['staged_config_sha256'], failed['remote_attempt'], 'continue', probe_sha,
            failed['forward_journal_sha256'], failed.get('forward_prior_journal_sha256', ''), *chain_args),
            repo, 'forward_continuation_attestation', capture=True))
        predecessor = json.loads(continuation_proof)
        state = Path('/var/lib/ultra-ansible') / ('upgrade-' + predecessor['version'])
        old_id = str(uuid.UUID(bytes=hashlib.sha256(str(state).encode()).digest()[:16], version=4))
        require(receipt.get('forward_journal_sha256') == failed['forward_journal_sha256'] and
                receipt.get('lifecycle_id') == old_id and receipt.get('architecture') == failed['remote_architecture'] and
                receipt.get('manifest_sha256') == failed['manifest_sha256'] and
                receipt.get('config_sha256') == failed['staged_config_sha256'] and
                receipt.get('attempt') == failed['remote_attempt'], 'manual_forward_continuation_receipt_invalid')
        prior=receipt.get('prior_candidate') or {}
        require(prior=={'commit':failed['commit'],'version':failed['version'],
                'remote_attempt':failed['remote_attempt'],'manifest_sha256':failed['manifest_sha256'],
                'staged_config_sha256':failed['staged_config_sha256'],
                'forward_journal_sha256':failed['forward_journal_sha256']} or prior=={},
                'manual_forward_continuation_receipt_invalid')
        chain=receipt.get('chain_attestation')
        if chain is not None:
            require(chain_requested, 'manual_forward_continuation_receipt_invalid')
            state_root=Path('/var/lib/ultra-ansible')
            original_state=state_root/('upgrade-'+predecessor['version'])
            prior_state=state_root/('upgrade-'+prior_journal['version'])
            target_state=state_root/('upgrade-'+version)
            expected_chain={'proof_sha256':failed['forward_journal_sha256'],'prior_journal_sha256':prior_journal_sha,
                'original_id':str(uuid.UUID(bytes=hashlib.sha256(str(original_state).encode()).digest()[:16],version=4)),
                'prior_id':str(uuid.UUID(bytes=hashlib.sha256(str(prior_state).encode()).digest()[:16],version=4)),
                'new_id':str(uuid.UUID(bytes=hashlib.sha256(str(target_state).encode()).digest()[:16],version=4))}
            allowed_phases=('start','restart') if same_candidate else ('start',)
            require(isinstance(chain,dict) and chain.get('phase') in allowed_phases and set(chain)==set(expected_chain)|{
                'phase','prior_evidence_sha256','original_handoff_sha256','original_evidence_sha256','original_retirement_sha256'} and
                all(chain.get(key)==value for key,value in expected_chain.items()) and
                all(isinstance(chain.get(key),str) and re.fullmatch('[a-f0-9]{64}',chain[key]) for key in
                    ('prior_evidence_sha256','original_handoff_sha256','original_evidence_sha256','original_retirement_sha256')),
                'manual_forward_continuation_receipt_invalid')
        return receipt

    continuation_receipt = None
    if continue_forward_only:
        old_binding = root / ('probe-binding-' + continuation_record['commit'] + '-' + continuation_record['remote_attempt'])
        require(old_binding.exists() and private_file(old_binding) == probe_sha.encode(), 'manual_operation_probe_changed')
        continuation_receipt = attest_continuation()
        require(same_candidate or continuation_receipt.get('operation_absent') is not True,
                'manual_forward_continuation_missing_prior_candidate')

    record = existing_record
    try:
        if journal.exists() and (not forward_only or same_candidate):
            record = existing_record
            backup_name = record.get('backup', '')
            require(re.fullmatch(r'install\.config\.before-' + re.escape(version) + r'-[0-9]+', backup_name), 'manual_backup_identity_invalid')
            backup = root / backup_name
            require(record.get('commit') == commit and record.get('version') == version and
                    record.get('adopt') == adopt, 'conflicting_unfinished_manual_operation')
            require(record.get('transport_binding') == transport_binding and record.get('manifest_sha256') == manifest_sha,
                    'manual_operation_transport_or_manifest_changed')
            require(record.get('remote_attempt') == attempt, 'manual_operation_attempt_changed')
            if record.get('stage') == 'prepared' and sha(current) == record.get('previous_sha256'):
                atomic_write(config, new, preserve_mode=True)
            else:
                require(sha(current) == record.get('config_sha256'), 'canonical_config_changed_during_operation')
        else:
            forward_journal_sha = ''
            if continue_forward_only:
                history = root / ('operation.forward-only-retry-' + str(time.time_ns()) + '.json')
                prior_operation_raw = private_file(journal)
                atomic_write(history, prior_operation_raw)
                forward_journal_raw = continuation_proof
                forward_journal_sha = continuation_record['forward_journal_sha256']
                baseline_files['forward-operation.json'] = forward_journal_raw
                if not same_candidate:
                    baseline_files['forward-prior-operation.json'] = prior_operation_raw
            elif forward_only:
                archived_journal = abandon_dispatched_manual_operation(root, journal, abandoned_record)
                forward_journal_raw = private_file(archived_journal)
                forward_journal_sha = sha(forward_journal_raw)
                baseline_files['forward-operation.json'] = forward_journal_raw
            atomic_write(backup, current)
            record = {'schema': 1, 'commit': commit, 'version': version, 'adopt': adopt,
                      'backup': backup.name, 'previous_sha256': sha(current), 'config_sha256': sha(new), 'stage': 'prepared', 'mutator_dispatched': False,
                      'transport_binding': transport_binding, 'manifest_sha256': manifest_sha, 'remote_attempt': attempt,
                      'probe_sha256': probe_sha, 'forward_only': bool(forward_only),
                      'forward_journal_sha256': forward_journal_sha}
            if continue_forward_only:
                record['forward_retry_history'] = history.name
                record['forward_retry_history_sha256'] = sha(private_file(history))
                if not same_candidate:
                    record['forward_prior_journal_sha256'] = sha(prior_operation_raw)
            if probe_raw is not None:
                atomic_write(probe_snapshot, probe_raw)
            atomic_write(journal, json.dumps(record).encode())
            require(canonical_file(config) == current, 'canonical_config_changed_before_update')
            atomic_write(config, new, preserve_mode=True)
        if probe_raw is not None:
            require(sha(subscription_probe_input(probe_snapshot)) == probe_sha, 'manual_operation_probe_changed')
            baseline_files.update({'subscription-probe-url': probe_raw, 'subscription-probe.sha256': probe_sha.encode()})
        if same_candidate:
            require(binding.exists() and private_file(binding) == probe_sha.encode(), 'manual_operation_probe_changed')
        else:
            atomic_write(binding, probe_sha.encode())
        installer = str(bundle / ('ultra-install-linux-' + architecture))
        commands = [('doctor', [installer, 'doctor', '--config', str(config)])]
        if adopt:
            commands += [('adoption_check', [installer, 'adopt', '--config', str(config), '--release-dir', str(bundle), '--adopt-runtime', '--check']),
                         ('adoption_apply', [installer, 'apply', '--config', str(config), '--adopt-runtime'])]
        else:
            commands += [('upgrade', [installer, 'operator-upgrade', '--config', str(config), '--release-dir', str(bundle),
                                      '--source-commit', commit, '--version', version,
                                      '--manifest-sha256', manifest_sha or sha((bundle / 'release-manifest.json').read_bytes()),
                                      '--config-sha256', sha(new)])]
            if forward_only:
                commands[-1][1].append('--forward-only')
            if probe_sha:
                commands[-1][1].extend(['--subscription-probe-url-file', str(probe_snapshot)])
            if retry_failed:
                commands[-1][1].append('--retry-failed')
        commands += [('status', [installer, 'status', '--config', str(config)])]
        if transport:
            require(sha(canonical_file(config)) == record['config_sha256'], 'canonical_config_changed_before_staging')
            if same_candidate:
                staged_receipt = continuation_receipt
            else:
                record['stage'] = 'bridge_staging'
                atomic_write(journal, json.dumps(record).encode())
                staged_receipt = stage_remote(repo, root, bundle, staged_config, transport, commit, version, manifest_sha, baseline_files)
            staged_architecture = staged_receipt.get('architecture')
            staged_config_sha = sha(staged_config)
            require(staged_receipt.get('config_sha256') == staged_config_sha and staged_receipt.get('manifest_sha256') == manifest_sha and
                    staged_receipt.get('attempt') == attempt, 'bridge_staging_receipt_invalid')
            require(record.get('remote_architecture', staged_architecture) == staged_architecture, 'bridge_architecture_changed')
            record['remote_architecture'] = staged_architecture
            record['staged_config_sha256'] = staged_config_sha
        for stage, command in commands:
            if continue_forward_only and not same_candidate and stage == 'upgrade':
                record['stage'] = 'forward_continuation_preflight'
                atomic_write(journal, json.dumps(record).encode())
                attest_continuation()
            if not same_candidate or stage == 'upgrade':
                record['stage'] = stage
            if stage in ('adoption_apply', 'upgrade'):
                record['mutator_dispatched'] = True
            atomic_write(journal, json.dumps(record).encode())
            print('manual-deploy: ' + stage, flush=True)
            if transport:
                stage_forward_only = forward_only and stage == 'upgrade'
                remote_args = [record['remote_architecture'], stage, '1' if retry_failed else '0',
                               '1' if stage_forward_only else '0', probe_sha,
                               record.get('forward_journal_sha256', '') if forward_only else '']
                if same_candidate and stage=='upgrade':
                    remote_args.append('1')
                elif continue_forward_only and not same_candidate:
                    remote_args += ['1' if stage=='upgrade' else '0', '/var/lib/ultra-ansible/upgrade-'+continuation_record['version'],
                                    '/var/lib/ultra-ansible/operator-inputs/manual-'+commit+'-'+attempt+'/forward-prior-operation.json',
                                    record['forward_prior_journal_sha256']]
                if same_candidate and record.get('forward_prior_journal_sha256'):
                    history=continuation_prior_history
                    require(history is not None, 'manual_forward_preflight_history_changed')
                    if stage!='upgrade':
                        remote_args.append('0')
                    remote_args += ['/var/lib/ultra-ansible/upgrade-'+history['version'],
                                    '/var/lib/ultra-ansible/operator-inputs/manual-'+commit+'-'+attempt+'/forward-prior-operation.json',
                                    record['forward_prior_journal_sha256']]
                    if stage=='upgrade':
                        prior_candidate=history
                        remote_args += [commit,version,manifest_sha,sha(staged_config),attempt,
                            prior_candidate['commit'],prior_candidate['version'],prior_candidate['remote_attempt'],
                            prior_candidate['manifest_sha256'],prior_candidate['staged_config_sha256'],
                            record['forward_prior_journal_sha256']]
                elif continue_forward_only and not same_candidate and stage=='upgrade':
                    remote_args += [commit,version,manifest_sha,sha(staged_config),attempt,
                        continuation_record['commit'],continuation_record['version'],continuation_record['remote_attempt'],
                        continuation_record['manifest_sha256'],continuation_record['staged_config_sha256'],
                        record['forward_prior_journal_sha256']]
                command = remote_command(transport, commit, version, manifest_sha, record.get('staged_config_sha256', record['config_sha256']), attempt,
                                         'run', *remote_args)
            run(command, repo, stage)
    except BaseException:
        if continue_forward_only and not same_candidate:
            persisted = json.loads(private_file(journal))
            if persisted.get('mutator_dispatched') is False:
                restore_forward_preflight(root, journal, persisted, config)
                raise
        # Read-only adoption comparison cannot have dispatched a mutating job.
        # After apply/upgrade dispatch, keep exact canonical inputs for recovery.
        if not record.get('mutator_dispatched', False) and record['stage'] in ('bridge_staging', 'doctor', 'adoption_check') and sha(canonical_file(config)) == record['config_sha256']:
            if transport and probe_sha:
                try:
                    run(remote_command(transport, commit, version, manifest_sha, sha(staged_config), attempt,
                                       'cleanup', probe_sha, record.get('forward_journal_sha256', '')), repo, 'probe_cleanup')
                except (DeployError, OSError):
                    print('manual-deploy: private bridge input cleanup unconfirmed; reconcile staged inputs before another attempt', file=sys.stderr)
            previous = private_file(backup)
            require(sha(previous) == record['previous_sha256'], 'canonical_backup_changed')
            atomic_write(config, previous, preserve_mode=True)
            if continue_forward_only:
                # No new mutator was dispatched: restore the failed operation's
                # recovery journal as well as its canonical config and credential.
                atomic_write(journal, private_file(history))
            else:
                journal.unlink()
                probe_snapshot.unlink(missing_ok=True)
            binding.unlink(missing_ok=True)
        else:
            print('manual-deploy: canonical inputs retained; reconcile the unfinished operation with ultra-install status before recovery; do not deploy another commit', file=sys.stderr)
        raise
    completed = remove_config_key(canonical_file(config), 'ULTRA_UPGRADE_BASELINE_FILE')
    record['stage'] = 'completed'
    record['final_config_sha256'] = sha(completed)
    atomic_write(journal, json.dumps(record).encode())
    atomic_write(config, completed, preserve_mode=True)
    cleanup_probe(record)
    journal.unlink()


def main():
    require(__debug__, 'python_optimization_disables_release_validation')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-only', action='store_true', help='verify/build candidate without changing canonical config or remote hosts')
    parser.add_argument('--config', help='canonical install.config path; defaults to install.config in this checkout')
    parser.add_argument('--retry-failed', action='store_true', help='explicitly retry the same failed upgrade after recovery preflight')
    parser.add_argument('--forward-only', action='store_true', help='abandon one dispatched failed upgrade without restoring its unknown relay')
    parser.add_argument('--continue-forward-only', action='store_true', help='continue a failed forward-only deployment before handoff, retaining its original predecessor proof')
    parser.add_argument('--subscription-probe-env-file', help='private local env file; read only ULTRA_SUBSCRIPTION_PROBE_URL (default: .env beside canonical config)')
    arguments = parser.parse_args()
    require(not arguments.subscription_probe_env_file or (not arguments.build_only and os.environ.get('ADOPT') != '1'),
            'subscription_probe_requires_upgrade')
    require(not arguments.continue_forward_only or (not arguments.forward_only and not arguments.retry_failed and
            not arguments.build_only and not arguments.subscription_probe_env_file and os.environ.get('ADOPT') != '1'),
            'manual_forward_continuation_arguments_invalid')
    repo = Path(__file__).resolve().parents[1]
    config = Path(os.path.abspath(arguments.config)) if arguments.config else repo / 'install.config'
    for executable in ['git', 'make', 'go', 'tar', 'sha256sum', 'bash']:
        require(shutil.which(executable), 'missing_prerequisite_' + executable)
    dirty = run(['git', 'status', '--porcelain', '--untracked-files=no'], repo, 'tracked_tree_check', capture=True)
    require(not dirty, 'tracked_tree_dirty_commit_before_deploy')
    commit = run(['git', 'rev-parse', '--verify', 'HEAD'], repo, 'source_commit', capture=True)
    require(re.fullmatch('[0-9a-f]{40}', commit), 'source_commit_invalid')
    require(os.environ.get('ADOPT', '0') in ('0', '1'), 'ADOPT_must_be_0_or_1')
    require(not arguments.retry_failed or os.environ.get('ADOPT') != '1', 'retry_failed_requires_upgrade')
    require(not arguments.forward_only or (not arguments.retry_failed and os.environ.get('ADOPT') != '1' and not arguments.build_only),
            'manual_forward_only_upgrade_only')
    version = 'v0.0.' + str(int(commit, 16))
    root = repo / 'dist' / 'manual'
    require(not (repo / 'dist').is_symlink(), 'dist_must_not_be_symlink')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not root.is_symlink() and root.stat().st_uid == os.geteuid() and
            stat.S_IMODE(root.stat().st_mode) == 0o700, 'manual_state_requires_owned_0700')
    with lock(root / 'deploy.lock'):
        bundle = build_candidate(repo, root, commit, version)
        print('manual-deploy: verified ' + version, flush=True)
        if not arguments.build_only:
            require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], repo, 'tracked_tree_recheck', capture=True), 'tracked_tree_changed_during_build')
            require(run(['git', 'rev-parse', '--verify', 'HEAD'], repo, 'source_commit_recheck', capture=True) == commit, 'HEAD_changed_during_build')
            with lock(canonical_config_lock(config)):
                current = canonical_file(config)
                validate_config_policy(current)
                if operator_requested():
                    for executable in ['ssh', 'ssh-keygen']:
                        require(shutil.which(executable), 'missing_prerequisite_' + executable)
                    operator_transport(os.environ.get('ULTRA_OPERATOR_INVENTORY'), current)
                rollout(repo, root, bundle, commit, version, os.environ.get('ADOPT') == '1', config, arguments.retry_failed,
                        arguments.subscription_probe_env_file, arguments.forward_only, arguments.continue_forward_only)
    print('manual-deploy: complete', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (DeployError, OSError, ValueError, AssertionError, KeyError, TypeError) as error:
        # Contract exceptions can include private paths; only our fixed codes are public.
        print('manual-deploy: ' + (str(error) if isinstance(error, DeployError) else 'local_validation_failed'), file=sys.stderr)
        sys.exit(1)
