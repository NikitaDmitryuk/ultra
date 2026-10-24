#!/usr/bin/env python3
"""Build committed HEAD and replace production non-DB hosts from install.config."""
import argparse
import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile


class DeployError(Exception):
    pass


def run(command, cwd, stage, capture=False, env=None):
    result = subprocess.run(command, cwd=cwd,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, env=env)
    require(result.returncode == 0, stage + '_failed_exit_' + str(result.returncode))
    return result.stdout.decode().strip() if capture else None


def require(condition, code):
    if not condition:
        raise DeployError(code)



def sha(raw):
    return hashlib.sha256(raw).hexdigest()



def canonical_file(path):
    """Read the non-secret canonical deployment config in either supported mode."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise DeployError('canonical_config_requires_owned_regular_readable_file') from None
        raise
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600,
                'canonical_config_requires_owned_regular_readable_file')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            return stream.read()
    finally:
        if descriptor is not None:
            os.close(descriptor)



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
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'manual_lock_not_private')
        require(info.st_uid == os.geteuid(), 'operator_lock_owner_mismatch')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeployError('operator_lock_busy') from None
        yield
    finally:
        os.close(descriptor)



def validate_operator_config(path):
    path = Path(path)
    require(path.is_absolute() and all(not parent.is_symlink() for parent in (path, *path.parents)),
            'canonical_config_symlink_forbidden')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == 0o600, 'canonical_config_requires_operator_0600')



def require_manual_state_directory(path, owner=None):
    if owner is None:
        owner = os.geteuid()
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
            stat.S_IMODE(info.st_mode) == 0o700, 'manual_state_requires_owned_0700')



def canonical_config_lock(path):
    resolved = Path(path).resolve(strict=True)
    return resolved.with_name('.' + resolved.name + '.manual-deploy.lock')



def validate_config_policy(raw):
    # Match installplan.DisallowedDeploymentSecret before creating any backup,
    # temporary input, or remote copy. The exact built Go parser runs below too.
    forbidden = {'TELEGRAM_BOT_TOKEN', 'ULTRA_CUTOVER_SUBSCRIPTION_URL',
                 'ULTRA_SUBSCRIPTION_PROBE_URL', 'ULTRA_RELAY_ADMIN_TOKEN', 'ULTRA_DB_DSN'}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key = line.split('=', 1)[0].strip().upper()
        signing = any(word in key for word in ['MINISIGN', 'SIGNING'])
        private = any(word in key for word in ['SECRET', 'PRIVATE', 'PASSWORD', 'PASSPHRASE'])
        require(key not in forbidden and not key.endswith('_API_KEY') and not (signing and private),
                'canonical_config_contains_forbidden_secret')
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
    # The candidate is built from an isolated clone. Do not inherit a host Go
    # cache that may be outside the writable workspace (for example a
    # read-only ~/.cache/go-build in sandboxed operators).
    go_cache = source / '.manual-go-build-cache'
    require(not go_cache.exists() and not go_cache.is_symlink(), 'manual_go_cache_path_unsafe')
    environment['GOCACHE'] = str(go_cache)
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
        # Some /tmp mounts prohibit executable Go build helpers. Use only our
        # private scratch directory when the operator did not select TMPDIR.
        with contextlib.ExitStack() as scratch:
            if not environment.get('TMPDIR'):
                temporary_build = scratch.enter_context(tempfile.TemporaryDirectory(prefix='.build-tmp-', dir=root))
                environment['TMPDIR'] = str(Path(temporary_build).resolve())
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


def config_candidate(raw, version, release):
    replacements = {'ULTRA_AUTOMATION_VERSION': version,
                    'ULTRA_AUTOMATION_RELEASE_DIR': str(release)}
    seen = set()
    lines = []
    for line in raw.decode().splitlines(keepends=True):
        match = re.match(r'^\s*([A-Z][A-Z0-9_]*)\s*=', line)
        if match and match[1] in {'ULTRA_UPGRADE_BASELINE_FILE', 'DATABASE_DUMP'}:
            continue
        if match and match[1] in replacements:
            key = match[1]
            require(key not in seen, 'duplicate_canonical_release_key')
            seen.add(key)
            line = key + '=' + json.dumps(replacements[key]) + '\n'
        lines.append(line)
    text = ''.join(lines)
    if text and not text.endswith('\n'):
        text += '\n'
    for key, value in replacements.items():
        if key not in seen:
            text += key + '=' + json.dumps(value) + '\n'
    return text.encode()


def replacement_command(bundle, config, commit, state, previous_configs):
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(arch is not None, 'unsupported_operator_architecture')
    command = [str(bundle / ('ultra-install-linux-' + arch)), 'replace-production',
            '--config', str(config), '--source-commit', commit,
            '--manifest-sha256', sha((bundle / 'release-manifest.json').read_bytes()),
            '--state-dir', str(state)]
    for previous_config in previous_configs:
        command.extend(['--previous-config', str(previous_config)])
    return command


def last_deployed_config(root):
    return root / 'last-deployed.config'


def attempted_configs(root):
    directory = root / 'replacement-attempts'
    if not directory.exists() and not directory.is_symlink():
        directory.mkdir(mode=0o700)
    require(not directory.is_symlink(), 'replacement_attempts_must_not_be_symlink')
    require_manual_state_directory(directory)
    paths = sorted(directory.iterdir())
    for path in paths:
        require(re.fullmatch(r'[0-9a-f]{64}\.config', path.name) is not None,
                'replacement_attempt_inventory_invalid')
        canonical_file(path)
    return paths


def remember_attempt(root, raw):
    directory = root / 'replacement-attempts'
    path = directory / (sha(raw) + '.config')
    if not path.exists():
        atomic_write(path, raw)
    return path


def replacement_may_have_mutated(state):
    stage_file = state / 'stage.json'
    if not stage_file.exists():
        return False
    try:
        stage = json.loads(stage_file.read_bytes()).get('stage', '')
    except (OSError, ValueError, AttributeError):
        return True
    return not (stage.startswith('discover-') or stage == 'primary-before-fence')


def main():
    require(__debug__, 'python_optimization_disables_release_validation')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-only', action='store_true',
                        help='build and verify candidate without changing config or hosts')
    parser.add_argument('--config', help='canonical config; defaults to checkout install.config')
    arguments = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    config = Path(os.path.abspath(arguments.config)) if arguments.config else repo / 'install.config'
    if not arguments.build_only:
        validate_operator_config(config)
        validate_config_policy(canonical_file(config))
    for executable in ['git', 'make', 'go', 'tar', 'sha256sum', 'bash']:
        require(shutil.which(executable), 'missing_prerequisite_' + executable)
    require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], repo,
                    'tracked_tree_check', capture=True), 'tracked_tree_dirty_commit_before_deploy')
    commit = run(['git', 'rev-parse', '--verify', 'HEAD'], repo, 'source_commit', capture=True)
    require(re.fullmatch('[0-9a-f]{40}', commit), 'source_commit_invalid')
    version = 'v0.0.' + str(int(commit, 16))
    root = repo / 'dist' / 'manual'
    require(all(not p.is_symlink() for p in (repo / 'dist', root)), 'dist_must_not_be_symlink')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require_manual_state_directory(root)
    with lock(root / 'deploy.lock'):
        bundle = build_candidate(repo, root, commit, version)
        print('manual-deploy: verified ' + version, flush=True)
        if not arguments.build_only:
            require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], repo,
                            'tracked_tree_recheck', capture=True), 'tracked_tree_changed_during_build')
            require(run(['git', 'rev-parse', '--verify', 'HEAD'], repo,
                        'source_commit_recheck', capture=True) == commit, 'HEAD_changed_during_build')
            # The replacement CLI takes the canonical lock and reads these exact
            # candidate inputs before fencing or changing any host.
            with lock(canonical_config_lock(config)):
                raw = canonical_file(config)
                validate_config_policy(raw)
                deployed_config = last_deployed_config(root)
                previous_configs = []
                try:
                    canonical_file(deployed_config)
                except FileNotFoundError:
                    pass
                else:
                    previous_configs.append(deployed_config)
                previous_configs.extend(attempted_configs(root))
                candidate_raw = config_candidate(raw, version, bundle)
                validate_config_policy(candidate_raw)
                attempt_preexisted = (root / 'replacement-attempts' / (sha(candidate_raw) + '.config')).exists()
                attempted = remember_attempt(root, candidate_raw)
                previous_configs.append(attempted)
                previous_configs = list(dict.fromkeys(previous_configs))
                atomic_write(config, candidate_raw)
            # The child takes the canonical lock itself, so only pin config
            # under this lock and release it before starting the replacement.
            state = Path(tempfile.mkdtemp(prefix='replacement-', dir=root))
            state.rmdir()
            command = replacement_command(bundle, config, commit, state, previous_configs)
            try:
                run(command, repo, 'replace_production')
            except DeployError:
                if not attempt_preexisted and not replacement_may_have_mutated(state):
                    attempted.unlink(missing_ok=True)
                raise
            with lock(canonical_config_lock(config)):
                atomic_write(deployed_config, canonical_file(config))
            for path in attempted_configs(root):
                path.unlink()
    print('manual-deploy: complete', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (DeployError, OSError, ValueError, AssertionError, KeyError, TypeError) as error:
        # Tool diagnostics and config errors may contain private input values.
        print('manual-deploy: ' + (str(error) if isinstance(error, DeployError) else 'local_validation_failed'), file=sys.stderr)
        sys.exit(1)
