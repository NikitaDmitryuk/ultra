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
import stat
import subprocess
import sys
import time
import uuid

# This process imports helpers from the frozen bundle before comparing its
# execution digest. Bytecode caches would change that digest before dispatch.
sys.dont_write_bytecode = True


class SafeJournal:
    """Private, bounded observations, outside immutable job/receipt trees."""
    MAX_SESSIONS = 128
    MAX_BYTES = 1024 * 1024
    MAX_EVENT = 4096
    MAX_AGE = 30 * 86400
    EVENTS = {'controller_start', 'controller_succeeded', 'controller_failed',
              'controller_timeout', 'controller_interrupted', 'task_start',
              'task_ok', 'task_skipped', 'task_failed', 'task_unreachable', 'task_retry',
              'logging_degraded'}

    @staticmethod
    def default_root():
        return Path('/var/log/ultra-ansible' if os.geteuid() == 0 else
                    '/tmp/ultra-ansible-diagnostics-' + str(os.geteuid()))

    @staticmethod
    def directory(path):
        path = Path(path)
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError('unsafe_diagnostic_directory')
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unsafe_diagnostic_directory')
        return path

    @staticmethod
    def open_private(path, flags):
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            os.close(fd)
            raise ValueError('unsafe_diagnostic_file')
        return fd

    @classmethod
    def create(cls, root, job_directory, operation):
        root = Path(root)
        if root.resolve().is_relative_to(Path(job_directory).resolve()):
            raise ValueError('diagnostic_directory_inside_job')
        root.mkdir(mode=0o700, exist_ok=True)
        cls.directory(root)
        lock = cls.open_private(root / 'retention.lock', os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            cls.prune(root)
            name = hashlib.sha256(str(Path(job_directory).absolute()).encode()).hexdigest() + '-' + uuid.uuid4().hex
            path = root / name
            path.mkdir(mode=0o700)
            journal = cls(path)
            try:
                journal.emit('controller_start', operation=operation)
            except (OSError, ValueError):
                journal.close()
                raise
            return journal
        finally:
            os.close(lock)

    @classmethod
    def prune(cls, root):
        """Under retention.lock; never unlink an active writer's session."""
        sessions = []
        for path in root.iterdir():
            if not re.fullmatch(r'[a-f0-9]{64}-[a-f0-9]{32}', path.name):
                continue
            cls.directory(path)
            sessions.append((path.stat().st_mtime, path))
        sessions.sort(key=lambda item: item[0])
        remaining = len(sessions)
        for modified, path in sessions:
            if remaining < cls.MAX_SESSIONS and time.time() - modified <= cls.MAX_AGE:
                continue
            fd = cls.open_private(path / 'active.lock', os.O_CREAT | os.O_RDWR)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                children = list(path.iterdir())
                if any(child.name not in {'active.lock', 'write.lock', 'events.jsonl', 'current.json',
                                          'first-failure.json', 'current.next'} for child in children):
                    continue
                # Validate all members before deleting any; never follow links.
                for child in children:
                    member = cls.open_private(child, os.O_RDONLY)
                    os.close(member)
                for child in children:
                    child.unlink()
                path.rmdir()
                remaining -= 1
            finally:
                os.close(fd)
        if remaining >= cls.MAX_SESSIONS:
            raise ValueError('diagnostic_session_limit')

    def __init__(self, path):
        self.path = self.directory(path)
        if not re.fullmatch(r'[a-f0-9]{64}-[a-f0-9]{32}', self.path.name):
            raise ValueError('unsafe_diagnostic_session')
        self.active = self.open_private(self.path / 'active.lock', os.O_CREAT | os.O_RDWR)
        fcntl.flock(self.active, fcntl.LOCK_SH)

    def close(self):
        if self.active is not None:
            os.close(self.active)
            self.active = None

    def repair_tail(self, fd):
        """Under write.lock, discard only a crash/short-write's unfinished line."""
        size = os.fstat(fd).st_size
        if not size:
            return
        tail = os.pread(fd, min(size, self.MAX_EVENT), max(0, size - self.MAX_EVENT))
        if tail.endswith(b'\n'):
            return
        boundary = tail.rfind(b'\n')
        if boundary < 0 and size > self.MAX_EVENT:
            raise ValueError('invalid_diagnostic_tail')
        os.ftruncate(fd, size - len(tail) + boundary + 1)
        os.fsync(fd)

    def emit(self, event, **fields):
        if event not in self.EVENTS:
            raise ValueError('unknown_diagnostic_event')
        # Callers supply only static source metadata and explicitly selected enums.
        value = {'schema_version': 1, 'event': event, 'time_ns': time.time_ns(), **fields}
        raw = (json.dumps(value, separators=(',', ':')) + '\n').encode()
        if len(raw) > self.MAX_EVENT:
            raise ValueError('diagnostic_event_too_large')
        lock = self.open_private(self.path / 'write.lock', os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous = {}
            try:
                fd = self.open_private(self.path / 'current.json', os.O_RDONLY)
                with os.fdopen(fd) as stream:
                    previous = json.loads(stream.read(self.MAX_EVENT + 1))
                if not isinstance(previous, dict):
                    raise ValueError('invalid_diagnostic_checkpoint')
            except FileNotFoundError:
                pass
            log = self.open_private(self.path / 'events.jsonl', os.O_CREAT | os.O_RDWR | os.O_APPEND)
            try:
                self.repair_tail(log)
                truncated = os.fstat(log).st_size + len(raw) > self.MAX_BYTES
                if not truncated:
                    with os.fdopen(log, 'ab', closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(log)
            finally:
                os.close(log)
            checkpoint = dict(value)
            if 'operation' in previous:
                checkpoint['operation'] = previous['operation']
            if 'task' not in checkpoint and 'task' in previous:
                checkpoint['task'] = previous['task']
                checkpoint['host'] = previous.get('host', '')
            checkpoint['truncated'] = truncated or previous.get('truncated', False)
            self.checkpoint(checkpoint)
            if event in ('task_failed', 'task_unreachable') and not fields.get('ignored', False):
                try:
                    fd = self.open_private(self.path / 'first-failure.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                except FileExistsError:
                    existing = self.open_private(self.path / 'first-failure.json', os.O_RDONLY)
                    os.close(existing)
                else:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
        finally:
            os.close(lock)

    def checkpoint(self, value):
        # Never truncate an existing temporary file (including hardlinks).
        temporary = self.path / 'current.next'
        try:
            stale = self.open_private(temporary, os.O_RDONLY)
        except FileNotFoundError:
            pass
        else:
            os.close(stale)
            temporary.unlink()
        fd = self.open_private(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream, separators=(',', ':'))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path / 'current.json')
            directory_fd = os.open(self.path, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    def best_effort(self, event, **fields):
        # Diagnostics must never mask the rollout outcome or prevent worker cleanup.
        try:
            if getattr(self, '_degraded', False):
                self.emit('logging_degraded')
            self.emit(event, **fields)
        except (OSError, ValueError):
            self._degraded = True
            return False
        self._degraded = False
        return True

LOCAL_OPERATIONS = {'handoff-recovery-controller', 'stage-recovery-preparation', 'initialize-recovery-monitor', 'rebuild-retained-primary', 'rebuild-retained-bridge', 'bootstrap-recovery-inspect', 'bootstrap-recovery-tools', 'wait-upgrade-readiness', 'bootstrap-forward-broker', 'contain-upgrade', 'drain-upgrade-workers', 'retain-artifacts', 'resume-schedules', 'rollback-adoption', 'reserve-rolledback-bootstrap', 'resume-adoption', 'lifecycle', 'prepare-controller', 'inspect-upgrade', 'preflight-retry', 'status-automation', 'inspect-release-hosts', 'resume-automation', 'configure-bot', 'configure-exit-operator', 'inspect-bootstrap', 'bootstrap', 'bootstrap-postgres', 'bootstrap-exit', 'bootstrap-bridge', 'bootstrap-automation', 'verify-bootstrap-automation', 'adopt', 'adopt-topology', 'upgrade', 'rollback', 'verify-release', 'commit-release', 'publish-release', 'ingress', 'reconcile', 'restore', 'restore-database', 'restore-peer', 'domain-cutover', 'backend-domain', 'upgrade-dns-migration', 'inspect-upgrade-runtime', 'inspect-upgrade-maintenance', 'upgrade-runtime', 'inspect-upgrade-domains', 'upgrade-domain'}
OPERATIONS = {'configure-exit'} | LOCAL_OPERATIONS

# Operation identities and authorization stay distinct even when implementation
# is shared. Never derive a playbook path from caller-provided input.
PLAYBOOKS = {operation: operation for operation in OPERATIONS}
PLAYBOOKS.update({'configure-exit-operator': 'configure-exit',
                 'domain-cutover': 'ingress'})


def operation_playbook(operation):
    try:
        return PLAYBOOKS[operation] + '.yml'
    except KeyError:
        raise ValueError('unsupported_operation') from None


def bootstrap_ca_name(inventory, alias):
    """Bind CA receipts to the frozen request policy, never self-reported mode."""
    host = inventory.get('all', {}).get('children', {}).get('exits', {}).get('hosts', {}).get(alias)
    if not isinstance(host, dict):
        raise ValueError('invalid_bootstrap_exit_identity')
    domain = host.get('ultra_tunnel_domain', '')
    if not domain:
        return None
    spec = host.get('ultra_spec', {})
    tls = spec.get('splithttp_tls', {})
    if (not isinstance(domain, str) or spec.get('role') != 'exit'
            or spec.get('tunnel_tls_provision') != 'acme_letsencrypt'
            or spec.get('splithttp_host') != domain or tls.get('server_name') != domain
            or tls.get('omit_sni') or tls.get('sni_mode') == 'omit'):
        raise ValueError('invalid_bootstrap_ca_policy')
    return domain


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


def configure_localhost(inventory):
    """Keep delegated controller tasks off remote hosts and home-dir temp paths."""
    if not isinstance(inventory, dict):
        raise ValueError('invalid_inventory')
    all_inventory = inventory.get('all')
    if all_inventory is None and 'all' not in inventory:
        all_inventory = {}
        inventory['all'] = all_inventory
    if not isinstance(all_inventory, dict):
        raise ValueError('invalid_inventory')
    hosts = all_inventory.setdefault('hosts', {})
    if not isinstance(hosts, dict) or 'localhost' in hosts:
        raise ValueError('controller_host_conflict')
    hosts['localhost'] = {
        'ansible_connection': 'local',
        'ansible_remote_tmp': '/dev/shm',
    }


def playbook_environment(directory, bundle, journal=None):
    environment = {
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': str(directory),
        'ANSIBLE_CONFIG': str(Path(bundle) / 'ansible.cfg'),
        # Ansible 2.20 creates module payloads with tempfile.mkdtemp(), which
        # follows TMPDIR instead of ANSIBLE_LOCAL_TEMP. Keep controller scratch
        # on tmpfs; /tmp and ~/.ansible/tmp can be quota-limited.
        'TMPDIR': '/dev/shm',
        'ANSIBLE_LOCAL_TEMP': '/dev/shm',
        'ANSIBLE_NOCOLOR': '1',
        'PYTHONDONTWRITEBYTECODE': '1',
        'ULTRA_ANSIBLE_DIAGNOSTIC_FILE': str(directory / 'diagnostic.json'),
    }
    if journal is not None:
        environment['ULTRA_ANSIBLE_EVENTS_DIR'] = str(journal.path)
        environment['ULTRA_ANSIBLE_SOURCE_ROOT'] = str(Path(bundle).resolve())
    return environment


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


def wait_local_process_group(group, timeout=5):
    """Wait for signalled local workers, ignoring already dead zombie entries.

    This proves only local process-group cleanup, never remote SSH quiescence.
    Linux /proc is required so permission/read failures fail closed.
    """
    deadline = time.monotonic() + timeout
    while True:
        alive = False
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                raw = (path / 'stat').read_text()
            except FileNotFoundError:
                continue
            fields = raw[raw.rindex(')') + 2:].split()
            if int(fields[2]) == group and fields[0] not in ('Z', 'X'):
                alive = True
                break
        if not alive:
            return
        if time.monotonic() >= deadline:
            raise OSError('local_worker_cleanup_unconfirmed')
        time.sleep(.01)


def run_playbook(arguments, bundle, environment, timeout=900):
    # Clean up local SSH workers before recording normal completion. This does
    # not prove remote quiescence after a failed/ambiguous SSH transport.
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
        wait_local_process_group(process.pid)


# A single local controller namespace is shared across jobs, lifecycle leases,
# and caller-selected workspace paths. No CLI/environment root override exists.
EXECUTION_ROOT = Path('/var/lib/ultra-ansible')
READ_ONLY_OPERATIONS = frozenset({
    'inspect-bootstrap', 'bootstrap-recovery-inspect', 'inspect-upgrade',
    'status-automation', 'inspect-release-hosts',
    'inspect-upgrade-maintenance', 'inspect-upgrade-domains', 'wait-upgrade-readiness',
})


def execution_binding(directory, bundle, job, raw):
    digest = hashlib.sha256()
    for path in sorted(Path(bundle).rglob('*')):
        if path.is_symlink():
            raise ValueError('unsafe_execution_bundle')
        if path.is_file():
            digest.update(path.relative_to(bundle).as_posix().encode() + b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode() + b'\n')
    return {'schema_version': 1, 'generation': '', 'operation': job['operation'],
            'job_directory': str(directory),
            'job_sha256': hashlib.sha256(load_private(directory / 'job.json', raw=True)).hexdigest(),
            'request_sha256': job['request_sha256'], 'bundle_sha256': digest.hexdigest(),
            # Hash the frozen request bytes, including its exact inventory and SSH
            # inputs; do not normalize away differences in a retry's inventory.
            'inventory_sha256': hashlib.sha256(raw).hexdigest(),
            'attempt': job.get('attempt', 1)}


def deployment_execution_admission(root):
    operations = root / 'deploy-operations'
    try:
        operations.lstat()
    except FileNotFoundError:
        return
    SafeJournal.directory(operations)
    def read(path, raw=False):
        fd = SafeJournal.open_private(path, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('execution_uncertain_reconciliation_required')
        return data if raw else json.loads(data)
    try:
        current = read(operations / 'current.json')
    except FileNotFoundError:
        return
    identity = current.get('request_sha256')
    if current.get('schema') != 1 or not isinstance(identity, str) or not re.fullmatch('[a-f0-9]{64}', identity):
        raise ValueError('execution_uncertain_reconciliation_required')
    operation = operations / identity
    SafeJournal.directory(operation)
    request = read(operation / 'request.json', raw=True)
    state = read(operation / 'state.json')
    if hashlib.sha256(request).hexdigest() != identity or state.get('schema') != 1 or state.get('request_sha256') != identity or not state.get('stage'):
        raise ValueError('execution_uncertain_reconciliation_required')
    if state.get('state') == 'completed' and state['stage'] == 'status':
        return
    suffix = ':/system.slice/ultra-deploy-' + identity + '.service'
    if state.get('state') != 'running' or not any(line.endswith(suffix) for line in Path('/proc/self/cgroup').read_text().splitlines()):
        raise ValueError('execution_uncertain_reconciliation_required')


def begin_execution(directory, bundle, job, raw, root):
    if job['operation'] in READ_ONLY_OPERATIONS:
        return None
    if root == Path('/var/lib/ultra-ansible'):
        import importlib.util
        source = Path(bundle) / 'library/ultra_execution_containment.py'
        spec = importlib.util.spec_from_file_location('ultra_execution_containment', source)
        containment = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(containment)
        containment.require_containment(directory, os.environ.get('ULTRA_EXECUTION_GENERATION'))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    SafeJournal.directory(root)
    lock = SafeJournal.open_private(root / 'execution-admission.lock', os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deployment_execution_admission(root)
        binding = execution_binding(directory, bundle, job, raw)
        generation = os.environ.get('ULTRA_EXECUTION_GENERATION')
        fence_path = root / 'execution-fence.json'
        try:
            saved = load_private(fence_path)
        except FileNotFoundError:
            saved = None
        if generation:
            binding['generation'] = generation
            if saved != binding:
                raise ValueError('execution_uncertain_reconciliation_required')
            # Consume the admission exactly once. A second controller using the
            # same generation must not dispatch while the first may still run.
        else:
            if saved is not None:
                raise ValueError('execution_uncertain_reconciliation_required')
            legacy_uncertain = False
            # Historical canonical queue jobs must fence newer job IDs too.
            for candidate in sorted(root.iterdir()):
                if candidate.is_dir() and (candidate / 'job.json').exists() and (candidate / 'receipt.json').exists():
                    previous = load_private(candidate / 'receipt.json')
                    old_job = validate(load_private(candidate / 'job.json'))
                    if (previous.get('state') != 'succeeded' and old_job['operation'] not in READ_ONLY_OPERATIONS
                            and not completed_failure(candidate, candidate / 'bundle', old_job,
                                                      load_private(candidate / 'request.json', raw=True), previous)):
                        binding = execution_binding(candidate, candidate / 'bundle', old_job,
                                                    load_private(candidate / 'request.json', raw=True))
                        legacy_uncertain = True
                        break
            if not legacy_uncertain and (directory / 'receipt.json').exists():
                previous = load_private(directory / 'receipt.json')
                legacy_uncertain = previous.get('state') != 'succeeded'
            for claim in directory.glob('execution-dispatch-*.json'):
                prior = load_private(claim)
                prior['generation'] = ''
                if prior == binding:
                    legacy_uncertain = True
            binding['generation'] = uuid.uuid4().hex
            fd = SafeJournal.open_private(fence_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, 'w') as stream:
                json.dump(binding, stream)
                stream.flush()
                os.fsync(stream.fileno())
            parent = os.open(root, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            if legacy_uncertain:
                raise ValueError('legacy_execution_uncertain')
        # Durable per-generation dispatch claim survives SIGKILL, unlike flock.
        claim = directory / ('execution-dispatch-' + binding['generation'] + '.json')
        fd = SafeJournal.open_private(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, 'w') as stream:
            json.dump(binding, stream)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return binding
    finally:
        os.close(lock)


def completed_failure(directory, bundle, job, raw, receipt):
    """A cached failed result is reusable only with its exact terminal proof."""
    try:
        complete = load_private(directory / 'execution-completion.json')
        fence = execution_binding(directory, bundle, job, raw)
        fence['generation'] = receipt['execution_generation']
        if (complete.get('fence') != fence or complete.get('outcome') != 'failed'
                or complete.get('local_cleanup') is not True
                or receipt.get('code') != 'ansible_failed' or receipt.get('exit_code') != 2
                or complete.get('receipt_sha256') != hashlib.sha256(
                    load_private(directory / 'receipt.json', raw=True)).hexdigest()):
            return False
        terminal_raw = load_private(directory / ('execution-terminal-' + fence['generation'] + '.json'), raw=True)
        terminal = json.loads(terminal_raw)
        return (complete.get('terminal_sha256') == hashlib.sha256(terminal_raw).hexdigest()
                and terminal.get('fence') == fence and terminal.get('outcome') == 'failed'
                and type(terminal.get('contacted_hosts')) is int and terminal['contacted_hosts'] > 0
                and terminal.get('pending_tasks') == 0 and terminal.get('unreachable_hosts') == 0
                and terminal.get('unmanaged_async') is False)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def finish_execution(directory, bundle, root, fence, outcome="succeeded", terminal=None):
    if fence is None:
        return
    current = execution_binding(directory, bundle, validate(load_private(directory / 'job.json')),
                                load_private(directory / 'request.json', raw=True))
    current['generation'] = fence['generation']
    if current != fence:
        raise ValueError('execution_completion_conflict')
    if root == Path('/var/lib/ultra-ansible'):
        import importlib.util
        source = Path(bundle) / 'library/ultra_execution_containment.py'
        spec = importlib.util.spec_from_file_location('ultra_execution_containment', source)
        containment = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(containment)
        proof = containment.completion_containment(directory, fence)
        # Transient proof is finalized by Go only after systemd stop/drain.
        atomic(directory / 'execution-containment.json', proof)
    atomic(directory / 'execution-completion.json', {
        'fence': fence, 'local_cleanup': True, 'outcome': outcome,
        'terminal_sha256': hashlib.sha256(terminal).hexdigest() if terminal else '',
        'receipt_sha256': hashlib.sha256(load_private(directory / 'receipt.json', raw=True)).hexdigest(),
    })
    if os.environ.get('ULTRA_EXECUTION_GENERATION') or (root == Path('/var/lib/ultra-ansible') and proof['mode'] == 'transient'):
        return  # The Go dispatcher validates the completion before retiring it.
    lock = SafeJournal.open_private(root / 'execution-admission.lock', os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if load_private(root / 'execution-fence.json') != fence:
            raise ValueError('execution_completion_conflict')
        if root == Path('/var/lib/ultra-ansible'):
            # Preserve the already-observed census for historical rc2 retry;
            # its exact receipt also closes a crash before fence unlink.
            atomic(directory / ('execution-drain-' + fence['generation'] + '.json'), {
                'proof': proof, 'completion_sha256': hashlib.sha256(
                    load_private(directory / 'execution-completion.json', raw=True)).hexdigest(),
            })
        (root / 'execution-fence.json').unlink()
        parent = os.open(root, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(lock)


def execute(directory, executable, bundle, diagnostics_root=None, execution_root=None):
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
        binary = directory / 'ultra-relay'
        if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != job['binary_sha256']:
            raise ValueError('binary_changed')
    configure_localhost(inventory)
    atomic(directory / 'inventory.json', inventory)
    atomic(directory / 'variables.json', variables)
    write_unsafe_variables(directory / 'variables.yml', variables)
    write_unsafe_variables(directory / 'inventory.yml', inventory)
    receipt = directory / 'receipt.json'
    if receipt.exists():
        saved = load_private(receipt)
        if saved.get('request_sha256') != job['request_sha256'] or saved.get('binary_sha256') != job['binary_sha256']:
            raise ValueError('receipt_conflict')
        if saved.get('state') == 'succeeded':
            return saved
        if saved.get('state') == 'failed':
            if job['operation'] not in READ_ONLY_OPERATIONS and not completed_failure(directory, bundle, job, raw, saved):
                begin_execution(directory, bundle, job, raw, execution_root or EXECUTION_ROOT)
            return saved  # Explicit retry creates a new attempt, never treats a failure as success.
    result_path = directory / 'result.json'
    result_path.unlink(missing_ok=True)
    fence = begin_execution(directory, bundle, job, raw, execution_root or EXECUTION_ROOT)
    journal = SafeJournal.create(diagnostics_root or SafeJournal.default_root(), directory, job['operation'])
    state = {**job, 'state': 'running', 'started_at': int(time.time())}
    if fence is not None:
        state['execution_generation'] = fence['generation']
    atomic(receipt, state)
    environment = playbook_environment(directory, bundle, journal)
    terminal_path = directory / ('execution-terminal-' + fence['generation'] + '.json') if fence else None
    if fence:
        environment['ULTRA_EXECUTION_BINDING'] = json.dumps(fence)
        environment['ULTRA_EXECUTION_TERMINAL_FILE'] = str(terminal_path)
    normal_failure_proof = None
    observation = 'controller_failed'
    try:
        exit_code = run_playbook([
            str(executable), '-i', str(directory / 'inventory.yml'),
            str(Path(bundle) / 'playbooks' / operation_playbook(job['operation'])),
            '--extra-vars', '@' + str(directory / 'variables.yml'),
        ], bundle, environment, timeout=700 if job['operation'] == 'wait-upgrade-readiness' else 900)
        if exit_code:
            if (directory / 'diagnostic.json').exists():
                state['diagnostic'] = load_private(directory / 'diagnostic.json')
            state.update(state='failed', code='ansible_failed', exit_code=exit_code)
            if exit_code == 2 and fence and terminal_path.exists():
                candidate_raw = load_private(terminal_path, raw=True)
                candidate = json.loads(candidate_raw)
                if (candidate.get('fence') == fence and candidate.get('outcome') == 'failed'
                        and type(candidate.get('contacted_hosts')) is int and candidate['contacted_hosts'] > 0
                        and candidate.get('pending_tasks') == 0 and candidate.get('unreachable_hosts') == 0
                        and candidate.get('unmanaged_async') is False):
                    normal_failure_proof = candidate_raw
        else:
            result = load_private(result_path)
            ca_name = (bootstrap_ca_name(inventory, variables.get('ultra_bootstrap_exit_host'))
                       if job['operation'] == 'bootstrap-exit' else None)
            if ca_name is not None:
                if ('cert_pin' in result or result.get('tls_auth') != 'ca'
                        or result.get('tls_server_name') != ca_name):
                    raise ValueError('invalid_bootstrap_ca_receipt')
            elif job['operation'] in ('configure-exit', 'bootstrap-exit') and not re.fullmatch(r'[a-f0-9]{64}', result.get('cert_pin', '')):
                raise ValueError('invalid_certificate_pin')
            if job['operation'] in ('bootstrap-postgres', 'bootstrap-exit', 'bootstrap-bridge') and result.get('verified') is not True:
                raise ValueError('invalid_bootstrap_component_acknowledgement')
            if job['operation'] == 'bootstrap-exit' and result.get('exit_host') != variables.get('ultra_bootstrap_exit_host'):
                raise ValueError('invalid_bootstrap_exit_identity')
            state.update(state='succeeded', result=result)
            observation = 'controller_succeeded'
    except InterruptedError:
        # Local cleanup does not establish remote quiescence. Keep the durable
        # fence closed for explicit reconciliation after cancellation.
        state.update(state='running', code='interrupted')
        observation = 'controller_interrupted'
    except subprocess.TimeoutExpired:
        state.update(state='failed', code='execution_failed')
        observation = 'controller_timeout'
    except (OSError, ValueError, subprocess.SubprocessError):
        state.update(state='failed', code='execution_failed')
    if state['state'] != 'running':
        state['finished_at'] = int(time.time())
    journal.best_effort(observation)
    journal.close()
    atomic(receipt, state)
    if state['state'] == 'succeeded' or normal_failure_proof is not None:
        finish_execution(directory, bundle, execution_root or EXECUTION_ROOT, fence, state['state'], normal_failure_proof)
    return state


def main():
    def interrupted(_signum, _frame):
        raise InterruptedError('controller_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser()
    parser.add_argument('--job', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--executable', required=True)
    parser.add_argument('--diagnostics-root', type=Path, default=None)
    args = parser.parse_args()
    directory = Path(args.job)
    fd = os.open(directory / 'execution.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            value = execute(directory, args.executable, args.bundle, args.diagnostics_root)
        except (ValueError, OSError, KeyError, TypeError):
            raise SystemExit('invalid_job') from None
    raise SystemExit(0 if value['state'] == 'succeeded' else 1)


if __name__ == '__main__':
    main()
