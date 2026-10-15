#!/usr/bin/python
"""Fail closed on DB replacement, missing destructive migrations or live writers."""
import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import subprocess
import tempfile
import time
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

from ansible.module_utils.basic import AnsibleModule


def document(path):
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 1048576:
        raise ValueError('database_preservation_evidence_invalid')
    return json.loads(path.read_text())


def atomic(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if path.parent.is_symlink() or not path.parent.is_dir() or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('database_preservation_directory_invalid')
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.database-')
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def database_selection(spec, database):
    dsn = spec['database']['dsn']
    parsed = urlsplit(dsn)
    if (parsed.scheme not in ('postgres', 'postgresql') or parsed.hostname not in ('localhost', '127.0.0.1', '::1')
            or parsed.port != 25432 or unquote(parsed.path) != '/' + database
            or not parsed.username or parsed.fragment
            or set(parse_qs(parsed.query, strict_parsing=True)) - {'sslmode', 'connect_timeout', 'application_name'}):
        raise ValueError('database_identity_migration_required')
    return hashlib.sha256(dsn.encode()).hexdigest()


def validate_observation(value):
    rows = value['migrations']
    versions = [row['version'] for row in rows]
    if (not isinstance(rows, list) or not 8 <= len(rows) <= 10000
            or any(type(version) is not int for version in versions)
            or versions != list(range(1, len(rows) + 1))
            or any(not isinstance(row.get('applied_at'), str) or not row['applied_at'] for row in rows)
            or not re.fullmatch(r'[0-9]+', value['cluster']) or value['cluster'] == '0'
            or type(value['oid']) is not int or value['oid'] <= 0 or value.get('primary') is not True):
        raise ValueError('database_preservation_schema_migration_required')
    return value


def observe(module, database):
    query = """SELECT json_build_object(
      'cluster', (SELECT system_identifier::text FROM pg_control_system()),
      'database', current_database(),
      'primary', NOT pg_is_in_recovery(),
      'oid', (SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
      'migrations', (SELECT json_agg(json_build_object('version',version,
          'applied_at',applied_at AT TIME ZONE 'UTC') ORDER BY version) FROM public.schema_migrations),
      'clients', (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
          AND backend_type='client backend' AND pid != pg_backend_pid()))"""
    sys.path.insert(0, '/opt/ultra-recovery')
    import db_connection
    parsed = db_connection.dsn_from_runtime(database)
    with db_connection.pgpass('/var/lib/ultra-recovery', parsed) as environment:
        result = subprocess.run(db_connection.connection_args(parsed, database, 'psql') + ['-XAtq', '-v', 'ON_ERROR_STOP=1', '-c', query], env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=8)
        code, output = result.returncode, result.stdout
    if code or len(output) > 1048576:
        raise ValueError('database_preservation_inspection_failed')
    value = validate_observation(json.loads(output))
    if value.get('database') != database:
        raise ValueError('database_identity_migration_required')
    return value


def same_database(baseline, current):
    if any(baseline.get(key) != current.get(key) for key in ('cluster', 'database', 'oid', 'migrations', 'selection')):
        raise ValueError('database_preservation_identity_or_history_changed')


def stopped(module):
    for unit in ('ultra-bot.service', 'ultra-relay.service', 'ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'):
        code, output, _ = module.run_command(['systemctl', 'show', '--property=LoadState', '--property=ActiveState', '--property=MainPID', '--property=ControlPID', unit])
        values = dict(line.split('=', 1) for line in output.splitlines())
        if code or values != {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'}:
            raise ValueError('database_preservation_writers_not_stopped')


def validate_processes(processes, own_pid, allowed=frozenset()):
    """Only direct argv tokens identify workers; never emit their arguments."""
    for pid, arguments in processes:
        if pid == own_pid or pid in allowed:
            continue
        if playbook_argv(arguments) is not None:
            raise ValueError('database_preservation_legacy_worker_unfenced')
        for argument in arguments:
            name = argument.rsplit(b'/', 1)[-1]
            if (name.startswith(b'ultra-install') or b'AnsiballZ_' in argument or b'/ansible-tmp-' in argument):
                raise ValueError('database_preservation_legacy_worker_unfenced')


def private_bytes(path):
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('database_preservation_controller_evidence_invalid')
    with path.open('rb') as source:
        value = source.read(1048577)
    if len(value) > 1048576:
        raise ValueError('database_preservation_controller_evidence_invalid')
    return value


def option(arguments, name):
    matches = [index for index, argument in enumerate(arguments) if argument == name]
    if len(matches) != 1 or matches[0] + 1 >= len(arguments):
        raise ValueError('database_preservation_controller_binding_invalid')
    return os.fsdecode(arguments[matches[0] + 1])


def playbook_argv(argv):
    """Recognize only the executable position, including Linux shebang argv."""
    if argv and argv[0].rsplit(b'/', 1)[-1] == b'ansible-playbook':
        return argv
    if (len(argv) > 1 and re.fullmatch(rb'python(?:3(?:\.[0-9]+)?)?', argv[0].rsplit(b'/', 1)[-1])
            and argv[1].rsplit(b'/', 1)[-1] == b'ansible-playbook'):
        return argv[1:]
    return None


def broker_identity(pid, argv, metadata, run_command,
                    unit_path=Path('/etc/systemd/system/ultra-ansible-controller.service')):
    """A broker is exempt only as the exact root systemd main process."""
    fail = 'worker_drain_broker_unverified'
    if (len(argv) != 4 or not re.fullmatch(rb'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}/ultra-install', argv[0])
            or argv[1:3] != [b'ansible-controller', b'--executable']
            or argv[3] != argv[0].rsplit(b'/', 1)[0] + b'/venv/bin/ansible-playbook'
            or metadata['uid'] != 0 or metadata['parent'] != 1):
        raise ValueError(fail)
    properties = ['Id', 'MainPID', 'ControlGroup', 'User', 'Group', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths']
    code, output, _ = run_command(['systemctl', 'show'] + ['--property=' + key for key in properties]
                                  + ['--', 'ultra-ansible-controller.service'])
    if code or len(output) > 65536:
        raise ValueError(fail)
    rows = [line.split('=', 1) for line in output.splitlines()]
    if any(len(row) != 2 for row in rows) or len(rows) != len(properties) or len(dict(rows)) != len(rows):
        raise ValueError(fail)
    values = dict(rows)
    expected = {'Id': 'ultra-ansible-controller.service', 'MainPID': str(pid),
                'ControlGroup': '/system.slice/ultra-ansible-controller.service', 'User': 'root', 'Group': 'root',
                'ActiveState': 'active', 'SubState': 'running', 'FragmentPath': str(unit_path), 'DropInPaths': ''}
    if values != expected or metadata.get('cgroup') != b'0::' + expected['ControlGroup'].encode() + b'\n':
        raise ValueError(fail)
    info = unit_path.lstat()
    if unit_path.is_symlink() or not unit_path.is_file() or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
        raise ValueError(fail)
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(unit_path.read_text())
        service = parser['Service']
        command = [os.fsencode(value) for value in shlex.split(service['ExecStart'])]
        if (command != argv or service['User'] != 'root' or service['Group'] != 'root'
                or service['KillMode'] != 'control-group' or service.get('ExecStartPre') or service.get('ExecStartPost')):
            raise ValueError(fail)
    except (configparser.Error, KeyError):
        raise ValueError(fail) from None
    # This process is the broker, not a playbook worker. service.go's dispatch
    # loop calls gate.jobLock before Execute: applying rejects all queued jobs.
    # The caller holds the old applying lease/OFD through this census and atomic
    # supersession, so a broker restart also cannot acquire an independent lock.
    return True


def controller_job(arguments, operation, phase, transaction):
    """Bind a live controller to exact frozen inputs, not its displayed name."""
    argv = playbook_argv(arguments)
    if argv is None:
        raise ValueError('database_preservation_controller_binding_invalid')
    inventory = Path(option(argv, b'-i'))
    directory = inventory.parent
    root = directory.parent
    if not directory.is_absolute() or directory.resolve() != directory:
        raise ValueError('database_preservation_controller_binding_invalid')
    for path in (directory, root):
        info = path.lstat()
        if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('database_preservation_controller_evidence_invalid')
    expected_id = str(uuid.UUID(bytes=hashlib.sha256(str(root).encode()).digest()[:16], version=4))
    if expected_id != operation:
        raise ValueError('database_preservation_controller_binding_invalid')
    raw = private_bytes(directory / 'request.json')
    request = json.loads(raw)
    job = json.loads(private_bytes(directory / 'job.json'))
    receipt = json.loads(private_bytes(directory / 'receipt.json'))
    digest = hashlib.sha256(raw).hexdigest()
    variables = request['variables']
    expected_operation = 'upgrade-runtime' if phase == 'baseline' else 'upgrade'
    if (job.get('schema_version') != 1 or job.get('operation') != expected_operation
            or job.get('request_sha256') != digest or receipt.get('request_sha256') != digest
            or receipt.get('binary_sha256') != job.get('binary_sha256') or receipt.get('state') != 'running'
            or receipt.get('operation') != expected_operation or type(receipt.get('started_at')) is not int
            or variables.get('ultra_lifecycle_id') != operation):
        raise ValueError('database_preservation_controller_binding_invalid')
    if variables.get('ultra_forward_only') is not True:
        raise ValueError('database_preservation_controller_binding_invalid')
    if phase == 'baseline':
        if (variables.get('ultra_runtime_action') != 'prepare'
                or variables['ultra_runtime_probe_requests']['bridge']['request']['transaction'] != transaction):
            raise ValueError('database_preservation_controller_binding_invalid')
        generation = int(transaction.rsplit('-', 1)[-1])
        stage = 'runtime-prepare' + ('-generation-' + str(generation) if generation != 1 else '')
    else:
        if variables.get('ultra_forward_only') is not True:
            raise ValueError('database_preservation_controller_binding_invalid')
        stage = 'activate'
    expected = [argv[0], b'-i', os.fsencode(directory / 'inventory.yml'),
                os.fsencode(directory / 'bundle/playbooks' / (expected_operation + '.yml')),
                b'--extra-vars', b'@' + os.fsencode(directory / 'variables.yml')]
    if directory.name != stage or argv != expected or inventory != directory / 'inventory.yml':
        raise ValueError('database_preservation_controller_binding_invalid')
    return directory, receipt['started_at']


def controller_allowances(processes, metadata, operation, phase, transaction, own_pid, verify_broker=None):
    bound, brokers = {}, set()
    for pid, arguments in processes:
        if len(arguments) > 1 and arguments[0].rsplit(b'/', 1)[-1].startswith(b'ultra-install') and arguments[1] == b'ansible-controller':
            if verify_broker is None or not verify_broker(pid, arguments, metadata[pid]):
                raise ValueError('database_preservation_broker_unverified')
            brokers.add(pid)
        if playbook_argv(arguments) is not None:
            directory, _ = controller_job(arguments, operation, phase, transaction)
            if metadata[pid]['uid'] != 0:
                raise ValueError('database_preservation_controller_process_unprivileged')
            bound[pid] = directory
    if len(brokers) != 1:
        raise ValueError('database_preservation_broker_unverified')
    # Every permitted playbook process belongs to one exact frozen request and
    # one connected current tree. Same-second stale roots cannot join that tree.
    roots = [pid for pid in bound if metadata[pid]['parent'] not in bound]
    if len(roots) != 1 or len(set(bound.values())) != 1:
        raise ValueError('database_preservation_controller_ambiguous')
    allowed = set(bound) | brokers
    current = metadata[roots[0]]['parent']
    seen, installers = set(), []
    arguments_by_pid = dict(processes)
    while current in metadata and current not in seen:
        seen.add(current)
        arguments = arguments_by_pid[current]
        if arguments and arguments[0].rsplit(b'/', 1)[-1].startswith(b'ultra-install'):
            if (metadata[current]['uid'] != 0 or len(arguments) < 2 or arguments[1] != b'operator-upgrade' or b'--forward-only' not in arguments
                    or Path(option(arguments, b'--job-dir')) != bound[roots[0]].parent):
                raise ValueError('database_preservation_controller_binding_invalid')
            installers.append(current)
            allowed.add(current)
        current = metadata[current]['parent']
    if len(installers) != 1:
        raise ValueError('database_preservation_controller_binding_invalid')
    current, seen = own_pid, set()
    while current in metadata and current not in seen and current not in bound:
        seen.add(current)
        current = metadata[current]['parent']
    if current not in bound:
        raise ValueError('database_preservation_module_unbound')
    allowed.update(seen)
    return allowed


def workers_drained(root=Path('/proc'), own_pid=None, operation=None, phase=None, transaction='', run_command=None):
    """Bounded, fail-closed bridge process census; do not read environments."""
    if own_pid is None:
        own_pid = os.getpid()
    processes = []
    metadata = {}
    scanned = 0
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        scanned += 1
        if scanned > 16384:
            raise ValueError('database_preservation_process_census_overflow')
        try:
            if operation is not None:
                before = (entry / 'stat').read_bytes()
                if len(before) > 4096:
                    raise ValueError('database_preservation_process_evidence_invalid')
            with (entry / 'cmdline').open('rb') as source:
                command = source.read(65537)
        except FileNotFoundError:
            continue  # A process that has exited cannot resume a DB writer.
        if len(command) > 65536:
            raise ValueError('database_preservation_process_evidence_invalid')
        processes.append((int(entry.name), command.rstrip(b'\0').split(b'\0')))
        if operation is not None:
            # /proc/<pid>/stat comm can contain spaces and ')' characters.
            try:
                cgroup = (entry / 'cgroup').read_bytes()
                after = (entry / 'stat').read_bytes()
                if len(after) > 4096 or len(cgroup) > 65536:
                    raise ValueError('database_preservation_process_evidence_invalid')
                fields = after.rsplit(b')', 1)[1].split()
                previous = before.rsplit(b')', 1)[1].split()
                if fields[19] != previous[19] or fields[1] != previous[1]:
                    raise ValueError('database_preservation_process_identity_changed')
                metadata[int(entry.name)] = {'parent': int(fields[1]), 'start': int(fields[19]), 'uid': entry.stat().st_uid, 'cgroup': cgroup}
            except FileNotFoundError:
                processes.pop()
    allowed = set()
    if operation is not None:
        allowed = controller_allowances(processes, metadata, operation, phase, transaction, own_pid,
            lambda pid, argv, info: broker_identity(pid, argv, info, run_command))
    validate_processes(processes, own_pid, allowed)


def delivered(baseline, config, policy, topology, status, receipt, now):
    primary = topology['primary']
    nodes = [node for node in topology['node_metadata'] if node['id'] == primary]
    targets = [target for target in policy['destinations'] if target.get('id') == primary and target.get('required') is True]
    if (len(nodes) != 1 or len(targets) != 1
            or nodes[0]['provider'].lower() == config['bridge_provider'].lower()
            or targets[0]['host'] != nodes[0]['host'] or nodes[0]['host'] not in receipt['destinations']
            or primary not in receipt['delivered_target_ids'] or policy.get('independent') is not True
            or status.get('state') != 'ready' or status.get('independent') is not True or status.get('primary') != primary
            or receipt.get('source') != 'bridge' or receipt.get('dump_verified') is not True
            or not baseline['capture_after'] < receipt['snapshot_at'] <= now
            or now - receipt['snapshot_at'] > 300 or receipt == baseline['previous_delivery']
            or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('backup_sha256', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('artifact_sha256', ''))):
        raise ValueError('database_preservation_independent_dump_required')


def main():
    module = AnsibleModule(argument_spec={
        'id': {'type': 'str', 'required': True},
        'phase': {'type': 'str', 'required': True, 'choices': ['baseline', 'stopped', 'capture-ready']},
        'transaction': {'type': 'str', 'default': ''},
    }, supports_check_mode=True)
    try:
        operation = module.params['id']
        if os.geteuid() != 0 or not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', operation):
            raise ValueError('database_preservation_operation_invalid')
        lease = document(Path('/var/lib/ultra-ansible/lifecycle.json'))
        if lease.get('id') != operation or lease.get('phase') != 'applying':
            raise ValueError('database_preservation_lease_invalid')
        workers_drained(operation=operation, phase=module.params['phase'], transaction=module.params.get('transaction', ''), run_command=module.run_command)
        config = document(Path('/etc/ultra-recovery/reconcile.json'))
        database = config['database']
        if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
            raise ValueError('database_preservation_database_invalid')
        if document(Path('/etc/ultra-recovery/backup.json'))['database'] != database:
            raise ValueError('database_identity_migration_required')
        spec = document(Path('/etc/ultra-relay/spec.json'))
        selection = database_selection(spec, database)
        # An override can make the bot write to a different DB. Refuse rather
        # than parse shell/systemd expansion or consult inherited environment.
        for name in ('/etc/ultra-relay/environment', '/etc/ultra-relay/bot.env'):
            path = Path(name)
            if path.exists():
                info = path.lstat()
                if path.is_symlink() or not path.is_file() or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 1048576:
                    raise ValueError('database_preservation_environment_invalid')
                if re.search(r'(?m)^\s*(?:export\s+)?ULTRA_DB_DSN\s*=', path.read_text()):
                    raise ValueError('database_identity_override_migration_required')
        if module.params['phase'] == 'baseline':
            transaction = module.params['transaction']
            if not re.fullmatch(re.escape(operation) + r'-runtime-[1-9][0-9]{0,3}', transaction):
                raise ValueError('database_preservation_transaction_invalid')
            journal = document(Path('/etc/ultra-recovery/runtime-transactions') / (transaction + '.json'))
            if journal.get('Version') != 1 or journal.get('Transaction') != transaction or journal.get('State') != 'prepared':
                raise ValueError('database_preservation_candidate_invalid')
            for name in ('Before', 'Candidate'):
                image = journal[name][0]
                if image.get('Exists') is not True or database_selection(json.loads(base64.b64decode(image['Data'], validate=True)), database) != selection:
                    raise ValueError('database_identity_migration_required')
                environment = base64.b64decode(journal[name][1]['Data'], validate=True).decode()
                if re.search(r'(?m)^\s*(?:export\s+)?ULTRA_DB_DSN\s*=', environment):
                    raise ValueError('database_identity_override_migration_required')
        else:
            stopped(module)
        current = observe(module, database)
        current['selection'] = selection
        if module.params['phase'] != 'baseline' and current['clients'] != 0:
            raise ValueError('database_preservation_clients_not_drained')
        path = Path('/var/lib/ultra-ansible/upgrade') / operation / 'database-preservation.json'
        if path.exists() or path.is_symlink():
            baseline = document(path)
            same_database(baseline, current)
        elif module.params['phase'] != 'baseline':
            raise ValueError('database_preservation_baseline_missing')
        elif not module.check_mode:
            atomic(path, current)
        if module.params['phase'] == 'stopped' and not module.check_mode:
            baseline['capture_after'] = int(time.time())
            baseline['previous_delivery'] = document(Path('/var/lib/ultra-recovery/last-success.json'))
            atomic(path, baseline)
            time.sleep(max(0, baseline['capture_after'] + 1 - time.time()))
        if module.params['phase'] == 'capture-ready':
            delivered(baseline, config, document(Path('/etc/ultra-recovery/backup.json')),
                      document(Path('/var/lib/ultra-recovery-reconcile/state.json')),
                      document(Path('/var/lib/ultra-relay/recovery-reconcile-status.json')),
                      document(Path('/var/lib/ultra-recovery/last-success.json')), time.time())
        module.exit_json(changed=False, verified=True)
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        module.fail_json(msg='database_preservation_migration_required')


if __name__ == '__main__':
    main()
