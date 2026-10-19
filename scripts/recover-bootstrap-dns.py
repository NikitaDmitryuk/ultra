#!/usr/bin/env python3
"""Explicitly adopt exact DNS records after bridge reimage; never write provider DNS.

First run with --stage to inspect. Repeat with --accept-sha256 from that output.
Only remote, non-native components-v1 bootstrap-postgres attempts are supported.
No original attempt or exported bundle is modified. Run the original apply next.
"""
import argparse
import array
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import types
import uuid


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted(path, directory=False, uid=None, private=True):
    path = Path(path)
    uid = os.geteuid() if uid is None else uid
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == uid and not info.st_mode & (0o077 if private else 0o022), 'untrusted_file')
    if not directory:
        require(info.st_nlink == 1, 'untrusted_file')
    for parent in path.parents:
        require(not parent.is_symlink(), 'untrusted_parent')
    return info


def read_private(path):
    trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20, 'input_too_large')
    return raw


@contextmanager
def locked(path, uid=None):
    trusted(Path(path).parent, directory=True, uid=uid)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        trusted(path, uid=uid)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def publication_prefix(path, raw):
    return '.dns-ownership-' + Path(path).name + '-' + sha(raw) + '-'


def create_only(path, raw):
    """Durable exclusive publication; never replace even a concurrently created file."""
    path = Path(path)
    trusted(path.parent, directory=True)
    fd, name = tempfile.mkstemp(prefix=publication_prefix(path, raw), dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(name, path, follow_symlinks=False)
        os.unlink(name)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def active_lease(operation, sock='/run/ultra-ansible/controller.sock',
                 lock='/var/lib/ultra-ansible/infrastructure.lock'):
    """Same lease-attach SCM_RIGHTS protocol and inode/flock checks as Go Client."""
    descriptors = []
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(sock)
            _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == 0, 'untrusted_broker')
            connection.sendall(canonical({'action': 'lease-attach', 'id': operation}) + b'\n')
            raw, controls, flags, _ = connection.recvmsg(65536, socket.CMSG_SPACE(12))
            for level, kind, data in controls:
                require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, 'invalid_broker_control')
                items = array.array('i')
                items.frombytes(data[:len(data) - len(data) % items.itemsize])
                descriptors.extend(items)
            require(not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC), 'truncated_broker_response')
            while b'\n' not in raw:
                part = connection.recv(65536 - len(raw))
                require(part and len(raw) + len(part) < 65536, 'invalid_broker_response')
                raw += part
            response = json.loads(raw)
            require(response.get('state') == 'applying' and not response.get('code') and len(descriptors) == 1,
                    'lifecycle_not_active')
        expected = trusted(lock, uid=0)
        offered = os.fstat(descriptors[0])
        require((expected.st_dev, expected.st_ino) == (offered.st_dev, offered.st_ino), 'untrusted_lease_descriptor')
        fcntl.flock(descriptors[0], fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.set_inheritable(descriptors[0], False)
        yield
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def exact_receipt(application, config, desired):
    require(config.get('provider') == 'vultr' and config.get('api_key_file') == '/etc/ultra-recovery/dns-api-key',
            'unsupported_dns_policy')
    zone = config.get('zone', '')
    require(isinstance(zone, str) and len(zone) <= 253 and '.' in zone
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in zone.split('.')),
            'invalid_zone')
    ttl = config.get('ttl', 300)
    require(type(ttl) is int and 120 <= ttl <= 86400, 'invalid_ttl')
    require(set(desired) == {'subscription', 'vpn', 'tunnel'}, 'unsupported_roles')
    records = application.API(config).records()  # GET only, never execute()/write().
    result, names, ids = {}, set(), set()
    for role, item in sorted(desired.items()):
        name = item['name']
        require(isinstance(name, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name)
                and name not in names, 'invalid_role_name')
        names.add(name)
        data = str(ipaddress.IPv4Address(item['data']))
        row = application.matching(records, name)
        target = {'type': 'A', 'name': name, 'data': data, 'ttl': ttl}
        require(row is not None and application.same(row, target), 'record_mismatch')
        require(set(row) == {'id', 'type', 'name', 'data', 'ttl'} and type(row['ttl']) is int
                and isinstance(row['id'], str) and re.fullmatch(r'[A-Za-z0-9-]+', row['id'])
                and row['id'] not in ids, 'record_identity_invalid')
        ids.add(row['id'])
        result[role] = row
    return {'version': 1, 'zone': zone, 'records': result}


def receipt_absent(path):
    require(not os.path.lexists(path) and not os.path.lexists(str(path) + '.next'), 'receipt_already_present')


def read_publication(path, uid=None):
    """Read one tool publication, recognizing only its exact interrupted second link.

    Callers must validate the expected bytes/binding before removing the staging
    link. Generic trusted()/read_private() continue to forbid all hardlinks.
    """
    path = Path(path)
    owner = trusted(path.parent, directory=True, uid=uid).st_uid
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == owner
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink in (1, 2), 'untrusted_file')
    def read_link(candidate):
        fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            current = os.fstat(stream.fileno())
            require((current.st_dev, current.st_ino, current.st_uid, current.st_mode, current.st_nlink) ==
                    (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink), 'receipt_changed')
            raw = stream.read((1 << 20) + 1)
        require(len(raw) <= 1 << 20, 'input_too_large')
        return raw
    raw = read_link(path)
    pending = None
    if info.st_nlink == 2:
        prefix = publication_prefix(path, raw)
        candidates = [item for item in path.parent.iterdir()
                      if re.fullmatch(re.escape(prefix) + '[a-z0-9_]{8}', item.name)]
        require(len(candidates) == 1, 'receipt_publication_invalid')
        pending = candidates[0]
        candidate = pending.lstat()
        require(stat.S_ISREG(candidate.st_mode)
                and (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino),
                'receipt_publication_invalid')
        require(read_link(pending) == raw, 'receipt_publication_invalid')
    else:
        trusted(path, uid=uid)
    return raw, pending


def finish_publication(path, publication, uid=None):
    require(read_publication(path, uid) == publication, 'receipt_changed')
    if publication[1] is not None:
        os.unlink(publication[1])
    sync_directory(Path(path).parent)
    trusted(path, uid=uid)


def read_existing_receipt(path, payload):
    binding = payload.get('reconcile')
    require(isinstance(binding, dict) and set(binding) ==
            {'request_sha256', 'job_sha256', 'operation', 'records_sha256'}
            and binding['operation'] == payload['operation']
            and binding['records_sha256'] == payload.get('accept')
            and all(isinstance(binding[key], str) and re.fullmatch('[a-f0-9]{64}', binding[key])
                    for key in ('request_sha256', 'job_sha256', 'records_sha256')), 'reconciliation_not_authorized')
    require(not os.path.lexists(str(path) + '.next'), 'receipt_pending')
    raw, pending = read_publication(path, uid=0)
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'receipt_duplicate_key')
            result[key] = value
        return result
    receipt = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(receipt, dict) and set(receipt) == {'version', 'zone', 'records'}
            and type(receipt['version']) is int and receipt['version'] == 1
            and sha(canonical(receipt)) == payload['accept'], 'receipt_binding_mismatch')
    if pending is not None:
        require(raw == canonical(receipt) + b'\n', 'receipt_publication_invalid')
    return receipt, raw, pending


def recover_host(payload, application, directory=Path('/etc/ultra-recovery'), lease=active_lease):
    require(os.geteuid() == 0, 'root_required')
    trusted(directory, directory=True, uid=0)
    path = directory / 'dns-receipt.json'
    with lease(payload['operation']), locked(str(path) + '.lock', uid=0):
        existing = None
        if os.path.lexists(path):
            existing = read_existing_receipt(path, payload)
        else:
            receipt_absent(path)
        first = exact_receipt(application, payload['config'], payload['desired'])
        digest = sha(canonical(first))
        result = {'records_sha256': digest, 'records': first['records'], 'created': False, 'reconciled': False}
        accepted = payload.get('accept', '')
        if not accepted:
            return result
        require(re.fullmatch('[a-f0-9]{64}', accepted) and accepted == digest, 'acceptance_mismatch')
        if existing is not None:
            require(canonical(existing[0]) == canonical(first), 'receipt_binding_mismatch')
        # Re-observe inside both locks, immediately before exclusive publication.
        second = exact_receipt(application, payload['config'], payload['desired'])
        require(sha(canonical(second)) == accepted, 'records_changed')
        if existing is not None:
            require(read_existing_receipt(path, payload) == existing, 'receipt_changed')
            finish_publication(path, existing[1:], uid=0)
            result['reconciled'] = True
        else:
            receipt_absent(path)
            create_only(path, canonical(second) + b'\n')
            result['created'] = True
        trusted(path, uid=0)
        return result


def frozen_inputs(stage):
    stage = Path(stage)
    require(stage.is_absolute() and str(stage) == os.path.normpath(stage)
            and stage.name == 'bootstrap-postgres', 'invalid_stage')
    attempt, root = stage.parent, stage.parent.parent.parent
    require(attempt.name.startswith('attempt-') and attempt.parent.name.startswith('bootstrap-'), 'invalid_attempt')
    for directory in (root, root / 'operator', attempt, stage):
        trusted(directory, directory=True)
    paths = [stage / 'request.json', stage / 'job.json', stage / 'receipt.json',
             attempt / 'execution-mode.json', attempt.parent / 'attempt.json']
    raw = {str(path): read_private(path) for path in paths}
    request, job, receipt, mode, active = [json.loads(raw[str(path)]) for path in paths]
    digest = sha(raw[str(paths[0])])
    require(job.get('schema_version') == 1 and job.get('operation') == 'bootstrap-postgres'
            and job.get('request_sha256') == digest and job.get('binary_sha256') == digest, 'invalid_job')
    require(receipt.get('state') == 'failed' and receipt.get('operation') == 'bootstrap-postgres'
            and receipt.get('request_sha256') == digest and receipt.get('binary_sha256') == digest, 'invalid_failed_receipt')
    require(active.get('active') == attempt.name and not active.get('complete'), 'inactive_attempt')
    require(mode.get('schema_version') == 1 and not mode.get('local') and not mode.get('native_adoption')
            and mode.get('bootstrap_engine') == 'components-v1' and mode.get('lock_directory') == str(root)
            and mode.get('operator_lock_directory') == str(root / 'operator'), 'unsupported_execution_mode')
    require(request['variables'].get('ultra_lock_directory') == str(root), 'lock_binding_changed')
    inventory = request['inventory']['all']
    hosts = inventory['children']['bridge']['hosts']
    require(set(hosts) == {'bridge'}, 'invalid_bridge_inventory')
    host = dict(inventory['vars'], **hosts['bridge'])
    require(host.get('ansible_connection', 'ssh') == 'ssh' and host.get('ansible_user') == 'root', 'unsupported_transport')
    address = str(ipaddress.IPv4Address(host['ansible_host']))
    require(mode.get('target', '').split('|')[0] == address, 'bridge_identity_changed')
    variables = dict(host, **request['variables'])
    operation = bytearray(hashlib.sha256(str(attempt).encode()).digest()[:16])
    operation[6] = (operation[6] & 15) | 64
    operation[8] = (operation[8] & 63) | 128
    payload = {'operation': str(uuid.UUID(bytes=bytes(operation))), 'config': variables['ultra_dns_config'],
               'desired': variables['ultra_dns_desired']}
    source = variables['ultra_dns_source_content']
    # Confirm source installed by frozen DNS task is the exact frozen application.
    payload['source_sha256'] = sha(source.encode())
    return root, raw, host, payload, {'request_sha256': digest, 'job_sha256': sha(raw[str(paths[1])])}


def ssh_arguments(host):
    require(not any(host.get(key) for key in ('ansible_ssh_args', 'ansible_ssh_executable',
                                             'ansible_ssh_extra_args')), 'unsupported_ssh_override')
    args = shlex.split(host['ansible_ssh_common_args'])
    expected = ['-F', '/dev/null', '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'UpdateHostKeys=no',
                '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o']
    require(args[:len(expected)] == expected and len(args) == len(expected) + 1
            and args[-1].startswith('UserKnownHostsFile=/'), 'unsupported_ssh_options')
    pins = Path(args[-1].split('=', 1)[1])
    trusted(pins, private=False)
    identity = Path(host['ansible_ssh_private_key_file'])
    trusted(identity)
    port = host.get('ansible_port', 22)
    require(type(port) is int and 1 <= port <= 65535, 'invalid_ssh_port')
    return ['ssh', *args, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-i', str(identity), '-p', str(port),
            'root@' + str(ipaddress.IPv4Address(host['ansible_host']))]


def audit_directory(root, binding, digest):
    path = root / 'dns-ownership-recovery'
    for part in (path, path / binding['request_sha256'], path / binding['request_sha256'] / digest):
        try:
            part.mkdir(mode=0o700)
            sync_directory(part.parent)
        except FileExistsError:
            pass
        trusted(part, directory=True)
    return part


def existing_completion(path, binding):
    publication = read_publication(path)
    raw = publication[0]
    completion = json.loads(raw)
    require(isinstance(completion, dict) and set(completion) == set(binding) | {'records'}
            and all(completion[key] == value for key, value in binding.items()), 'audit_completion_changed')
    return publication, completion['records']


def operator(stage, accepted=''):
    root, originals, host, payload, binding = frozen_inputs(stage)
    with ExitStack() as stack:
        stack.enter_context(locked(root / 'operator' / 'infrastructure.lock'))
        stack.enter_context(locked(root / 'infrastructure.lock'))
        for directory in (root, root / 'operator'):
            # This narrow tool does not implement recovery-anchor authorization.
            # Refuse provisioned recovery admission rather than bypassing it.
            require(not any(os.path.lexists(directory / name) for name in
                            ('recovery-anchor.json', 'recovery-fence.json')), 'recovery_admission_unsupported')
        for path, before in originals.items():
            require(read_private(path) == before, 'frozen_inputs_changed')
        # Second validation is under the same locks as ordinary apply.
        _, _, current_host, current_payload, current_binding = frozen_inputs(stage)
        require((current_host, current_payload, current_binding) == (host, payload, binding), 'frozen_inputs_changed')
        payload['accept'] = accepted
        audit = None
        if accepted:
            require(re.fullmatch('[a-f0-9]{64}', accepted), 'invalid_acceptance')
            audit = audit_directory(root, binding, accepted)
            accepted_binding = dict(binding, operation=payload['operation'], records_sha256=accepted)
            intent = canonical(accepted_binding) + b'\n'
            if os.path.lexists(audit / 'intent.json'):
                publication = read_publication(audit / 'intent.json')
                require(publication[0] == intent, 'audit_binding_changed')
                finish_publication(audit / 'intent.json', publication)
                payload['reconcile'] = accepted_binding
            else:
                require(not os.path.lexists(audit / 'completed.json'), 'audit_intent_missing')
                create_only(audit / 'intent.json', intent)
            if os.path.lexists(audit / 'completed.json'):
                publication, records = existing_completion(audit / 'completed.json', accepted_binding)
                observed = {'version': 1, 'zone': payload['config']['zone'], 'records': records}
                require(sha(canonical(observed)) == accepted
                        and publication[0] == canonical(dict(accepted_binding, records=records)) + b'\n',
                        'audit_completion_changed')
                finish_publication(audit / 'completed.json', publication)
        command = shlex.join(['python3', '-c', Path(__file__).read_text(), '--host'])
        process = subprocess.run([*ssh_arguments(host), command], input=canonical(payload),
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90)
        require(process.returncode == 0 and len(process.stdout) <= 65536, 'remote_recovery_failed')
        result = json.loads(process.stdout)
        require(set(result) == {'records_sha256', 'records', 'created', 'reconciled'}
                and type(result['created']) is bool and type(result['reconciled']) is bool,
                'invalid_remote_result')
        observed = {'version': 1, 'zone': payload['config']['zone'], 'records': result['records']}
        require(sha(canonical(observed)) == result['records_sha256']
                and (result['created'] != result['reconciled']) == bool(accepted)
                and (accepted or not result['created'] and not result['reconciled'])
                and (not result['reconciled'] or 'reconcile' in payload),
                'invalid_remote_digest')
        if accepted:
            require(result['records_sha256'] == accepted, 'unconfirmed_recovery')
            completion = canonical(dict(accepted_binding, records=result['records'])) + b'\n'
            completed = audit / 'completed.json'
            if os.path.lexists(completed):
                require(read_private(completed) == completion, 'audit_completion_changed')
            else:
                create_only(completed, completion)
        return result


def main():
    if sys.argv[1:] == ['--host']:
        signal.alarm(60)
        payload = json.loads(sys.stdin.buffer.read(65537))
        require(len(canonical(payload)) <= 65536, 'input_too_large')
        source = Path('/opt/ultra-recovery/dns.py')
        trusted(source, uid=0, private=False)
        raw = source.read_bytes()
        require(sha(raw) == payload['source_sha256'], 'dns_application_changed')
        application = types.ModuleType('frozen_dns')
        exec(compile(raw, str(source), 'exec'), application.__dict__)
        result = recover_host(payload, application)
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--stage', required=True)
        parser.add_argument('--accept-sha256', default='')
        args = parser.parse_args()
        result = operator(args.stage, args.accept_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Paths, provider exceptions and private request values never enter logs.
        print('dns_ownership_recovery_failed', file=sys.stderr)
        sys.exit(1)
