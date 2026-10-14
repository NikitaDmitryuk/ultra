#!/usr/bin/env python3
"""Owned Vultr A-record reconciliation. No zone creation, deletion, or implicit adoption."""
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = 'https://api.vultr.com'
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def fail(code):
    raise ValueError('dns_' + code) from None


def private(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        fail('private_file_required')
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        fail('private_file_permissions')
    return path


def save(path, state):
    path = Path(path)
    if path.is_symlink():
        fail('receipt_symlink')
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = path.with_name(path.name + '.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RejectedWrite(ValueError):
    """Provider explicitly rejected the mutation; no unknown commit outcome."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, config):
        self.token = private(config['api_key_file']).read_text().strip()
        if not self.token or any(c.isspace() for c in self.token):
            fail('invalid_credential')
        self.path = '/v2/domains/' + config['zone'] + '/records'
        self.zone = config['zone']
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, url, body=None):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.netloc != 'api.vultr.com' or parsed.fragment or not (parsed.path == self.path or re.fullmatch(re.escape(self.path) + r'/[A-Za-z0-9-]+', parsed.path)):
            fail('untrusted_api_url')
        for attempt in range(3 if method == 'GET' else 1):
            request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'}, method=method)
            try:
                with self.opener.open(request, timeout=15) as response:
                    raw = response.read(2 * 1024 * 1024 + 1)
                    if len(raw) > 2 * 1024 * 1024:
                        fail('response_limit')
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as error:
                error.close()
                if method == 'GET' and (error.code == 429 or 500 <= error.code <= 599) and attempt < 2:
                    retry_after = error.headers.get('Retry-After', '') if error.headers else ''
                    delay = min(2, max(0, int(retry_after))) if retry_after.isdigit() else 0.25 * (attempt + 1)
                    time.sleep(delay)
                    continue
                if method != 'GET' and 400 <= error.code < 500 and error.code != 408:
                    raise RejectedWrite('dns_write_rejected') from None
                fail('api_request_failed')
            except (OSError, ValueError, http.client.HTTPException):
                fail('api_request_failed')

    def records(self):
        url = ORIGIN + self.path + '?per_page=100'
        result, seen = [], set()
        for _ in range(100):
            if url in seen:
                fail('pagination_loop')
            seen.add(url)
            page = self.request('GET', url)
            if not isinstance(page, dict) or not isinstance(page.get('records'), list):
                fail('invalid_records')
            if not all(isinstance(row, dict) for row in page['records']):
                fail('invalid_records')
            zone = self.path.split('/')[3]
            for row in page['records']:
                name = row.get('name')
                if not isinstance(name, str): fail('invalid_record_name')
                name = name.rstrip('.').lower()
                if name == zone: name = ''
                elif name.endswith('.' + zone): name = name[:-len(zone)-1]
                # The API also returns relative multi-label names. Only our exact
                # role labels are managed; unrelated names remain untouched.
                result.append(dict(row, name=name))
            next_url = page.get('meta', {}).get('links', {}).get('next')
            if not next_url:
                return result
            parsed = urllib.parse.urlsplit(next_url)
            if parsed.scheme != 'https' or parsed.netloc != 'api.vultr.com' or parsed.path != self.path or parsed.fragment:
                fail('untrusted_pagination')
            url = next_url
        fail('pagination_limit')

    def write(self, operation, target, record_id=None):
        url = ORIGIN + self.path
        if operation == 'PATCH':
            if not re.fullmatch(r'[A-Za-z0-9-]+', str(record_id)):
                fail('invalid_record_id')
            url += '/' + str(record_id)
        self.request(operation, url, target)


def normalized(record):
    try:
        return {key: record[key] for key in ('id', 'type', 'name', 'data', 'ttl')}
    except (KeyError, TypeError):
        fail('invalid_record')


def matching(records, name):
    found = [normalized(row) for row in records if row.get('name') == name]
    if len(found) > 1 or (found and found[0]['type'] != 'A'):
        fail('conflicting_records')
    return found[0] if found else None


def same(record, target):
    return record is not None and all(record.get(key) == value for key, value in target.items())


def execute(config, desired, receiptpath):
    path = Path(receiptpath)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _execute(config, desired, receiptpath)


def _execute(config, desired, receiptpath):
    zone = config.get('zone', '')
    ttl = config.get('ttl', 300)
    if config.get('provider') != 'vultr' or len(zone) > 253 or '.' not in zone or not all(LABEL.fullmatch(x) for x in zone.split('.')):
        fail('invalid_policy')
    if type(ttl) is not int or not 120 <= ttl <= 86400 or set(desired) not in ({'subscription', 'vpn'}, {'subscription', 'vpn', 'backend'}):
        fail('invalid_policy')
    targets = {}
    for role, item in desired.items():
        if not LABEL.fullmatch(item.get('name', '')):
            fail('invalid_label')
        try:
            address = str(ipaddress.IPv4Address(item['data']))
        except (ValueError, KeyError):
            fail('invalid_address')
        targets[role] = {'type': 'A', 'name': item['name'], 'data': address, 'ttl': ttl}
    if len({row['name'] for row in targets.values()}) != len(targets):
        fail('duplicate_roles')
    path = Path(receiptpath)
    state = {'version': 1, 'zone': zone, 'records': {}}
    if path.exists() or path.is_symlink():
        try:
            state = json.loads(private(path).read_text())
        except (ValueError, OSError):
            fail('invalid_receipt')
        if not isinstance(state, dict) or state.get('version') != 1 or state.get('zone') != zone or not isinstance(state.get('records'), dict):
            fail('receipt_policy_mismatch')
    # Public-only callers must retain an already-owned backend introduced by the
    # bounded certificate migration. Absence from an older plan is not deletion.
    if 'backend' in state['records'] and 'backend' not in targets:
        owned_backend = state['records']['backend']
        if not isinstance(owned_backend, dict) or set(owned_backend) != {'id', 'type', 'name', 'data', 'ttl'}:
            fail('invalid_receipt')
        targets['backend'] = {key: owned_backend[key] for key in ('type', 'name', 'data', 'ttl')}
        if len({row['name'] for row in targets.values()}) != len(targets):
            fail('duplicate_roles')
    if not set(state['records']) <= set(targets):
        fail('invalid_receipt')
    for row in state['records'].values():
        if not isinstance(row, dict) or set(row) != {'id', 'type', 'name', 'data', 'ttl'} or not re.fullmatch(r'[A-Za-z0-9-]+', str(row['id'])):
            fail('invalid_receipt')
    pending = state.get('pending')
    if pending:
        if not isinstance(pending, dict) or pending.get('role') not in targets or pending.get('operation') not in ('POST', 'PATCH'):
            fail('invalid_pending')
        if pending['operation'] == 'PATCH' and (not isinstance(pending.get('before'), dict) or pending.get('before') != state['records'].get(pending['role'])):
            fail('invalid_pending')
        if pending['operation'] == 'POST' and (pending.get('before') is not None or pending['role'] in state['records']):
            fail('invalid_pending')
    api = API(config)
    for role, target in targets.items():
        pending = state.get('pending')
        if pending and pending.get('role') not in targets:
            fail('invalid_pending')
        # Finish an interrupted role first; no different write can replace its journal.
        if pending and pending['role'] != role:
            continue
        records = api.records()
        current = matching(records, target['name'])
        owned = state['records'].get(role)
        if pending:
            if pending.get('target') != target:
                fail('pending_policy_changed')
            if same(current, target) and (pending['operation'] == 'POST' or current['id'] == pending['before']['id']):
                state['records'][role] = current
                state.pop('pending')
                save(path, state)
                continue
            if pending['operation'] == 'POST':
                if current is not None:
                    fail('pending_conflict')
                # Absence after ambiguous POST is not permission to create a duplicate.
                fail('pending_create_unconfirmed')
            if current != pending['before']:
                fail('record_drift')
        elif owned:
            if current != owned:
                fail('record_drift')
            if same(current, target):
                continue
        elif current is not None:
            fail('foreign_record')
        if owned and owned['name'] != target['name']:
            fail('owned_name_change_requires_migration')
        operation = 'PATCH' if owned else 'POST'
        state['pending'] = {'role': role, 'operation': operation, 'before': current, 'target': target}
        save(path, state)
        try:
            api.write(operation, target, current['id'] if current else None)
        except RejectedWrite:
            state.pop('pending')
            save(path, state)
            raise
        confirmed = matching(api.records(), target['name'])
        if not same(confirmed, target) or (current and confirmed['id'] != current['id']):
            fail('write_unconfirmed')
        state['records'][role] = confirmed
        state.pop('pending')
        save(path, state)
    if set(state['records']) != set(targets) or state.get('pending'):
        # An interrupted second role can skip the first above; next call verifies all.
        fail('reconcile_incomplete')
    # Verify both again, including roles skipped while resuming an interrupted write.
    records = api.records()
    for role, target in targets.items():
        if matching(records, target['name']) != state['records'][role] or not same(state['records'][role], target):
            fail('record_drift')
    return {'ready': True, 'records': state['records']}


def wait_ready(config, desired, timeout=120):
    """Bounded resolver and authoritative proof; caller supplies the dig dependency."""
    import subprocess
    deadline = time.monotonic() + timeout
    def query(*args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail('propagation_timeout')
        result = subprocess.run(['dig', '+short', '+time=2', '+tries=1', *args],
            capture_output=True, text=True, timeout=min(5, remaining), check=True)
        return {line.strip().rstrip('.') for line in result.stdout.splitlines() if line.strip()}
    while time.monotonic() < deadline:
        try:
            nameservers = query(config['zone'], 'NS')
            if nameservers != {'ns1.vultr.com', 'ns2.vultr.com'}:
                raise ValueError('pending nameservers')
            ready = True
            for item in desired.values():
                name = item['name'] + '.' + config['zone']
                expected = {item['data']}
                if query(name, 'A') != expected:
                    ready = False
                for nameserver in nameservers:
                    if query('@' + nameserver, name, 'A') != expected:
                        ready = False
            if ready:
                return
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    fail('propagation_timeout')
