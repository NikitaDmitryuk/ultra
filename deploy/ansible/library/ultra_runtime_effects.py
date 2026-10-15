#!/usr/bin/python
"""Confined runtime dependency transaction. No secret or file body leaves host."""
import base64
import difflib
import fcntl
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import socket
import stat
import subprocess
import time
import tempfile
from ansible.module_utils.basic import AnsibleModule

CLASSES = {'coordinated_tunnel', 'listener', 'warp_service', 'tunnel_tls_provision'}
STATE = Path('/etc/ultra-recovery/runtime-transactions')
FIREWALL = ('/etc/ufw/user.rules', '/etc/ufw/user6.rules')
FIREWALL_DEPENDENCIES = ('/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/before.rules', '/etc/ufw/after.rules', '/etc/ufw/before6.rules', '/etc/ufw/after6.rules', '/etc/ufw/sysctl.conf')
WATCHDOG = ('/usr/local/bin/ultra-warp-watchdog', '/etc/systemd/system/ultra-warp-watchdog.service', '/etc/systemd/system/ultra-warp-watchdog.timer')
CERTIFICATE = ('/etc/ultra-relay/fullchain.pem', '/etc/ultra-relay/privkey.pem')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def atomic(path, raw, mode=0o600, uid=None, gid=None):
    if path.is_symlink():
        raise ValueError('effect_symlink')
    fd, temporary_name = tempfile.mkstemp(prefix='.' + path.name + '.effects-', dir=path.parent)
    temporary = Path(temporary_name)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        if uid is not None:
            os.fchown(stream.fileno(), uid, gid)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def image(path, relay=False):
    if path.is_symlink():
        raise ValueError('effect_symlink')
    if not path.exists():
        return None
    info = path.stat()
    owners = {os.geteuid()}
    if relay:
        try:
            owners.add(pwd.getpwnam('ultra-relay').pw_uid)
        except KeyError:
            pass
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
        raise ValueError('effect_untrusted_file')
    raw = path.read_bytes()
    return {'data': base64.b64encode(raw).decode(), 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}


def bytes_of(value):
    return base64.b64decode(value['data']) if value is not None else None


def added_firewall_lines(before, after, ports, source, marker):
    """Only additive exact requested UFW tuples/rules may become owned effects."""
    added = []
    pending_tuple = None
    for tag, a, b, c, d in difflib.SequenceMatcher(a=before.splitlines(keepends=True), b=after.splitlines(keepends=True), autojunk=False).get_opcodes():
        if tag == 'equal':
            continue
        if tag != 'insert':
            raise ValueError('firewall_prior_rule_changed')
        for raw in after.splitlines(keepends=True)[c:d]:
            line = raw.decode('ascii').strip()
            if not line:
                continue
            if line.startswith('### tuple ### '):
                fields = line[len('### tuple ### '):].split()
                comment = fields.pop() if len(fields) == 8 else ''
                if comment not in ('comment=' + marker, 'comment=' + marker.encode().hex()):
                    raise ValueError('firewall_grant_marker_missing')
                if (len(fields) != 7 or fields[:2] != ['allow', 'tcp'] or fields[2] not in {str(p) for p in ports}
                        or fields[3] not in ('0.0.0.0/0', '::/0') or fields[4] != 'any' or fields[6] != 'in'
                        or fields[5] not in ({source, source + '/32'} if source else {'0.0.0.0/0', '::/0'})):
                    raise ValueError('firewall_added_tuple_not_owned')
                if pending_tuple is not None:
                    raise ValueError('firewall_tuple_without_rule')
                pending_tuple = fields[2]
            elif line.startswith('-A ufw-user-input '):
                words = shlex.split(line)
                flags = {}
                try:
                    for index in range(2, len(words), 2):
                        key, value = words[index:index + 2]
                        if key in flags:
                            raise ValueError('duplicate')
                        flags[key] = value
                except ValueError:
                    raise ValueError('firewall_added_rule_not_owned') from None
                allowed = {'-p', '--dport', '-j'} | ({'-s'} if source else set())
                if (set(flags) != allowed or flags.get('-p') != 'tcp' or flags.get('-j') != 'ACCEPT'
                        or pending_tuple != flags.get('--dport')
                        or flags.get('--dport') not in {str(p) for p in ports}
                        or (source and flags.get('-s') not in (source, source + '/32'))):
                    raise ValueError('firewall_added_rule_not_owned')
                pending_tuple = None
            else:
                raise ValueError('firewall_unrelated_line_added')
            added.append(raw)
    if pending_tuple is not None:
        raise ValueError('firewall_tuple_without_rule')
    return added


def firewall_has_grant(raw, port, source):
    for line in raw.decode('ascii').splitlines():
        if not line.startswith('-A ufw-user-input '):
            continue
        words = line.split()
        try:
            flags = dict(zip(words[2::2], words[3::2], strict=True))
        except ValueError:
            continue
        if flags.get('-p') == 'tcp' and flags.get('--dport') == str(port) and flags.get('-j') == 'ACCEPT':
            if not flags.get('-s') or (source and flags.get('-s') in (source, source + '/32')):
                return True
    return False


class Effects:
    def __init__(self, root=Path('/'), runner=None):
        self.root = root
        self.runner = runner or self.command

    @contextmanager
    def locked(self):
        directory = self.path(str(STATE))
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = directory.stat()
        if directory.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('effect_directory_untrusted')
        fd = os.open(directory / 'effects.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError('effect_lock_untrusted')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def path(self, name):
        return self.root / name.lstrip('/')

    def command(self, argv, allowed=(0,)):
        executable = Path(argv[0])
        info = executable.stat()
        if executable.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('effect_executable_untrusted')
        result = subprocess.run(argv, capture_output=True, timeout=45, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if result.returncode not in allowed:
            raise ValueError('effect_command_failed')
        return result.stdout

    def journal(self, request):
        identifier = request['request']['transaction']
        if not re.fullmatch(r'[a-z0-9-]{1,80}', identifier):
            raise ValueError('effect_transaction_invalid')
        return self.path(str(STATE / (identifier + '.effects.json')))

    def save(self, path, state):
        if not path.parent.exists():
            path.parent.mkdir(mode=0o700, parents=True)
        info = path.parent.stat()
        if path.parent.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('effect_directory_untrusted')
        atomic(path, json.dumps(state, sort_keys=True).encode())

    def read_state(self, path):
        value = image(path)
        if value is None:
            return None
        if value['mode'] != 0o600:
            raise ValueError('effect_journal_not_private')
        return json.loads(bytes_of(value))

    def validate_unit_links(self, unit):
        directory = self.path('/etc/systemd/system')
        if unit == 'ultra-bot.service':
            expected_parent = 'multi-user.target.wants'
        elif unit == 'ultra-warp-watchdog.timer':
            expected_parent = 'timers.target.wants'
        else:
            expected_parent = None
        target = '/etc/systemd/system/' + unit
        for link in directory.glob('*/' + unit):
            if not link.is_symlink() or link.parent.name != expected_parent or link.lstat().st_uid != os.geteuid() or os.readlink(link) != target:
                raise ValueError('effect_nonstandard_unit_link')

    def unit(self, unit):
        if unit != 'warp-svc.service':
            self.validate_unit_links(unit)
        active = self.runner(['/usr/bin/systemctl', 'is-active', unit], (0, 3, 4)).decode().strip()
        enabled = self.runner(['/usr/bin/systemctl', 'is-enabled', unit], (0, 1, 4)).decode().strip()
        if active not in ('active', 'inactive', 'unknown') or enabled not in ('enabled', 'disabled', 'static', 'not-found'):
            raise ValueError('effect_service_state_unsupported')
        return {'active': active, 'enabled': enabled}

    def warp(self):
        registration = self.runner(['/usr/bin/warp-cli', '--accept-tos', 'registration', 'show'])
        settings = self.runner(['/usr/bin/warp-cli', '--accept-tos', 'settings']).decode()
        mode = re.findall(r'(?m)^\s*(?:\([^()\r\n]*\)\s*)?Mode:\s*(WarpProxy|Proxy)(?: on port ([0-9]+))?\s*$', settings)
        port = re.findall(r'(?m)^\s*(?:\([^()\r\n]*\)\s*)?Proxy Port:\s*([0-9]+)\s*$', settings)
        if len(mode) != 1 or (not mode[0][1] and len(port) != 1):
            raise ValueError('warp_existing_proxy_registration_required')
        proxy_port = int(mode[0][1] or port[0])
        status = self.runner(['/usr/bin/warp-cli', '--accept-tos', 'status']).decode()
        matches = re.findall(r'(?m)^.*Status(?: update)?:\s*(Connected|Disconnected)\s*$', status)
        if len(matches) != 1 or not 1 <= proxy_port <= 65535:
            raise ValueError('warp_state_uncertain')
        invariant = re.sub(r'(?m)^.*(?:Mode:|Proxy Port:).*\n?', '', settings)
        return {'port': proxy_port, 'connected': matches[0] == 'Connected', 'registration': digest(registration), 'invariant': digest(invariant.encode())}

    def firewall(self):
        executable = self.path('/usr/sbin/ufw')
        if not executable.exists():
            return {'active': False, 'executable': None}
        identity = image(executable)
        status = self.runner(['/usr/sbin/ufw', 'status']).decode()
        if not status.startswith(('Status: active\n', 'Status: inactive\n')):
            raise ValueError('firewall_state_uncertain')
        dependencies = {}
        for name in FIREWALL_DEPENDENCIES:
            value = image(self.path(name))
            dependencies[name] = digest(json.dumps(value, sort_keys=True).encode())
        return {'active': status.startswith('Status: active\n'), 'executable': digest(bytes_of(identity)), 'dependencies': dependencies}

    def tls(self, plan):
        if plan['role'] != 'exit' or not plan.get('tls'):
            return
        for name in CERTIFICATE:
            value = image(self.path(name), relay=True)
            if value is None or value['mode'] & 0o077:
                raise ValueError('tls_existing_private_pair_required')
        cert, key = (str(self.path(name)) for name in CERTIFICATE)
        public_cert = self.runner(['/usr/bin/openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
        public_key = self.runner(['/usr/bin/openssl', 'pkey', '-in', key, '-pubout'])
        if public_cert != public_key:
            raise ValueError('tls_key_pair_mismatch')
        self.runner(['/usr/bin/openssl', 'x509', '-in', cert, '-checkend', '300', '-noout'])
        if plan['tls_provision'] == 'self_signed':
            der = self.runner(['/usr/bin/openssl', 'x509', '-in', cert, '-outform', 'DER'])
            if digest(der) != plan.get('certificate_pin'):
                raise ValueError('tls_frozen_db_pin_required')
        elif plan['tls_provision'] == 'user_provided':
            hostname = plan.get('tls_name')
            if not isinstance(hostname, str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', hostname):
                raise ValueError('tls_hostname_required')
            self.runner(['/usr/bin/openssl', 'verify', '-CAfile', '/etc/ssl/certs/ca-certificates.crt', '-purpose', 'sslserver', '-verify_hostname', hostname, cert])
        else:
            raise ValueError('tls_provision_migration_required')

    def inspect(self, plan, assets):
        if not isinstance(plan, dict) or not set(plan.get('classes', [])) <= CLASSES or plan.get('role') not in ('bridge', 'exit'):
            raise ValueError('effect_plan_invalid')
        for port in plan.get('ports', []):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('effect_plan_invalid')
        if plan.get('source'):
            ipaddress.IPv4Address(plan['source'])
        self.tls(plan)
        if plan.get('bot_service'):
            bot = self.unit('ultra-bot.service')
            if (plan.get('bot_enabled') and bot['enabled'] == 'not-found') or bot['enabled'] not in ('enabled', 'disabled', 'not-found'):
                raise ValueError('bot_existing_managed_unit_required')
            unit_file = image(self.path('/etc/systemd/system/ultra-bot.service'))
            if bot['enabled'] != 'not-found' and unit_file is None:
                raise ValueError('bot_owned_unit_required')
        firewall = self.firewall() if 'listener' in plan['classes'] else None
        warp = None
        if 'warp_service' in plan['classes']:
            if plan['role'] != 'exit':
                raise ValueError('warp_exit_required')
            if self.unit('warp-svc.service')['active'] != 'active':
                raise ValueError('warp_installed_active_daemon_required')
            warp = self.warp()
            timer = self.unit('ultra-warp-watchdog.timer')
            service = self.unit('ultra-warp-watchdog.service')
            if service['active'] == 'active':
                raise ValueError('warp_watchdog_busy')
            if plan.get('warp') and not 1 <= plan.get('warp_port', 0) <= 65535:
                raise ValueError('warp_port_invalid')
            for name in WATCHDOG:
                current = image(self.path(name))
                expected = assets[name].replace('{{ ultra_warp_port }}', str(warp['port'])).encode()
                if current is not None and (bytes_of(current) != expected or current['mode'] != (0o755 if name == WATCHDOG[0] else 0o644)):
                    raise ValueError('warp_foreign_watchdog_file')
            warp['timer'], warp['service'] = timer, service
        return firewall, warp

    def prepare(self, request_raw, plan, assets):
        request = json.loads(request_raw)
        path = self.journal(request)
        binding = digest(request_raw.encode())
        prior = self.read_state(path)
        if prior is not None:
            if prior['binding_sha256'] != binding or prior['plan'] != plan:
                raise ValueError('effect_request_changed')
            return prior
        firewall, warp = self.inspect(plan, assets)
        bot = self.unit('ultra-bot.service') if plan.get('bot_service') else None
        if bot and ((plan.get('bot_enabled') and bot['enabled'] == 'not-found') or bot['enabled'] not in ('enabled', 'disabled', 'not-found')):
            raise ValueError('bot_existing_managed_unit_required')
        paths = ['/etc/systemd/system/ultra-bot.service'] if bot and bot['enabled'] != 'not-found' else []
        if firewall and firewall['active']:
            paths.extend(FIREWALL)
        if warp:
            paths.extend(WATCHDOG)
        if plan.get('tls') and plan['role'] == 'exit':
            paths.extend(CERTIFICATE)
        before = {name: image(self.path(name), relay=name in CERTIFICATE) for name in paths}
        if firewall and firewall['active'] and any(before[name] is None for name in FIREWALL):
            raise ValueError('firewall_complete_private_before_required')
        candidate = dict(before)
        if warp:
            for name in WATCHDOG:
                candidate[name] = {'data': base64.b64encode(assets[name].replace('{{ ultra_warp_port }}', str(plan.get('warp_port') or warp['port'])).encode()).decode(), 'mode': 0o755 if name == WATCHDOG[0] else 0o644, 'uid': os.geteuid(), 'gid': os.getegid()}
        state = {'version': 1, 'binding_sha256': binding, 'plan': plan, 'state': 'prepared', 'before': before, 'candidate': candidate, 'firewall': firewall, 'warp': warp, 'grants': [], 'marker': 'ultra-runtime-' + request['request']['transaction'], 'bot': bot}
        self.save(path, state)
        return state

    def validate_files(self, state):
        for name, before in state['before'].items():
            current = image(self.path(name), relay=name in CERTIFICATE)
            if current not in (before, state['candidate'][name]):
                if name in FIREWALL and state['state'] in ('applying', 'rolling_back'):
                    added_firewall_lines(bytes_of(before), bytes_of(current), state['plan']['ports'], state['plan'].get('source', ''), state['marker'])
                    state['candidate'][name] = current
                    additions = added_firewall_lines(bytes_of(before), bytes_of(current), state['plan']['ports'], state['plan'].get('source', ''), state['marker'])
                    grant = {'file': name, 'lines': [base64.b64encode(line).decode() for line in additions], 'uid': current['uid'], 'mode': current['mode']}
                    state['grants'] = [item for item in state['grants'] if item['file'] != name] + [grant]
                else:
                    raise ValueError('effect_file_third_state')
        if state['firewall'] and self.firewall() != state['firewall']:
            raise ValueError('firewall_identity_drift')
        if state['warp']:
            current = self.warp()
            before = state['warp']
            ports = {before['port'], state['plan'].get('warp_port') or before['port']}
            if self.unit('ultra-warp-watchdog.service')['active'] == 'active':
                raise ValueError('warp_watchdog_busy')
            if current['port'] not in ports or current['registration'] != before['registration'] or current['invariant'] != before['invariant']:
                raise ValueError('warp_state_third_state')

    def wait_proxy(self, port):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1) as connection:
                    connection.sendall(b'\x05\x01\x00')
                    if connection.recv(2) == b'\x05\x00':
                        return
            except OSError:
                pass
            time.sleep(0.2)
        raise ValueError('warp_proxy_unverified')

    def transition(self, request_raw, plan, assets, action):
        request = json.loads(request_raw)
        path = self.journal(request)
        state = self.read_state(path)
        if state is None:
            if action in ('rollback', 'status'):
                return {'state': 'rolled_back', 'bound': False}
            raise ValueError('effect_prepared_transaction_required')
        if not plan:
            plan = state['plan']
        if state['version'] != 1 or state['binding_sha256'] != digest(request_raw.encode()) or state['plan'] != plan:
            raise ValueError('effect_request_changed')
        if state.get('state') not in ('prepared', 'applying', 'applied', 'rolling_back', 'rolled_back'):
            raise ValueError('effect_journal_invalid')
        self.validate_files(state)
        if action == 'status':
            return state
        if action in ('accept', 'accept-rollback'):
            expected = 'applied' if action == 'accept' else 'rolled_back'
            if state['state'] != expected:
                raise ValueError('effect_acceptance_phase_invalid')
            if state.get('bot'):
                enabled = bool(plan.get('bot_enabled')) if action == 'accept' else state['bot']['active'] == 'active'
                self.runner(['/usr/bin/systemctl', 'start' if enabled else 'stop', 'ultra-bot.service'], (0,) if enabled else (0, 5))
                active = self.unit('ultra-bot.service')['active']
                if active != ('active' if enabled else 'inactive') and not (not enabled and active == 'unknown' and state['bot']['enabled'] == 'not-found'):
                    raise ValueError('bot_activity_unverified')
            self.save(path, state)
            return state
        if action == 'commit':
            if state['state'] != 'applied':
                raise ValueError('effect_not_applied')
            ledger_path = self.path('/etc/ultra-recovery/runtime-firewall-owned.json')
            ledger_image = image(ledger_path)
            ledger = json.loads(bytes_of(ledger_image)) if ledger_image else {'version': 1, 'operations': {}}
            if ledger_image and ledger_image['mode'] != 0o600:
                raise ValueError('firewall_ledger_not_private')
            receipt = {'binding_sha256': state['binding_sha256'], 'grants': state['grants']}
            old = ledger['operations'].get(request['request']['transaction'])
            if old is not None and old != receipt:
                raise ValueError('firewall_ledger_drift')
            ledger['operations'][request['request']['transaction']] = receipt
            atomic(ledger_path, json.dumps(ledger, sort_keys=True).encode())
            return state
        if action == 'verify':
            if state['state'] != 'applied':
                raise ValueError('effect_not_applied')
            self.tls(plan)
            if state.get('bot') and self.unit('ultra-bot.service')['enabled'] != ('enabled' if plan.get('bot_enabled') else 'disabled'):
                raise ValueError('bot_enable_state_unverified')
            if state['warp']:
                live = self.warp()
                if live['connected'] != bool(plan.get('warp')) or (plan.get('warp') and live['port'] != plan['warp_port']):
                    raise ValueError('warp_candidate_unverified')
                if plan.get('warp'):
                    self.wait_proxy(plan['warp_port'])
            return state
        if action == 'apply' and state['state'] == 'rolled_back':
            raise ValueError('effect_transaction_finished')
        target = state['before'] if action == 'rollback' else state['candidate']
        state['state'] = 'rolling_back' if action == 'rollback' else 'applying'
        self.save(path, state)
        if state['firewall'] and state['firewall']['active']:
            if action == 'apply':
                for port in sorted(set(plan['ports'])):
                    current = image(self.path(FIREWALL[0]))
                    if firewall_has_grant(bytes_of(current), port, plan.get('source', '')):
                        continue
                    arguments = ['/usr/sbin/ufw', 'allow']
                    if plan.get('source'):
                        arguments.extend(['from', plan['source'], 'to', 'any', 'port', str(port), 'proto', 'tcp'])
                    else:
                        arguments.append(str(port) + '/tcp')
                    arguments.extend(['comment', state['marker']])
                    try:
                        self.runner(arguments)
                    finally:
                        # A lost command reply cannot leave an unbound candidate.
                        for name in FIREWALL:
                            current_file = image(self.path(name))
                            if current_file is None or any(current_file[key] != state['before'][name][key] for key in ('uid', 'gid', 'mode')):
                                raise ValueError('firewall_file_owner_drift')
                            additions = added_firewall_lines(bytes_of(state['before'][name]), bytes_of(current_file), plan['ports'], plan.get('source', ''), state['marker'])
                            state['candidate'][name] = current_file
                            grant = {'file': name, 'lines': [base64.b64encode(line).decode() for line in additions], 'uid': current_file['uid'], 'mode': current_file['mode']}
                            state['grants'] = [item for item in state['grants'] if item['file'] != name] + [grant]
                        self.save(path, state)
            else:
                for name in FIREWALL:
                    value = state['before'][name]
                    atomic(self.path(name), bytes_of(value), value['mode'], value['uid'], value['gid'])
                self.runner(['/usr/sbin/ufw', 'reload'])
        if state['warp']:
            self.runner(['/usr/bin/systemctl', 'stop', 'ultra-warp-watchdog.timer'])
            self.runner(['/usr/bin/systemctl', 'stop', 'ultra-warp-watchdog.service'])
            live = self.warp()
            wanted_port = state['warp']['port'] if action == 'rollback' else plan.get('warp_port') or state['warp']['port']
            if live['port'] != wanted_port:
                self.runner(['/usr/bin/warp-cli', '--accept-tos', 'proxy', 'port', str(wanted_port)])
            connected = state['warp']['connected'] if action == 'rollback' else bool(plan.get('warp'))
            self.runner(['/usr/bin/warp-cli', '--accept-tos', 'connect' if connected else 'disconnect'])
        for name, value in target.items():
            if name in FIREWALL or name in CERTIFICATE or name == '/etc/systemd/system/ultra-bot.service':
                continue
            path_to_file = self.path(name)
            if value is None:
                if path_to_file.exists():
                    path_to_file.unlink()
            else:
                atomic(path_to_file, bytes_of(value), value['mode'], value['uid'], value['gid'])
        if state['warp']:
            self.runner(['/usr/bin/systemctl', 'daemon-reload'])
            timer = state['warp']['timer'] if action == 'rollback' else {'enabled': 'enabled' if plan.get('warp') else 'disabled', 'active': 'active' if plan.get('warp') else 'inactive'}
            if timer['enabled'] in ('enabled', 'disabled'):
                self.runner(['/usr/bin/systemctl', 'enable' if timer['enabled'] == 'enabled' else 'disable', 'ultra-warp-watchdog.timer'])
            elif timer['enabled'] == 'not-found':
                self.runner(['/usr/bin/systemctl', 'disable', 'ultra-warp-watchdog.timer'], (0, 1))
            self.runner(['/usr/bin/systemctl', 'start' if timer['active'] == 'active' else 'stop', 'ultra-warp-watchdog.timer'], (0, 5) if timer['active'] != 'active' else (0,))
        if state.get('bot'):
            wanted = state['bot']['enabled'] if action == 'rollback' else ('enabled' if plan.get('bot_enabled') else 'disabled')
            if wanted in ('enabled', 'disabled'):
                self.runner(['/usr/bin/systemctl', 'enable' if wanted == 'enabled' else 'disable', 'ultra-bot.service'])
        state['state'] = 'rolled_back' if action == 'rollback' else 'applied'
        self.save(path, state)
        return state


def main():
    module = AnsibleModule(argument_spec={'action': {'type': 'str', 'choices': ['inspect', 'prepare', 'status', 'apply', 'rollback', 'verify', 'commit', 'accept', 'accept-rollback'], 'required': True},
                                         'request_json': {'type': 'str', 'required': True, 'no_log': True},
                                         'plan': {'type': 'dict', 'default': {}, 'no_log': True},
                                         'warp_assets': {'type': 'dict', 'default': {}, 'no_log': True}}, supports_check_mode=False)
    try:
        effects = Effects()
        args = module.params
        with effects.locked():
            if args['action'] == 'inspect':
                effects.inspect(args['plan'], args['warp_assets'])
                result = {'state': 'checked', 'bound': False}
            elif args['action'] == 'prepare':
                result = effects.prepare(args['request_json'], args['plan'], args['warp_assets'])
            else:
                result = effects.transition(args['request_json'], args['plan'], args['warp_assets'], args['action'])
        module.exit_json(changed=args['action'] in ('apply', 'rollback'), verified=True, phase=result['state'], bound=result.get('bound', True))
    except Exception:
        module.fail_json(msg='runtime_effect_transaction_unverified')


if __name__ == '__main__':
    main()
