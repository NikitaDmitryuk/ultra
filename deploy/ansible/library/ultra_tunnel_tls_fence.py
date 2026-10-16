#!/usr/bin/python
"""Durable, request-bound exclusion of managed exit certificate deployment.

The fence owns only the packaged certbot service/timer and the fixed Ultra
deployment hook. Private certificate/renewal checkpoints stay on the host;
the module emits only their digest and never authorizes an upgrade.
"""
import base64
import contextlib
import configparser
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import tempfile
import time


STATE = '/var/lib/ultra-tunnel-tls'
HOOK = '/etc/letsencrypt/renewal-hooks/deploy/ultra-tunnel'
UNITS = ('certbot.service', 'certbot.timer')
HOOK_FENCE = b'''# The root-only lock is provisioned with the hook. Hold it through both moves
# and service restart; an installer snapshot must observe one complete pair.
exec 9<>/var/lib/ultra-tunnel-tls/pair.lock
flock -x 9
# A durable fence survives controller failure and reboot. A blocked renewal
# must fail visibly so certbot does not report a successful relay deployment.
[ ! -e /var/lib/ultra-tunnel-tls/blocked ]
[ ! -L /var/lib/ultra-tunnel-tls/blocked ]
'''

# Exact legacy deployment hook supported for adoption. Keep the rendering test
# against the shipped Jinja template: an unknown edited hook is never adopted.
LEGACY_HOOK = b'''#!/bin/sh
set -eu
lineage=/etc/letsencrypt/live/DOMAIN
# Certbot invokes global hooks for every lineage. Ignore unrelated certificates.
[ "${RENEWED_LINEAGE:-}" = "$lineage" ] || exit 0
openssl x509 -in "$lineage/fullchain.pem" -noout -checkhost DOMAIN
openssl x509 -in "$lineage/fullchain.pem" -noout -checkend 86400
openssl verify -purpose sslserver -verify_hostname DOMAIN -CApath /etc/ssl/certs -untrusted "$lineage/fullchain.pem" "$lineage/cert.pem"
cert_key=$(openssl x509 -in "$lineage/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)
private_key=$(openssl pkey -in "$lineage/privkey.pem" -pubout -outform DER | openssl dgst -sha256)
[ "$cert_key" = "$private_key" ]
# Existing canonical files must be regular files, never redirected destinations.
for name in fullchain.pem privkey.pem; do
    target=/etc/ultra-relay/$name
    [ ! -L "$target" ]
    [ ! -e "$target" ] || [ -f "$target" ]
done
stage=$(mktemp -d /etc/ultra-relay/.tls-XXXXXX)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -o ultra-relay -g ultra-relay -m 0600 "$lineage/fullchain.pem" "$stage/fullchain.pem"
install -o ultra-relay -g ultra-relay -m 0600 "$lineage/privkey.pem" "$stage/privkey.pem"
mv -f "$stage/fullchain.pem" /etc/ultra-relay/fullchain.pem
mv -f "$stage/privkey.pem" /etc/ultra-relay/privkey.pem
# Xray loads the pair once. No leaf pin is distributed: clients verify CA + name.
if [ "${ULTRA_TUNNEL_BOOTSTRAP:-}" != 1 ] && systemctl is-active --quiet ultra-relay.service; then
    systemctl restart ultra-relay.service
fi
'''


def hook_bytes(domain, legacy=False):
    raw = LEGACY_HOOK.replace(b'DOMAIN', domain.encode())
    if legacy:
        return raw
    anchor = b'[ "${RENEWED_LINEAGE:-}" = "$lineage" ] || exit 0\n'
    return raw.replace(anchor, anchor + HOOK_FENCE)


def valid_domain(value):
    if not isinstance(value, str) or not 3 <= len(value) <= 253 or '.' not in value:
        return False
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def sha(value):
    return hashlib.sha256(value).hexdigest()


class Fence:
    def __init__(self, root=Path('/'), runner=None, sleeper=time.sleep, process_check=None):
        self.root = Path(root)
        self.runner = runner or self.command
        self.sleeper = sleeper
        self.process_check = process_check or self.owned_processes

    def path(self, name):
        return self.root / name.lstrip('/')

    @staticmethod
    def command(argv):
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if result.returncode or len(result.stdout) > 65536:
            raise ValueError('tunnel_fence_command_failed')
        return result.stdout.decode()

    def parents(self, path, relay=False):
        for parent in (path.parent, *path.parent.parents):
            info = parent.lstat()
            allowed = info.st_uid == os.geteuid()
            if relay and parent == self.path('/etc/ultra-relay') and stat.S_IMODE(info.st_mode) == 0o700:
                try:
                    allowed = allowed or info.st_uid == pwd.getpwnam('ultra-relay').pw_uid
                except KeyError:
                    pass
            if not stat.S_ISDIR(info.st_mode) or not allowed or info.st_mode & 0o022:
                raise ValueError('tunnel_fence_untrusted_parent')
            if parent == self.root:
                return
        raise ValueError('tunnel_fence_untrusted_parent')

    def read(self, name, limit=65536):
        path = self.path(name)
        self.parents(path)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > limit):
                raise ValueError('tunnel_fence_untrusted_file')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('tunnel_fence_untrusted_file')
            return raw
        finally:
            os.close(fd)

    def atomic(self, name, raw, mode=0o600):
        path = self.path(name)
        self.parents(path)
        if path.is_symlink():
            raise ValueError('tunnel_fence_untrusted_file')
        fd, temporary = tempfile.mkstemp(prefix='.tls-fence-', dir=path.parent)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self.sync(path.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def lock(self, name):
        path = self.path(STATE + '/' + name)
        self.parents(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError('tunnel_fence_lock_untrusted')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('tunnel_fence_busy') from None
            yield
        finally:
            os.close(fd)

    def show(self, unit):
        keys = ('LoadState', 'ActiveState', 'FragmentPath', 'DropInPaths', 'UnitFileState')
        if unit.endswith('.service'):
            keys += ('MainPID', 'ControlPID', 'ControlGroup')
        output = self.runner(['/usr/bin/systemctl', 'show', *['--property=' + key for key in keys], '--', unit])
        rows = [line.split('=', 1) for line in output.splitlines()]
        if any(len(row) != 2 for row in rows) or len(rows) != len(keys) or set(dict(rows)) != set(keys):
            raise ValueError('tunnel_fence_unit_unverified')
        value = dict(rows)
        if unit.endswith('.timer'):
            # A timer has no service process properties. systemctl omits
            # unknown properties rather than returning MainPID=0 for timers.
            value.update(MainPID='0', ControlPID='0', ControlGroup='')
        return value

    def unit(self, name):
        value = self.show(name)
        fragment = value['FragmentPath']
        if (value['LoadState'] != 'loaded' or value['DropInPaths']
                or fragment not in ('/usr/lib/systemd/system/' + name, '/lib/systemd/system/' + name)
                or value['ActiveState'] not in ('active', 'inactive', 'activating', 'deactivating')
                or not all(re.fullmatch(r'[0-9]+', value[key]) for key in ('MainPID', 'ControlPID'))
                or os.path.lexists(self.path('/etc/systemd/system/' + name))):
            raise ValueError('tunnel_fence_unit_unverified')
        # /lib is often a symlink to /usr/lib. Resolve only this fixed vendor
        # alias, then apply the regular trusted-file checks to its final path.
        if fragment.startswith('/lib/'):
            fragment = '/usr/lib/' + fragment[len('/lib/'):]
        raw = self.read(fragment)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read_string(raw.decode())
        if name.endswith('.service'):
            service = parser['Service']
            argv = shlex.split(service['ExecStart'])
            if (value['UnitFileState'] != 'static' or service.get('Type') != 'oneshot' or service.get('User', 'root') != 'root'
                    or service.get('RemainAfterExit', 'no') not in ('no', 'false')
                    or argv not in (['/usr/bin/certbot', '-q', 'renew'], ['/usr/bin/certbot', '-q', 'renew', '--no-random-sleep-on-renew'])
                    or any(key.startswith(('ExecStartPre', 'ExecStartPost', 'ExecStop')) for key in service)):
                raise ValueError('tunnel_fence_unit_unverified')
        elif value['UnitFileState'] not in ('enabled', 'disabled') or parser['Timer'].get('Unit', 'certbot.service') != 'certbot.service':
            raise ValueError('tunnel_fence_unit_unverified')
        value['source_sha256'] = sha(raw)
        value['source'] = fragment
        return value

    def owned_processes(self):
        # A second/manual certbot invocation is outside the managed timer's
        # ownership. Do not print argv, which could contain ACME credentials.
        for process in self.path('/proc').iterdir():
            if not process.name.isdigit():
                continue
            try:
                argv = (process / 'cmdline').read_bytes().split(b'\0')
                relevant = any(token.rsplit(b'/', 1)[-1] == b'certbot' or token == HOOK.encode() for token in argv)
                if relevant and (process / 'cgroup').read_bytes() != b'0::/system.slice/certbot.service\n':
                    raise ValueError('tunnel_fence_unmanaged_renewal')
            except (FileNotFoundError, ProcessLookupError):
                continue

    def save(self, value):
        self.atomic(STATE + '/journal.json', json.dumps(value, sort_keys=True).encode())

    def ensure_state(self, create):
        path = self.path(STATE)
        self.parents(path)
        if not os.path.lexists(path) and create:
            try:
                path.mkdir(mode=0o700)
                self.sync(path.parent)
            except FileExistsError:
                pass
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('tunnel_fence_directory_untrusted')

    def journal(self):
        try:
            value = json.loads(self.read(STATE + '/journal.json'))
        except FileNotFoundError:
            return None
        if (not isinstance(value, dict) or value.get('version') != 1
                or value.get('state') not in ('freezing', 'frozen', 'releasing', 'released')
                or not re.fullmatch(r'[0-9a-f]{64}', value.get('binding', ''))
                or type(value.get('legacy_hook')) is not bool
                or set(value.get('units', {})) != set(UNITS)):
            raise ValueError('tunnel_fence_journal_invalid')
        return value

    def mask(self, name):
        path = self.path('/etc/systemd/system/' + name)
        self.parents(path)
        if os.path.lexists(path):
            info = path.lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or os.readlink(path) != '/dev/null':
                raise ValueError('tunnel_fence_mask_drift')
        else:
            os.symlink('/dev/null', path)
            self.sync(path.parent)

    def masks(self, value, required=True):
        for name, baseline in value['units'].items():
            if sha(self.read(baseline['source'])) != baseline['source_sha256']:
                raise ValueError('tunnel_fence_unit_drift')
            path = self.path('/etc/systemd/system/' + name)
            if os.path.lexists(path):
                info = path.lstat()
                if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or os.readlink(path) != '/dev/null':
                    raise ValueError('tunnel_fence_mask_drift')
            elif required:
                raise ValueError('tunnel_fence_mask_missing')

    def blocked(self, binding):
        if self.read(STATE + '/blocked') != binding.encode():
            raise ValueError('tunnel_fence_binding_changed')

    def hook(self, expected):
        raw = self.read(HOOK)
        if raw not in expected or stat.S_IMODE(self.path(HOOK).lstat().st_mode) != 0o700:
            raise ValueError('tunnel_fence_hook_drift')
        return raw

    def drained(self, value):
        self.masks(value)
        self.process_check()
        for name in UNITS:
            active = self.show(name)
            if (active['LoadState'] != 'masked' or active['UnitFileState'] != 'masked' or active['DropInPaths'] or active['FragmentPath'] != '/dev/null'
                    or active['ActiveState'] not in ('inactive', 'failed')
                    or active['MainPID'] != '0' or active['ControlPID'] != '0'):
                raise ValueError('tunnel_fence_renewal_not_drained')

    def image(self, name, relay=False, private=False):
        path = self.path(name)
        self.parents(path, relay=relay)
        owners = {os.geteuid()}
        if relay:
            try:
                owners.add(pwd.getpwnam('ultra-relay').pw_uid)
            except KeyError:
                pass
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_nlink != 1
                    or info.st_size > 4 * 1024 * 1024 or info.st_mode & 0o022
                    or (private and stat.S_IMODE(info.st_mode) != 0o600)):
                raise ValueError('tunnel_preservation_file_untrusted')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('tunnel_preservation_file_untrusted')
            return {'data': base64.b64encode(raw).decode(), 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        finally:
            os.close(fd)

    def closure(self, domain, fence_state=None, pair_images=None):
        """Read the bounded private renewal closure; never return it remotely."""
        pair = ('/etc/ultra-relay/fullchain.pem', '/etc/ultra-relay/privkey.pem')
        images = {name: pair_images[name] if pair_images is not None else self.image(name, relay=True, private=True) for name in pair}
        # Certbot merges global configuration and executes all global hooks.
        # This bounded dedicated-exit contract cannot attest arbitrary scripts
        # or secret-bearing challenge configuration from another installation.
        for directory, expected in (('pre', []), ('post', []), ('deploy', ['ultra-tunnel'])):
            path = self.path('/etc/letsencrypt/renewal-hooks/' + directory)
            if os.path.lexists(path):
                self.parents(path / 'placeholder')
                if sorted(entry.name for entry in path.iterdir()) != expected:
                    raise ValueError('tunnel_preservation_foreign_global_hook')
            elif expected:
                raise ValueError('tunnel_preservation_hook_missing')
        renewal_dir = self.path('/etc/letsencrypt/renewal')
        self.parents(renewal_dir / 'placeholder')
        if sorted(path.name for path in renewal_dir.glob('*.conf')) != [domain + '.conf']:
            raise ValueError('tunnel_preservation_foreign_lineage')
        for name in ('/etc/letsencrypt/cli.ini', '/root/.config/letsencrypt/cli.ini'):
            if os.path.lexists(self.path(name)):
                images[name] = self.image(name)
                settings = [line.strip() for line in base64.b64decode(images[name]['data']).decode().splitlines()
                            if line.strip() and not line.lstrip().startswith(('#', ';'))]
                if any(not re.fullmatch(r'max-log-backups\s*=\s*0', line) for line in settings):
                    raise ValueError('tunnel_preservation_global_config_unverified')
        spec = json.loads(base64.b64decode(self.image('/etc/ultra-relay/spec.json', relay=True)['data']))
        tls = spec.get('splithttp_tls', {})
        if (spec.get('role') != 'exit' or spec.get('tunnel_tls_provision') != 'acme_letsencrypt'
                or spec.get('mimic_preset') != 'standard' or spec.get('tunnel_transport') != 'splithttp'
                or spec.get('splithttp_host') != domain or tls.get('server_name') != domain or tls.get('omit_sni', False)
                or tls.get('sni_mode', '') not in ('', 'auto', 'send')
                or spec.get('exit', {}).get('pinned_peer_cert_sha256')
                or spec.get('exit_cert') != {'cert_file': pair[0], 'key_file': pair[1]}
                or type(spec.get('vless_port')) is not int or not 1 <= spec['vless_port'] <= 65535 or spec['vless_port'] == 80):
            raise ValueError('tunnel_preservation_spec_identity_unverified')
        identity = {key: spec.get(key) for key in ('role', 'tunnel_tls_provision', 'mimic_preset', 'tunnel_transport',
                                                  'splithttp_host', 'splithttp_path', 'splithttp_tls', 'exit_cert', 'vless_port', 'exit')}
        renewal_name = '/etc/letsencrypt/renewal/' + domain + '.conf'
        images[renewal_name] = self.image(renewal_name)
        renewal = base64.b64decode(images[renewal_name]['data']).decode()
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string('[lineage]\n' + renewal)
        line, params = parser['lineage'], parser['renewalparams']
        live = '/etc/letsencrypt/live/' + domain
        archive = '/etc/letsencrypt/archive/' + domain
        kinds = ('cert', 'chain', 'fullchain', 'privkey')
        if (line.get('archive_dir') != archive or any(line.get(kind) != live + '/' + kind + '.pem' for kind in kinds)
                or params.get('authenticator') != 'webroot'
                or params.get('server') != 'https://acme-v02.api.letsencrypt.org/directory'
                or not re.fullmatch(r'[a-f0-9]{1,128}', params.get('account', ''))
                or params.get('webroot_path', '').rstrip(', ') != '/var/www/ultra-tunnel-acme'
                or any(key in params for key in ('pre_hook', 'post_hook', 'deploy_hook', 'renew_hook', 'manual_auth_hook', 'manual_cleanup_hook'))):
            raise ValueError('tunnel_preservation_renewal_unverified')
        webroot = parser['[webroot_map]'] if '[webroot_map]' in parser else {}
        if dict(webroot) != {domain: '/var/www/ultra-tunnel-acme'}:
            raise ValueError('tunnel_preservation_renewal_unverified')
        links, generation = {}, None
        for kind in kinds:
            path = self.path(live + '/' + kind + '.pem')
            self.parents(path)
            info = path.lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError('tunnel_preservation_lineage_unverified')
            target = os.readlink(path)
            match = re.fullmatch(r'../../archive/' + re.escape(domain) + '/' + kind + r'([1-9][0-9]*)\.pem', target)
            if match is None or (generation is not None and match.group(1) != generation):
                raise ValueError('tunnel_preservation_lineage_unverified')
            generation = match.group(1)
            links[live + '/' + kind + '.pem'] = target
            name = archive + '/' + kind + generation + '.pem'
            images[name] = self.image(name, private=kind == 'privkey')
        if any(images[pair[index]]['data'] != images[archive + '/' + kind + generation + '.pem']['data']
               for index, kind in enumerate(('fullchain', 'privkey'))):
            raise ValueError('tunnel_preservation_undeployed_lineage')
        leaf = base64.b64decode(images[archive + '/cert' + generation + '.pem']['data'])
        chain = base64.b64decode(images[archive + '/chain' + generation + '.pem']['data'])
        if base64.b64decode(images[archive + '/fullchain' + generation + '.pem']['data']) != leaf + chain:
            raise ValueError('tunnel_preservation_lineage_inconsistent')
        account = '/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/' + params['account']
        for name in ('meta.json', 'regr.json', 'private_key.json'):
            images[account + '/' + name] = self.image(account + '/' + name, private=name == 'private_key.json')
        nginx = '/etc/nginx/conf.d/ultra-tunnel-acme.conf'
        images[nginx] = self.image(nginx)
        expected_nginx = ('server {\n    listen 80;\n    server_name ' + domain + ';\n'
                          '    location ^~ /.well-known/acme-challenge/ { root /var/www/ultra-tunnel-acme; }\n'
                          '    location / { return 404; }\n}\n').encode()
        if base64.b64decode(images[nginx]['data']) != expected_nginx:
            raise ValueError('tunnel_preservation_nginx_unverified')
        webroot_path = self.path('/var/www/ultra-tunnel-acme')
        self.parents(webroot_path / 'placeholder')
        webroot_info = webroot_path.lstat()
        if stat.S_IMODE(webroot_info.st_mode) != 0o755:
            raise ValueError('tunnel_preservation_webroot_unverified')
        images[HOOK] = self.image(HOOK)
        fence_state = fence_state or self.journal()
        for baseline in fence_state['units'].values():
            images[baseline['source']] = self.image(baseline['source'])
        return {'images': images, 'links': links, 'spec_identity': identity,
                'webroot': {'mode': stat.S_IMODE(webroot_info.st_mode), 'uid': webroot_info.st_uid, 'gid': webroot_info.st_gid},
                'renewal_units': fence_state['units'], 'legacy_hook': fence_state['legacy_hook']}

    def validate_pair(self, closure, domain):
        # Validate immutable private copies, never paths inside relay-owned
        # directories that could be redirected between openssl invocations.
        validation_root = self.path(STATE) if self.path(STATE).is_dir() else None
        with tempfile.TemporaryDirectory(prefix='.tls-validate-', dir=validation_root) as tmp:
            paths = []
            for name in ('fullchain.pem', 'privkey.pem'):
                path = Path(tmp) / name
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(base64.b64decode(closure['images']['/etc/ultra-relay/' + name]['data']))
                paths.append(str(path))
            cert, key = paths
            public_cert = self.runner(['/usr/bin/openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
            public_key = self.runner(['/usr/bin/openssl', 'pkey', '-in', key, '-pubout'])
            if not public_cert or public_cert != public_key:
                raise ValueError('tunnel_preservation_pair_mismatch')
            self.runner(['/usr/bin/openssl', 'x509', '-in', cert, '-checkend', '86400', '-noout'])
            self.runner(['/usr/bin/openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', domain,
                         '-CApath', '/etc/ssl/certs', '-untrusted', cert, cert])

    def checkpoint(self, action, binding, domain):
        self.blocked(binding)
        value = self.journal()
        if value['state'] != 'frozen' or value['binding'] != binding:
            raise ValueError('tunnel_preservation_not_frozen')
        self.drained(value)
        # Called while control.lock is held. pair.lock also excludes a manual
        # invocation of the known deployment hook during the read/validation.
        with self.lock('pair.lock'):
            current = self.closure(domain)
            self.validate_pair(current, domain)
            if self.closure(domain) != current:
                raise ValueError('tunnel_preservation_concurrent_change')
            path = STATE + '/preservation-' + binding + '.json'
            try:
                previous = json.loads(self.read(path, limit=32 * 1024 * 1024))
            except FileNotFoundError:
                if action != 'capture':
                    raise ValueError('tunnel_preservation_checkpoint_missing') from None
                previous = {'version': 1, 'binding': binding, 'closure': current}
                raw = json.dumps(previous, sort_keys=True).encode()
                if len(raw) > 4 * 1024 * 1024:
                    raise ValueError('tunnel_preservation_checkpoint_too_large')
                self.atomic(path, raw)
            if previous != {'version': 1, 'binding': binding, 'closure': current}:
                raise ValueError('tunnel_preservation_checkpoint_drift')
            return sha(json.dumps(previous, sort_keys=True).encode())

    def restore(self, action, binding, domain):
        self.blocked(binding)
        value = self.journal()
        if value['binding'] != binding or value['state'] != 'frozen':
            raise ValueError('tunnel_preservation_not_frozen')
        self.drained(value)
        path = STATE + '/preservation-' + binding + '.json'
        saved = json.loads(self.read(path, limit=4 * 1024 * 1024))
        if saved.get('version') != 1 or saved.get('binding') != binding:
            raise ValueError('tunnel_preservation_checkpoint_drift')
        pair = ('/etc/ultra-relay/fullchain.pem', '/etc/ultra-relay/privkey.pem')
        expected = saved['closure']
        images = {name: expected['images'][name] for name in pair}
        owners = {os.geteuid()}
        try:
            owners.add(pwd.getpwnam('ultra-relay').pw_uid)
        except KeyError:
            pass
        if any(image.get('mode') != 0o600 or image.get('uid') not in owners
               or type(image.get('gid')) is not int or image['gid'] < 0 for image in images.values()):
            raise ValueError('tunnel_preservation_checkpoint_untrusted')
        with self.lock('pair.lock'):
            self.validate_pair(expected, domain)
            if self.closure(domain, pair_images=images) != expected:
                raise ValueError('tunnel_preservation_nonpair_drift')
            missing = []
            for name in pair:
                try:
                    current = self.image(name, relay=True, private=True)
                except FileNotFoundError:
                    missing.append(name)
                    continue
                if current != images[name]:
                    raise ValueError('tunnel_preservation_foreign_pair')
            if action == 'restore' and missing:
                relay = self.show('ultra-relay.service')
                if relay['ActiveState'] not in ('inactive', 'failed') or relay['MainPID'] != '0' or relay['ControlPID'] != '0':
                    raise ValueError('tunnel_preservation_relay_not_stopped')
                # Missing or exact-before is the only accepted state. Unknown
                # replacement bytes are never overwritten. Each atomic write is
                # independently retryable after a crash between the pair files.
                for name in missing:
                    target = self.path(name)
                    self.parents(target, relay=True)
                    fd, temporary = tempfile.mkstemp(prefix='.tls-restore-', dir=target.parent)
                    try:
                        with os.fdopen(fd, 'wb') as stream:
                            os.fchmod(stream.fileno(), images[name]['mode'])
                            os.fchown(stream.fileno(), images[name]['uid'], images[name]['gid'])
                            stream.write(base64.b64decode(images[name]['data']))
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(temporary, target)
                        self.sync(target.parent)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
                if self.closure(domain) != expected:
                    raise ValueError('tunnel_preservation_restore_unverified')
            return {'verified': True, 'state': 'frozen', 'binding': binding, 'needs_restore': bool(missing) if action == 'check-restore' else False}

    def inspect(self, request, binding, candidate_hook, legacy_hook):
        value = None
        if os.path.lexists(self.path(STATE)):
            self.ensure_state(create=False)
            value = self.journal()
        if value and value['state'] != 'released':
            if value['binding'] != binding:
                raise ValueError('tunnel_fence_request_changed')
            self.masks(value, required=value['state'] == 'frozen')
            if value['state'] == 'frozen':
                self.hook((candidate_hook,))
        else:
            value = {'units': {name: self.unit(name) for name in UNITS}, 'legacy_hook': self.read(HOOK) == legacy_hook}
        self.process_check()
        before = self.closure(request['domain'], value)
        self.validate_pair(before, request['domain'])
        if self.closure(request['domain'], value) != before:
            raise ValueError('tunnel_preservation_concurrent_change')
        return {'verified': True, 'state': 'inspected', 'binding': binding}

    def execute(self, action, request_json, hook_sha256, attempts=30, require_checkpoint=False):
        if (action not in ('inspect', 'inspect-compensation', 'acquire', 'status', 'release', 'capture', 'verify', 'check-restore', 'restore')
                or not isinstance(request_json, str) or len(request_json) > 65536
                or not re.fullmatch(r'[a-f0-9]{64}', hook_sha256)):
            raise ValueError('tunnel_fence_request_invalid')
        request = json.loads(request_json)
        if (not isinstance(request, dict) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', request.get('transaction', ''))
                or not valid_domain(request.get('domain'))):
            raise ValueError('tunnel_fence_request_invalid')
        candidate_hook = hook_bytes(request['domain'])
        legacy_hook = hook_bytes(request['domain'], legacy=True)
        if sha(candidate_hook) != hook_sha256:
            raise ValueError('tunnel_fence_hook_unverified')
        # Reject unrecognized hooks before even provisioning lock metadata on a
        # legacy host. Recheck after taking the control lock below.
        if self.read(HOOK) not in (candidate_hook, legacy_hook):
            raise ValueError('tunnel_fence_hook_unverified')
        binding = sha((request_json + '\n' + hook_sha256).encode())
        if action == 'inspect':
            return self.inspect(request, binding, candidate_hook, legacy_hook)
        self.ensure_state(create=action == 'acquire')
        with self.lock('control.lock'):
            value = self.journal()
            if value and value['binding'] != binding:
                if value['state'] != 'released' or action != 'acquire':
                    raise ValueError('tunnel_fence_request_changed')
                value = None
            if action == 'inspect-compensation':
                if value is None or value['state'] not in ('frozen', 'releasing', 'released'):
                    raise ValueError('tunnel_preservation_compensation_unbound')
                if value['state'] == 'frozen':
                    return self.restore('check-restore', binding, request['domain'])
                # A lost release reply can follow complete runtime rollback.
                # Missing-pair recovery is no longer authorized once releasing;
                # prove the actual current closure before retrying release.
                return self.inspect(request, binding, candidate_hook, legacy_hook)
            hook = self.read(HOOK)
            if hook not in (candidate_hook, legacy_hook):
                raise ValueError('tunnel_fence_hook_unverified')
            info = self.path(HOOK).lstat()
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('tunnel_fence_hook_unverified')
            if value is None:
                if action != 'acquire':
                    raise ValueError('tunnel_fence_request_unbound')
                if os.path.lexists(self.path(STATE + '/blocked')):
                    raise ValueError('tunnel_fence_foreign_marker')
                units = {name: self.unit(name) for name in UNITS}
                self.process_check()
                value = {'version': 1, 'binding': binding, 'state': 'freezing', 'units': units, 'legacy_hook': hook == legacy_hook,
                         'request': request, 'request_json': request_json, 'hook_sha256': hook_sha256}
                self.save(value)  # Persist ownership before any external effect.
            if value['state'] == 'frozen' and hook != candidate_hook:
                raise ValueError('tunnel_fence_hook_drift')
            if value['state'] == 'released':
                if action in ('capture', 'verify', 'check-restore', 'restore'):
                    raise ValueError('tunnel_preservation_not_frozen')
                if require_checkpoint and not re.fullmatch(r'[a-f0-9]{64}', value.get('release_preservation_sha256', '')):
                    raise ValueError('tunnel_preservation_release_unverified')
                if hook != (legacy_hook if value['legacy_hook'] else candidate_hook):
                    raise ValueError('tunnel_fence_hook_drift')
                if os.path.lexists(self.path(STATE + '/blocked')):
                    raise ValueError('tunnel_fence_foreign_marker')
                self.masks(value, required=False)
                if any(os.path.lexists(self.path('/etc/systemd/system/' + name)) for name in UNITS):
                    raise ValueError('tunnel_fence_mask_drift')
                return {'verified': True, 'state': 'released', 'binding': binding}
            if action == 'acquire':
                if value['state'] not in ('freezing', 'frozen'):
                    raise ValueError('tunnel_fence_phase_invalid')
                if os.path.lexists(self.path(STATE + '/blocked')):
                    self.blocked(binding)
                self.masks(value, required=False)
                for name in UNITS:
                    self.mask(name)
                self.runner(['/usr/bin/systemctl', 'daemon-reload'])
                self.runner(['/usr/bin/systemctl', 'stop', 'certbot.timer'])
                # Never kill an issuance or block its deploy-hook. Drain the
                # already-running managed service before creating the marker,
                # so a renewed lineage is deployed normally before the snapshot.
                # Do not hold pair.lock while waiting for that hook to complete.
                for _ in range(attempts):
                    self.process_check()
                    active = self.show('certbot.service')
                    if active['ActiveState'] in ('inactive', 'failed') and active['MainPID'] == active['ControlPID'] == '0':
                        break
                    self.sleeper(1)
                else:
                    raise ValueError('tunnel_fence_renewal_not_drained')
                with self.lock('pair.lock'):
                    self.drained(value)
                    # Known legacy hooks are replaced only after their managed
                    # renewal has fully drained. Retry accepts either exact
                    # before/candidate bytes around this atomic write.
                    if self.hook((legacy_hook, candidate_hook)) == legacy_hook:
                        self.atomic(HOOK, candidate_hook, mode=0o700)
                    if os.path.lexists(self.path(STATE + '/blocked')):
                        self.blocked(binding)
                    else:
                        self.atomic(STATE + '/blocked', binding.encode())
                    self.masks(value)
                    value['state'] = 'frozen'
                    self.save(value)
            elif action == 'status':
                if value['state'] != 'frozen':
                    raise ValueError('tunnel_fence_not_frozen')
                self.blocked(binding)
                self.drained(value)
            elif action in ('capture', 'verify'):
                evidence = self.checkpoint(action, binding, request['domain'])
                return {'verified': True, 'state': 'frozen', 'binding': binding, 'preservation_sha256': evidence}
            elif action in ('check-restore', 'restore'):
                return self.restore(action, binding, request['domain'])
            elif action == 'release':
                if value['state'] not in ('freezing', 'frozen', 'releasing'):
                    raise ValueError('tunnel_fence_phase_invalid')
                self.process_check()
                if value['state'] == 'releasing' and require_checkpoint and not re.fullmatch(r'[a-f0-9]{64}', value.get('release_preservation_sha256', '')):
                    raise ValueError('tunnel_preservation_release_unverified')
                if value['state'] != 'releasing':
                    if require_checkpoint:
                        value['release_preservation_sha256'] = self.checkpoint('verify', binding, request['domain'])
                    if value['state'] == 'frozen':
                        self.blocked(binding)
                        self.drained(value)
                    else:
                        # An interrupted freeze may own only some masks and
                        # has not yet exposed a certificate snapshot.
                        if os.path.lexists(self.path(STATE + '/blocked')):
                            self.blocked(binding)
                        self.masks(value, required=False)
                    value['state'] = 'releasing'
                    self.save(value)
                self.masks(value, required=False)
                # Restore the exact original hook while systemd renewal remains
                # excluded. This restores bytes on rollback and keeps the fence
                # primitive independent of release acceptance policy.
                with self.lock('pair.lock'):
                    original_hook = legacy_hook if value['legacy_hook'] else candidate_hook
                    if self.hook((legacy_hook, candidate_hook)) != original_hook:
                        self.atomic(HOOK, original_hook, mode=0o700)
                for name in UNITS:
                    path = self.path('/etc/systemd/system/' + name)
                    if os.path.lexists(path):
                        path.unlink()
                        self.sync(path.parent)
                self.runner(['/usr/bin/systemctl', 'daemon-reload'])
                # Remove the marker before restoring the timer. A crash here
                # leaves a releasing journal; its retry still restores activity.
                with self.lock('pair.lock'):
                    marker = self.path(STATE + '/blocked')
                    if os.path.lexists(marker):
                        self.blocked(binding)
                        marker.unlink()
                        self.sync(marker.parent)
                if value['units']['certbot.timer']['ActiveState'] == 'active':
                    self.runner(['/usr/bin/systemctl', 'start', 'certbot.timer'])
                value['state'] = 'released'
                self.save(value)
            return {'verified': True, 'state': value['state'], 'binding': binding}


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'choices': ['inspect', 'inspect-compensation', 'acquire', 'status', 'release', 'capture', 'verify', 'check-restore', 'restore'], 'required': True},
        'request_json': {'type': 'str', 'required': True, 'no_log': True},
        'hook_sha256': {'type': 'str', 'required': True},
        'require_checkpoint': {'type': 'bool', 'default': False},
    }, supports_check_mode=False)
    try:
        if os.geteuid() != 0:
            raise ValueError('tunnel_fence_root_required')
        result = Fence().execute(module.params['action'], module.params['request_json'], module.params['hook_sha256'],
                                 require_checkpoint=module.params['require_checkpoint'])
        module.exit_json(changed=module.params['action'] not in ('inspect', 'inspect-compensation', 'status', 'verify', 'check-restore'), **result)
    except Exception:
        module.fail_json(msg='tunnel_tls_fence_unverified')


if __name__ == '__main__':
    main()
