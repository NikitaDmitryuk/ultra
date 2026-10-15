#!/usr/bin/env python3
"""Production restore phases on an explicitly prepared, fenced replacement VM."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request

from recovery import atomic_json, repository
from restore_common import APP_UNITS, AUTOMATION_UNITS, PHASES, fence, safe_target, sha, stage_manifests, system_unit, safe_error_code


def run(args, data=None, timeout=180):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise ValueError('host_command_failed')
    return result.stdout


def identifier(value):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value):
        raise ValueError('unsupported_database_identifier')
    return '"' + value + '"'


def database_spec(spec):
    value = urllib.parse.urlsplit(spec.get('database', {}).get('dsn', ''))
    if value.scheme not in ('postgres', 'postgresql') or value.hostname not in ('localhost', '127.0.0.1') or value.port != 25432:
        raise ValueError('dedicated_database_tunnel_uri_required')
    name, user = urllib.parse.unquote(value.path.lstrip('/')), urllib.parse.unquote(value.username or '')
    identifier(name); identifier(user)
    password = urllib.parse.unquote(value.password or '')
    if not password or '\x00' in password or '\n' in password:
        raise ValueError('application_database_password_required')
    return name, user, password


def unit_environment(unit, root=Path('/')):
    """Read only the supported systemd directives; never execute saved shell text."""
    directory = Path(root) / 'etc/systemd/system'
    files = [directory / unit] + sorted((directory / (unit + '.d')).glob('*.conf'))
    values, envfiles, user = {}, [], 'root'
    for path in files:
        if not path.exists() or path.is_symlink():
            continue
        section = ''
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(('#', ';')):
                continue
            if line.startswith('['):
                section = line
            if section != '[Service]' or '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key == 'User':
                user = value
            elif key == 'Environment':
                if not value:
                    values.clear()
                for item in shlex.split(value):
                    name, content = item.split('=', 1)
                    values[name] = content
            elif key == 'EnvironmentFile':
                if not value:
                    envfiles.clear()
                else:
                    envfiles.extend(shlex.split(value))
    for filename in envfiles:
        optional = filename.startswith('-')
        filename = filename.removeprefix('-')
        if not filename.startswith('/') or any(char in filename for char in ('%', '*', '?')):
            raise ValueError('unsupported_environment_file')
        path = Path(root) / filename.lstrip('/')
        if optional and not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith(('#', ';')):
                continue
            if '=' not in line or line.endswith('\\'):
                raise ValueError('unsupported_environment_syntax')
            name, value = line.split('=', 1)
            parts = shlex.split(value, comments=False)
            if len(parts) > 1:
                raise ValueError('unsupported_environment_value')
            values[name.strip()] = parts[0] if parts else ''
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('invalid_service_user')
    return user, values


def relocate_spec(spec, old_address, new_public_host):
    """Change owned published endpoints while retaining users, SNI and exits."""
    old_hosts = {old_address, spec.get('public_host')}
    spec['public_host'] = new_public_host
    primary = spec.get('primary_xhttp')
    if primary and primary.get('host') in old_hosts:
        primary['host'] = new_public_host
    for key in ('subscription_bridges', 'subscription_preview_bridges', 'public_entries'):
        for entry in spec.get(key, []):
            if entry.get('host') in old_hosts:
                entry['host'] = new_public_host
    return spec


def certificate_files(value):
    result = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ('cert_file', 'certificate_file', 'key_file') and isinstance(item, str) and item.startswith('/'):
                result.append(item)
            else:
                result.extend(certificate_files(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(certificate_files(item))
    return result


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('write_symlink_rejected')
    temporary = path.with_name('.' + path.name + '.restore-pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
        stream.flush(); os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
    os.replace(temporary, path)



def relocate_deployment(deployment, plan):
    deployment['bridge_ipv4'] = plan['new_bridge_address']
    deployment['bridge_provider'] = plan['new_bridge_provider']
    deployment['database_host'] = plan['database_host']
    if (deployment.get('ingress') or {}).get('public_host') == plan['old_bridge_address']:
        deployment['ingress']['public_host'] = plan['new_bridge_address']
    return deployment


def install_files(stage, state, artifacts, root=Path('/')):
    # Active unit paths remain masked until the named activation phase. Their
    # originals stay in stage; inert /opt templates are installed normally.
    for source, manifest, prefix in ((stage, state, 'state/'), (stage / 'artifacts', artifacts, '')):
        for name, row in manifest['files'].items():
            if name == 'database.dump':
                continue
            relative = name.removeprefix(prefix)
            if system_unit(relative):
                continue
            target = safe_target(root, relative)
            write(target, (source / name).read_bytes(), row['mode'])


def restore_certbot_lineages(stage, state, root=Path("/")):
    """Rebuild only selected Certbot lineages; older bundles contain flat PEMs."""
    kinds = ('cert', 'privkey', 'chain', 'fullchain')
    for selected in sorted(state['files']):
        match = re.fullmatch(r'state/etc/letsencrypt/renewal/([A-Za-z0-9][A-Za-z0-9_.-]{0,252})\.conf', selected)
        if not match:
            continue
        name = match[1]
        values = {}
        for line in (Path(stage) / selected).read_text().splitlines():
            if line.lstrip().startswith('['):
                break
            if '=' in line and not line.lstrip().startswith('#'):
                key, value = (part.strip() for part in line.split('=', 1))
                if key in values:
                    raise ValueError('certbot_lineage_invalid')
                values[key] = value
        archive = 'etc/letsencrypt/archive/' + name
        live = 'etc/letsencrypt/live/' + name
        if values.get('archive_dir') != '/' + archive or any(values.get(k) != '/' + live + '/' + k + '.pem' for k in kinds):
            raise ValueError('certbot_lineage_invalid')
        entries = []
        for kind in kinds:
            relative = live + '/' + kind + '.pem'
            row = state['files'].get('state/' + relative)
            source = Path(stage) / 'state' / relative
            if not row or not source.is_file() or sha(source) != row['sha256']:
                raise ValueError('certbot_lineage_state_incomplete')
            # Check parents even when a previous activation already linked PEMs.
            safe_target(root, relative + '.lineage-check')
            target = Path(root) / relative
            if target.is_symlink():
                link = target.readlink()
                if not re.fullmatch(r'\.\./\.\./archive/' + re.escape(name) + '/' + kind + r'[1-9][0-9]*\.pem', str(link)):
                    raise ValueError('certbot_lineage_invalid')
                safe_target(root, archive + '/' + link.name)
            if not target.is_file() or sha(target) != row['sha256']:
                raise ValueError('certbot_lineage_state_changed')
            entries.append((kind, source, target, target.stat()))
        # Reuse an interrupted generation or choose a free version without
        # overwriting any older archive content included by a future bundle.
        for version in range(1, 10001):
            destinations = [safe_target(root, archive + '/' + k + str(version) + '.pem') for k in kinds]
            if all(not p.exists() or (p.is_file() and sha(p) == sha(entry[1])) for p, entry in zip(destinations, entries)):
                break
        else:
            raise ValueError('certbot_lineage_version_limit')
        for directory, original in ((Path(root)/'etc/letsencrypt/archive', Path(root)/'etc/letsencrypt/live'), (Path(root)/archive, Path(root)/live)):
            directory.mkdir(parents=True, exist_ok=True)
            metadata = original.stat()
            os.chown(directory, -1, metadata.st_gid)
            directory.chmod(metadata.st_mode & 0o777)
        for destination, (kind, source, target, metadata) in zip(destinations, entries):
            if not destination.exists():
                write(destination, source.read_bytes(), metadata.st_mode & 0o777)
            os.chown(destination, metadata.st_uid, metadata.st_gid)
            destination.chmod(metadata.st_mode & 0o777)
            link = Path('../../archive') / name / destination.name
            pending = target.with_name('.' + target.name + '.restore-link')
            if pending.is_symlink() and pending.readlink() == link:
                pass  # Previous process stopped immediately before replacement.
            elif pending.exists() or pending.is_symlink():
                raise ValueError('certbot_lineage_invalid')
            else:
                pending.symlink_to(link)
            os.replace(pending, target)



def restore_units(stage, state, root=Path('/')):
    for name, row in state['files'].items():
        relative = name.removeprefix('state/')
        if not name.startswith('state/') or not system_unit(relative):
            continue
        target = Path(root) / relative
        # Do not recreate enabled links before explicit activation. Only regular
        # base units and drop-ins are needed; enable commands create correct links.
        if any(part.endswith('.wants') or part.endswith('.requires') for part in target.parts):
            continue
        if target.is_symlink():
            if target.readlink() != Path('/dev/null'):
                raise ValueError('foreign_unit_symlink')
            target.unlink()
        write(safe_target(root, relative), (stage / name).read_bytes(), row['mode'])


def seed_artifact_cache(repo, name, expected, stream):
    """Reuse the verified generation's original ciphertext on the new primary."""
    import hashlib
    import tempfile
    from recovery import MAX_BYTES, sync_directory
    if not re.fullmatch(r'artifact-[a-f0-9]{64}\.age', name) or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('invalid_artifact_reference')
    repo = repository(repo, 'bridge')
    with (repo / '.capture-lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        fd, temporary = tempfile.mkstemp(prefix='.restore-artifact-', dir=repo)
        try:
            digest = hashlib.sha256(); size = 0
            with os.fdopen(fd, 'wb') as output:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    size += len(chunk)
                    if size > MAX_BYTES: raise ValueError('encrypted_backup_exceeds_bounds')
                    digest.update(chunk); output.write(chunk)
                output.flush(); os.fsync(output.fileno())
            if not size or digest.hexdigest() != expected:
                raise ValueError('staged_manifest_mismatch')
            target = repo / name
            if target.is_symlink(): raise ValueError('restore_destination_symlink')
            if target.exists() and sha(target) != expected:
                # A previous failed restore may have re-encrypted identical bytes.
                # Preserve that local cache; immutable receiver objects never change.
                previous = repo / (name + '.pre-restore-' + sha(target))
                if previous.is_symlink(): raise ValueError('restore_destination_symlink')
                if not previous.exists(): os.replace(target, previous)
            os.replace(temporary, target); sync_directory(repo)
        finally:
            Path(temporary).unlink(missing_ok=True)


def restore_fleet_directory(path='/etc/ultra-fleet'):
    directory = Path(path)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('restored_fleet_identity_directory_invalid')
    relay = pwd.getpwnam('ultra-relay')
    os.chown(directory, 0, relay.pw_gid)
    directory.chmod(0o750)


class Host:
    def __init__(self, directory, plan):
        self.directory = Path(directory)
        self.plan = plan
        self.stage = self.directory / 'stage'
        self.status_path = self.directory / 'host-status.json'
        self.status = json.loads(self.status_path.read_text()) if self.status_path.exists() else {'completed': []}
        if self.status.get('restore_id', plan['restore_id']) != plan['restore_id']:
            raise ValueError('restore_marker_conflict')
        self.status['restore_id'] = plan['restore_id']

    def persist(self):
        atomic_json(self.status_path, self.status)

    def prepare(self):
        if os.geteuid() != 0:
            raise ValueError('root_target_required')
        owner = self.directory.parent / 'target-owner.json'
        if owner.exists() and json.loads(owner.read_text()).get('restore_id') != self.plan['restore_id']:
            raise ValueError('target_owned_by_another_restore')
        architecture = run(['uname', '-m']).decode().strip()
        if architecture not in ('x86_64', 'aarch64') or architecture != self.plan['architecture']:
            raise ValueError('target_generation_architecture_mismatch')
        os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        if os_release.get('ID', '').strip('"') != 'ubuntu' or os_release.get('VERSION_ID', '').strip('"') != '24.04':
            raise ValueError('ubuntu_24_04_target_required')
        machine = Path('/etc/machine-id').read_text().strip()
        if not re.fullmatch(r'[a-f0-9]{32}', machine):
            raise ValueError('machine_identity_required')
        if self.status.get('machine_id', machine) != machine:
            raise ValueError('target_machine_changed')
        if not self.status.get('prepared') and Path('/etc/ultra-relay/spec.json').exists():
            raise ValueError('target_already_contains_ultra')
        atomic_json(owner, {'restore_id': self.plan['restore_id']})
        for tool in ('python3', 'age', 'nginx', 'systemctl', 'ssh', 'curl', 'openssl'):
            if not shutil.which(tool):
                raise ValueError('prepared_target_tools_missing')
        if shutil.disk_usage('/var/lib').free < 3 * 1024**3:
            raise ValueError('target_disk_insufficient')
        if not self.status.get('prepared'):
            if Path('/etc/ultra-relay/spec.json').exists():
                raise ValueError('target_already_contains_ultra')
            self.status.update(prepared=True, machine_id=machine)
            self.persist()  # Own the dedicated target before installing any state.

    def unpack(self):
        if self.stage.exists():
            return stage_manifests(self.stage)
        if sha(self.directory / 'stage.tar.gz') != self.plan['stage_sha256']:
            raise ValueError('stage_transport_checksum_mismatch')
        temporary = self.directory / 'stage.pending'
        if temporary.exists():
            shutil.rmtree(temporary)  # Only this run's incomplete staging directory.
        temporary.mkdir(mode=0o700)
        try:
            with tarfile.open(self.directory / 'stage.tar.gz') as archive:
                members = archive.getmembers()
                if len(members) > 45000 or sum(item.size for item in members) > 1024**3:
                    raise ValueError('stage_archive_exceeds_bounds')
                seen = set()
                for item in members:
                    name = item.name
                    if name in seen or name.startswith('/') or '..' in Path(name).parts or not item.isfile():
                        raise ValueError('invalid_stage_archive')
                    seen.add(name)
                    target = temporary / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    write(target, archive.extractfile(item).read(), 0o600)
            stage_manifests(temporary)
            temporary.rename(self.stage)
        except Exception:
            shutil.rmtree(temporary)
            raise
        return stage_manifests(self.stage)

    def install(self):
        state, artifacts = self.unpack()
        self.status['snapshot_at'] = state['snapshot_at']
        install_files(self.stage, state, artifacts)
        spec_path = Path('/etc/ultra-relay/spec.json')
        spec = json.loads(spec_path.read_text())
        name, user, _ = database_spec(spec)
        relocate_spec(spec, self.plan['old_bridge_address'], self.plan['public_host'])
        # DSN already requires loopback; preserve role, password, query options.
        write(spec_path, json.dumps(spec))
        deployment_path = Path('/etc/ultra-recovery/deployment.json')
        if deployment_path.exists():
            deployment = json.loads(deployment_path.read_text())
            atomic_json(deployment_path, relocate_deployment(deployment, self.plan))
        Path('/var/www/ultra-acme/.well-known/acme-challenge').mkdir(parents=True, exist_ok=True)
        for directory in (Path('/var/www'), *Path('/var/www').rglob('*')):
            if directory.is_dir() and not directory.is_symlink():
                directory.chmod(0o755)
        # Read saved units from a private view while active unit paths stay masked.
        view = self.directory / 'unit-view'
        view.mkdir(exist_ok=True, mode=0o700)
        for filename in state['files']:
            if filename.startswith('state/'):
                target = view / filename.removeprefix('state/')
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.stage / filename, target)
        environments = {}
        for unit in APP_UNITS:
            service_user, values = unit_environment(unit, view)
            environments[unit] = values
            try:
                account = pwd.getpwnam(service_user)
            except KeyError:
                raise ValueError('restored_service_account_missing') from None
            if unit == 'ultra-relay.service':
                inventory = {item.removeprefix('state/') for item in state['files']} | set(artifacts['files'])
                for filename in certificate_files(spec):
                    if filename.lstrip('/') not in inventory:
                        raise ValueError('referenced_certificate_missing_from_generation')
                    certificate = safe_target('/', filename.lstrip('/'))
                    os.chown(certificate, account.pw_uid, account.pw_gid)
                    certificate.chmod(0o600)
                    for parent in certificate.parents:
                        if parent in (Path('/etc'), Path('/var'), Path('/usr'), Path('/opt'), Path('/')):
                            break
                        if parent.stat().st_mode & 0o001 == 0:
                            os.chown(parent, -1, account.pw_gid)
                            parent.chmod(parent.stat().st_mode & 0o777 | 0o050)
            folders = ('/etc/ultra-relay', '/var/lib/ultra-relay') if unit == 'ultra-relay.service' else ('/var/lib/ultra-bot',)
            for folder in folders:
                if Path(folder).exists():
                    run(['chown', '-R', service_user + ':' + service_user, folder])
            for key, value in values.items():
                if key.startswith('ULTRA_') and value and key.endswith(('_KEY_FILE', '_STATE_DIR')):
                    target = safe_target('/', value.lstrip('/'))
                    if not target.exists():
                        raise ValueError('restored_service_resource_missing')
                    if target.is_dir():
                        run(['chown', '-R', service_user + ':' + service_user, str(target)])
                    else:
                        os.chown(target, account.pw_uid, account.pw_gid)
                        target.chmod(0o600)
            if values.get('ULTRA_DB_DSN'):
                if database_spec({'database': {'dsn': values['ULTRA_DB_DSN']}})[:2] != (name, user):
                    raise ValueError('separate_bot_database_unsupported')
        # New asset parent directories need traversal by the unprivileged relay.
        for base in ('/usr/local/share/xray', '/usr/share/xray'):
            if Path(base).exists():
                for path in (Path(base), *Path(base).rglob('*')):
                    if path.is_dir() and not path.is_symlink():
                        path.chmod(0o755)
        # Backup preserves files; recreate traversal permissions on the root-owned
        # parent separately, without making it writable by the runtime account.
        restore_fleet_directory()
        relay = environments['ultra-relay.service']
        if not relay.get('ULTRA_VULTR_SSH_KEY_FILE'):
            raise ValueError('backup_automation_identity_required')
        # Preserve intended environment for final activation; no values are output.
        atomic_json(self.directory / 'service-environment.json', environments)
        reconcile_path = Path('/etc/ultra-recovery/reconcile.json')
        reconcile_config = json.loads(reconcile_path.read_text())
        reconcile_config['bridge_provider'] = self.plan['new_bridge_provider']
        reconcile_config['database_host'] = self.plan['database_host']
        atomic_json(reconcile_path, reconcile_config)
        backup_config = json.loads(Path('/etc/ultra-recovery/backup.json').read_text())
        # Old provider receipts do not establish independence for this new primary.
        # Reconciliation may set this true only after validating fresh deliveries.
        backup_config['independent'] = False
        backup_config['database_host'] = self.plan['database_host']
        atomic_json('/etc/ultra-recovery/backup.json', backup_config)
        repo = Path(backup_config['repository'])
        if repo != Path('/var/lib/ultra-recovery') or backup_config['source'] != 'bridge':
            raise ValueError('unsupported_primary_repository')
        if (repo / '.ultra-recovery-repository').exists():
            repository(repo, 'bridge')
        else:
            repository(repo, 'bridge', initialize=True)
        self.status['database_name'] = name
        self.persist()

    def override(self, final=False):
        values = {'ULTRA_VULTR_BRIDGE_IP': self.plan['new_bridge_address']}
        if not final:
            values['ULTRA_VULTR_KEY_FILE'] = ''
        envfile = Path('/etc/ultra-recovery/restored-environment')
        write(envfile, ''.join(key + '=' + json.dumps(value) + '\n' for key, value in values.items()))
        for unit in APP_UNITS:
            write('/etc/systemd/system/' + unit + '.d/zzzz-recovery-restore.conf', '[Service]\nEnvironmentFile=' + str(envfile) + '\n')

    def activate(self):
        state, _ = stage_manifests(self.stage)
        restore_certbot_lineages(self.stage, state)
        restore_units(self.stage, state)
        self.override()
        # Re-mask automation after restoring its base units; preserve files in
        # the stage and activate them only after the public ingress switch.
        for unit in AUTOMATION_UNITS:
            path = Path('/etc/systemd/system') / unit
            if path.exists() and not path.is_symlink():
                path.unlink()
        run(['nginx', '-t'])
        run(['/usr/local/bin/ultra-relay', '-check', '-spec', '/etc/ultra-relay/spec.json'])

    def api(self, path):
        env = json.loads((self.directory / 'service-environment.json').read_text())['ultra-relay.service']
        spec = json.loads(Path('/etc/ultra-relay/spec.json').read_text())
        address = spec.get('admin_listen', '127.0.0.1:8443')
        if not re.fullmatch(r'(?:127\.0\.0\.1|localhost):[0-9]+', address):
            raise ValueError('loopback_admin_api_required')
        request = urllib.request.Request('http://' + address + path, headers={'Authorization': 'Bearer ' + env['ULTRA_RELAY_ADMIN_TOKEN']})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def wait_runtime(self):
        until = time.monotonic() + self.plan.get('readiness_timeout', 900)
        while time.monotonic() < until:
            try:
                value = self.api('/v1/hardening')
                runtime = value['runtime']
                if runtime['mode'] == 'online' and runtime['revision'] == runtime['applied_revision'] and not runtime.get('error') and not value.get('reload', {}).get('error'):
                    return
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(3)
        raise ValueError('runtime_readiness_timeout')

    def automation(self):
        state, _ = stage_manifests(self.stage)
        # Only automatic units; never recopy application config over live state.
        for name, row in state['files'].items():
            relative = name.removeprefix('state/')
            if system_unit(relative) and any(Path(relative).parts[3] in (unit, unit + '.d') for unit in AUTOMATION_UNITS):
                if any(part.endswith('.wants') for part in Path(relative).parts):
                    continue
                target = Path('/') / relative
                if target.is_symlink() and target.readlink() == Path('/dev/null'):
                    target.unlink()
                write(target, (self.stage / name).read_bytes(), row['mode'])
        self.override(final=True)

    def ready(self):
        # One passive observation per Ansible attempt. The operator releases the
        # infrastructure lease between attempts so background proofs can progress.
        self.wait_runtime()
        try:
            backup = json.loads(Path('/var/lib/ultra-recovery/last-success.json').read_text())
            controller = json.loads(Path('/var/lib/ultra-relay/recovery-reconcile-status.json').read_text())
            from recovery_status import independent_generation
            config = json.loads(Path('/etc/ultra-recovery/reconcile.json').read_text())
            controller_state = json.loads((Path(config['state_dir']) / 'state.json').read_text())
            if (0 <= time.time() - backup.get('snapshot_at', 0) <= 300
                    and controller.get('state') == 'ready' and controller.get('independent') is True
                    and independent_generation(config, controller_state, controller, backup)
                    and 0 <= time.time() - controller_state.get('updated_at', 0) <= 120
                    and 0 <= time.time() - controller.get('updated_at', 0) <= 120):
                self.status['ready_at'] = int(time.time())
                return
        except (OSError, ValueError, KeyError, TypeError):
            pass
        raise ValueError('backup_monitor_replica_readiness_timeout')

    def ingress(self):
        if self.plan.get('ingress_mode', 'forward') == 'direct':
            self.direct_ingress()
            return
        if self.plan.get('ingress_confirmed') is not True:
            raise ValueError('verified_public_ingress_required')

    def direct_ingress(self):
        import dns
        policy = json.loads(dns.private('/etc/ultra-recovery/dns.json').read_text())
        config, previous = policy['config'], dict(policy['desired'])
        if set(previous) not in ({'subscription', 'vpn'}, {'subscription', 'vpn', 'backend'}):
            raise ValueError('restored_dns_policy_required')
        # Older bootstrap plans may save only the public pair while DNS ownership
        # already includes the separately migrated backend. Move that owned record
        # with the bridge rather than silently retaining the fenced source address.
        receipt = json.loads(dns.private('/etc/ultra-recovery/dns-receipt.json').read_text())
        backend = receipt.get('records', {}).get('backend')
        if backend is not None:
            if (receipt.get('version') != 1 or receipt.get('zone') != config['zone']
                    or not isinstance(backend, dict)
                    or set(backend) != {'id', 'type', 'name', 'data', 'ttl'}
                    or backend['type'] != 'A' or not re.fullmatch(r'[A-Za-z0-9-]+', str(backend['id']))
                    or not isinstance(backend['name'], str) or not dns.LABEL.fullmatch(backend['name'])
                    or type(backend['ttl']) is not int or not 120 <= backend['ttl'] <= 86400):
                raise ValueError('restored_backend_dns_ownership_required')
            ipaddress.IPv4Address(backend['data'])
            if 'backend' in previous and previous['backend'].get('name') != backend['name']:
                raise ValueError('restored_backend_dns_policy_mismatch')
            previous['backend'] = {'name': backend['name'], 'data': backend['data']}
        elif 'backend' in previous:
            raise ValueError('restored_backend_dns_ownership_required')
        names = {role: previous[role]['name'] + '.' + config['zone'] for role in previous}
        if names['subscription'] != self.plan['subscription_domain'] or names['vpn'] != self.plan['public_host']:
            raise ValueError('restored_dns_policy_mismatch')
        desired = {role: dict(previous[role], data=self.plan['new_bridge_address']) for role in previous}
        backend_port = None
        backend_hostname = None
        if backend is not None:
            _, environment = unit_environment('ultra-bot.service')
            # A completed migration rollback retains ownership of the unused
            # backend A record. Move it too, but probe the effective bot identity.
            backend_hostname = environment.get('ULTRA_BOT_DOMAIN', '')
            if (not isinstance(backend_hostname, str) or not 1 <= len(backend_hostname) <= 253
                    or '.' not in backend_hostname
                    or not all(dns.LABEL.fullmatch(label) for label in backend_hostname.split('.'))):
                raise ValueError('restored_backend_hostname_required')
            try:
                backend_port = int(environment['ULTRA_BOT_PORT'])
            except (KeyError, TypeError, ValueError):
                raise ValueError('restored_backend_port_required') from None
            if not 1 <= backend_port <= 65535:
                raise ValueError('restored_backend_port_required')
        # Before publishing the A records, validate public certificates against
        # the replacement IP, bypassing DNS but preserving hostname validation.
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        for role in ('subscription', 'vpn'):
            name = names[role]
            with socket.create_connection((self.plan['new_bridge_address'], 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=name):
                    pass
        if backend_port is not None:
            with socket.create_connection(('127.0.0.1', backend_port), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=backend_hostname):
                    pass
        run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '30',
             '--resolve', names['subscription'] + ':443:' + self.plan['new_bridge_address'],
             'https://' + names['subscription'] + '/healthz'])
        fence(self.plan['fence'], 'bridge', self.plan['target_host'], self.plan['old_bridge_address'], migration=self.plan.get('migration_identity'))
        dns.execute(config, desired, '/etc/ultra-recovery/dns-receipt.json')
        dns.wait_ready(config, desired, timeout=120)
        # Persist the new intent only after authoritative convergence. Never
        # compensate a partially published cutover by pointing at the dead VM.
        dns.save('/etc/ultra-recovery/dns.json', {'config': config, 'desired': desired})
        for role in ('subscription', 'vpn'):
            name = names[role]
            with socket.create_connection((name, 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=name):
                    pass
        if backend_port is not None:
            with socket.create_connection(('127.0.0.1', backend_port), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=backend_hostname):
                    pass
        run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '30',
             'https://' + names['subscription'] + '/healthz'])

    def verify_resume(self):
        if self.status.get('machine_id') != Path('/etc/machine-id').read_text().strip():
            raise ValueError('target_machine_changed')
        if 'install' in self.status['completed']:
            state, artifacts = stage_manifests(self.stage)
            spec = json.loads(Path('/etc/ultra-relay/spec.json').read_text())
            if spec.get('public_host') != self.plan['public_host']:
                raise ValueError('restored_public_endpoint_changed')
            for name, row in artifacts['files'].items():
                if sha(safe_target('/', name)) != row['sha256']:
                    raise ValueError('installed_artifact_changed')

    def phase(self, action):
        if action not in PHASES:
            raise ValueError('invalid_host_phase')
        fence(self.plan['fence'], 'bridge', self.plan['target_host'], self.plan['old_bridge_address'], migration=self.plan.get('migration_identity'))
        index = PHASES.index(action)
        required = list(PHASES[:index])
        if not set(required) <= set(self.status['completed']):
            raise ValueError('restore_phase_order')
        if action in self.status['completed'] and action != 'ready':
            self.verify_resume()
            if action == 'activate':
                run(['nginx', '-t'])
            if action == 'ingress' and self.plan.get('ingress_mode') == 'direct':
                self.direct_ingress()
            return self.status
        getattr(self, action)()
        if action not in self.status['completed']:
            self.status['completed'].append(action)
        self.persist()
        return self.status


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--phase', required=True, choices=(*PHASES, 'fence-check', 'runtime-check'))
    args = parser.parse_args()
    plan = json.load(__import__('sys').stdin)
    if not re.fullmatch(r'[a-f0-9]{64}', plan['restore_id']) or Path(args.directory) != Path('/var/lib/ultra-restore') / plan['restore_id']:
        raise ValueError('invalid_restore_directory')
    if plan.get('migration_identity') is not None:
        from restore_common import migration_identity
        proof = migration_identity(plan['migration_identity'])
        if Path('/etc/machine-id').read_text().strip() != proof['target_machine_id']:
            raise ValueError('migration_target_machine_mismatch')
    with (Path(args.directory).parent / 'target.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.phase in ('fence-check', 'runtime-check'):
            fence(plan['fence'], 'bridge', plan['target_host'], plan['old_bridge_address'], migration=plan.get('migration_identity'))
            if args.phase == 'runtime-check':
                Host(args.directory, plan).wait_runtime()
            result = {}
        else:
            result = Host(args.directory, plan).phase(args.phase)
    print(json.dumps({key: result[key] for key in ('restore_id', 'completed', 'machine_id', 'snapshot_at', 'ready_at') if key in result}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(json.dumps({'restore_error_code': safe_error_code(error)}))
