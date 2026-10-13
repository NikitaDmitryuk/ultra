#!/usr/bin/env python3
"""Production restore phases on an explicitly prepared, fenced replacement VM."""
import argparse
import fcntl
import hashlib
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


def sql(query, database='postgres'):
    return run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database], query.encode()).decode().strip()


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def identifier(value):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value):
        raise ValueError('unsupported_database_identifier')
    return '"' + value + '"'


def database_spec(spec):
    value = urllib.parse.urlsplit(spec.get('database', {}).get('dsn', ''))
    if value.scheme not in ('postgres', 'postgresql') or value.hostname not in ('localhost', '127.0.0.1', '::1') or (value.port or 5432) != 5432:
        raise ValueError('local_postgres_uri_required')
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
        if not self.status.get('dependencies'):
            run(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'update'], timeout=600)
            run(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', '--no-install-recommends',
                 'postgresql-16', 'postgresql-client-16', 'nginx', 'libnginx-mod-stream', 'certbot',
                 'dnsutils', 'age', 'openssh-client', 'curl', 'openssl', 'ca-certificates', 'iproute2'], timeout=900)
            self.status['dependencies'] = True
            self.persist()
        for tool in ('python3', 'age', 'nginx', 'systemctl', 'ssh', 'curl', 'openssl'):
            if not shutil.which(tool):
                raise ValueError('prepared_target_tools_missing')
        if not Path('/usr/lib/postgresql/16/bin/pg_restore').is_file():
            raise ValueError('prepared_postgres_16_required')
        if shutil.disk_usage('/var/lib').free < 3 * 1024**3:
            raise ValueError('target_disk_insufficient')
        if not self.status.get('prepared'):
            if Path('/etc/ultra-relay/spec.json').exists():
                raise ValueError('target_already_contains_ultra')
            if sql("SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname!='postgres'") != '0':
                raise ValueError('target_contains_application_databases')
            if sql("SELECT current_setting('server_version_num')::int/10000") != '16' or sql('SELECT pg_is_in_recovery()') != 'f':
                raise ValueError('empty_postgres_16_primary_required')
            if sql("SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')") != '0':
                raise ValueError('external_tablespaces_unsupported')
            self.status.update(prepared=True, machine_id=machine)
            self.persist()  # Own the dedicated target before installing any state.
        run(['systemctl', 'mask', '--now', *APP_UNITS, *AUTOMATION_UNITS])

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
            deployment['bridge_ipv4'] = self.plan['new_bridge_address']
            deployment['bridge_provider'] = self.plan['new_bridge_provider']
            if (deployment.get('ingress') or {}).get('public_host') == self.plan['old_bridge_address']:
                deployment['ingress']['public_host'] = self.plan['new_bridge_address']
            atomic_json(deployment_path, deployment)
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
                run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', service_user])
                account = pwd.getpwnam(service_user)
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
        relay = environments['ultra-relay.service']
        if not relay.get('ULTRA_REPLICATION_KEY_FILE') or not relay.get('ULTRA_VULTR_SSH_KEY_FILE'):
            raise ValueError('replication_automation_state_required')
        # Preserve intended environment for final activation; no values are output.
        atomic_json(self.directory / 'service-environment.json', environments)
        reconcile_path = Path('/etc/ultra-recovery/reconcile.json')
        reconcile_config = json.loads(reconcile_path.read_text())
        reconcile_config['bridge_provider'] = self.plan['new_bridge_provider']
        atomic_json(reconcile_path, reconcile_config)
        backup_config = json.loads(Path('/etc/ultra-recovery/backup.json').read_text())
        # Old provider receipts do not establish independence for this new primary.
        # Reconciliation may set this true only after validating fresh deliveries.
        backup_config['independent'] = False
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

    def database(self):
        spec = json.loads(Path('/etc/ultra-relay/spec.json').read_text())
        name, user, password = database_spec(spec)
        if not self.status.get('database_intent'):
            if sql('SELECT count(*) FROM pg_database WHERE datname=' + literal(name)) != '0':
                raise ValueError('database_not_created_by_this_restore')
            self.status['database_intent'] = name
            self.persist()
        if self.status['database_intent'] != name:
            raise ValueError('database_intent_changed')
        if sql('SELECT count(*) FROM pg_roles WHERE rolname=' + literal(user)) == '0':
            sql('CREATE ROLE ' + identifier(user) + ' LOGIN PASSWORD ' + literal(password))
        else:
            sql('ALTER ROLE ' + identifier(user) + ' LOGIN PASSWORD ' + literal(password))
        # Resume a failed import only while applications are persistently masked.
        if any(not Path('/etc/systemd/system', unit).is_symlink() or Path('/etc/systemd/system', unit).readlink() != Path('/dev/null') for unit in APP_UNITS):
            raise ValueError('database_restore_requires_inactive_apps')
        run(['runuser', '-u', 'postgres', '--', 'dropdb', '--if-exists', name])
        run(['runuser', '-u', 'postgres', '--', 'createdb', '-O', user, name])
        dump = (self.stage / 'database.dump').read_bytes()
        run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '--role=' + user, '-d', name], dump, timeout=600)
        reference = 'ultra_restore_reference_' + self.plan['restore_id'][:16]
        run(['runuser', '-u', 'postgres', '--', 'dropdb', '--if-exists', reference])
        run(['runuser', '-u', 'postgres', '--', 'createdb', reference])
        try:
            run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '-d', reference], dump, timeout=600)
            tables = json.loads(sql("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'", name))
            for table in tables:
                query = "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]') FROM " + identifier(table) + ' t'
                if sql(query, name) != sql(query, reference):
                    raise ValueError('restored_table_mismatch')
            self.status['tables_verified'] = len(tables)
            self.status['restored_schema'] = int(sql('SELECT max(version) FROM schema_migrations', name))
            release = json.loads((self.stage / 'artifacts/opt/ultra-recovery/release-manifest.json').read_text())
            if not release['database_schema_min'] <= self.status['restored_schema'] <= release['database_schema_max']:
                raise ValueError('release_incompatible_with_restored_schema')
        finally:
            run(['runuser', '-u', 'postgres', '--', 'dropdb', '--if-exists', reference])
        env = json.loads((self.directory / 'service-environment.json').read_text())['ultra-relay.service']
        credentials = json.loads(Path(env['ULTRA_REPLICATION_KEY_FILE']).read_text())
        role, secret = credentials['user'], credentials['password']
        if not re.fullmatch(r'ultra_recovery(?:_[a-z0-9]{1,24})?', role) or not re.fullmatch(r'[a-f0-9]{64}', secret) or credentials['port'] != 5432:
            raise ValueError('unsupported_replication_credentials')
        if sql('SELECT count(*) FROM pg_roles WHERE rolname=' + literal(role)) == '0':
            sql('CREATE ROLE ' + identifier(role) + ' LOGIN REPLICATION')
        sql('ALTER ROLE ' + identifier(role) + ' LOGIN REPLICATION PASSWORD ' + literal(secret) + '; GRANT pg_monitor TO ' + identifier(role))
        for setting, value in (('listen_addresses', 'localhost'), ('wal_level', 'replica'), ('max_replication_slots', '10'), ('max_wal_senders', '10'), ('max_slot_wal_keep_size', '1GB')):
            sql('ALTER SYSTEM SET ' + setting + '=' + literal(value))
        hba = Path(sql('SHOW hba_file'))
        marker = '# ultra-restore-' + self.plan['restore_id']
        if marker not in hba.read_text():
            with hba.open('a') as stream:
                stream.write('\nhost replication ' + role + ' 127.0.0.1/32 scram-sha-256 ' + marker + '\nhost postgres ' + role + ' 127.0.0.1/32 scram-sha-256 ' + marker + '\n')
        run(['systemctl', 'restart', 'postgresql'])
        self.status['system_identifier'] = sql('SELECT system_identifier FROM pg_control_system()')
        sql("UPDATE node_replication SET state='not_configured',detail='restored_primary_requires_reseed',checked_at=now()", name)

    def nodes(self):
        import sys
        sys.path.insert(0, '/opt/ultra-recovery')
        import reconcile
        config = reconcile.read_config('/etc/ultra-recovery/reconcile.json')
        return reconcile, config, reconcile.desired_nodes(config, reconcile.discover(config))[0]

    def peer_reseed(self):
        module, config, nodes = self.nodes()
        source = Path(__file__).with_name('restore_peer.py').read_text()
        completed = self.status.setdefault('reseeded_nodes', [])
        for node in nodes:
            if node['id'] in completed:
                continue
            # The new fenced bridge must be admitted before pinned SSH can reach
            # a provider-managed exit. Existing old-primary rules are preserved.
            ports = json.loads(sql("SELECT coalesce(json_agg(port),'[]') FROM exit_nodes WHERE enabled AND address=" + literal(node['address']), self.status['database_name']))
            if len(ports) != 1 or not isinstance(ports[0], int) or not 1 <= ports[0] <= 65535:
                raise ValueError('unique_persisted_exit_tunnel_required')
            peer = {'address': self.plan['new_bridge_address']}
            module.ensure_provider_peer_rule(config, node, peer)
            module.ensure_provider_peer_rule(config, node, peer, port=ports[0])
            module.allow_peer(config, node, peer, port=ports[0])
            payload = {'action': 'reseed', 'restore_id': self.plan['restore_id'],
                       'system_identifier': self.status['system_identifier'], 'old_bridge_address': self.plan['old_bridge_address'],
                       'new_bridge_address': self.plan['new_bridge_address'], 'tunnel_port': ports[0]}
            bootstrap = 'import json,sys; payload=json.load(sys.stdin); exec(' + repr(source) + ')'
            module.execute(config, node, ['python3', '-c', bootstrap], input=json.dumps(payload).encode(), stdout=subprocess.PIPE, timeout=90)
            completed.append(node['id']); self.persist()

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
        run(['systemctl', 'mask', '--now', *AUTOMATION_UNITS])
        run(['systemctl', 'daemon-reload'])
        run(['nginx', '-t'])
        run(['/usr/local/bin/ultra-relay', '-check', '-spec', '/etc/ultra-relay/spec.json'])
        run(['systemctl', 'enable', '--now', 'ultra-relay.service'])
        self.wait_runtime()
        run(['systemctl', 'enable', '--now', 'ultra-bot.service', 'nginx.service'])

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
        run(['systemctl', 'unmask', *AUTOMATION_UNITS])
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
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'restart', 'ultra-relay.service'])
        self.wait_runtime()
        run(['systemctl', 'enable', '--now', 'ultra-recovery-backup.timer', 'ultra-recovery-reconcile.timer', 'certbot.timer'])
        run(['systemctl', 'start', 'ultra-recovery-backup.service', 'ultra-recovery-reconcile.service'], timeout=600)

    def ready(self):
        self.wait_runtime()
        until = time.monotonic() + self.plan.get('readiness_timeout', 900)
        while time.monotonic() < until:
            try:
                backup = json.loads(Path('/var/lib/ultra-recovery/last-success.json').read_text())
                controller = json.loads(Path('/var/lib/ultra-relay/recovery-reconcile-status.json').read_text())
                replicas = json.loads(sql("SELECT coalesce(json_agg(json_build_object('state',r.state,'age',extract(epoch from now()-r.checked_at))),'[]') FROM exit_nodes n LEFT JOIN node_replication r ON r.node_id=n.id WHERE n.enabled", self.status['database_name']))
                if (0 <= time.time() - backup.get('snapshot_at', 0) <= 300
                        and controller.get('state') == 'ready' and controller.get('independent') is True
                        and 0 <= time.time() - controller.get('updated_at', 0) <= 120
                        and replicas and all(row['state'] == 'streaming' and row['age'] is not None and 0 <= row['age'] <= 90 for row in replicas)):
                    self.status['ready_at'] = int(time.time())
                    self.status['replicas_ready'] = len(replicas)
                    return
            except (OSError, ValueError, KeyError, TypeError):
                pass
            time.sleep(5)
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
        config, previous = policy['config'], policy['desired']
        if set(previous) != {'subscription', 'vpn'}:
            raise ValueError('restored_dns_policy_required')
        names = {role: previous[role]['name'] + '.' + config['zone'] for role in previous}
        if names['subscription'] != self.plan['subscription_domain'] or names['vpn'] != self.plan['public_host']:
            raise ValueError('restored_dns_policy_mismatch')
        desired = {role: dict(previous[role], data=self.plan['new_bridge_address']) for role in previous}
        # Before publishing either A record, validate both certificates against
        # the replacement IP, bypassing DNS but preserving hostname validation.
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        for name in names.values():
            with socket.create_connection((self.plan['new_bridge_address'], 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=name):
                    pass
        run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '30',
             '--resolve', names['subscription'] + ':443:' + self.plan['new_bridge_address'],
             'https://' + names['subscription'] + '/healthz'])
        fence(self.plan['fence'], 'bridge', self.plan['target_host'], self.plan['old_bridge_address'])
        dns.execute(config, desired, '/etc/ultra-recovery/dns-receipt.json')
        dns.wait_ready(config, desired, timeout=120)
        # Persist the new intent only after authoritative convergence. Never
        # compensate a partially published cutover by pointing at the dead VM.
        dns.save('/etc/ultra-recovery/dns.json', {'config': config, 'desired': desired})
        for name in names.values():
            with socket.create_connection((name, 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=name):
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
        if 'database' in self.status['completed']:
            if sql('SELECT system_identifier FROM pg_control_system()') != self.status['system_identifier']:
                raise ValueError('restored_database_identity_changed')
            if int(sql('SELECT max(version) FROM schema_migrations', self.status['database_name'])) != self.status['restored_schema']:
                raise ValueError('restored_database_schema_changed')
        if 'activate' in self.status['completed']:
            run(['systemctl', 'is-active', '--quiet', *APP_UNITS, 'nginx.service'])

    def phase(self, action):
        if action not in PHASES:
            raise ValueError('invalid_host_phase')
        fence(self.plan['fence'], 'bridge', self.plan['target_host'], self.plan['old_bridge_address'])
        index = PHASES.index(action)
        required = list(PHASES[:index])
        if not set(required) <= set(self.status['completed']):
            raise ValueError('restore_phase_order')
        if action in self.status['completed'] and action != 'ready':
            self.verify_resume()
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
    parser.add_argument('--phase', required=True, choices=PHASES)
    args = parser.parse_args()
    plan = json.load(__import__('sys').stdin)
    if not re.fullmatch(r'[a-f0-9]{64}', plan['restore_id']) or Path(args.directory) != Path('/var/lib/ultra-restore') / plan['restore_id']:
        raise ValueError('invalid_restore_directory')
    with (Path(args.directory).parent / 'target.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = Host(args.directory, plan).phase(args.phase)
    print(json.dumps({key: result[key] for key in ('restore_id', 'completed', 'machine_id', 'snapshot_at', 'tables_verified', 'restored_schema', 'replicas_ready', 'ready_at') if key in result}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(json.dumps({'restore_error_code': safe_error_code(error)}))
