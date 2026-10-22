#!/usr/bin/env python3
"""Build guarded desired recovery state. No host mutations or installation."""
import hashlib
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile
import uuid
CONFIG = Path('/etc/ultra-recovery')
ROOT = Path('/opt/ultra-recovery')
UNITS = Path('/etc/systemd/system')
# Use the helper staged and verified beside this planner, never an older copy
# under ROOT that an earlier release may have left behind.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import db_connection


def query(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode:
        raise ValueError('bootstrap_discovery_unavailable')
    return result.stdout


def query_database(database, statement):
    dsn = db_connection.dsn_from_runtime(database)
    with tempfile.TemporaryDirectory(prefix='ultra-db-query-') as directory:
        with db_connection.pgpass(directory, dsn) as environment:
            result = subprocess.run(db_connection.connection_args(dsn, database, 'psql') +
                                    ['-XAtq', '-v', 'ON_ERROR_STOP=1', '-c', statement],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=20, env=environment)
    if result.returncode:
        raise ValueError('bootstrap_discovery_unavailable')
    return result.stdout


def read_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('\"\'')
    return values


def plan(config):
    database = config['database']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
        raise ValueError('invalid_bootstrap_database')
    identity = '/etc/ultra-fleet/id_ed25519'
    if not Path(identity).is_file() or not Path(identity + '.pub').is_file():
        raise ValueError('fleet_automation_identity_missing')
    trusted = Path(config['known_hosts_file']).read_bytes()
    if (CONFIG / 'known_hosts').exists() and (CONFIG / 'known_hosts').read_bytes() != trusted:
        raise ValueError('explicit_ssh_pin_rotation_required')
    cloud = '/var/lib/ultra-relay/automation/vultr-api-key'
    if not config.get('cloud_key_file') and not Path(cloud).is_file():
        raise ValueError('cloud_api_key_input_required')
    previous_manifest = ROOT / 'release-manifest.json'
    previous = json.loads(previous_manifest.read_text()) if previous_manifest.exists() else {}
    version = previous.get('version', '')
    if version and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', version):
        raise ValueError('invalid_previous_tool_version')
    for tool in config.get('tools', []):
        current = Path(tool['destination'])
        if current.is_symlink():
            raise ValueError('managed_tool_symlink')
        if current.exists() and hashlib.sha256(current.read_bytes()).hexdigest() != tool['sha256']:
            original = ROOT / 'releases' / version / current.name
            if current == Path('/usr/local/bin/ultra-client'):
                expected_client = next((item.get('sha256') for item in previous.get('assets', []) if item.get('name') == 'ultra-client-linux-' + config['architecture']), None)
                if hashlib.sha256(current.read_bytes()).hexdigest() == expected_client:
                    continue
            if (not version or not original.is_file() or original.is_symlink()
                    or hashlib.sha256(original.read_bytes()).hexdigest() != hashlib.sha256(current.read_bytes()).hexdigest()):
                raise ValueError('unverified_existing_recovery_tool')
    files = []

    def desired(path, data, mode='0600', owner='root'):
        files.append({'destination': str(path), 'content': data.decode() if isinstance(data, bytes) else data,
                      'mode': mode, 'owner': owner, 'group': owner})

    def document(name, value):
        desired(CONFIG / name, json.dumps(value, sort_keys=True))

    desired(CONFIG / 'known_hosts', trusted)
    token = read_env('/etc/ultra-relay/bot.env').get('TELEGRAM_BOT_TOKEN')
    if not token:
        raise ValueError('existing_bot_token_unavailable')
    desired(CONFIG / 'primary-bot-token', token)
    rows = json.loads(query_database(database,
                    "SELECT COALESCE(json_agg(json_build_object('id',id,'address',address)), '[]'::json) FROM exit_nodes WHERE enabled"))
    nodes = []
    for item in config['static_nodes']:
        address = str(ipaddress.ip_address(item['address']))
        matches = [row for row in rows if row['address'] == address]
        if len(matches) != 1:
            raise ValueError('static_node_not_uniquely_persisted')
        identifier = str(uuid.UUID(matches[0]['id']))
        nodes.append(dict(item, id=identifier, known_hosts=str(CONFIG / 'known_hosts')))
        pinfile = Path('/var/lib/ultra-relay/vultr') / identifier / 'known_hosts'
        if pinfile.exists():
            def keys(path):
                lines = query(['ssh-keygen', '-F', address, '-f', str(path)]).decode().splitlines()
                return {tuple(line.split()[1:3]) for line in lines if line and not line.startswith('#')}
            if not keys(pinfile) or keys(pinfile) != keys(config['known_hosts_file']):
                raise ValueError('existing_operation_pin_differs')
        else:
            desired(pinfile, trusted, owner='ultra-relay')
    document('static-budgets.json', config['static_nodes'])
    if config.get('dns'):
        policy = dict(config['dns'])
        if not policy.get('api_key_file') and not (CONFIG / 'dns-api-key').exists():
            raise ValueError('derived_dns_key_missing')
        policy['api_key_file'] = str(CONFIG / 'dns-api-key')
        desired_records = {role: {'name': policy[field], 'data': config['bridge_ipv4']}
                           for role, field in [('subscription', 'subscription_name'), ('vpn', 'vpn_name')]}
        document('dns.json', {'config': policy, 'desired': desired_records})
    state_paths = ['/etc/ultra-fleet', '/etc/ultra-relay', str(CONFIG), '/var/lib/ultra-relay/automation/vultr-api-key',
                   '/etc/systemd/system/ultra-relay.service', '/etc/systemd/system/ultra-relay.service.d',
                   '/etc/ultra-db-tunnel', '/etc/systemd/system/ultra-db-tunnel.service',
                   '/etc/systemd/system/ultra-bot.service', '/var/lib/ultra-recovery-reconcile/heartbeat_ed25519',
                   '/var/lib/ultra-recovery-reconcile/heartbeat_ed25519.pub'] + config.get('state_paths', [])
    spec = json.loads(Path(config['spec']).read_text())
    for candidate in ('/etc/systemd/system/ultra-bot.service.d', '/var/lib/ultra-bot', '/etc/nginx/sites-available/ultra-bot',
                      '/var/lib/ultra-ingress/managed.json', '/etc/nginx/conf.d/ultra-vpn.conf', '/var/www/ultra-site'):
        if Path(candidate).exists():
            state_paths.append(candidate)
    receipt = Path('/var/lib/ultra-ingress/managed.json')
    if receipt.exists():
        for name, expected in json.loads(receipt.read_text()).items():
            if not name.startswith(('/etc/nginx/', '/etc/letsencrypt/renewal-hooks/', '/var/www/ultra-')):
                continue
            path = Path(name)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError('managed_ingress_artifact_changed')
            state_paths.append(name)
    domains = {config['bridge_url'].split('/')[2].split(':')[0]}
    if config.get('ingress'):
        domains.add(config['ingress']['domain'])
    for domain in domains:
        live = Path('/etc/letsencrypt/live') / domain
        if live.exists():
            state_paths.append(str(live))
        cert = Path('/etc/letsencrypt/renewal') / (domain + '.conf')
        if not cert.exists():
            continue
        state_paths.extend([str(cert), str(live)])
        account = re.search(r'^account\s*=\s*([a-f0-9]+)\s*$', cert.read_text(), re.M)
        if account:
            matches = list(Path('/etc/letsencrypt/accounts').glob('*/directory/' + account.group(1)))
            if len(matches) != 1:
                raise ValueError('acme_account_not_unique')
            state_paths.append(str(matches[0]))
    artifact_paths = ['/usr/local/bin/ultra-relay', '/usr/local/bin/ultra-bot', '/usr/local/bin/ultra-client',
                      '/usr/local/bin/ultra-install', '/usr/local/libexec/ultra-relay-emergency',
                      '/usr/local/libexec/ultra-emergency-manifest.json', str(ROOT / 'release-manifest.json')]
    if config.get('release_signature') is True:
        artifact_paths.extend(['/usr/local/libexec/ultra-emergency-manifest.json.minisig', str(ROOT / 'release-manifest.json.minisig')])
    artifact_paths += [str(ROOT / name) for name in config['recovery_tool_members']]
    artifact_paths += [str(ROOT / name) for name in ('tools-manifest.json','tools.tar.gz','tools-inventory.json')]
    artifact_paths += config.get('artifact_paths', [])
    if spec.get('geo_assets_dir'):
        artifact_paths.append(spec['geo_assets_dir'])
    if config.get('controller_directory'):
        artifact_paths.append(config['controller_directory'])
        state_paths.extend(['/var/lib/ultra-ansible/channel', '/var/lib/ultra-ansible/retention', '/etc/ultra-ansible', '/etc/systemd/system/ultra-ansible-controller.service'])
    for name in config['recovery_tool_members']:
        if name.endswith(('.service', '.timer')):
            state_paths.append(str(UNITS / name))
    database_host = str(ipaddress.ip_address(config['database_host']))
    backup = {'source': 'bridge', 'repository': '/var/lib/ultra-recovery', 'database': database,
              'database_host': database_host,
              'recipient': config['age_recipient'], 'identity_file': identity, 'known_hosts': str(CONFIG / 'known_hosts'),
              'destinations': [{'id': n['id'], 'name': n['name'], 'host': 'root@' + n['address'], 'required': True} for n in nodes],
              'independent': False, 'state_paths': sorted(set(state_paths)), 'artifact_paths': sorted(set(artifact_paths)), 'diagnostic_status': True}
    # The subscription keyring is installed by a later runtime upgrade.
    # Capture it once present without making pre-upgrade backups fail.
    backup['optional_state_paths'] = ['/var/lib/ultra-relay/automation/subscription-keys.json']
    if config.get('controller_directory'):
        # These journals may not exist before the first reservation/retirement.
        # Capture must reselect them around pg_dump to detect first publication.
        backup['optional_state_paths'] += ['/var/lib/ultra-ansible/lifecycle.json',
                                           '/var/lib/ultra-ansible/lifecycle-retired.json']
    existing_backup = CONFIG / 'backup.json'
    if existing_backup.exists():
        existing = json.loads(existing_backup.read_text())
        if existing['recipient'] != backup['recipient']:
            raise ValueError('explicit_recovery_key_rotation_required')
        backup['destinations'] = existing['destinations']
        backup['independent'] = existing.get('independent', False)
    document('backup.json', backup)
    reconcile = {'database': database, 'database_host': database_host,
                 'bridge_provider': config['bridge_provider'], 'vultr_state_dir': '/var/lib/ultra-relay/vultr',
                 'ssh_identity_file': identity, 'vultr_api_key_file': cloud, 'api_key_owner': 'ultra-relay', 'ssh_identity_owner': 'ultra-relay',
                 'backup_config': str(CONFIG / 'backup.json'), 'state_dir': '/var/lib/ultra-recovery-reconcile',
                 'status_file': '/var/lib/ultra-relay/recovery-reconcile-status.json', 'status_group': 'ultra-relay',
                 'bundle_dir': '/opt/ultra-recovery', 'client_binary': '/usr/local/bin/ultra-client', 'installer_binary': '/opt/ultra-ansible/current/ultra-install',
                 'ansible_executable': '/opt/ultra-ansible/current/venv/bin/ansible-playbook',
                 'bot_token_file': str(CONFIG / 'primary-bot-token'), 'chat_id_file': str(CONFIG / 'admin-chat-id'),
                 'probe_profile_file': str(CONFIG / 'probe.json'), 'bridge_url': config['bridge_url'],
                 'payload_url': 'https://www.cloudflare.com/cdn-cgi/trace', 'static_nodes': nodes, 'monitor_spec_file': config['spec']}
    document('reconcile.json', reconcile)
    deployment = {key: config[key] for key in ('version', 'bridge_ipv4', 'bridge_provider', 'bridge_url', 'database')}
    deployment['database_host'] = database_host
    deployment['controller_directory'] = config.get('controller_directory')
    deployment.update(ingress=config.get('ingress'), ssh_identity_file=identity, known_hosts_file=str(CONFIG / 'known_hosts'), static_nodes=nodes)
    document('deployment.json', deployment)
    return {'files': files, 'nodes': nodes, 'environment': read_env('/etc/ultra-relay/environment'), 'verified': True}


def write_plan(output, value):
    """Publish secret desired state privately; stdout is never a transport."""
    output = Path(output)
    parent = output.parent.lstat()
    if (not output.is_absolute() or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077):
        raise ValueError('private_plan_directory_required')
    try:
        previous = output.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(previous.st_mode) or previous.st_uid != os.geteuid()
                or stat.S_IMODE(previous.st_mode) & 0o077):
            raise ValueError('private_plan_file_required')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.parent,
                                         prefix='.recovery-plan-', delete=False) as stream:
            temporary = stream.name
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        # Replace the directory entry itself, never follow an existing symlink.
        os.replace(temporary, output)
        temporary = None
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    arguments = parser.parse_args(argv)
    try:
        write_plan(arguments.output, plan(json.load(sys.stdin)))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('recovery_bootstrap_discovery_failed') from None


if __name__ == '__main__':
    main()
