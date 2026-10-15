#!/usr/bin/python
"""Bind public domain evidence to a fixed private upgrade transaction."""
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import stat
from ansible.module_utils.basic import AnsibleModule

HOST = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')
HASH = re.compile(r'[a-f0-9]{64}\Z')


def trusted(path, private=False, relay_spec=False):
    if path.is_symlink():
        raise ValueError('domain_symlink')
    info = path.stat()
    owners = {os.geteuid()}
    if relay_spec:
        try:
            owners.add(pwd.getpwnam('ultra-relay').pw_uid)
        except KeyError:
            pass
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_mode & (0o077 if private else 0o022):
        raise ValueError('domain_untrusted_file')
    return path.read_bytes()


def directive(raw, key):
    names = re.findall(rb'^\s*' + key.encode() + rb'\s+([^;\s]+)\s*;\s*$', raw, re.M)
    values = set(x.decode('ascii') for x in names)
    if len(values) != 1 or not HOST.fullmatch(next(iter(values))):
        raise ValueError('domain_identity_uncertain')
    return next(iter(values))


def normalized_nodes(nodes):
    if not isinstance(nodes, list):
        raise ValueError('domain_policy_uncertain')
    normalized = []
    for node in nodes:
        if not isinstance(node, dict) or not all(isinstance(node.get(key), str) for key in ('name', 'address', 'provider')):
            raise ValueError('domain_policy_uncertain')
        normalized.append({key: node.get(key) for key in ('name', 'address', 'provider', 'budget')})
    return sorted(normalized, key=lambda item: (item['name'], item['address']))


def current_experiment_ports(root, specification, receipt):
    """Recover active public port metadata only from the managed profile the app loads."""
    path = '/etc/ultra-relay/experimental-profile.json'
    if specification.get('experimental_profile_file') != path:
        raise ValueError('domain_experiment_profile_unbound')
    raw = trusted(root / path.lstrip('/'))
    if receipt.get(path) != hashlib.sha256(raw).hexdigest():
        raise ValueError('domain_experiment_profile_unmanaged')
    profile = json.loads(raw)
    endpoint = profile.get('endpoint') if isinstance(profile, dict) else None
    status_port = profile.get('status_port') if isinstance(profile, dict) else None
    experimental_port = endpoint.get('port') if isinstance(endpoint, dict) else None
    if (type(status_port) is not int or not 1 <= status_port <= 65535 or
            type(experimental_port) is not int or not 1 <= experimental_port <= 65535 or
            status_port == experimental_port):
        raise ValueError('domain_experiment_profile_invalid')
    return {'status_port': status_port, 'experimental_port': experimental_port}


def inspect(root=Path('/'), policy=None):
    spec = json.loads(trusted(root / 'etc/ultra-relay/spec.json', relay_spec=True))
    primary = spec.get('primary_xhttp')
    if spec.get('role') != 'bridge' or not primary or not primary.get('published', True) or primary.get('port') != 443:
        raise ValueError('domain_published_primary_required')
    receipt = json.loads(trusted(root / 'var/lib/ultra-ingress/managed.json', True))
    files = {}
    for name in ('ultra-subscription.conf', 'ultra-vpn.conf'):
        path = '/etc/nginx/conf.d/' + name
        raw = trusted(root / path.lstrip('/'))
        digest = hashlib.sha256(raw).hexdigest()
        if receipt.get(path) != digest:
            raise ValueError('domain_foreign_listener')
        files[name] = raw
    dns = json.loads(trusted(root / 'etc/ultra-recovery/dns.json', True))
    if not isinstance(dns, dict) or not isinstance(dns.get('config'), dict):
        raise ValueError('domain_policy_uncertain')
    dns_ttl = dns['config'].get('ttl', 300)
    if type(dns_ttl) is not int or not 1 <= dns_ttl <= 86400:
        raise ValueError('domain_policy_uncertain')
    deployment = json.loads(trusted(root / 'etc/ultra-recovery/deployment.json', True))
    ingress = deployment.get('ingress') if isinstance(deployment, dict) else None
    if not isinstance(deployment, dict) or not isinstance(ingress, dict):
        raise ValueError('domain_policy_uncertain')
    email = ingress.get('email')
    forward_host = ingress.get('forward_host', '')
    ingress_mode = deployment.get('ingress_mode')
    if ingress_mode is None:
        ingress_mode = 'forward' if forward_host else 'direct'
    if (not isinstance(email, str) or not email.strip() or
            not isinstance(forward_host, str) or
            not isinstance(ingress_mode, str) or not ingress_mode):
        raise ValueError('domain_policy_uncertain')
    policy_ports = {}
    staging_port_unrecorded = 'staging_port' not in ingress
    if not staging_port_unrecorded:
        value = ingress.get('staging_port')
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError('domain_policy_uncertain')
        policy_ports['staging_port'] = value
    missing_runtime_ports = {'status_port', 'experimental_port'} - set(ingress)
    if missing_runtime_ports:
        # Older cutovers replaced the recovery ingress object without these
        # fields. They are recoverable only from the exact managed profile
        # referenced by the live relay spec; desired values are never used as
        # evidence for the prior runtime.
        observed = current_experiment_ports(root, spec, receipt)
        for key in ('status_port', 'experimental_port'):
            if key in ingress:
                value = ingress.get(key)
                if type(value) is not int or not 1 <= value <= 65535 or value != observed[key]:
                    raise ValueError('domain_experiment_profile_conflict')
            policy_ports[key] = observed[key]
    else:
        for key in ('status_port', 'experimental_port'):
            value = ingress.get(key)
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError('domain_policy_uncertain')
            policy_ports[key] = value
    backup = json.loads(trusted(root / 'etc/ultra-recovery/backup.json', True))
    backup_state = backup.get('state_paths', [])
    backup_artifacts = backup.get('artifact_paths', [])
    desired_state = policy.get('state_paths', []) if policy is not None else []
    desired_artifacts = policy.get('artifact_paths', []) if policy is not None else []
    for paths in (backup_state, backup_artifacts, desired_state, desired_artifacts):
        if (not isinstance(paths, list) or any(not isinstance(path, str) or not path.startswith('/') for path in paths)):
            raise ValueError('domain_backup_policy_uncertain')
    reconcile = json.loads(trusted(root / 'etc/ultra-recovery/reconcile.json', True))
    admin_id = trusted(root / 'etc/ultra-recovery/admin-chat-id', True).decode('utf-8').strip()
    environment = trusted(root / 'etc/ultra-relay/environment', True).decode('utf-8')
    bot_ports = re.findall(r'^ULTRA_BOT_PORT=(\d+)$', environment, re.M)
    if len(bot_ports) != 1 or not 1 <= int(bot_ports[0]) <= 65535:
        raise ValueError('domain_bot_port_uncertain')
    result = {'zone': dns['config']['zone'], 'dns_ttl': dns_ttl, 'verified': True, 'subscription': directive(files['ultra-subscription.conf'], 'server_name'),
              'backend': directive(files['ultra-subscription.conf'], 'proxy_ssl_name'),
              'vpn': primary['server_name'], 'public_host': primary['host'],
              'path': primary['path'], 'backend_port': primary['backend_port'],
              'gateway_port': spec.get('gateway_vless_port', 18081), 'bot_port': int(bot_ports[0]), 'bridge_url': deployment.get('bridge_url', ''),
              'fingerprint': primary.get('fingerprint', 'firefox'),
              'bridge_ipv4': deployment.get('bridge_ipv4', ''),
              'state_paths_match': set(desired_state) <= set(backup_state),
              'artifact_paths_match': set(desired_artifacts) <= set(backup_artifacts)}
    if policy is not None:
        desired_nodes = normalized_nodes(policy.get('static_nodes'))
        current_nodes = normalized_nodes(deployment.get('static_nodes'))
        reconciled_nodes = normalized_nodes(reconcile.get('static_nodes'))
        result.update({
            'acme_email_matches': email == policy.get('email'),
            'forward_host_matches': forward_host == policy.get('forward_host'),
            'ingress_mode_matches': ingress_mode == policy.get('ingress_mode'),
            'staging_port_matches': (not staging_port_unrecorded and
                                     policy_ports['staging_port'] == policy.get('staging_port')),
            'staging_port_unrecorded': staging_port_unrecorded,
            'status_port_matches': policy_ports['status_port'] == policy.get('status_port'),
            'experimental_port_matches': policy_ports['experimental_port'] == policy.get('experimental_port'),
            'age_recipient_matches': backup.get('recipient') == policy.get('age_recipient'),
            'bridge_provider_matches': (deployment.get('bridge_provider') == policy.get('bridge_provider')
                                        and reconcile.get('bridge_provider') == policy.get('bridge_provider')),
            'static_nodes_match': current_nodes == desired_nodes and reconciled_nodes == desired_nodes,
            'admin_id_matches': admin_id == str(policy.get('admin_telegram_id')),
        })
    for name in ('vpn', 'public_host'):
        if not HOST.fullmatch(result[name]):
            raise ValueError('domain_identity_uncertain')
    return result


def bound_inspect(transaction, desired, policy, root=Path('/')):
    if not HASH.fullmatch(transaction):
        raise ValueError('domain_transaction_invalid')
    directory = root / ('var/lib/ultra-ingress/upgrade-' + transaction)
    if directory.is_symlink():
        raise ValueError('domain_symlink')
    if directory.exists():
        info = directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('domain_untrusted_directory')
    else:
        directory.mkdir(mode=0o700)
    path = directory / 'binding.json'
    if path.exists() or path.is_symlink():
        binding = json.loads(trusted(path, True))
        if (binding.get('desired') != desired or binding.get('policy') != policy
                or binding.get('transaction') != transaction):
            raise ValueError('domain_request_changed')
        return binding['evidence']
    evidence = inspect(root, policy)
    binding = {'version': 1, 'transaction': transaction, 'desired': desired, 'policy': policy, 'evidence': evidence}
    raw = json.dumps(binding, sort_keys=True).encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return evidence


def checkpoint(directory, action, root=Path('/')):
    import base64
    directory = Path(directory)
    if not re.fullmatch(r'/var/lib/ultra-ingress/ansible-[a-f0-9]{64}', str(directory)):
        raise ValueError('domain_transaction_invalid')
    directory = root / str(directory).lstrip('/')
    if directory.is_symlink():
        raise ValueError('domain_symlink')
    if action == 'baseline':
        directory.mkdir(mode=0o700, exist_ok=True)
    journal = directory / 'owned-before.json'
    if not journal.exists() and action == 'validate':
        return {'verified': True}
    owned = json.loads(trusted(journal, True)) if journal.exists() else {'images': []}
    manifest_path = root / 'var/lib/ultra-ingress/managed.json'
    manifest = json.loads(trusted(manifest_path, True))
    for path, expected in manifest.items():
        if not path.startswith(('/etc/nginx/', '/etc/letsencrypt/renewal-hooks/', '/var/www/ultra-', '/etc/ultra-relay/domain-public.env', '/etc/systemd/system/ultra-bot.service.d/')):
            continue
        data = trusted(root / path.lstrip('/'))
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('domain_owned_file_drift')
    sealed = directory / ('upgrade-before-owned.json' if action == 'baseline' else 'upgrade-owned.json')
    if action in ('seal', 'baseline'):
        value = {'version': 1, 'manifest': manifest}
        raw = json.dumps(value, sort_keys=True).encode()
        if sealed.exists() or sealed.is_symlink():
            if trusted(sealed, True) != raw:
                raise ValueError('domain_checkpoint_changed')
        else:
            fd = os.open(sealed, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    else:
        if sealed.exists() or sealed.is_symlink():
            expected = json.loads(trusted(sealed, True))['manifest']
        else:
            baseline = directory / 'upgrade-before-owned.json'
            expected = json.loads(trusted(baseline, True))['manifest']
        images = {item['path']: item for item in owned['images']}
        for path in set(expected) | set(manifest) | set(images):
            observed = manifest.get(path)
            image = images.get(path)
            prior = hashlib.sha256(base64.b64decode(image['content'])).hexdigest() if image and image['present'] else None
            if image:
                allowed = {prior, expected.get(path)} if expected else {prior}
                if observed not in allowed:
                    raise ValueError('domain_checkpoint_file_drift')
            elif observed != expected.get(path):
                raise ValueError('domain_checkpoint_receipt_drift')
    return {'verified': True}


def main():
    module = AnsibleModule(argument_spec={'action': {'type': 'str', 'choices': ['inspect', 'baseline', 'seal', 'validate'], 'default': 'inspect'},
                                         'transaction': {'type': 'str', 'default': ''},
                                         'ingress_transaction': {'type': 'str', 'default': ''},
                                         'desired': {'type': 'dict', 'default': {}},
                                         'policy': {'type': 'dict', 'default': {}}}, supports_check_mode=False)
    try:
        if module.params['action'] == 'inspect':
            result = bound_inspect(module.params['transaction'], module.params['desired'], module.params['policy'])
        else:
            result = checkpoint(module.params['ingress_transaction'], module.params['action'])
        module.exit_json(changed=False, **result)
    except Exception:
        module.fail_json(msg='upgrade_domain_evidence_unverified')


if __name__ == '__main__':
    main()
