#!/usr/bin/python
"""Journal the bounded bot TLS/SNI transition. Never print file contents."""
import base64
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
from ansible.module_utils.basic import AnsibleModule


def digest(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def read(path):
    if path.is_symlink():
        raise ValueError('backend_symlink')
    if not path.exists():
        return None
    owners = {os.geteuid()}
    if str(path).endswith('/etc/ultra-relay/environment'):
        try:
            owners.add(pwd.getpwnam('ultra-relay').pw_uid)
        except KeyError:
            pass
    if not path.is_file() or path.stat().st_uid not in owners or path.stat().st_mode & 0o022:
        raise ValueError('backend_untrusted_file')
    return path.read_bytes()


def atomic(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    prior = path.stat() if path.exists() else None
    temporary = path.with_name(path.name + '.backend-next')
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        if prior is not None:
            os.fchown(stream.fileno(), prior.st_uid, prior.st_gid)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def env_set(data, key, old, value):
    text = data.decode()
    pattern = re.compile(r'^' + re.escape(key) + r'=(.*)$', re.M)
    values = pattern.findall(text)
    if len(values) != 1 or values[0].strip('"\'') != old:
        raise ValueError('backend_environment_drift')
    return pattern.sub(lambda _: key + '=' + value, text).encode()


def prepare(directory, old, new, public, root=Path('/'), preserve_recovery=False, old_port=8444, new_port=8444):
    path = directory / 'state.json'
    policy = {'old': old, 'new': new, 'public': public, 'old_port': old_port, 'new_port': new_port}
    existing = read(path)
    if existing is not None:
        state = json.loads(existing)
        if state['policy'] != policy:
            raise ValueError('backend_transaction_policy_mismatch')
        if state['phase'] == 'rolled_back':
            for item in state['files']:
                expected = base64.b64decode(item['before']) if item['before'] is not None else None
                if read(Path(item['path'])) != expected:
                    raise ValueError('backend_transaction_file_drift')
            state['phase'] = 'prepared'
            atomic(path, json.dumps(state, sort_keys=True).encode(), 0o600)
        return state
    environment = root / 'etc/ultra-relay/environment'
    before = read(environment)
    if before is None or environment.stat().st_mode & 0o077:
        raise ValueError('backend_private_environment_required')
    after = env_set(before, 'ULTRA_BOT_DOMAIN', old, new)
    if old_port != new_port:
        after = env_set(after, 'ULTRA_BOT_PORT', str(old_port), str(new_port))
    # Preserve the already public origin even when it formerly defaulted to BOT_DOMAIN.
    public_pattern = re.compile(rb'^ULTRA_BOT_PUBLIC_URL=.*$', re.M)
    if len(public_pattern.findall(after)) > 1:
        raise ValueError('backend_duplicate_origin')
    if public_pattern.search(after):
        after = public_pattern.sub(('ULTRA_BOT_PUBLIC_URL=https://' + public).encode(), after)
    else:
        after = after.rstrip(b'\n') + ('\nULTRA_BOT_PUBLIC_URL=https://' + public + '\n').encode()
    manifest_path = root / 'var/lib/ultra-ingress/managed.json'
    manifest_before = read(manifest_path)
    manifest = json.loads(manifest_before)
    changes = [(environment, before, after, 0o600)]
    proxy_count = 0
    proxy_port_count = 0
    for candidate in sorted((root / 'etc/nginx/conf.d').glob('*.conf')):
        data = read(candidate)
        replacement = re.sub(rb'(proxy_ssl_name\s+)' + re.escape(old.encode()) + rb'(\s*;)',
                             lambda match: match[1] + new.encode() + match[2], data)
        if old_port != new_port:
            port_pattern = rb'(proxy_pass\s+https://127\.0\.0\.1:)' + str(old_port).encode() + rb'(\s*;)'
            replacement, count = re.subn(port_pattern,
                                          lambda match: match[1] + str(new_port).encode() + match[2], replacement)
            proxy_port_count += count
        if replacement == data:
            continue
        canonical = '/' + str(candidate.relative_to(root))
        if manifest.get(canonical) != digest(data):
            raise ValueError('backend_foreign_proxy_configuration')
        proxy_count += 1
        changes.append((candidate, data, replacement, candidate.stat().st_mode & 0o777))
        manifest[canonical] = digest(replacement)
    if old != new and not proxy_count:
        raise ValueError('backend_owned_proxy_required')
    if old_port != new_port and proxy_port_count < 1:
        raise ValueError('backend_owned_proxy_port_required')
    hook = root / 'etc/letsencrypt/renewal-hooks/deploy/ultra-backend-domain'
    hook_before = read(hook)
    hook_name = '/' + str(hook.relative_to(root))
    if hook_before is not None and manifest.get(hook_name) != digest(hook_before):
        raise ValueError('backend_foreign_renewal_hook')
    hook_after = ('#!/bin/sh\nset -eu\nif [ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/' + new +
                  '" ]; then\n    nginx -t\n    systemctl reload nginx\n    systemctl try-restart ultra-bot.service\nfi\n').encode()
    changes.append((hook, hook_before, hook_after, 0o755))
    manifest[hook_name] = digest(hook_after)
    changes.append((manifest_path, manifest_before, json.dumps(manifest, sort_keys=True).encode(), 0o600))
    # Make the certificate and ownership state available to future recovery bundles.
    backup_path = root / 'etc/ultra-recovery/backup.json'
    backup_before = read(backup_path)
    if backup_before is not None and not preserve_recovery:
        backup = json.loads(backup_before)
        paths = set(backup['state_paths'])
        paths.update(('/etc/ultra-relay/environment', '/etc/ultra-recovery', '/var/lib/ultra-ingress',
                      '/etc/nginx/conf.d', '/etc/letsencrypt/renewal-hooks/deploy',
                      '/etc/letsencrypt/live/' + new, '/etc/letsencrypt/archive/' + new,
                      '/etc/letsencrypt/renewal/' + new + '.conf'))
        renewal = root / ('etc/letsencrypt/renewal/' + new + '.conf')
        renewal_data = read(renewal)
        if renewal_data is None:
            raise ValueError('backend_renewal_configuration_missing')
        account = re.search(rb'^account\s*=\s*([a-f0-9]+)\s*$', renewal_data, re.M)
        if account:
            accounts = list((root / 'etc/letsencrypt/accounts').glob('*/directory/' + account[1].decode()))
            if len(accounts) != 1 or accounts[0].is_symlink() or not accounts[0].is_dir():
                raise ValueError('backend_acme_account_missing')
            paths.add('/' + str(accounts[0].relative_to(root)))
        backup['state_paths'] = sorted(paths)
        changes.append((backup_path, backup_before, json.dumps(backup, sort_keys=True).encode(), 0o600))
    files = []
    for target, original, desired, mode in changes:
        owner = target.stat() if target.exists() else None
        files.append({'path': str(target), 'mode': mode, 'uid': owner.st_uid if owner else os.geteuid(), 'gid': owner.st_gid if owner else os.getegid(), 'before': base64.b64encode(original).decode() if original is not None else None,
                      'after': base64.b64encode(desired).decode()})
    state = {'version': 1, 'policy': policy, 'phase': 'prepared', 'files': files}
    atomic(path, json.dumps(state, sort_keys=True).encode(), 0o600)
    return state



def rollback(directory, old, new, public, root=Path('/'), old_port=8444, new_port=8444):
    """Recover an unprepared attempt only with positive proof of the old backend.

    Provisioning before prepare is additive (DNS, ACME listener, certificate).
    Missing state alone cannot authorize recovery: reject mixed backend bytes or
    incomplete ownership writes, then let the role verify Nginx and live ingress.
    """
    policy = {'old': old, 'new': new, 'public': public, 'old_port': old_port, 'new_port': new_port}
    existing = read(directory / 'state.json')
    if existing is not None:
        if json.loads(existing)['policy'] != policy:
            raise ValueError('backend_transaction_policy_mismatch')
        return transition(directory, 'rollback')
    environment = root / 'etc/ultra-relay/environment'
    data = read(environment)
    if data is None or environment.stat().st_mode & 0o077:
        raise ValueError('backend_private_environment_required')
    env_set(data, 'ULTRA_BOT_DOMAIN', old, old)
    manifest_path = root / 'var/lib/ultra-ingress/managed.json'
    pending = manifest_path.with_name(manifest_path.name + '.pending')
    if pending.exists() or pending.is_symlink():
        raise ValueError('backend_pending_ownership_transaction')
    manifest = json.loads(read(manifest_path))
    proxy_count = 0
    for candidate in sorted((root / 'etc/nginx/conf.d').glob('*.conf')):
        content = read(candidate)
        names = re.findall(rb'proxy_ssl_name\s+([^;\s]+)\s*;', content)
        if new.encode() in names:
            raise ValueError('backend_unjournalled_proxy_change')
        if old.encode() in names:
            canonical = '/' + str(candidate.relative_to(root))
            if manifest.get(canonical) != digest(content):
                raise ValueError('backend_foreign_proxy_configuration')
            proxy_count += 1
    if old != new and not proxy_count:
        raise ValueError('backend_owned_proxy_required')
    # An interrupted listener write cannot silently become accepted ownership.
    challenge = root / 'etc/nginx/conf.d/ultra-backend-acme.conf'
    challenge_data = read(challenge)
    if challenge_data is not None and manifest.get('/etc/nginx/conf.d/ultra-backend-acme.conf') != digest(challenge_data):
        raise ValueError('backend_foreign_challenge_configuration')
    hook = root / 'etc/letsencrypt/renewal-hooks/deploy/ultra-backend-domain'
    hook_data = read(hook)
    if hook_data is not None:
        if manifest.get('/etc/letsencrypt/renewal-hooks/deploy/ultra-backend-domain') != digest(hook_data):
            raise ValueError('backend_foreign_renewal_hook')
        if ('/etc/letsencrypt/live/' + new).encode() in hook_data:
            raise ValueError('backend_unjournalled_renewal_hook')
    return {'phase': 'unmodified', 'policy': policy}


def receipt_transition(item, current, action):
    before = json.loads(base64.b64decode(item['before']))
    after = json.loads(base64.b64decode(item['after']))
    active = json.loads(current)
    changed = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
    target = before if action in ('rollback', 'verify-rollback') else after
    for key in set(before) | set(after) | set(active):
        observed = active.get(key)
        if key in changed:
            permitted = (after.get(key),) if action == 'verify' else (before.get(key),) if action == 'verify-rollback' else (before.get(key), after.get(key))
            if observed not in permitted:
                raise ValueError('backend_transaction_receipt_drift')
        elif key in before and observed != before[key]:
            raise ValueError('backend_transaction_receipt_drift')
        # All coexisting entries must attest the actual root-owned regular file.
        if observed is not None and key not in changed:
            content = read(Path(key))
            if content is None or digest(content) != observed:
                raise ValueError('backend_transaction_owned_file_drift')
    result = dict(active)
    for key in changed:
        if key in target:
            result[key] = target[key]
        else:
            result.pop(key, None)
    return json.dumps(result, sort_keys=True).encode()


def transition(directory, action):
    path = directory / 'state.json'
    state = json.loads(read(path))
    if state.get('version') != 1:
        raise ValueError('backend_invalid_transaction')
    if action == 'verify-rollback':
        if state['phase'] != 'rolled_back':
            raise ValueError('backend_not_rolled_back')
        expected_phase = 'rolled_back'
    elif action == 'verify':
        if state['phase'] not in ('applied', 'verified'):
            raise ValueError('backend_not_applied')
        expected_phase = 'verified'
    elif action == 'activate':
        if state['phase'] not in ('prepared', 'applying', 'applied', 'verified'):
            raise ValueError('backend_invalid_activation_phase')
        expected_phase = 'applied'
    elif action == 'rollback':
        if state['phase'] == 'rolled_back':
            return state
        expected_phase = 'rolled_back'
    else:
        raise ValueError('backend_invalid_action')
    # Check the complete set before mutating any file; resume accepts only journalled bytes.
    receipt_values = {}
    for item in state['files']:
        target_path = Path(item['path'])
        current = read(target_path)
        if current is not None and 'uid' in item:
            info = target_path.stat()
            if info.st_uid != item['uid'] or info.st_gid != item['gid'] or info.st_mode & 0o777 != item['mode']:
                raise ValueError('backend_transaction_owner_drift')
        before = base64.b64decode(item['before']) if item['before'] is not None else None
        after = base64.b64decode(item['after'])
        choices = (after,) if action == 'verify' else (before,) if action == 'verify-rollback' else (before, after)
        if item['path'].endswith('/var/lib/ultra-ingress/managed.json'):
            receipt_values[item['path']] = receipt_transition(item, current, action)
        elif current not in choices:
            raise ValueError('backend_transaction_file_drift')
    if action == 'activate':
        state['phase'] = 'applying'
        atomic(path, json.dumps(state, sort_keys=True).encode(), 0o600)
    if action not in ('verify', 'verify-rollback'):
        for item in state['files']:
            target = Path(item['path'])
            value = item['before'] if action == 'rollback' else item['after']
            if value is None:
                if target.exists():
                    target.unlink()
                    sync(target.parent)
            else:
                data = receipt_values[item['path']] if item['path'].endswith('/var/lib/ultra-ingress/managed.json') else base64.b64decode(value)
                atomic(target, data, item['mode'])
    state['phase'] = expected_phase
    atomic(path, json.dumps(state, sort_keys=True).encode(), 0o600)
    return state


def main():
    module = AnsibleModule(argument_spec={
        'directory': {'type': 'path', 'required': True},
        'action': {'type': 'str', 'choices': ['prepare', 'activate', 'verify', 'rollback', 'verify-rollback'], 'required': True},
        'old': {'type': 'str', 'required': True}, 'new': {'type': 'str', 'required': True},
        'public': {'type': 'str', 'required': True},
        'old_port': {'type': 'int', 'required': True}, 'new_port': {'type': 'int', 'required': True},
        'preserve_recovery': {'type': 'bool', 'default': False},
    }, supports_check_mode=False)
    try:
        params = module.params
        for key in ('old', 'new', 'public'):
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', params[key]):
                raise ValueError('invalid_backend_hostname')
        for key in ('old_port', 'new_port'):
            if not 1 <= params[key] <= 65535:
                raise ValueError('invalid_backend_port')
        directory = Path(params['directory'])
        if not re.fullmatch(r'/var/lib/ultra-ingress/backend-[a-f0-9]{64}', str(directory)) or directory.is_symlink():
            raise ValueError('backend_invalid_directory')
        if params['action'] == 'prepare':
            state = prepare(directory, params['old'], params['new'], params['public'], preserve_recovery=params['preserve_recovery'], old_port=params['old_port'], new_port=params['new_port'])
        elif params['action'] == 'rollback':
            state = rollback(directory, params['old'], params['new'], params['public'], old_port=params['old_port'], new_port=params['new_port'])
        else:
            prior = json.loads(read(directory / 'state.json'))
            if prior['policy'] != {'old': params['old'], 'new': params['new'], 'public': params['public'], 'old_port': params['old_port'], 'new_port': params['new_port']}:
                raise ValueError('backend_transaction_policy_mismatch')
            state = transition(directory, params['action'])
        module.exit_json(changed=state['phase'] != 'unmodified', phase=state['phase'])
    except Exception:
        module.fail_json(msg='backend_domain_transaction_failed')


if __name__ == '__main__':
    main()
