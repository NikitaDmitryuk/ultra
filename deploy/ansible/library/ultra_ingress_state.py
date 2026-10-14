#!/usr/bin/python
"""Ingress specification transitions; operating-system changes belong to Ansible."""
import hashlib
import json
import os
from pathlib import Path
import re
from ansible.module_utils.basic import AnsibleModule


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, content, mode=0o600):
    temporary = path.with_name(path.name + '.next')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(content)
        os.fchmod(stream.fileno(), mode)
        if path.exists():
            prior = path.stat()
            os.fchown(stream.fileno(), prior.st_uid, prior.st_gid)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate(plan):
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', plan['domain']) or '..' in plan['domain']:
        raise ValueError('invalid_domain')
    if not re.fullmatch(r'/[a-zA-Z0-9_-]+', plan['path']):
        raise ValueError('invalid_http_path')
    if plan.get('fingerprint', 'firefox') not in ('chrome', 'firefox'):
        raise ValueError('invalid_fingerprint')
    ports = []
    for key in ('backend_port', 'gateway_port', 'staging_port', 'status_port', 'experimental_port'):
        if key not in plan and key in ('status_port', 'experimental_port'):
            continue
        value = plan[key]
        if type(value) is not int or not 1024 <= value <= 65535:
            raise ValueError('invalid_port')
        ports.append(value)
    if len(set(ports)) != len(ports):
        raise ValueError('duplicate_ports')


def recovery_candidate(current, saved, backend_port):
    result = dict(current)
    primary = saved.get('primary_xhttp')
    if primary and primary.get('published', True):
        result['primary_xhttp'] = dict(primary)
        if saved.get('public_xhttp_tls'):
            result['public_xhttp_tls'] = saved['public_xhttp_tls']
        else:
            result.pop('public_xhttp_tls', None)
    else:
        tls = saved['public_xhttp_tls']
        result['public_xhttp_tls'] = tls
        result['primary_xhttp'] = {'host': result['public_host'], 'backend_port': backend_port, 'published': True,
                                  **{key: value for key, value in tls.items() if key not in ('certificate_file', 'key_file')}}
    result['legacy_public_enabled'] = False
    return result


def candidate(before, plan, action):
    validate(plan)
    if before.get('role') != 'bridge':
        raise ValueError('bridge_spec_required')
    prior = before.get('primary_xhttp') or {}
    if action == 'cutover':
        if not prior or not prior.get('published', True) or prior.get('port') != 443:
            raise ValueError('cutover_requires_published_primary')
        if prior['path'] != plan['path'] or prior['backend_port'] != plan['backend_port']:
            raise ValueError('cutover_cannot_change_transport')
        result = json.loads(json.dumps(before))
        result['primary_xhttp']['host'] = plan['public_host']
        result['primary_xhttp']['server_name'] = plan['domain']
        for descriptor in result.get('subscription_bridges', []):
            if descriptor.get('security') != 'tls':
                continue
            fields = ('host', 'server_name', 'port', 'path')
            if any(descriptor.get(field) != prior.get(field) for field in fields):
                raise ValueError('cutover_unknown_tls_publication')
            descriptor['host'] = plan['public_host']
            descriptor['server_name'] = plan['domain']
        return result
    if action == 'stage' and prior and prior.get('published', True):
        raise ValueError('published_ingress_requires_explicit_cutover')
    port = int(plan['staging_port']) if action == 'stage' else 443
    profile = {'host': plan.get('public_host') or plan['domain'], 'port': port,
               'server_name': plan['domain'], 'path': plan['path'], 'mode': 'stream-up',
               'fingerprint': plan.get('fingerprint') or prior.get('fingerprint', 'firefox'),
               'xmux': prior.get('xmux', {'maxConnections': '2', 'hMaxRequestTimes': '600-900', 'hMaxReusableSecs': '1800-3000'}),
               'backend_port': int(plan['backend_port']), 'published': action != 'stage'}
    if prior and prior.get('published', True) and action == 'activate':
        for field in ('host', 'port', 'server_name', 'path', 'backend_port'):
            if prior.get(field) != profile.get(field):
                raise ValueError('published_ingress_requires_explicit_cutover')
        profile = prior
    result = dict(before)
    result['primary_xhttp'] = profile
    result['gateway_vless_port'] = int(plan['gateway_port'])
    result['experimental_profile_file'] = '/etc/ultra-relay/experimental-profile.json'
    if action != 'stage':
        result['legacy_public_enabled'] = False
        result.pop('public_xhttp_tls', None)
    return result


def transition(specification, directory, plan, action, phase, check=False):
    specification = Path(specification)
    directory = Path(directory)
    if not specification.is_absolute() or not directory.is_absolute():
        raise ValueError('absolute_state_paths_required')
    if specification.is_symlink() or directory.is_symlink():
        raise ValueError('state_symlink')
    state_path = directory / 'state.json'
    before_path = directory / 'before.json'
    candidate_path = directory / 'candidate.json'
    site_before = directory / 'site.before'
    for path in (state_path, before_path, candidate_path):
        if path.is_symlink():
            raise ValueError('state_symlink')
    current = specification.read_bytes()
    request_sha = digest(json.dumps({'plan': plan, 'action': action}, sort_keys=True).encode())
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if state['request_sha'] != request_sha:
            raise ValueError('operation_inputs_changed')
        before = before_path.read_bytes()
        target = candidate_path.read_bytes()
        if digest(before) != state['before_sha'] or digest(target) != state['candidate_sha']:
            raise ValueError('saved_spec_corrupted')
        if digest(current) not in (state['before_sha'], state['candidate_sha']):
            raise ValueError('active_spec_drift')
    else:
        if phase != 'prepare':
            raise ValueError('prepared_operation_required')
        before = current
        original = directory.parent / 'spec.before.json'
        if action == 'rollback':
            selected = recovery_candidate(json.loads(before), json.loads(original.read_text()), int(plan['backend_port']))
        else:
            selected = candidate(json.loads(before), plan, action)
        target = json.dumps(selected, sort_keys=True).encode()
        state = {'request_sha': request_sha, 'before_sha': digest(before), 'candidate_sha': digest(target)}
        if not check:
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not original.exists():
                atomic(original, before)
            if action == 'cutover':
                site = Path('/etc/nginx/conf.d/ultra-vpn.conf')
                if site.is_symlink() or not site.is_file():
                    raise ValueError('cutover_primary_site_required')
                legacy = Path('/etc/nginx/conf.d/ultra-vpn-legacy.conf')
                prior = json.loads(before).get('primary_xhttp', {})
                same_publication = prior.get('host') == plan['public_host'] and prior.get('server_name') == plan['domain']
                if legacy.is_symlink() or (legacy.exists() and not same_publication and legacy.read_bytes() != site.read_bytes()):
                    raise ValueError('cutover_legacy_alias_requires_explicit_review')
                atomic(site_before, site.read_bytes())
            atomic(before_path, before)
            atomic(candidate_path, target)
            atomic(state_path, json.dumps(state, sort_keys=True).encode())
    previous = json.loads(before).get('primary_xhttp', {})
    already_published = action == 'cutover' and previous.get('host') == plan['public_host'] and previous.get('server_name') == plan['domain']
    if phase == 'prepare':
        return {'changed': False, 'candidate': str(candidate_path), 'before': str(before_path), 'profile': json.loads(target)['primary_xhttp'], 'site_before': str(site_before), 'already_published': already_published}
    selected = before if phase == 'rollback' else target
    changed = current != selected
    if changed and not check:
        atomic(specification, selected)
    return {'changed': changed, 'candidate': str(candidate_path), 'before': str(before_path), 'profile': json.loads(target)['primary_xhttp'], 'site_before': str(site_before), 'already_published': already_published}


def main():
    module = AnsibleModule(argument_spec={
        'specification': {'type': 'path', 'default': '/etc/ultra-relay/spec.json'},
        'directory': {'type': 'path', 'required': True},
        'plan': {'type': 'dict', 'required': True, 'no_log': True},
        'action': {'type': 'str', 'choices': ['stage', 'activate', 'rollback', 'cutover'], 'required': True},
        'phase': {'type': 'str', 'choices': ['prepare', 'commit', 'rollback'], 'default': 'prepare'},
    }, supports_check_mode=True)
    try:
        module.exit_json(**transition(module.params['specification'], module.params['directory'],
                                      module.params['plan'], module.params['action'], module.params['phase'], module.check_mode))
    except (OSError, KeyError, ValueError, TypeError):
        module.fail_json(msg='ingress_state_transition_failed')


if __name__ == '__main__':
    main()
