#!/usr/bin/env python3
"""Ingress state regressions use generated private state, never live infrastructure."""
import importlib.util
import json
from pathlib import Path
import tempfile
import ansible.module_utils.basic as ansible_basic
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator
import yaml

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_ingress_state.py'
specification = importlib.util.spec_from_file_location('state', source)
state = importlib.util.module_from_spec(specification)
specification.loader.exec_module(state)
plan = {'domain': 'edge.example.com', 'email': 'ops@example.com', 'forward_host': '',
        'public_host': 'edge.example.com', 'path': '/connect',
        'backend_port': 18080, 'gateway_port': 18081, 'staging_port': 18443,
        'status_port': 18082, 'experimental_port': 18444}
captured_spec = {}
class ArgumentSpecCaptured(Exception):
    pass
ansible_module = state.AnsibleModule
def capture_argument_spec(argument_spec, **kwargs):
    captured_spec.update(argument_spec)
    raise ArgumentSpecCaptured
state.AnsibleModule = capture_argument_spec
try:
    state.main()
except ArgumentSpecCaptured:
    pass
finally:
    state.AnsibleModule = ansible_module
plan_argument = captured_spec['plan']
assert plan_argument.get('no_log') is not True
def serialized_profile(argument):
    if hasattr(ansible_basic, '_PARSED_MODULE_ARGS'):
        ansible_basic._PARSED_MODULE_ARGS = {}
    module = object.__new__(state.AnsibleModule)
    module.params = {'plan': plan}
    module.no_log_values = set()
    validation = ModuleArgumentSpecValidator({'plan': argument}).validate(module.params)
    module.no_log_values.update(validation._no_log_values)
    output = {}
    module.add_path_info = lambda result: None
    module._record_module_result = lambda result: output.update(result)
    module._return_formatted({'profile': {'server_name': plan['domain']}})
    return output['profile']['server_name']
assert serialized_profile(plan_argument) == plan['domain']
assert serialized_profile({**plan_argument, 'no_log': True}) == 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
main_tasks = yaml.safe_load((source.parents[1] / 'roles/ingress/tasks/main.yml').read_text())
def flatten_tasks(tasks):
    for task in tasks:
        yield task
        for section in ('block', 'rescue', 'always'):
            yield from flatten_tasks(task.get(section, []))
all_tasks = list(flatten_tasks(main_tasks))
for task_name in ('Prepare durable specification transition before infrastructure changes',
                  'Commit checked relay specification', 'Restore relay specification before image'):
    task = next(task for task in all_tasks if task.get('name') == task_name)
    assert task.get('no_log') is True, f'{task_name} must suppress plan output at task level'
incomplete_plan = dict(plan)
del incomplete_plan['status_port']
try:
    state.validate(incomplete_plan)
    raise AssertionError('incomplete ingress policy was accepted')
except ValueError:
    pass
documented_plan = dict(plan)
del documented_plan['forward_host']
state.validate(documented_plan)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    specification = root / 'spec.json'
    before = {'role': 'bridge', 'database': {'dsn': 'retained'}, 'public_host': 'old.example.com',
              'public_xhttp_tls': {'port': 5443, 'server_name': 'old.example.com', 'path': '/old', 'certificate_file': '/cert', 'key_file': '/key'}}
    specification.write_text(json.dumps(before))
    operation = root / 'operation'
    prepared = state.transition(specification, operation, plan, 'stage', 'prepare')
    candidate = Path(prepared['candidate']).read_bytes()
    assert json.loads(candidate)['database'] == before['database']
    assert state.transition(specification, operation, plan, 'stage', 'commit')['changed']
    assert not state.transition(specification, operation, plan, 'stage', 'commit')['changed']
    assert Path(state.transition(specification, operation, plan, 'stage', 'prepare')['candidate']).read_bytes() == candidate
    assert state.transition(specification, operation, plan, 'stage', 'rollback')['changed']
    assert json.loads(specification.read_text()) == before
    specification.write_text('{"role":"bridge","foreign":true}')
    try:
        state.transition(specification, operation, plan, 'stage', 'commit')
        raise AssertionError('drift accepted')
    except ValueError:
        pass
published = {'role': 'bridge', 'database': {'dsn': 'retained'},
             'primary_xhttp': {'host': 'old.example.com', 'server_name': 'old.example.com', 'port': 443,
                               'path': '/connect', 'backend_port': 18080, 'fingerprint': 'firefox'}}
try:
    state.candidate(published, plan, 'stage')
    raise AssertionError('published endpoint replaced by ordinary stage')
except ValueError:
    pass
try:
    state.candidate(published, plan, 'activate')
    raise AssertionError('published endpoint changed without cutover')
except ValueError:
    pass
cutover = state.candidate(published, plan, 'cutover')
assert cutover['database'] == published['database']
assert cutover['primary_xhttp']['host'] == 'edge.example.com'
assert published['primary_xhttp']['host'] == 'old.example.com'
path_cutover = state.candidate(published, dict(plan, path='/next'), 'cutover')
assert path_cutover['primary_xhttp']['path'] == '/next'
assert published['primary_xhttp']['path'] == '/connect'
assert state.needs_domain_alias(b'server_name edge.example.com;\n', 'edge.example.com') is False
assert state.needs_domain_alias(b'server_name old.example.com;\n', 'edge.example.com') is True
recovered = state.recovery_candidate(cutover, published, 18080)
assert recovered['primary_xhttp'] == published['primary_xhttp']
assert recovered['database'] == cutover['database']
print('Ansible ingress stage, replay, drift, cutover and rollback regressions passed')

# Adoption must retain every published/legacy/experimental runtime field. The
# ordinary activate candidate reproduces the previous destructive transition.
preserved = {'role': 'bridge', 'public_host': 'edge.example.com',
             'gateway_vless_port': 18081, 'experimental_profile_file': '/custom/experiment.json',
             'legacy_public_enabled': True,
             'public_xhttp_tls': {'port': 5443, 'server_name': 'legacy.example.com',
                                  'path': '/legacy', 'certificate_file': '/cert', 'key_file': '/key'},
             'primary_xhttp': {'host': 'edge.example.com', 'server_name': 'edge.example.com',
                               'port': 443, 'path': '/connect', 'backend_port': 18080,
                               'mode': 'packet-up', 'fingerprint': 'firefox', 'published': True}}
activated = state.candidate(preserved, plan, 'activate')
assert activated['experimental_profile_file'] != preserved['experimental_profile_file']
assert activated['legacy_public_enabled'] is False
assert 'public_xhttp_tls' not in activated
assert state.candidate(preserved, plan, 'adopt') == preserved
for key, value in [('domain', 'other.example.com'), ('public_host', 'other.example.com'),
                   ('path', '/other'), ('backend_port', 18082), ('gateway_port', 18082),
                   ('fingerprint', 'chrome')]:
    try:
        state.candidate(preserved, dict(plan, **{key: value}), 'adopt')
        raise AssertionError('adoption accepted mismatched ' + key)
    except ValueError:
        pass
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    specification = root / 'spec.json'
    raw = json.dumps(preserved, indent=2).encode() + b'\n'
    specification.write_bytes(raw)
    result = state.transition(specification, root / 'adopt', plan, 'adopt', 'prepare', check=True)
    assert result['profile'] == preserved['primary_xhttp']
    assert specification.read_bytes() == raw
    assert not (root / 'adopt').exists()

ownership_source = source.with_name('ultra_ingress_adopt.py')
loader = importlib.util.spec_from_file_location('adopt', ownership_source)
adopt = importlib.util.module_from_spec(loader)
loader.loader.exec_module(adopt)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    site = root / 'etc/nginx/conf.d/ultra-vpn.conf'
    site.parent.mkdir(parents=True)
    site.write_text('preserved public configuration\n')
    receipt = root / 'var/lib/ultra-ingress/managed.json'
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({'/etc/nginx/conf.d/ultra-vpn.conf': state.digest(site.read_bytes())}))
    # Fixtures may be owned by an unprivileged test runner; production still
    # requires root ownership for the receipt and each protected file.
    original_stat = Path.stat
    from types import SimpleNamespace
    def fixture_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=result.st_mode, st_size=result.st_size)
    Path.stat = fixture_stat
    try:
        expected = [{'path': '/etc/nginx/conf.d/ultra-vpn.conf', 'content': site.read_text()}]
        legacy_hook = root / 'etc/letsencrypt/renewal-hooks/deploy/ultra-vpn'
        legacy_hook.parent.mkdir(parents=True)
        template = source.parents[1] / 'roles/ingress/templates/legacy-renewal-hook.j2'
        legacy_hook.write_text(template.read_text().replace('{{ ultra_ingress.domain }}', plan['domain']))
        manifest = json.loads(receipt.read_text())
        manifest['/etc/letsencrypt/renewal-hooks/deploy/ultra-vpn'] = state.digest(legacy_hook.read_bytes())
        receipt.write_text(json.dumps(manifest))
        legacy_expected = expected + [{'alternatives': [
            {'path': '/etc/letsencrypt/renewal-hooks/deploy/ultra-ansible', 'content': 'new hook'},
            {'path': '/etc/letsencrypt/renewal-hooks/deploy/ultra-vpn', 'content': legacy_hook.read_text()}]}]
        assert adopt.verify(root, '/var/lib/ultra-ingress/managed.json', legacy_expected)['verified']
        before = {path: path.read_bytes() for path in (site, receipt, legacy_hook)}
        assert adopt.verify(root, '/var/lib/ultra-ingress/managed.json', expected)['verified']
        assert all(path.read_bytes() == data for path, data in before.items())
        for bad in [dict(expected[0], content='different backend'),
                    {'path': '/etc/nginx/conf.d/missing.conf', 'content': 'unowned'}]:
            try:
                adopt.verify(root, '/var/lib/ultra-ingress/managed.json', [bad])
                raise AssertionError('unproven publication accepted')
            except ValueError:
                pass
        # Render the role's actual expected-file assembly, including template_vars.
        # The retained old listener and hook follow the frozen bot domain, while
        # the publication plan has moved to a different domain after cutover.
        import yaml
        from jinja2.nativetypes import NativeEnvironment
        role = source.parents[1] / 'roles/ingress'
        environment = NativeEnvironment(keep_trailing_newline=True)
        environment.filters['combine'] = lambda original, updates: dict(original, **updates)
        values = {'ultra_ingress': plan, 'ultra_bot_domain': 'old.example.com',
                  'ingress_public_port': 443}
        def template_lookup(kind, name, template_vars=None):
            assert kind == 'template'
            context = dict(values, **(template_vars or {}))
            return environment.from_string((role / 'templates' / name).read_text()).render(context)
        values['lookup'] = template_lookup
        tasks = yaml.safe_load((role / 'tasks/adopt.yml').read_text())
        tls_check = next(task for task in tasks if task['name'] ==
                         'Verify preserved primary HTTPS handshake with authenticated SNI')
        assert tls_check['register'] == 'ingress_adopt_tls_ready'
        assert tls_check['retries'] == 30 and tls_check['delay'] == 2
        assert 'ingress_adopt_tls_ready.ready' in tls_check['until']
        # A graceful Nginx reload returns before replacement workers have
        # necessarily loaded the new certificate. Activation must wait for the
        # authenticated target, just as adoption does, before rolling back.
        main_tasks = yaml.safe_load((role / 'tasks/main.yml').read_text())
        transaction = next(task for task in main_tasks if task['name'] ==
                           'Apply validated ingress transaction')['block']
        install_owned = next(task for task in transaction if task['name'] == 'Install owned ingress configuration')
        commit_spec = next(task for task in transaction if task['name'] == 'Commit checked relay specification')
        assert 'notify' not in install_owned and 'notify' not in commit_spec
        relay_restart = next(index for index, task in enumerate(transaction)
                             if task.get('name') == 'Restart relay for checked ingress specification')
        bot_restart = next(task for task in transaction
                           if task.get('name') == 'Restart bot after public-origin cutover')
        nginx_reload = next(index for index, task in enumerate(transaction)
                            if task.get('name') == 'Reload Nginx for checked ingress configuration')
        relay_readiness = next(index for index, task in enumerate(transaction)
                               if task.get('name') == 'Verify restarted relay application readiness')
        activation_tls = next(task for task in transaction if task['name'] ==
                              'Verify primary HTTPS handshake with authenticated SNI')
        tls_index = transaction.index(activation_tls)
        assert relay_restart < relay_readiness < transaction.index(bot_restart) < nginx_reload < tls_index
        assert transaction[relay_restart]['ansible.builtin.systemd_service'] == {
            'name': 'ultra-relay.service', 'state': 'restarted'}
        assert bot_restart['when'] == "ingress_action == 'cutover'"
        assert transaction[nginx_reload]['ansible.builtin.systemd_service'] == {
            'name': 'nginx.service', 'enabled': True, 'state': 'reloaded'}
        assert activation_tls['register'] == 'ingress_tls_ready'
        assert activation_tls['retries'] == 30 and activation_tls['delay'] == 2
        assert 'ingress_tls_ready.ready' in activation_tls['until']
        assert activation_tls['ultra_ingress_probe'] == {
            'kind': 'tls', 'address': '{{ ultra_bridge_ipv4 }}',
            'hostname': '{{ ingress_transition.profile.server_name }}',
            'port': '{{ ingress_transition.profile.port }}'}
        probe_spec = importlib.util.spec_from_file_location('probe', source.with_name('ultra_ingress_probe.py'))
        probe = importlib.util.module_from_spec(probe_spec)
        probe_spec.loader.exec_module(probe)
        mismatch = __import__('ssl').SSLCertVerificationError(62, 'sanitized fixture')
        assert probe.tls_failure_code(mismatch) == 'ingress_tls_hostname_mismatch'
        assert probe.tls_failure_code(ConnectionRefusedError()) == 'ingress_tls_listener_unavailable'
        assert probe.tls_failure_code(TimeoutError()) == 'ingress_tls_timeout'
        callback = (source.parents[1] / 'callback_plugins/safe_result.py').read_text()
        assert "'ingress_tls_hostname_mismatch'" in callback
        initial = next(task for task in tasks if task['name'] == 'Assemble publication ownership checks')
        values['ingress_adopt_files'] = [
            {'path': item['path'], 'content': environment.from_string(item['content']).render(values)}
            if 'path' in item else {'alternatives': [
                {'path': choice['path'], 'content': environment.from_string(choice['content']).render(values)}
                for choice in item['alternatives']]}
            for item in initial['ansible.builtin.set_fact']['ingress_adopt_files']]
        original_expected = values['ingress_adopt_files']
        additions = next(task for task in tasks if task['name'] ==
                         'Add the frozen bot-domain hook with its preserved cutover dependencies')
        values.update(additions.get('vars', {}))
        cutover_expected = environment.from_string(
            additions['ansible.builtin.set_fact']['ingress_adopt_files']).render(values)
        frozen_hook = cutover_expected[1]['alternatives'][-1]
        assert frozen_hook['requires'][1]['content'] == '#!/bin/sh\nset -eu\nnginx -t\nsystemctl reload nginx\n'
        site.write_text(cutover_expected[0]['content'])
        legacy_hook.write_text(frozen_hook['content'])
        for requirement in frozen_hook['requires']:
            target = root / requirement['path'].lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(requirement['content'])
        lineage = root / frozen_hook['lineage'].lstrip('/')
        lineage.mkdir(parents=True)
        for name in ('fullchain.pem', 'privkey.pem'):
            (lineage / name).write_text('generated certificate fixture')
        owned_paths = [cutover_expected[0]['path'], frozen_hook['path'],
                       *[item['path'] for item in frozen_hook['requires']]]
        manifest = {name: state.digest((root / name.lstrip('/')).read_bytes()) for name in owned_paths}
        receipt.write_text(json.dumps(manifest))
        def rejected(configuration=cutover_expected):
            try:
                adopt.verify(root, '/var/lib/ultra-ingress/managed.json', configuration)
            except ValueError:
                return
            raise AssertionError('unproven frozen-domain adoption accepted')
        # Regression: the original role expected the new-domain lineage and fails.
        rejected(original_expected)
        before = {path: path.read_bytes() for path in root.rglob('*') if path.is_file()}
        assert adopt.verify(root, '/var/lib/ultra-ingress/managed.json', cutover_expected)['verified']
        assert all(path.read_bytes() == data for path, data in before.items())
        # Even receipt-approved bytes must match exact templates and known domains.
        for drift in [frozen_hook['content'].replace('old.example.com', 'foreign.example.com'),
                      frozen_hook['content'].replace('nginx -t', 'nginx -t; echo foreign')]:
            legacy_hook.write_text(drift)
            changed_manifest = dict(manifest, **{frozen_hook['path']: state.digest(legacy_hook.read_bytes())})
            receipt.write_text(json.dumps(changed_manifest))
            rejected()
        legacy_hook.write_text(frozen_hook['content'])
        receipt.write_text(json.dumps(manifest))
        for requirement in frozen_hook['requires']:
            target = root / requirement['path'].lstrip('/')
            content = target.read_bytes()
            target.unlink()
            receipt.write_text(json.dumps({name: digest for name, digest in manifest.items()
                                          if name != requirement['path']}))
            rejected()  # Missing dependency.
            target.write_bytes(content)
            rejected()  # Present but unowned dependency.
            receipt.write_text(json.dumps(manifest))
            target.write_text('foreign configuration')
            rejected()  # Hash drift.
            receipt.write_text(json.dumps(dict(manifest, **{
                requirement['path']: state.digest(target.read_bytes())})))
            rejected()  # Receipt-approved command or vhost drift.
            target.write_bytes(content)
            receipt.write_text(json.dumps(manifest))
        for name in ('fullchain.pem', 'privkey.pem'):
            certificate = lineage / name
            certificate.unlink()
            rejected()
            certificate.write_text('generated certificate fixture')
        import copy
        for requirements in [None, {}, ['invalid'], [{'path': '/unowned'}],
                             [{'path': '../escape', 'content': 'foreign'}]]:
            malformed = copy.deepcopy(cutover_expected)
            malformed[1]['alternatives'][-1]['requires'] = requirements
            rejected(malformed)
        for invalid_lineage in ['/etc/letsencrypt/live/../foreign', '/tmp/foreign', 42]:
            malformed = copy.deepcopy(cutover_expected)
            malformed[1]['alternatives'][-1]['lineage'] = invalid_lineage
            rejected(malformed)
        # Malformed requirements fail closed even when a preceding hook matches.
        malformed = copy.deepcopy(cutover_expected)
        malformed[1]['alternatives'].insert(0, {'path': frozen_hook['path'], 'content': frozen_hook['content']})
        malformed[1]['alternatives'][-1]['requires'] = None
        rejected(malformed)
        expected = cutover_expected
        site.write_text('changed')
        try:
            adopt.verify(root, '/var/lib/ultra-ingress/managed.json', expected)
            raise AssertionError('owned ingress drift accepted')
        except ValueError:
            pass
    finally:
        Path.stat = original_stat
print('Ansible adoption preserves runtime and ingress bytes; frozen-domain cutover dependencies verified; mismatched publication and ownership drift rejected')

# Post-acceptance retirement is pinned to the original cutover transaction,
# its candidate spec, an acceptance marker, and the exact managed bytes.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    operation = root / 'operation'
    operation.mkdir()
    plan = dict(plan, domain='new.example.com', public_host='public.example.com', path='/next', retain_aliases=True)
    before = {'role': 'bridge', 'primary_xhttp': {'host': 'old.example.com', 'server_name': 'old.example.com',
              'port': 443, 'path': '/connect', 'backend_port': 18080}}
    selected = dict(before, primary_xhttp=dict(before['primary_xhttp'], host=plan['public_host'],
                     server_name=plan['domain'], path=plan['path']))
    raw_before, raw_target = json.dumps(before, sort_keys=True).encode(), json.dumps(selected, sort_keys=True).encode()
    (operation / 'before.json').write_bytes(raw_before)
    (operation / 'candidate.json').write_bytes(raw_target)
    (root / 'spec.json').write_bytes(raw_target)
    aliases = []
    manifest = {}
    nginx = root / 'etc/nginx/conf.d'
    nginx.mkdir(parents=True)
    for old_content in ('old VPN server block\n', 'old subscription server block\n'):
        sha = state.digest(old_content.encode())
        path = '/etc/nginx/conf.d/ultra-domain-alias-' + sha + '.conf'
        aliases.append({'path': path, 'content': old_content, 'mode': '0644'})
        (root / path.lstrip('/')).write_text(old_content)
        manifest[path] = sha
    unrelated = nginx / 'unrelated.conf'
    unrelated.write_text('foreign nginx config\n')
    receipt = root / 'managed.json'
    receipt.write_text(json.dumps(manifest, sort_keys=True))
    (operation / 'owned-before.json').write_text(json.dumps({'images': [], 'aliases': aliases}, sort_keys=True))
    candidate_sha = state.digest(raw_target)
    request_sha = state.digest(json.dumps({'plan': plan, 'action': 'cutover'}, sort_keys=True).encode())
    (operation / 'state.json').write_text(json.dumps({'request_sha': request_sha,
        'before_sha': state.digest(raw_before), 'candidate_sha': candidate_sha}, sort_keys=True))
    prepare_retirement = lambda selected_plan=plan: state.retire_aliases(
        root / 'spec.json', operation, selected_plan, receipt, operation / 'acceptance.json', root=root)
    def reject_retirement(selected_plan=plan):
        try:
            prepare_retirement(selected_plan)
        except ValueError:
            return
        raise AssertionError('unsafe alias retirement accepted')
    target_mismatch = dict(plan, domain='other.example.com')
    reject_retirement(target_mismatch)
    reject_retirement()  # No marker means the acceptance action has not succeeded.
    (operation / 'acceptance.json').write_text(json.dumps({'verified': True, 'transaction_sha256': '0' * 64,
        'domain': plan['domain'], 'public_host': plan['public_host']}))
    reject_retirement()  # A marker for any other candidate cannot authorize deletion.
    (operation / 'acceptance.json').write_text(json.dumps({'verified': True, 'transaction_sha256': candidate_sha,
        'domain': plan['domain'], 'public_host': plan['public_host']}))
    retirement = prepare_retirement()
    assert len(retirement['aliases']) == 2
    assert retirement['target_path'] == '/next'
    first = aliases[0]['path']
    (root / first.lstrip('/')).write_text('foreign replacement\n')
    reject_retirement()
    (root / first.lstrip('/')).write_text(aliases[0]['content'])
    selected_aliases = prepare_retirement()['aliases']
    assert {item['path'] for item in selected_aliases} == {item['path'] for item in aliases}
    # Simulate the ownership-safe helper's completed unlink and receipt update,
    # then retry: the already removed alias is omitted and the remaining one is safe.
    first_live = root / first.lstrip('/')
    first_live.unlink()
    manifest.pop(first)
    receipt.write_text(json.dumps(manifest, sort_keys=True))
    retry = prepare_retirement()
    assert retry['aliases'] == [{'path': aliases[1]['path']}]
    assert unrelated.read_text() == 'foreign nginx config\n'
    (operation / 'owned-before.json').write_text(json.dumps({'images': [], 'aliases': []}, sort_keys=True))
    assert prepare_retirement()['aliases'] == []
print('Ansible alias retirement requires matching acceptance and candidate; rejects target/byte drift; partial retry is idempotent and leaves unrelated files')

import yaml
ingress_playbook = yaml.safe_load((source.parents[1] / 'playbooks/ingress.yml').read_text())
bridge_tasks = ingress_playbook[1]['tasks']
acceptance_check = next(index for index, task in enumerate(bridge_tasks)
                        if task.get('name') == 'Verify subscription identities and tunnel payload before recording acceptance')
marker_write = next(index for index, task in enumerate(bridge_tasks)
                    if task.get('name') == 'Record verified cutover acceptance for explicit later retirement')
assert acceptance_check < marker_write
assert bridge_tasks[acceptance_check]['ultra_cutover_probe']['phase'] == 'verify'
assert bridge_tasks[acceptance_check]['ultra_cutover_probe']['path'] == "{{ ingress_acceptance_candidate.profile.path | default('') }}"
retirement_check = next(index for index, task in enumerate(bridge_tasks)
                        if task.get('name') == 'Verify subscription and tunnel payload after old aliases are retired')
assert bridge_tasks[retirement_check]['ultra_cutover_probe']['path'] == "{{ ingress_retirement.target_path | default('') }}"
assert bridge_tasks[marker_write]['ansible.builtin.copy']['dest'] == '{{ ultra_ingress_transaction }}/acceptance.json'
assert ingress_playbook[0]['tasks'][0]['when'] == "ultra_ingress_action not in ['adopt', 'accept', 'retire']"
retention_plan = bridge_tasks[0]['ansible.builtin.set_fact']['ingress_retention_plan']
assert "'subscription_domain': ultra_subscription_domain" in retention_plan
finalize_source = (source.with_name('ultra_cutover_finalize.py')).read_text()
assert "target['ingress'] = persisted_ingress(module.params['ingress'])" in finalize_source
finalizer_spec = importlib.util.spec_from_file_location('finalizer', source.with_name('ultra_cutover_finalize.py'))
finalizer = importlib.util.module_from_spec(finalizer_spec)
finalizer_spec.loader.exec_module(finalizer)
complete_ingress = {'domain': 'edge.example.com', 'email': 'ops@example.com', 'path': '/connect',
    'forward_host': '', 'public_host': 'public.example.com', 'backend_port': 18080,
    'gateway_port': 18081, 'staging_port': 18443, 'status_port': 18082, 'experimental_port': 18444}
metadata_ingress = finalizer.persisted_ingress(dict(complete_ingress, subscription_domain='sync.example.com',
    fingerprint='firefox', retain_aliases=True))
assert metadata_ingress == complete_ingress
without_forward_host = dict(complete_ingress)
del without_forward_host['forward_host']
assert finalizer.persisted_ingress(without_forward_host)['forward_host'] == ''
for missing_or_invalid in (
        {key: value for key, value in complete_ingress.items() if key != 'status_port'},
        dict(complete_ingress, status_port='18082'),
        dict(complete_ingress, experimental_port=True),
        dict(complete_ingress, experimental_port=18082),
):
    try:
        finalizer.persisted_ingress(missing_or_invalid)
    except ValueError:
        pass
    else:
        raise AssertionError('incomplete or invalid ingress recovery metadata was accepted')
assert finalizer.merge_backup_paths(['/etc/ultra-relay', '/srv/old'], ['/srv/new']) == [
    '/etc/ultra-relay', '/srv/new', '/srv/old']
backup_inventory = {'state_paths': ['/etc/ultra-relay', '/srv/old-state'],
                    'artifact_paths': ['/usr/local/bin/old-tool']}
inventory = finalizer.apply_backup_paths(backup_inventory, ['/srv/new-state'], ['/usr/local/bin/new-tool'])
assert inventory == {'/etc/ultra-relay', '/srv/old-state', '/srv/new-state'}
assert backup_inventory['state_paths'] == ['/etc/ultra-relay', '/srv/new-state', '/srv/old-state']
assert backup_inventory['artifact_paths'] == ['/usr/local/bin/new-tool', '/usr/local/bin/old-tool']
for bad in (['relative'], ['/']):
    try:
        finalizer.merge_backup_paths([], bad)
    except ValueError:
        pass
    else:
        raise AssertionError('unsafe recovery path was accepted')
print('Ingress acceptance marker is ordered after successful readiness, TLS, subscription and payload probes; acceptance/retirement bypass routine configuration roles')
