#!/usr/bin/env python3
"""Ingress state regressions use generated private state, never live infrastructure."""
import importlib.util
import json
from pathlib import Path
import tempfile

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_ingress_state.py'
specification = importlib.util.spec_from_file_location('state', source)
state = importlib.util.module_from_spec(specification)
specification.loader.exec_module(state)
plan = {'domain': 'edge.example.com', 'public_host': 'edge.example.com', 'path': '/connect',
        'backend_port': 18080, 'gateway_port': 18081, 'staging_port': 18443}
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
        site.write_text('changed')
        try:
            adopt.verify(root, '/var/lib/ultra-ingress/managed.json', expected)
            raise AssertionError('owned ingress drift accepted')
        except ValueError:
            pass
    finally:
        Path.stat = original_stat
print('Ansible adoption preserves runtime and ingress bytes; mismatched publication and ownership drift rejected')
