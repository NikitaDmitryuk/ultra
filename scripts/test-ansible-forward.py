#!/usr/bin/env python3
"""Known-forward adoption regressions run entirely in generated temporary roots."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_forward_state.py'
specification = importlib.util.spec_from_file_location('forward', source)
forward = importlib.util.module_from_spec(specification)
specification.loader.exec_module(forward)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    nginx = root / 'etc/nginx'
    (nginx / 'stream.d').mkdir(parents=True)
    (nginx / 'conf.d').mkdir()
    main = nginx / 'nginx.conf'
    main.write_text('events {}\nhttp {}\n')
    generated, observed = forward.prepare(root, '192.0.2.1', 'bot.example.com', 8444)
    assert len(generated) == 3
    assert 'stream {' in generated[-1]['content']
    assert main.read_text() == 'events {}\nhttp {}\n'
    for relative, (desired, legacy) in forward.configurations('192.0.2.1', 'bot.example.com', 8444).items():
        (nginx / relative).write_text(legacy)
    forward.prepare(root, '192.0.2.1', 'bot.example.com', 8444)
    target = nginx / 'stream.d/bot-proxy.conf'
    target.write_text('foreign listener')
    try:
        forward.prepare(root, '192.0.2.1', 'bot.example.com', 8444)
        raise AssertionError('foreign configuration accepted')
    except ValueError:
        pass
    # Existing new ownership receipt permits changing the bridge address.
    desired = forward.configurations('192.0.2.1', 'bot.example.com', 8444)['stream.d/bot-proxy.conf'][0]
    target.write_text(desired)
    current = root / 'var/lib/ultra-ingress/forward-managed.json'
    current.parent.mkdir(parents=True)
    acme = nginx / 'conf.d/acme-proxy.conf'
    current.write_text(json.dumps({str(target): hashlib.sha256(target.read_bytes()).hexdigest(),
                                  str(acme): hashlib.sha256(acme.read_bytes()).hexdigest()}))
    generated, _ = forward.prepare(root, '192.0.2.2', 'bot.example.com', 8444)
    assert '192.0.2.2:8444' in generated[0]['content']
    main.write_text('events {}\nhttp {}\nstream { include /foreign/*.conf; }\n')
    try:
        forward.prepare(root, '192.0.2.2', 'bot.example.com', 8444)
        raise AssertionError('foreign stream context accepted')
    except ValueError:
        pass
print('Ansible forward ownership, repeated reconciliation and foreign-context guards passed')

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    nginx = root / 'etc/nginx'
    (nginx / 'stream.d').mkdir(parents=True)
    (nginx / 'conf.d').mkdir()
    main = nginx / 'nginx.conf'
    main.write_text(forward.main_candidate('events {}\nhttp {}\n'))
    for relative, (desired, legacy) in forward.configurations('192.0.2.1', 'bot.example.com', 8444).items():
        (nginx / relative).write_text(legacy)
    original_stat = Path.stat
    from types import SimpleNamespace
    def fixture_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=result.st_mode, st_size=result.st_size)
    Path.stat = fixture_stat
    try:
        before = {path: path.read_bytes() for path in (main, nginx / 'stream.d/bot-proxy.conf', nginx / 'conf.d/acme-proxy.conf')}
        forward.prepare(root, '192.0.2.1', 'bot.example.com', 8444, verify_existing=True)
        assert all(path.read_bytes() == data for path, data in before.items())
        assert not (root / 'var/lib/ultra-ingress/forward-managed.json').exists()
        for bridge, domain in [('192.0.2.2', 'bot.example.com'), ('192.0.2.1', 'other.example.com')]:
            try:
                forward.prepare(root, bridge, domain, 8444, verify_existing=True)
                raise AssertionError('mismatched preserved forward publication accepted')
            except ValueError:
                pass
        (nginx / 'stream.d/bot-proxy.conf').unlink()
        try:
            forward.prepare(root, '192.0.2.1', 'bot.example.com', 8444, verify_existing=True)
            raise AssertionError('missing preserved forward publication accepted')
        except ValueError:
            pass
    finally:
        Path.stat = original_stat
print('Ansible preserved legacy forwarding verified without changes; missing or mismatched publications rejected')
