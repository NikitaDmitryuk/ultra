#!/usr/bin/env python3
"""Prepare a private candidate spec; never applies it or changes firewall/services."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile


def prepare(spec, port=24443, publish=False, android_accepted=False):
    spec = copy.deepcopy(spec)
    primary = spec.get('primary_xhttp') or {}
    if spec.get('role') != 'bridge' or primary.get('published', True) is not True or not primary.get('host'):
        raise ValueError('published primary HTTPS bridge required')
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('invalid reserve port')
    occupied = {80, 443, 11800, primary.get('port'), primary.get('backend_port'), spec.get('gateway_vless_port')}
    for key in ('admin_listen',):
        value = spec.get(key, '127.0.0.1:8443')
        occupied.add(int(value.rsplit(':', 1)[1]))
    occupied.add(int((spec.get('stats') or {}).get('api_listen', '127.0.0.1:10085').rsplit(':', 1)[1]))
    for key in ('public_xhttp_tls', 'bot_telegram_proxy'):
        occupied.add((spec.get(key) or {}).get('port'))
    if port in occupied:
        raise ValueError('reserve port conflicts with an existing listener')
    reality = spec.get('reality') or {}
    if not reality.get('private_key') or not reality.get('public_key') or not reality.get('server_names') or not reality.get('dest'):
        raise ValueError('existing REALITY credentials and destination required')
    # Avoid enabling an old optional listener on the Nginx port.
    spec['anti_censor'] = dict(spec.get('anti_censor') or {}, public_xhttp_port=0)
    spec['vless_port'], spec['legacy_public_enabled'] = port, True
    if publish:
        if not android_accepted:
            raise ValueError('Android Wi-Fi and mobile acceptance required for publication')
        if spec.get('subscription_bridges'):
            raise ValueError('existing publication list requires explicit reconciliation')
        spec['subscription_bridges'] = [
            dict(id='https', host=primary['host'], port=primary['port'], security='tls', transport='xhttp',
                 server_name=primary['server_name'], path=primary['path'], fingerprint=primary.get('fingerprint', 'chrome')),
            dict(id='reality', host=spec['public_host'], port=port, security='reality', transport='tcp',
                 public_key=reality['public_key'], server_name=reality['server_names'][0],
                 short_id=(reality.get('short_ids') or [''])[0], fingerprint=reality.get('fingerprint') or 'chrome')]
    return spec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--port', type=int, default=24443)
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--android-accepted', action='store_true')
    parser.add_argument('--check-binary', required=True, help='matching new ultra-relay binary for --check')
    args = parser.parse_args()
    target = Path(args.output)
    if target.exists() or target.resolve() == Path(args.spec).resolve():
        raise ValueError('new output path required; working spec cannot be overwritten')
    candidate = prepare(json.loads(Path(args.spec).read_text()), args.port, args.publish, args.android_accepted)
    fd, pending = tempfile.mkstemp(prefix='.reserve-', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(candidate, stream)
            stream.flush()
            os.fsync(stream.fileno())
        if args.check_binary:
            subprocess.run([args.check_binary, '-spec', pending, '-check'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        os.link(pending, target)  # No overwrite, including a concurrent creation.
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(pending)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('reserve preparation failed; configuration values suppressed')
