#!/usr/bin/env python3
"""Independent read-only health probes and durable Telegram send-only alerts."""
import argparse
import json
import os
from pathlib import Path
import random
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from recovery import atomic_json, private, read_config

MAX_EVENTS = 100

def curl(url, proxy=None):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('HTTPS probe URL required')
    args = ['curl', '--silent', '--fail', '--max-time', '8', '--connect-timeout', '4', '--max-filesize', '16384']
    if proxy:
        if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', proxy):
            raise ValueError('loopback probe SOCKS required')
        args += ['--proxy', 'socks5h://' + proxy, '--noproxy', '']
    else:
        args += ['--noproxy', '*']
    result = subprocess.run(args + [url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    return result.returncode == 0


def checks(config, now):
    results = {}
    if config['mode'] == 'primary':
        results['bridge_https'] = curl(config['bridge_url'])
        results['vpn_payload'] = curl(config['payload_url'], config['probe_socks'])
        if 'service_quota_available' in config:
            results['monitor_quota_available'] = config['service_quota_available'] is True
        status = Path(config['backup_status'])
        try:
            saved = json.loads(status.read_text())
            age = now - saved['snapshot_at']
            backup_check = 'independent_backup' if config.get('backup_independent', True) else 'backup_generation'
            results[backup_check] = 0 <= age <= 300
        except (OSError, ValueError, KeyError, TypeError):
            backup_check = 'independent_backup' if config.get('backup_independent', True) else 'backup_generation'
            results[backup_check] = False
    elif config['mode'] == 'peer':
        host = config['peer_host']
        if not re.fullmatch(r'[A-Za-z0-9_.@:-]+', host) or host.startswith('-'):
            raise ValueError('invalid peer host')
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=5']
        if config.get('peer_identity_file'):
            command += ['-i', config['peer_identity_file'], '-o', 'IdentitiesOnly=yes']
        if config.get('peer_known_hosts'):
            command += ['-o', 'UserKnownHostsFile=' + config['peer_known_hosts']]
        result = subprocess.run(command + [host, 'cat /var/lib/ultra-monitor/heartbeat.json'], capture_output=True, timeout=8)
        try:
            heartbeat = json.loads(result.stdout)
            age = now - heartbeat['updated_at']
            results['us_monitor'] = result.returncode == 0 and 0 <= age <= 120
            results['us_notifications'] = results['us_monitor'] and not heartbeat.get('send_error')
        except (ValueError, KeyError, TypeError):
            results['us_monitor'] = False
            results['us_notifications'] = False
    else:
        raise ValueError('unsupported monitor mode')
    return results


def transition(state, results, now, node):
    previous = state.get('checks', {})
    streaks = state.setdefault('streaks', {})
    accepted = dict(previous)
    changed = []
    for key, ok in sorted(results.items()):
        streak = streaks.setdefault(key, {'ok': ok, 'count': 0})
        streak['count'] = streak['count'] + 1 if streak['ok'] == ok else 1
        streak['ok'] = ok
        if streak['count'] >= 2 and previous.get(key) != ok:
            accepted[key] = ok
            changed.append(key + ': ' + ('восстановлено' if ok else 'недоступно'))
    state['checks'] = accepted
    # A healthy initial baseline needs no unsolicited notification.
    if changed and (previous or any(not ok for ok in accepted.values())):
        queue = state.setdefault('queue', [])
        queue.append({'text': 'ultra ' + node + '\n' + '\n'.join(changed), 'attempts': 0, 'next_at': now})
        if len(queue) > MAX_EVENTS:
            queue[:] = queue[-MAX_EVENTS:]
            state['queue_overflow_at'] = now
    return state


def send(token, chat, message):
    request = urllib.request.Request('https://api.telegram.org/bot' + token + '/sendMessage',
                                    data=urllib.parse.urlencode({'chat_id': chat, 'text': message}).encode())
    # Explicitly avoid the bridge/exit SOCKS proxy and inherited proxy variables.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            result = json.loads(response.read(65536))
            if result.get('ok'):
                return 'sent', 0
            return 'retry', result.get('parameters', {}).get('retry_after', 0)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            try:
                result = json.loads(exc.read(65536))
                return 'retry', result.get('parameters', {}).get('retry_after', 0)
            except (ValueError, TypeError):
                return 'retry', 60
        if exc.code == 403:
            return 'blocked', 0
        return 'retry', 0
    except (OSError, ValueError):
        return 'retry', 0


def drain(state, token, chat, now, sender=send):
    queue = state.setdefault('queue', [])
    if not queue or queue[0]['next_at'] > now:
        return
    event = queue[0]
    outcome, retry_after = sender(token, chat, event['text'])
    if outcome == 'sent':
        queue.pop(0)
        state['last_sent_at'] = now
        state.pop('send_error', None)
    elif outcome == 'blocked':
        queue.pop(0)
        state['send_error'] = 'telegram_recipient_blocked'
    else:
        event['attempts'] += 1
        delay = min(3600, 5 * 2 ** min(event['attempts'], 10))
        event['next_at'] = now + max(float(retry_after or 0), delay + random.uniform(0, delay / 4))
        state['send_error'] = 'telegram_unavailable'


def cycle(config, directory):
    now = time.time()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError('private monitor directory required')
    path = directory / 'state.json'
    state = json.loads(private(path).read_text()) if path.exists() else {}
    try:
        results = checks(config, now)
        results['probe_execution'] = True
    except (OSError, ValueError, subprocess.SubprocessError):
        results = {'probe_execution': False}
    transition(state, results, now, config['node'])
    atomic_json(path, state)  # Queue survives termination during ambiguous Telegram response.
    token = private(config['token_file']).read_text().strip()
    if not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]+', token):
        raise ValueError('invalid monitor bot token')
    drain(state, token, config['chat_id'], now)
    atomic_json(path, state)
    atomic_json(directory / 'heartbeat.json', {'updated_at': now, 'checks': state.get('checks', {}), 'current_checks': results, 'pending': len(state.get('queue', [])), 'send_error': state.get('send_error')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--state', default='/var/lib/ultra-monitor')
    args = parser.parse_args()
    os.umask(0o077)
    cycle(read_config(args.config), args.state)

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('monitor failed; sensitive details suppressed')
