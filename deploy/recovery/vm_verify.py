#!/usr/bin/env python3
"""Verify loopback VPN and compatible fallback in a restored, isolated drill VM."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import time
import urllib.request

from vm_guest import run, sql, write


def api(path):
    request = urllib.request.Request('http://127.0.0.1:8443' + path, headers={'Authorization': 'Bearer drill-admin-token'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def wait_ready(mode):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            state = api('/v1/hardening')['runtime']
            if state['mode'] == mode and state['revision'] == state['applied_revision'] and not state['error']:
                return state
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    raise RuntimeError('relay readiness timeout')


def receive(channel, size):
    data = b''
    while len(data) < size:
        chunk = channel.recv(size - len(data))
        if not chunk:
            raise RuntimeError('truncated SOCKS reply')
        data += chunk
    return data


def udp():
    with socket.create_connection(('127.0.0.1', 19808), timeout=10) as control:
        control.sendall(b'\x05\x01\x00')
        if receive(control, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS greeting failed')
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        response = receive(control, 4)
        if response[:4] != b'\x05\x00\x00\x01':
            raise RuntimeError('SOCKS UDP association failed')
        response += receive(control, 6)
        if len(response) != 10 or response[:4] != b'\x05\x00\x00\x01':
            raise RuntimeError('SOCKS UDP association failed')
        target = (socket.inet_ntoa(response[4:8]), struct.unpack('!H', response[8:10])[0])
        payload = b'ultra-vm-drill-udp'
        packet = b'\x00\x00\x00\x01' + socket.inet_aton('8.8.8.8') + struct.pack('!H', 19444) + payload
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(10)
            channel.sendto(packet, target)
            if channel.recv(65535)[10:] != payload:
                raise RuntimeError('UDP payload mismatch')


def payload():
    deadline = time.monotonic() + 75
    while True:
        try:
            data = run(['curl', '--fail', '--silent', '--max-time', '10', '--socks5-hostname', '127.0.0.1:19808', '--noproxy', '', 'https://8.8.8.8:19443/payload'])
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise RuntimeError('HTTPS payload deadline')
            time.sleep(2)
    if data != b'x' * 65536:
        raise RuntimeError('HTTPS payload mismatch')
    udp()


def verify():
    initial = wait_ready('online')
    uid = sql("SELECT u.uuid FROM users u JOIN user_exit_quotas q ON q.user_uuid=u.uuid WHERE u.is_active AND u.kind='vless' AND NOT q.blocked AND q.limit_bytes-q.used_bytes>1048576 LIMIT 1")
    if not uid:
        raise RuntimeError('existing eligible fixture access unavailable')
    export = api('/v1/users/' + uid + '/client')
    write('/etc/ultra-drill/client.json', json.dumps(export))
    write('/etc/systemd/system/ultra-drill-client.service', '[Service]\nExecStart=/usr/local/bin/ultra-drill-client -config /etc/ultra-drill/client.json -profile primary_xhttp_tls -socks 127.0.0.1:19808 -http 127.0.0.1:19809\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', 'ultra-drill-client'])
    time.sleep(4)
    payload()
    with urllib.request.urlopen('http://127.0.0.1:18444/healthz', timeout=10) as response:
        if response.status != 200:
            raise RuntimeError('bot HTTP failed')
    # Stop before exchanging binary: both versions use the same durable journal.
    initial = api('/v1/hardening')['runtime']
    run(['systemctl', 'stop', 'ultra-relay'])
    run(['/usr/local/bin/ultra-drill-state', '-state', '/var/lib/ultra-relay/runtime.db', '-baseline', '/etc/ultra-drill/allowances.json'])
    fallback = Path('/usr/local/libexec/ultra-reliability-fallback-relay')
    if not fallback.is_file():
        raise RuntimeError('compatible fallback absent')
    write('/etc/systemd/system/ultra-relay.service.d/drill.conf', '[Service]\nExecStart=\nExecStart=' + str(fallback) + ' -cache-only -spec /etc/ultra-relay/spec.json -log-level error\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', 'ultra-relay'])
    cached = wait_ready('cache_only')
    if initial['confirmed_at'] != cached['confirmed_at'] or initial['expires_at'] != cached['expires_at']:
        raise RuntimeError('fallback renewed lease')
    payload()
    run(['systemctl', 'stop', 'ultra-relay'])
    run(['/usr/local/bin/ultra-drill-state', '-state', '/var/lib/ultra-relay/runtime.db', '-baseline', '/etc/ultra-drill/allowances.json', '-compare'])
    run(['systemctl', 'start', 'ultra-relay'])
    result_path = Path('/var/lib/ultra-drill-result.json')
    result = json.loads(result_path.read_text())
    result.update({'https_tcp_udp': True, 'bot_http_without_telegram': True, 'fallback_payload': True, 'fallback_preserved_lease': True, 'fallback_no_quota_refund': True})
    write(result_path, json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        verify()
    except RuntimeError as error:
        raise SystemExit('isolated VM verification failed: ' + str(error))
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('isolated VM verification failed; sensitive details suppressed')
