#!/usr/bin/env python3
"""Optional Android/Termux probe: fresh HTTPS connections and uncached UDP DNS requests."""
import argparse
import concurrent.futures
import ipaddress
import json
import secrets
import socket
import struct
import time
import urllib.parse
import urllib.request


def https_probe(url):
    try:
        request = urllib.request.Request(url, headers={'Connection': 'close', 'Cache-Control': 'no-cache'})
        # Ignore desktop shell proxy variables; Android's VPN captures the socket.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
            body = response.read(8193)
            if response.status != 200 or len(body) > 8192:
                return False, None
        address = None
        try:
            address = json.loads(body).get('ip')
        except (ValueError, AttributeError):
            for line in body.decode('utf-8', errors='replace').splitlines():
                if line.startswith('ip='):
                    address = line[3:]
                    break
        if address:
            address = str(ipaddress.ip_address(address))
        return True, address
    except (OSError, ValueError):
        return False, None


def udp_probe(resolver):
    # Unique question avoids a successful replay from a previous iteration.
    identifier = secrets.randbits(16)
    labels = [secrets.token_hex(8), 'example', 'com']
    question = b''.join(bytes([len(label)]) + label.encode() for label in labels) + b'\0' + struct.pack('!HH', 1, 1)
    packet = struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + question
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect((resolver, 53))
            client.send(packet)
            reply = client.recv(4096)
        if len(reply) < 12:
            return False
        ident, flags, questions, _, _, _ = struct.unpack('!HHHHHH', reply[:12])
        return ident == identifier and bool(flags & 0x8000) and questions == 1 and reply[12:12 + len(question)] == question
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--https-url', required=True, help='HTTPS IP-echo JSON {"ip":"..."} or ip= trace')
    parser.add_argument('--resolver', default='1.1.1.1', help='literal IPv4 DNS resolver')
    parser.add_argument('--duration', type=int, default=600)
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.https_url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        parser.error('HTTPS URL without credentials required')
    if ipaddress.ip_address(args.resolver).version != 4 or not 1 <= args.duration <= 3600:
        parser.error('IPv4 resolver and duration 1..3600 required')
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
        while time.monotonic() - start < args.duration:
            tick = time.monotonic()
            tcp = workers.submit(https_probe, args.https_url)
            udp = workers.submit(udp_probe, args.resolver)
            tcp_ok, address = tcp.result()
            udp_ok = udp.result()
            print(json.dumps({'elapsed': round(time.monotonic() - start, 3), 'tcp': tcp_ok, 'ip': address, 'udp': udp_ok}), flush=True)
            time.sleep(max(0, 2 - (time.monotonic() - tick)))


if __name__ == '__main__':
    main()
