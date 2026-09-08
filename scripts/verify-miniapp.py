#!/usr/bin/env python3
"""Verify public DNS/TLS separately from the bridge backend, without secrets."""
import http.client
import ipaddress
import socket
import ssl
import sys
from urllib.parse import urlsplit


def addresses(bridge, domain, port, public_url, ingress):
    ipaddress.ip_address(bridge)
    expected = str(ipaddress.ip_address(ingress or bridge))
    url = public_url or f'https://{domain}:{port}'
    u = urlsplit(url)
    if (u.scheme != 'https' or not u.hostname or u.username or u.password
            or u.path not in ('', '/') or u.query or u.fragment or '?' in url or '#' in url):
        raise ValueError('invalid public HTTPS origin')
    public_port = u.port or 443
    if not 0 < int(port) < 65536 or not 0 < public_port < 65536:
        raise ValueError('invalid port')
    return u.hostname, public_port, expected


def probe(host, port, target=None):
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, timeout=15, context=context)
    try:
        if target:
            conn.sock = context.wrap_socket(socket.create_connection((target, port), 15), server_hostname=host)
        else:
            conn.connect()  # Real system resolver, exactly as a client connection.
        peer = conn.sock.getpeername()[0]
        conn.request('GET', '/happ')
        response = conn.getresponse()
        response.read(1 << 20)
        return peer, response.status
    finally:
        conn.close()


def verify(bridge, domain, port, public_url='', ingress='', check=probe):
    host, public_port, expected = addresses(bridge, domain, port, public_url, ingress)
    ok = True
    for label, args, wanted in [('public', (host, public_port), expected),
                                 ('backend', (domain, int(port), bridge), bridge)]:
        try:
            peer, status = check(*args)
            passed = peer == wanted and status == 200
            print(f'{label}: ip={peer} expected={wanted} HTTP={status} ok={passed}')
            ok = ok and passed
        except (OSError, http.client.HTTPException) as error:
            print(f'{label}: failed={type(error).__name__}')
            ok = False
    return ok


if __name__ == '__main__':
    try:
        sys.exit(0 if verify(*sys.argv[1:]) else 1)
    except (ValueError, TypeError):
        print('Invalid Mini App address configuration', file=sys.stderr)
        sys.exit(2)
