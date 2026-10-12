#!/usr/bin/env python3
"""Loopback-only HTTPS and UDP targets for an externally isolated VM drill."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import threading


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = b'x' * 65536
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('8.8.8.8', 19444))
        while True:
            data, address = s.recvfrom(65535)
            s.sendto(data, address)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    args = parser.parse_args()
    threading.Thread(target=udp, daemon=True).start()
    server = ThreadingHTTPServer(('8.8.8.8', 19443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
