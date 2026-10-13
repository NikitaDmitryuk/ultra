#!/usr/bin/env python3
"""Dependency-only local proxy for synthetic VM acceptance, never production APIs."""
import argparse
import http.server
import select
import socket
import socketserver
import urllib.parse

HOSTS = frozenset(('archive.ubuntu.com', 'security.ubuntu.com', 'ports.ubuntu.com',
                   'cloud-images.ubuntu.com', 'github.com', 'api.github.com',
                   'release-assets.githubusercontent.com', 'objects.githubusercontent.com',
                   'raw.githubusercontent.com', 'codeload.github.com'))


def allowed(host):
    return host.lower().rstrip('.') in HOSTS


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass
    def do_CONNECT(self):
        try:
            host, port = self.path.rsplit(':', 1)
            if not allowed(host) or port != '443':
                self.send_error(403); return
            with socket.create_connection((host, 443), timeout=20) as upstream:
                self.send_response(200); self.end_headers()
                self.connection.settimeout(60);upstream.settimeout(60)
                while True:
                    readable, _, _ = select.select([self.connection, upstream], [], [], 60)
                    if not readable: break
                    for source in readable:
                        data=source.recv(65536)
                        if not data:return
                        (upstream if source is self.connection else self.connection).sendall(data)
        except OSError:
            self.close_connection=True
    def do_GET(self):
        url=urllib.parse.urlsplit(self.path)
        if url.scheme!='http' or not allowed(url.hostname or '') or (url.port or 80)!=80:
            self.send_error(403);return
        try:
            with socket.create_connection((url.hostname,80),timeout=20) as upstream:
                path=urllib.parse.urlunsplit(('', '', url.path or '/', url.query, ''))
                headers=''.join(key+': '+value+'\r\n' for key,value in self.headers.items() if key.lower() not in ('connection','proxy-connection','host'))
                upstream.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+url.hostname+'\r\nConnection: close\r\n'+headers+'\r\n').encode())
                while True:
                    data=upstream.recv(65536)
                    if not data:break
                    self.connection.sendall(data)
            self.close_connection=True
        except OSError:self.close_connection=True


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads=True


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=3128)
    args=parser.parse_args();Server(('127.0.0.1',args.port),Proxy).serve_forever()
