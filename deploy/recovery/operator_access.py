#!/usr/bin/env python3
"""Run a private operator VPN and SSH through its loopback SOCKS transport."""
import argparse
import os
from pathlib import Path
import re
import select
import shlex
import socket
import struct
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ssh_policy import ssh_options


def endpoint(value):
    match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})', value)
    if not match or not 1 <= int(match[1]) <= 65535:
        raise ValueError('loopback SOCKS endpoint required')
    return '127.0.0.1', int(match[1])


def target(value):
    if not re.fullmatch(r'[A-Za-z0-9_.:@-]+', value) or value.startswith('-'):
        raise ValueError('invalid SSH destination')
    return value


def receive(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise OSError('SOCKS connection closed')
        result.extend(chunk)
    return bytes(result)


def connect(proxy, host, port):
    if not 1 <= port <= 65535:
        raise ValueError('invalid target port')
    encoded = host.encode('idna')
    if not encoded or len(encoded) > 255:
        raise ValueError('invalid target host')
    sock = socket.create_connection(endpoint(proxy), timeout=10)
    try:
        sock.sendall(b'\x05\x01\x00')
        if receive(sock, 2) != b'\x05\x00':
            raise OSError('SOCKS authentication rejected')
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded + struct.pack('!H', port))
        reply = receive(sock, 4)
        if reply[:3] != b'\x05\x00\x00':
            raise OSError('SOCKS target rejected')
        if reply[3] == 1:
            receive(sock, 6)
        elif reply[3] == 4:
            receive(sock, 18)
        elif reply[3] == 3:
            receive(sock, receive(sock, 1)[0] + 2)
        else:
            raise OSError('invalid SOCKS reply')
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def pump(sock):
    with sock:
        inputs = [sock, sys.stdin.buffer]
        while inputs:
            readable, _, _ = select.select(inputs, [], [])
            for source in readable:
                if source is sock:
                    data = sock.recv(32768)
                    if not data:
                        return
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    data = os.read(sys.stdin.fileno(), 32768)
                    if data:
                        sock.sendall(data)
                    else:
                        sock.shutdown(socket.SHUT_WR)
                        inputs.remove(source)


def ssh_args(proxy, host, jump=None, forward=None, command=()):
    endpoint(proxy)
    target(host)
    script = str(Path(__file__).resolve())
    transport = [sys.executable, script, 'proxy', '--socks', proxy, '--host', '%h', '--port', '%p']
    if jump:
        target(jump)
        transport = [sys.executable, script, 'ssh', '--socks', proxy, '--forward', '%h:%p', jump]
    result = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
              '-o', 'UpdateHostKeys=no', *ssh_options('probe'),
              '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ProxyJump=none',
              '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
              '-o', 'ProxyCommand=' + shlex.join(transport)]
    if forward:
        result += ['-W', forward]
    return result + [host] + list(command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    proxy = commands.add_parser('proxy', help=argparse.SUPPRESS)
    proxy.add_argument('--socks', required=True)
    proxy.add_argument('--host', required=True)
    proxy.add_argument('--port', type=int, required=True)
    ssh = commands.add_parser('ssh')
    ssh.add_argument('--socks', default='127.0.0.1:18928')
    ssh.add_argument('--jump')
    ssh.add_argument('--forward', help=argparse.SUPPRESS)
    ssh.add_argument('host')
    ssh.add_argument('command', nargs=argparse.REMAINDER)
    vpn = commands.add_parser('vpn')
    vpn.add_argument('--binary', required=True)
    vpn.add_argument('--profile', required=True)
    vpn.add_argument('--socks', default='127.0.0.1:18928')
    vpn.add_argument('--http', default='127.0.0.1:18929')
    args = parser.parse_args()
    if args.mode == 'proxy':
        pump(connect(args.socks, args.host, args.port))
    elif args.mode == 'ssh':
        command = ssh_args(args.socks, args.host, args.jump, args.forward, args.command)
        os.execvp(command[0], command)
    else:
        endpoint(args.socks)
        endpoint(args.http)
        profile = Path(args.profile)
        if profile.is_symlink() or not profile.is_file() or profile.stat().st_mode & 0o077:
            raise ValueError('private regular profile required (0600)')
        command = [str(Path(args.binary).resolve()), '-config', str(profile.resolve()),
                   '-socks', args.socks, '-http', args.http]
        # Foreground execution permits a terminal or systemd user unit to own
        # the process. No credentials are copied, rendered, or logged here.
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
            try:
                return child.wait()
            except KeyboardInterrupt:
                child.terminate()
                return child.wait(timeout=10)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('operator transport failed; private details suppressed')
