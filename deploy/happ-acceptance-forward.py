#!/usr/bin/env python3
"""Temporary TCP aliases for isolated Happ acceptance; starts closed, stores no credentials."""
import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import signal
import stat
import time


class AliasForward:
    def __init__(self, aliases, control, listen='127.0.0.1', ttl=900, max_connections=32):
        self.aliases = aliases
        self.control = Path(control)
        self.listen = listen
        self.ttl = ttl
        self.maximum = max_connections
        self.enabled = {name: False for name in aliases}
        self.accepted = {name: 0 for name in aliases}
        self.forwarded = {name: 0 for name in aliases}
        self.connections = {}
        self.servers = {}
        self.control_server = None
        self.control_connections = 0
        self.started = time.monotonic()
        self.stopped = asyncio.Event()
        self.socket_inode = None

    async def start(self):
        parent = self.control.parent.stat()
        if not self.control.is_absolute() or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError('control directory must be absolute, owned by this UID and mode 0700')
        if self.control.exists() or self.control.is_symlink():
            raise ValueError('control socket already exists')
        try:
            for name, (target, target_port, listen_port) in self.aliases.items():
                if not ipaddress.ip_address(target).is_loopback:
                    raise ValueError('only loopback upstreams are permitted')
                self.servers[name] = await asyncio.start_server(
                    lambda r, w, name=name: self.handle_stream(name, r, w), self.listen, listen_port)
            self.control_server = await asyncio.start_unix_server(self.handle_control, str(self.control), limit=256)
            self.socket_inode = self.control.stat().st_ino
            os.chmod(self.control, 0o600)
        except BaseException:
            await self.close()
            raise

    def status(self):
        return {'elapsed': round(time.monotonic() - self.started, 3),
                'aliases': {name: {'enabled': self.enabled[name], 'active': sum(1 for n, _ in self.connections.values() if n == name),
                                   'accepted': self.accepted[name], 'forwarded': self.forwarded[name]}
                            for name in self.aliases}}

    def set_state(self, name, enabled):
        names = list(self.aliases) if name == 'all' else [name]
        if any(n not in self.aliases for n in names) or not isinstance(enabled, bool):
            raise ValueError('invalid alias or state')
        for n in names:
            self.enabled[n] = enabled
        if not enabled:
            for task, (n, writers) in list(self.connections.items()):
                if n in names:
                    for writer in writers:
                        writer.transport.abort()
                    task.cancel()
        return self.status()

    async def handle_control(self, reader, writer):
        if self.control_connections >= 4:
            writer.close()
            return
        self.control_connections += 1
        try:
            line = await asyncio.wait_for(reader.readline(), 2)
            if len(line) > 256 or not line.endswith(b'\n'):
                raise ValueError('invalid command')
            request = json.loads(line)
            if request.get('command') == 'status':
                result = self.status()
            elif request.get('command') == 'set':
                result = self.set_state(request.get('alias'), request.get('enabled'))
            else:
                raise ValueError('invalid command')
            writer.write(json.dumps(result).encode() + b'\n')
            await writer.drain()
        except (ValueError, TypeError, AttributeError, asyncio.TimeoutError, ConnectionError):
            writer.write(b'{"error":"invalid command"}\n')
        finally:
            self.control_connections -= 1
            writer.close()
            await writer.wait_closed()

    async def handle_stream(self, name, reader, writer):
        self.accepted[name] += 1
        if not self.enabled[name] or len(self.connections) >= self.maximum:
            writer.close()
            await writer.wait_closed()
            return
        task = asyncio.current_task()
        writers = [writer]
        self.connections[task] = (name, writers)
        pumps = []
        try:
            host, port, _ = self.aliases[name]
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
            writers.append(upstream_writer)
            if not self.enabled[name]:
                return
            self.forwarded[name] += 1

            async def pump(source, destination):
                while True:
                    data = await asyncio.wait_for(source.read(65536), 120)
                    if not data:
                        destination.write_eof()
                        await destination.drain()
                        return
                    destination.write(data)
                    await destination.drain()

            pumps = [asyncio.create_task(pump(reader, upstream_writer)), asyncio.create_task(pump(upstream_reader, writer))]
            await asyncio.gather(*pumps)
        except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            for peer in writers:
                peer.close()
            await asyncio.gather(*(peer.wait_closed() for peer in writers), return_exceptions=True)
            self.connections.pop(task, None)

    async def close(self):
        self.enabled = dict.fromkeys(self.aliases, False)
        servers = [server for server in [*self.servers.values(), self.control_server] if server]
        for server in servers:
            server.close()
        for task, (_, writers) in list(self.connections.items()):
            for writer in writers:
                writer.transport.abort()
            task.cancel()
        if self.connections:
            await asyncio.gather(*list(self.connections), return_exceptions=True)
        for server in servers:
            await server.wait_closed()
        if self.socket_inode is not None:
            try:
                if self.control.lstat().st_ino == self.socket_inode:
                    self.control.unlink()
            except FileNotFoundError:
                pass

    async def run(self):
        await self.start()
        try:
            await asyncio.wait_for(self.stopped.wait(), self.ttl)
        except asyncio.TimeoutError:
            pass
        finally:
            await self.close()


async def control_command(path, command, alias):
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(path), 2)
    try:
        request = {'command': 'status'} if command == 'status' else {'command': 'set', 'alias': alias, 'enabled': command == 'up'}
        writer.write(json.dumps(request).encode() + b'\n')
        await writer.drain()
        return json.loads(await asyncio.wait_for(reader.readline(), 2))
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', required=True, help='socket in existing private 0700 directory')
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--listen', default='127.0.0.1')
    serve.add_argument('--primary-port', type=int, required=True)
    serve.add_argument('--reserve-port', type=int, required=True)
    serve.add_argument('--primary-target-port', type=int, default=443)
    serve.add_argument('--reserve-target-port', type=int, default=24443)
    serve.add_argument('--ttl', type=int, default=900)
    serve.add_argument('--max-connections', type=int, default=32)
    for name in ['up', 'down']:
        commands.add_parser(name).add_argument('alias', choices=['primary', 'reserve', 'all'])
    commands.add_parser('status')
    args = parser.parse_args()
    if args.command != 'serve':
        print(json.dumps(await control_command(args.control, args.command, getattr(args, 'alias', None))))
        return
    ports = [args.primary_port, args.reserve_port, args.primary_target_port, args.reserve_target_port]
    if any(not 1 <= port <= 65535 for port in ports) or args.primary_port == args.reserve_port or any(port in ports[2:] for port in ports[:2]):
        parser.error('distinct alias ports must not overlap upstreams')
    if not 1 <= args.ttl <= 3600 or not 1 <= args.max_connections <= 64:
        parser.error('TTL must be 1..3600 seconds; connections 1..64')
    if not ipaddress.ip_address(args.listen).is_loopback and os.geteuid() != 0:
        parser.error('public aliases require root')
    forward = AliasForward({'primary': ('127.0.0.1', args.primary_target_port, args.primary_port),
                            'reserve': ('127.0.0.1', args.reserve_target_port, args.reserve_port)},
                           args.control, args.listen, args.ttl, args.max_connections)
    loop = asyncio.get_running_loop()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, forward.stopped.set)
    await forward.run()


if __name__ == '__main__':
    asyncio.run(main())
