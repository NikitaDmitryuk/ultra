import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('acceptance_forward', Path(__file__).resolve().parents[1] / 'deploy/happ-acceptance-forward.py')
forward = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forward)


class ForwardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        os.chmod(self.directory.name, 0o700)
        self.upstreams = []
        self.forward = None
        self.clients = []

    async def asyncTearDown(self):
        if self.forward:
            await asyncio.wait_for(self.forward.close(), 3)
        for reader, writer in self.clients:
            writer.close()
            await writer.wait_closed()
        for server in self.upstreams:
            server.close()
            await server.wait_closed()
        self.directory.cleanup()

    async def setup_forward(self, handler, **kwargs):
        upstream = await asyncio.start_server(handler, '127.0.0.1', 0)
        self.upstreams.append(upstream)
        port = upstream.sockets[0].getsockname()[1]
        self.forward = forward.AliasForward({'primary': ('127.0.0.1', port, 0), 'reserve': ('127.0.0.1', port, 0)},
                                            str(Path(self.directory.name) / 'control.sock'), **kwargs)
        await self.forward.start()
        return self.forward

    async def client(self, alias='primary'):
        port = self.forward.servers[alias].sockets[0].getsockname()[1]
        client = await asyncio.open_connection('127.0.0.1', port)
        self.clients.append(client)
        return client

    async def wait_status(self, name, expected):
        for _ in range(100):
            if self.forward.status()['aliases'][name]['active'] == expected:
                return
            await asyncio.sleep(.01)
        self.fail('connection accounting did not settle')

    async def echo(self, reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_closed_default_and_unix_permissions(self):
        await self.setup_forward(self.echo)
        self.assertEqual(os.stat(self.forward.control).st_mode & 0o777, 0o600)
        reader, _ = await self.client()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        self.assertEqual(self.forward.forwarded['primary'], 0)
        result = await forward.control_command(str(self.forward.control), 'up', 'primary')
        self.assertTrue(result['aliases']['primary']['enabled'])
        self.assertFalse(result['aliases']['reserve']['enabled'])

    async def test_half_close_preserves_delayed_response(self):
        async def respond_after_eof(reader, writer):
            body = await reader.read()
            await asyncio.sleep(.02)
            writer.write(body[::-1])
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        await self.setup_forward(respond_after_eof)
        self.forward.set_state('primary', True)
        reader, writer = await self.client()
        writer.write(b'half-close-request')
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'tseuqer-esolc-flah')
        await self.wait_status('primary', 0)

    async def test_down_aborts_only_test_alias_and_reenable(self):
        await self.setup_forward(self.echo)
        self.forward.set_state('all', True)
        primary_reader, primary_writer = await self.client('primary')
        reserve_reader, reserve_writer = await self.client('reserve')
        for reader, writer in [(primary_reader, primary_writer), (reserve_reader, reserve_writer)]:
            writer.write(b'before'); await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 1), b'before')
        stamp = self.forward.set_state('primary', False)['elapsed']
        self.assertGreaterEqual(stamp, 0)
        self.assertEqual(await asyncio.wait_for(primary_reader.read(), 1), b'')
        reserve_writer.write(b'after'); await reserve_writer.drain()
        self.assertEqual(await asyncio.wait_for(reserve_reader.readexactly(5), 1), b'after')
        closed_reader, _ = await self.client('primary')
        self.assertEqual(await asyncio.wait_for(closed_reader.read(), 1), b'')
        self.forward.set_state('primary', True)
        reader, writer = await self.client('primary')
        writer.write(b'restored'); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(8), 1), b'restored')

    async def test_both_down_leave_upstream_available(self):
        await self.setup_forward(self.echo)
        self.forward.set_state('all', True)
        self.forward.set_state('all', False)
        for name in ['primary', 'reserve']:
            reader, _ = await self.client(name)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        host, port, _ = self.forward.aliases['primary']
        reader, writer = await asyncio.open_connection(host, port)
        self.clients.append((reader, writer))
        writer.write(b'ordinary-path'); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(13), 1), b'ordinary-path')

    async def test_connection_limit_is_global(self):
        await self.setup_forward(self.echo, max_connections=1)
        self.forward.set_state('all', True)
        first_reader, first_writer = await self.client()
        first_writer.write(b'first'); await first_writer.drain()
        self.assertEqual(await asyncio.wait_for(first_reader.readexactly(5), 1), b'first')
        extra_reader, _ = await self.client('reserve')
        self.assertEqual(await asyncio.wait_for(extra_reader.read(), 1), b'')
        self.assertEqual(self.forward.forwarded['reserve'], 0)

    async def test_ttl_closes_ports_streams_and_owned_socket(self):
        await self.setup_forward(self.echo, ttl=.1)
        # start() is exercised above; run expiry against the same started instance.
        async def already_started():
            pass
        self.forward.start = already_started
        self.forward.set_state('all', True)
        port = self.forward.servers['primary'].sockets[0].getsockname()[1]
        reader, writer = await self.client()
        writer.write(b'active'); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 1), b'active')
        await self.forward.run()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        self.assertFalse(self.forward.control.exists())
        with self.assertRaises(OSError):
            await asyncio.open_connection('127.0.0.1', port)

    async def test_control_oversize_and_unknown_rejected(self):
        await self.setup_forward(self.echo)
        for command in [b'x' * 300 + b'\n', b'{"command":"set","alias":"wrong","enabled":true}\n']:
            reader, writer = await asyncio.open_unix_connection(str(self.forward.control))
            writer.write(command); await writer.drain()
            result = json.loads(await asyncio.wait_for(reader.readline(), 1))
            self.assertIn('error', result)
            writer.close(); await writer.wait_closed()
        self.assertFalse(any(self.forward.enabled.values()))

    async def test_private_directory_and_existing_socket_preserved(self):
        control = Path(self.directory.name) / 'control.sock'
        control.write_text('owned by another process')
        fixture = forward.AliasForward({}, str(control))
        with self.assertRaises(ValueError):
            await fixture.start()
        self.assertEqual(control.read_text(), 'owned by another process')
        control.unlink()
        os.chmod(self.directory.name, 0o755)
        with self.assertRaises(ValueError):
            await fixture.start()


if __name__ == '__main__':
    unittest.main()
