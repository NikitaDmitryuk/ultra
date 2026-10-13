import importlib.util
from pathlib import Path
import socket
import threading
import unittest

spec = importlib.util.spec_from_file_location('ultra_operator', Path(__file__).with_name('operator_access.py'))
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class OperatorTests(unittest.TestCase):
    def serve(self, reply, expected_host=b'bridge.example', expected_port=22):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        address = '127.0.0.1:' + str(listener.getsockname()[1])
        errors = []

        def handler():
            try:
                with listener, listener.accept()[0] as client:
                    self.assertEqual(operator.receive(client, 3), b'\x05\x01\x00')
                    client.sendall(b'\x05')
                    client.sendall(b'\x00')
                    self.assertEqual(operator.receive(client, 4), b'\x05\x01\x00\x03')
                    length = operator.receive(client, 1)[0]
                    self.assertEqual(operator.receive(client, length), expected_host)
                    self.assertEqual(int.from_bytes(operator.receive(client, 2), 'big'), expected_port)
                    for byte in reply:
                        client.sendall(bytes([byte]))
                    if reply[1] == 0:
                        client.sendall(b'SSH-2.0-fixture\r\n')
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=handler, daemon=True)
        thread.start()
        return address, thread, errors

    def test_server_first_banner_after_fragmented_socks_replies(self):
        for reply in (b'\x05\x00\x00\x01' + b'\x00' * 6,
                      b'\x05\x00\x00\x04' + b'\x00' * 18,
                      b'\x05\x00\x00\x03\x03abc\x00\x16'):
            with self.subTest(address_type=reply[3]):
                address, thread, errors = self.serve(reply)
                with operator.connect(address, 'bridge.example', 22) as client:
                    client.settimeout(2)
                    self.assertEqual(operator.receive(client, 17), b'SSH-2.0-fixture\r\n')
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

    def test_target_failure_is_rejected_before_streaming(self):
        address, thread, errors = self.serve(b'\x05\x05\x00\x01' + b'\x00' * 6)
        with self.assertRaises(OSError):
            operator.connect(address, 'bridge.example', 22)
        thread.join(timeout=2)
        # The client's intentional close may interrupt the remainder of the
        # synthetic error response; no data can reach an SSH process.
        self.assertTrue(all(isinstance(error, (BrokenPipeError, ConnectionResetError)) for error in errors))

    def test_only_loopback_proxy_and_safe_ssh_destinations(self):
        for value in ('0.0.0.0:1080', 'proxy.example:1080', '127.0.0.1:0', '127.0.0.1:65536'):
            with self.assertRaises(ValueError):
                operator.endpoint(value)
        for value in ('-oProxyCommand=bad', 'host;bad', 'host bad', '$(bad)'):
            with self.assertRaises(ValueError):
                operator.ssh_args('127.0.0.1:1080', value)
        command = operator.ssh_args('127.0.0.1:1080', 'ultra-bridge', 'ultra-exit', command=['true'])
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertIn('BatchMode=yes', command)
        self.assertIn('ProxyJump=none', command)
        self.assertEqual(command[-2:], ['ultra-bridge', 'true'])


if __name__ == '__main__':
    unittest.main()
