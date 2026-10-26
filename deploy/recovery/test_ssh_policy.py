import json
from pathlib import Path
import unittest
import ssh_policy


class SSHPolicyTests(unittest.TestCase):
    def test_options_use_shared_timeout_and_keep_strict_pins(self):
        self.assertEqual(ssh_policy.POLICY['version'], 1)
        self.assertIn('ConnectTimeout=15', ssh_policy.ssh_options('probe'))
        self.assertIn('ConnectTimeout=30', ssh_policy.ssh_options('mutate'))
        self.assertIn('ServerAliveInterval=5', ssh_policy.ssh_options())
        self.assertIn('ServerAliveCountMax=2', ssh_policy.ssh_options())
        self.assertIn('StrictHostKeyChecking=yes', ssh_policy.ssh_options())
        self.assertIn('UpdateHostKeys=no', ssh_policy.ssh_options())


if __name__ == '__main__':
    unittest.main()
