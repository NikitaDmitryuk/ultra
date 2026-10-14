import unittest

import vm_download_proxy


class DownloadProxyTests(unittest.TestCase):
    def test_native_postgres_dependencies_are_allowed(self):
        for host in ('www.postgresql.org', 'apt.postgresql.org'):
            self.assertTrue(vm_download_proxy.allowed(host))

    def test_dependency_exception_does_not_allow_provider_or_suffix_hosts(self):
        for host in ('api.vultr.com', 'api.telegram.org', 'apt.postgresql.org.example.net'):
            self.assertFalse(vm_download_proxy.allowed(host))


if __name__ == '__main__':
    unittest.main()
