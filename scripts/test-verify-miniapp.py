import importlib.util
import pathlib
import ssl
import unittest

spec = importlib.util.spec_from_file_location('verify', pathlib.Path(__file__).with_name('verify-miniapp.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

class VerifyTests(unittest.TestCase):
    def test_ingress_and_backend_separate(self):
        calls=[]
        def check(*args):
            calls.append(args)
            return (args[2] if len(args)==3 else '192.0.2.2',200)
        self.assertTrue(v.verify('192.0.2.1','bot.example','8444','https://bot.example','192.0.2.2',check))
        self.assertEqual(calls,[('bot.example',443),('bot.example',8444,'192.0.2.1')])
    def test_cached_wrong_ip_is_failure(self):
        self.assertFalse(v.verify('192.0.2.1','bot.example','8444','https://bot.example','192.0.2.2',lambda *args:('192.0.2.1',200)))
    def test_certificate_failure_not_hidden_by_backend(self):
        def check(*args):
            if len(args)==2:raise ssl.SSLCertVerificationError()
            return ('192.0.2.1',200)
        self.assertFalse(v.verify('192.0.2.1','bot.example','8444',check=check))
    def test_http_error_fails(self):
        self.assertFalse(v.verify('192.0.2.1','bot.example','8444',check=lambda *args:('192.0.2.1',503)))
    def test_legacy_defaults_and_invalid_origin(self):
        self.assertEqual(v.addresses('192.0.2.1','bot.example','8444','',''),('bot.example',8444,'192.0.2.1'))
        for url in ['http://bot.example','https://u:p@bot.example','https://bot.example/sub/secret','https://bot.example?q=s','https://bot.example#s']:
            with self.assertRaises(ValueError):v.addresses('192.0.2.1','bot.example','8444',url,'')

if __name__=='__main__':unittest.main()
