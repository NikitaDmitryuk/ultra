import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('reserve', Path(__file__).resolve().parents[1] / 'deploy/prepare-reality-reserve.py')
reserve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reserve)

class ReserveTests(unittest.TestCase):
    def fixture(self):
        return {'role':'bridge','public_host':'192.0.2.1','vless_port':443,'legacy_public_enabled':False,
                'primary_xhttp':{'host':'192.0.2.1','port':443,'backend_port':18080,'server_name':'example.test','path':'/vpn'},
                'reality':{'private_key':'fixture-only','public_key':'fixture-only','server_names':['target.test'],'dest':'target.test:443'},
                'anti_censor':{'public_xhttp_port':443}}
    def test_stage_preserves_working_primary_and_does_not_publish(self):
        source=self.fixture(); staged=reserve.prepare(source)
        self.assertEqual(staged['primary_xhttp'],source['primary_xhttp'])
        self.assertFalse(source['legacy_public_enabled'])
        self.assertEqual(staged['vless_port'],24443)
        self.assertEqual(staged['anti_censor']['public_xhttp_port'],0)
        self.assertNotIn('subscription_bridges',staged)
    def test_publication_requires_device_acceptance(self):
        with self.assertRaises(ValueError):reserve.prepare(self.fixture(),publish=True)
        published=reserve.prepare(self.fixture(),publish=True,android_accepted=True)
        self.assertEqual([entry['security'] for entry in published['subscription_bridges']],['tls','reality'])
        self.assertNotIn('private_key',published['subscription_bridges'][1])
    def test_conflicts_fail_before_changes(self):
        for port in (80,443,8443,10085,11800,18080,0,65536):
            with self.subTest(port=port), self.assertRaises(ValueError):reserve.prepare(self.fixture(),port)
        source=self.fixture();source['reality']={}
        with self.assertRaises(ValueError):reserve.prepare(source)

if __name__ == '__main__':unittest.main()
