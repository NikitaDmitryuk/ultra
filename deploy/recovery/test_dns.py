import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ultra_dns', Path(__file__).with_name('dns.py'))
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)


class FakeAPI:
    def __init__(self):
        self.rows = []
        self.writes = []
        self.lose = False
        self.before_write = None

    def records(self):
        return copy.deepcopy(self.rows)

    def write(self, operation, target, record_id=None):
        if self.before_write:
            self.before_write(operation, target)
        self.writes.append(operation)
        if operation == 'POST':
            self.rows.append(dict(target, id=str(len(self.rows) + 1)))
        else:
            next(row for row in self.rows if row['id'] == record_id).update(target)
        if self.lose:
            self.lose = False
            raise ValueError('dns_api_request_failed')


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.receipt = Path(self.tmp.name) / 'receipt.json'
        self.config = {'provider':'vultr', 'zone':'example.com', 'ttl':300, 'api_key_file':'unused'}
        self.desired = {'subscription':{'name':'sync','data':'192.0.2.1'},'vpn':{'name':'edge','data':'192.0.2.2'}}
        self.api = FakeAPI()
        patcher = patch.object(dns, 'API', return_value=self.api)
        patcher.start()
        self.addCleanup(patcher.stop)

    def execute(self):
        return dns.execute(self.config, self.desired, self.receipt)

    def test_create_repeat_patch_and_journal_precedes_write(self):
        def before(operation, target):
            pending = json.loads(self.receipt.read_text())['pending']
            self.assertEqual(pending['operation'], operation)
            self.assertEqual(pending['target'], target)
        self.api.before_write = before
        self.assertTrue(self.execute()['ready'])
        self.assertEqual(self.api.writes, ['POST','POST'])
        self.execute()
        self.assertEqual(len(self.api.writes), 2)
        self.desired['vpn']['data'] = '192.0.2.3'
        self.execute()
        self.assertEqual(self.api.writes[-1], 'PATCH')
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)

    def test_lost_post_reply_recovers_exact_target_without_duplicate(self):
        self.api.lose = True
        with self.assertRaises(ValueError): self.execute()
        self.assertIn('pending', json.loads(self.receipt.read_text()))
        self.assertTrue(self.execute()['ready'])
        self.assertEqual(self.api.writes, ['POST','POST'])

    def test_lost_patch_reply_recovers_and_partial_second_role(self):
        self.execute()
        self.desired['vpn']['data'] = '192.0.2.3'
        self.api.lose = True
        with self.assertRaises(ValueError): self.execute()
        self.assertTrue(self.execute()['ready'])
        self.assertEqual(self.api.writes, ['POST','POST','PATCH'])

    def test_foreign_duplicate_cname_and_owned_drift_fail(self):
        for rows in ([{'id':'x','type':'A','name':'sync','data':'192.0.2.1','ttl':300}],
                     [{'id':'x','type':'CNAME','name':'sync','data':'other.example.com','ttl':300}],
                     [{'id':str(i),'type':'A','name':'sync','data':'192.0.2.1','ttl':300} for i in range(2)]):
            self.api.rows = rows
            with self.assertRaises(ValueError): self.execute()
            self.assertFalse(self.api.writes)
        self.api.rows = []
        self.execute()
        self.api.rows[0]['data'] = '192.0.2.99'
        with self.assertRaisesRegex(ValueError,'drift'): self.execute()
        self.assertEqual(len(self.api.writes), 2)

    def test_definite_rejection_clears_pending_without_retry(self):
        with patch.object(self.api, 'write', side_effect=dns.RejectedWrite('dns_write_rejected')) as write:
            with self.assertRaises(dns.RejectedWrite): self.execute()
            self.assertEqual(write.call_count, 1)
        self.assertNotIn('pending', json.loads(self.receipt.read_text()))
        self.assertTrue(self.execute()['ready'])

    def test_pending_conflict_or_absence_never_blindly_reposts(self):
        self.api.lose = True
        with self.assertRaises(ValueError): self.execute()
        self.api.rows = []
        with self.assertRaisesRegex(ValueError,'unconfirmed'): self.execute()
        self.assertEqual(self.api.writes, ['POST'])

    def test_public_policy_rejects_apex_or_invalid_role(self):
        self.desired['vpn']['name'] = '@'
        with self.assertRaises(ValueError): self.execute()
        self.assertFalse(self.api.writes)


class PropagationTests(unittest.TestCase):
    def test_wait_checks_recursive_and_each_authoritative_server(self):
        import subprocess
        config={'zone':'example.com'}
        desired={'subscription':{'name':'sync','data':'192.0.2.1'},'vpn':{'name':'edge','data':'192.0.2.1'}}
        queries=[]
        def run(args,**kwargs):
            queries.append(args)
            return subprocess.CompletedProcess(args,0,stdout='ns1.vultr.com.\nns2.vultr.com.\n' if args[-1]=='NS' else '192.0.2.1\n')
        with patch('subprocess.run',side_effect=run):dns.wait_ready(config,desired,timeout=2)
        self.assertEqual(len(queries),7)
        self.assertEqual(sum('@ns1.vultr.com' in args for args in queries),2)
        self.assertEqual(sum('@ns2.vultr.com' in args for args in queries),2)


class HTTPTests(unittest.TestCase):
    def test_get_retries_are_capped_and_mutations_never_retry(self):
        api = object.__new__(dns.API)
        api.path = '/v2/domains/example.com/records'
        api.token = 'secret-fixture-token'
        from unittest.mock import Mock
        api.opener = Mock()
        api.opener.open.side_effect = dns.urllib.error.HTTPError('private-url', 503, 'secret-fixture-token', {}, None)
        with patch.object(dns.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, '^dns_api_request_failed$'):
                api.request('GET', dns.ORIGIN + api.path)
        self.assertEqual(api.opener.open.call_count, 3)
        api.opener.reset_mock()
        with self.assertRaisesRegex(ValueError, '^dns_api_request_failed$'):
            api.request('POST', dns.ORIGIN + api.path, {'type':'A'})
        self.assertEqual(api.opener.open.call_count, 1)

    def test_record_names_normalize_relative_and_fqdn(self):
        api = object.__new__(dns.API)
        api.path = '/v2/domains/example.com/records'
        rows = [{'name':'sync'}, {'name':'edge.example.com.'}, {'name':'example.com'}]
        with patch.object(api, 'request', return_value={'records':rows}):
            self.assertEqual([row['name'] for row in api.records()], ['sync','edge',''])
        with patch.object(api, 'request', return_value={'records':[{'name':'_acme-challenge.foo'},{'name':'x.y'},{'name':'edge.foreign.test'}]}):
            self.assertEqual([row['name'] for row in api.records()], ['_acme-challenge.foo','x.y','edge.foreign.test'])

    def test_pagination_url_is_not_followed_off_provider(self):
        api = object.__new__(dns.API)
        api.path = '/v2/domains/example.com/records'
        with patch.object(api,'request',return_value={'records':[], 'meta':{'links':{'next':'https://evil.example/steal'}}}) as request:
            with self.assertRaisesRegex(ValueError,'pagination'): api.records()
            self.assertEqual(request.call_count,1)

    def test_api_url_rejected_before_authorization_can_leave(self):
        api = object.__new__(dns.API)
        api.path = '/v2/domains/example.com/records'
        with self.assertRaisesRegex(ValueError,'untrusted'): api.request('GET','https://api.vultr.com.evil.example/path')
        self.assertIsNone(dns.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.example'))


if __name__ == '__main__': unittest.main()
