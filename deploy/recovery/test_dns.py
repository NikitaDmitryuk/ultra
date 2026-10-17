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

    def delete_owned(self, owned):
        if owned not in self.rows:
            raise ValueError('dns_record_drift')
        self.writes.append('DELETE')
        self.rows.remove(owned)
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

    def test_backend_extension_preserves_public_records_and_recovers_lost_create(self):
        self.execute()
        before = copy.deepcopy(self.api.rows)
        self.desired['backend'] = {'name': 'core', 'data': '192.0.2.1'}
        self.api.lose = True
        with self.assertRaises(ValueError): self.execute()
        self.assertTrue(self.execute()['ready'])
        self.assertEqual(self.api.rows[:2], before)
        self.assertEqual(self.api.writes, ['POST', 'POST', 'POST'])
        self.execute()
        self.assertEqual(len(self.api.writes), 3)

    def test_legacy_public_policy_retains_and_verifies_owned_backend(self):
        self.desired['backend'] = {'name': 'core', 'data': '192.0.2.1'}
        self.execute()
        del self.desired['backend']
        self.assertTrue(self.execute()['ready'])
        self.assertEqual(len(self.api.writes), 3)
        self.api.rows[-1]['data'] = '192.0.2.99'
        with self.assertRaisesRegex(ValueError, 'record_drift'): self.execute()
        self.assertEqual(len(self.api.writes), 3)

    def test_backend_cannot_share_public_role_name(self):
        self.desired['backend'] = dict(self.desired['subscription'])
        with self.assertRaisesRegex(ValueError, 'duplicate_roles'): self.execute()
        self.assertFalse(self.api.writes)

    def test_public_policy_rejects_apex_or_invalid_role(self):
        self.desired['vpn']['name'] = '@'
        with self.assertRaises(ValueError): self.execute()
        self.assertFalse(self.api.writes)


class DNSMigrationTests(unittest.TestCase):
    def setUp(self):
        DNSTests.setUp(self)
        dns.execute(self.config, self.desired, self.receipt)
        self.old_bytes = self.receipt.read_bytes()
        self.old_rows = copy.deepcopy(self.api.rows)
        self.new = Path(self.tmp.name) / 'candidate.json'
        self.journal = Path(self.tmp.name) / 'migration.json'
        self.desired = {'subscription': {'name': 'newsync', 'data': '192.0.2.1'},
                        'vpn': {'name': 'newedge', 'data': '192.0.2.2'}}
        self.acceptance = 'a' * 64

    def call(self, action, acceptance=None):
        function = getattr(dns, action + '_migration')
        args = [self.config, self.desired, self.receipt, self.new, self.journal]
        if action in ('promote', 'retire'):
            args.append(self.acceptance if acceptance is None else acceptance)
        return function(*args)

    def test_prepare_preserves_old_receipt_and_records_promote_never_deletes(self):
        result = self.call('prepare')
        self.assertEqual(result['phase'], 'prepared')
        self.assertEqual(result['active_receipt'], str(self.receipt))
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)
        self.assertEqual(self.api.rows[:2], self.old_rows)
        self.call('prepare')
        self.assertEqual(self.api.writes, ['POST'] * 4)
        result = self.call('promote')
        self.assertEqual(result['active_receipt'], str(self.new))
        self.call('promote')
        self.assertEqual(self.api.writes, ['POST'] * 4)
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)

    def test_ambiguous_post_recovers_exact_target_without_duplicate(self):
        self.api.lose = True
        with self.assertRaisesRegex(ValueError, 'api_request_failed'):
            self.call('prepare')
        self.assertEqual(json.loads(self.journal.read_text())['phase'], 'preparing')
        self.assertIn('pending', json.loads(self.new.read_text()))
        self.call('prepare')
        self.assertEqual(self.api.writes, ['POST'] * 4)
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)

    def test_ambiguous_post_absence_never_reposts_or_claims_rollback(self):
        self.api.lose = True
        with self.assertRaises(ValueError):
            self.call('prepare')
        self.api.rows = self.api.rows[:2]
        for action in ('prepare', 'rollback'):
            with self.assertRaisesRegex(ValueError, 'pending_create_unconfirmed'):
                self.call(action)
        self.assertEqual(self.api.writes, ['POST'] * 3)

    def test_rollback_resolves_ambiguous_post_and_deletes_only_candidate(self):
        self.api.lose = True
        with self.assertRaises(ValueError):
            self.call('prepare')
        result = self.call('rollback')
        self.assertEqual(result['phase'], 'rolled_back')
        self.assertEqual(result['active_receipt'], str(self.receipt))
        self.assertEqual(self.api.rows, self.old_rows)
        self.assertEqual(self.api.writes, ['POST'] * 3 + ['DELETE'])
        self.call('rollback')
        self.call('prepare')
        self.assertEqual(self.api.writes, ['POST'] * 3 + ['DELETE'])

    def test_foreign_collision_or_old_drift_prevents_creation(self):
        foreign = dict(self.desired['subscription'], id='foreign', type='A', ttl=300)
        self.api.rows.append(foreign)
        with self.assertRaisesRegex(ValueError, 'foreign_record'):
            self.call('prepare')
        self.call('rollback')
        self.assertIn(foreign, self.api.rows)
        self.assertEqual(self.api.writes, ['POST'] * 2)
        self.journal.unlink()
        self.new.unlink()
        self.api.rows[0]['data'] = '192.0.2.99'
        with self.assertRaisesRegex(ValueError, 'record_drift'):
            self.call('prepare')
        self.assertEqual(self.api.writes, ['POST'] * 2)

    def test_retirement_requires_immutable_caller_acceptance(self):
        self.call('prepare')
        with self.assertRaisesRegex(ValueError, 'acceptance_mismatch'):
            self.call('retire')
        with self.assertRaisesRegex(ValueError, 'acceptance_required'):
            self.call('promote', '')
        self.call('promote')
        with self.assertRaisesRegex(ValueError, 'acceptance_mismatch'):
            self.call('retire', 'b' * 64)
        self.assertNotIn('DELETE', self.api.writes)

    def test_retire_and_lost_delete_reply_are_idempotent(self):
        self.call('prepare')
        self.call('promote')
        self.api.lose = True
        with self.assertRaisesRegex(ValueError, 'api_request_failed'):
            self.call('retire')
        state = json.loads(self.journal.read_text())
        self.assertEqual(state['phase'], 'retiring')
        self.assertEqual(state['pending_delete'], self.old_rows[0])
        self.assertEqual(self.call('retire')['phase'], 'retired')
        self.call('retire')
        self.call('promote')
        self.call('prepare')
        self.assertEqual(self.api.writes, ['POST'] * 4 + ['DELETE'] * 2)
        self.assertEqual({row['name'] for row in self.api.rows}, {'newsync', 'newedge'})
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)
        with self.assertRaisesRegex(ValueError, 'rollback_unavailable'):
            self.call('rollback')

    def test_rollback_lost_delete_reply_is_idempotent(self):
        self.call('prepare')
        self.call('promote')
        self.api.lose = True
        with self.assertRaises(ValueError):
            self.call('rollback')
        self.assertEqual(self.call('rollback')['phase'], 'rolled_back')
        self.call('rollback')
        self.assertEqual(self.api.rows, self.old_rows)
        self.assertEqual(self.api.writes, ['POST'] * 4 + ['DELETE'] * 2)

    def test_ambiguous_uncommitted_delete_retries_only_the_exact_owned_id(self):
        self.call('prepare')
        self.call('promote')
        with patch.object(self.api, 'delete_owned', side_effect=ValueError('dns_api_request_failed')):
            with self.assertRaises(ValueError):
                self.call('retire')
        self.assertEqual(self.api.rows[:2], self.old_rows)
        self.assertEqual(self.call('retire')['phase'], 'retired')
        self.assertEqual(self.api.writes, ['POST'] * 4 + ['DELETE'] * 2)

    def test_partial_rollback_journal_cannot_be_promoted_after_interruption(self):
        self.api.lose = True
        with self.assertRaises(ValueError):
            self.call('prepare')
        with patch.object(self.api, 'delete_owned', side_effect=ValueError('dns_api_request_failed')):
            with self.assertRaises(ValueError):
                self.call('rollback')
        self.assertEqual(json.loads(self.journal.read_text())['phase'], 'rolling_back')
        with self.assertRaisesRegex(ValueError, 'acceptance_mismatch'):
            self.call('promote')
        self.assertEqual(self.call('rollback')['phase'], 'rolled_back')
        self.assertEqual(self.api.rows, self.old_rows)

    def test_preparing_candidate_cannot_discard_shared_backend(self):
        old_desired = {'subscription': {'name': 'sync', 'data': '192.0.2.1'},
                       'vpn': {'name': 'edge', 'data': '192.0.2.2'},
                       'backend': {'name': 'core', 'data': '192.0.2.1'}}
        dns.execute(self.config, old_desired, self.receipt)
        self.api.lose = True
        with self.assertRaises(ValueError):
            self.call('prepare')
        state = json.loads(self.new.read_text())
        state['records'].pop('backend')
        dns.save(self.new, state)
        with self.assertRaisesRegex(ValueError, 'candidate_changed'):
            self.call('prepare')
        self.assertNotIn('DELETE', self.api.writes)

    def test_shared_public_and_backend_ids_survive_retirement(self):
        # Existing callers can extend the live receipt with a backend.
        old_desired = {'subscription': {'name': 'sync', 'data': '192.0.2.1'},
                       'vpn': {'name': 'edge', 'data': '192.0.2.2'},
                       'backend': {'name': 'core', 'data': '192.0.2.1'}}
        dns.execute(self.config, old_desired, self.receipt)
        self.old_bytes = self.receipt.read_bytes()
        self.desired['subscription'] = old_desired['subscription']
        foreign = {'id': 'foreign', 'type': 'TXT', 'name': 'other', 'data': 'untouched', 'ttl': 300}
        self.api.rows.append(foreign)
        self.call('prepare')
        self.call('promote')
        self.call('retire')
        self.assertEqual({row['name'] for row in self.api.rows}, {'sync', 'newedge', 'core', 'other'})
        self.assertIn(foreign, self.api.rows)
        self.assertEqual(self.api.writes.count('DELETE'), 1)
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)

    def test_backend_change_is_prepared_promoted_then_old_owned_backend_retired(self):
        old_desired = {'subscription': {'name': 'sync', 'data': '192.0.2.1'},
                       'vpn': {'name': 'edge', 'data': '192.0.2.2'},
                       'backend': {'name': 'bot-old', 'data': '192.0.2.3'}}
        dns.execute(self.config, old_desired, self.receipt)
        self.old_bytes = self.receipt.read_bytes()
        self.desired['subscription'] = old_desired['subscription']
        self.desired['vpn'] = old_desired['vpn']
        self.desired['backend'] = {'name': 'bot-new', 'data': '192.0.2.4'}
        foreign = {'id': 'foreign', 'type': 'TXT', 'name': 'untouched', 'data': 'value', 'ttl': 300}
        self.api.rows.append(foreign)
        self.call('prepare')
        candidate = json.loads(self.new.read_text())
        self.assertEqual(candidate['records']['backend']['name'], 'bot-new')
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)
        self.assertIn(old_desired['backend'] | {'id': '3', 'type': 'A', 'ttl': 300}, self.api.rows)
        self.call('promote')
        self.assertIn('bot-old', {row['name'] for row in self.api.rows})
        self.assertEqual(self.call('retire')['phase'], 'retired')
        self.assertEqual({row['name'] for row in self.api.rows if row['type'] == 'A'},
                         {'sync', 'edge', 'bot-new'})
        self.assertIn(foreign, self.api.rows)
        self.assertEqual(self.api.writes.count('DELETE'), 1)
        self.assertEqual(self.receipt.read_bytes(), self.old_bytes)

    def test_explicit_backend_removal_retires_only_old_backend_and_omission_preserves(self):
        old_desired = {'subscription': {'name': 'sync', 'data': '192.0.2.1'},
                       'vpn': {'name': 'edge', 'data': '192.0.2.2'},
                       'backend': {'name': 'bot-old', 'data': '192.0.2.3'}}
        dns.execute(self.config, old_desired, self.receipt)
        self.old_bytes = self.receipt.read_bytes()
        self.desired['subscription'] = old_desired['subscription']
        self.desired['vpn'] = old_desired['vpn']
        # Omitting backend retains the exact existing owned record in the candidate.
        self.call('prepare')
        self.assertEqual(json.loads(self.new.read_text())['records']['backend']['name'], 'bot-old')
        self.call('rollback')
        self.new.unlink()
        self.journal.unlink()
        self.desired['backend'] = None
        self.call('prepare')
        self.assertNotIn('backend', json.loads(self.new.read_text())['records'])
        self.call('promote')
        self.call('retire')
        self.assertEqual({row['name'] for row in self.api.rows if row['type'] == 'A'},
                         {'sync', 'edge'})
        self.assertEqual(self.api.writes.count('DELETE'), 1)

    def test_backend_target_cannot_collide_with_public_name(self):
        self.desired['backend'] = {'name': 'newsync', 'data': '192.0.2.4'}
        with self.assertRaisesRegex(ValueError, 'duplicate_roles'):
            self.call('prepare')
        self.assertEqual(self.api.writes, ['POST', 'POST'])

    def test_candidate_or_old_record_drift_never_authorizes_delete(self):
        self.call('prepare')
        self.call('promote')
        for candidate in (False, True):
            with self.subTest(candidate=candidate):
                row = next(row for row in self.api.rows if row['name'] == ('newsync' if candidate else 'sync'))
                row['data'] = '192.0.2.99'
                with self.assertRaisesRegex(ValueError, 'record_drift'):
                    self.call('retire')
                self.assertNotIn('DELETE', self.api.writes)
                row['data'] = '192.0.2.1'

    def test_same_name_update_and_zone_change_require_migration(self):
        self.desired['subscription'] = {'name': 'sync', 'data': '192.0.2.99'}
        with self.assertRaisesRegex(ValueError, 'migration_requires_new_names'):
            self.call('prepare')
        self.config['zone'] = 'example.net'
        with patch.object(self.api, 'records') as records:
            with self.assertRaisesRegex(ValueError, 'zone_change_requires_migration'):
                self.call('prepare')
            records.assert_not_called()
        self.assertEqual(self.api.writes, ['POST'] * 2)

    def test_pending_policy_or_candidate_receipt_changes_fail(self):
        self.call('prepare')
        self.desired['vpn']['name'] = 'different'
        with self.assertRaisesRegex(ValueError, 'migration_policy_changed'):
            self.call('prepare')
        self.desired['vpn']['name'] = 'newedge'
        state = json.loads(self.new.read_text())
        state['records']['vpn']['id'] = 'foreign'
        dns.save(self.new, state)
        with self.assertRaisesRegex(ValueError, 'migration_candidate_changed'):
            self.call('rollback')
        self.assertNotIn('DELETE', self.api.writes)


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
    def test_delete_owned_checks_exact_name_contents_and_id_before_request(self):
        api = object.__new__(dns.API)
        api.path = '/v2/domains/example.com/records'
        owned = {'id': 'owned-id', 'type': 'A', 'name': 'sync', 'data': '192.0.2.1', 'ttl': 300}
        with patch.object(api, 'records', return_value=[owned]), patch.object(api, 'request') as request:
            api.delete_owned(owned)
            request.assert_called_once_with('DELETE', dns.ORIGIN + api.path + '/owned-id')
        for drift in (dict(owned, id='foreign-id'), dict(owned, data='192.0.2.99'), dict(owned, name='renamed')):
            with patch.object(api, 'records', return_value=[drift]), patch.object(api, 'request') as request:
                with self.assertRaisesRegex(ValueError, 'record_drift'):
                    api.delete_owned(owned)
                request.assert_not_called()

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
        api.opener.reset_mock()
        with self.assertRaisesRegex(ValueError, '^dns_api_request_failed$'):
            api.request('DELETE', dns.ORIGIN + api.path + '/owned-id')
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
