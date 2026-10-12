import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch
import monitor

class MonitorTests(unittest.TestCase):
    def test_same_provider_generation_is_not_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / 'status.json'
            status.write_text(json.dumps({'snapshot_at':100}))
            config={'mode':'primary','bridge_url':'https://bridge.invalid','payload_url':'https://payload.invalid','probe_socks':'127.0.0.1:10818','backup_status':str(status),'backup_independent':False}
            with patch.object(monitor,'curl',return_value=True):
                results=monitor.checks(config,150)
                self.assertTrue(results['backup_generation'])
                self.assertNotIn('independent_backup',results)
                self.assertFalse(monitor.checks(config,401)['backup_generation'])
    def test_no_startup_healthy_noise_and_two_observations(self):
        state={}
        monitor.transition(state,{'vpn':True},1,'US')
        monitor.transition(state,{'vpn':True},2,'US')
        self.assertFalse(state.get('queue'))
        monitor.transition(state,{'vpn':False},3,'US')
        self.assertTrue(state['checks']['vpn'])
        monitor.transition(state,{'vpn':False},4,'US')
        self.assertFalse(state['checks']['vpn']);self.assertEqual(len(state['queue']),1)
    def test_429_durable_retry_does_not_mark_sent(self):
        state={'queue':[{'text':'failure','attempts':0,'next_at':0}]}
        monitor.drain(state,'dummy','admin',100,lambda *_:('retry',120))
        self.assertEqual(len(state['queue']),1)
        self.assertGreaterEqual(state['queue'][0]['next_at'],220)
        self.assertNotIn('last_sent_at',state)
        monitor.drain(state,'dummy','admin',300,lambda *_:('sent',0))
        self.assertFalse(state['queue']);self.assertEqual(state['last_sent_at'],300)
    def test_recipient_block_does_not_stall_other_messages(self):
        state={'queue':[{'text':'a','attempts':0,'next_at':0},{'text':'b','attempts':0,'next_at':0}]}
        monitor.drain(state,'dummy','admin',100,lambda *_:('blocked',0))
        self.assertEqual(len(state['queue']),1);self.assertEqual(state['send_error'],'telegram_recipient_blocked')
    def test_full_queue_is_bounded(self):
        state={'checks':{'vpn':True},'queue':[{'text':'old','attempts':0,'next_at':0}]*monitor.MAX_EVENTS}
        monitor.transition(state,{'vpn':False},1,'US');monitor.transition(state,{'vpn':False},2,'US')
        self.assertEqual(len(state['queue']),monitor.MAX_EVENTS);self.assertIn('queue_overflow_at',state)
