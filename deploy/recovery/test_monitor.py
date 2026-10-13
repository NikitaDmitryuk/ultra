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

class ServiceMonitorTests(unittest.TestCase):
    def test_missing_heartbeat_is_not_a_telegram_delivery_failure(self):
        import subprocess
        config={'mode':'peer','peer_host':'root@192.0.2.1'}
        with patch.object(monitor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 255, stdout=b'')):
            results=monitor.checks(config,150)
        self.assertFalse(results['us_monitor'])
        self.assertNotIn('us_notifications',results)

    def test_stale_heartbeat_is_not_a_telegram_delivery_failure(self):
        import subprocess
        config={'mode':'peer','peer_host':'root@192.0.2.1'}
        value=json.dumps({'updated_at':1,'send_error':'telegram_unavailable'}).encode()
        with patch.object(monitor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=value)):
            results=monitor.checks(config,150)
        self.assertFalse(results['us_monitor'])
        self.assertNotIn('us_notifications',results)

    def test_mode_change_clears_old_health_and_preserves_send_queue(self):
        import time
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            state=root/'state.json'
            state.write_text(json.dumps({'mode':'primary','checks':{'vpn_payload':True},'streaks':{'vpn_payload':{'ok':True,'count':2}},'queue':[{'text':'old alarm','next_at':time.time()+3600,'attempts':1}]}));state.chmod(0o600)
            token=root/'token';token.write_text('123:fixture');token.chmod(0o600)
            with patch.object(monitor,'checks',return_value={'us_monitor':True,'us_notifications':True}):
                monitor.cycle({'mode':'peer','node':'peer','token_file':str(token),'chat_id':'fixture'},root)
            saved=json.loads(state.read_text())
            self.assertNotIn('vpn_payload',saved['checks'])
            self.assertNotIn('vpn_payload',saved['streaks'])
            self.assertEqual(saved['queue'][0]['text'],'old alarm')
            self.assertEqual(saved['mode'],'peer')

    def test_probe_has_small_response_bound_and_no_redirect(self):
        import subprocess
        with patch.object(monitor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as call:
            self.assertTrue(monitor.curl('https://probe.example/health','127.0.0.1:10818'))
        args=call.call_args.args[0]
        self.assertEqual(args[args.index('--max-filesize')+1], '16384')
        self.assertNotIn('--location', args)
    def test_quota_is_distinct_from_payload_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            status=Path(directory)/'status.json'
            status.write_text(json.dumps({'snapshot_at':100}))
            config={'mode':'primary','bridge_url':'https://bridge.invalid','payload_url':'https://payload.invalid','probe_socks':'127.0.0.1:10818','backup_status':str(status),'service_quota_available':False}
            with patch.object(monitor,'curl',return_value=True):
                result=monitor.checks(config,110)
            self.assertTrue(result['vpn_payload'])
            self.assertFalse(result['monitor_quota_available'])
