import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vm_deployment_repair_acceptance as repair


class DeploymentRepairTests(unittest.TestCase):
    def topology(self, root):
        for name in ('synthetic_operator_key','known_hosts'):
            path=root/name;path.write_bytes(b'fixture-only');path.chmod(0o600)
        value={'synthetic_only':True,'network_restrict':True,'isolation_verified_at':1,
            'nodes':{name:repair.endpoint(i) for i,name in enumerate(repair.NODES)},
            'identity':str(root/'synthetic_operator_key'),'known_hosts':str(root/'known_hosts'),'base_image':'/image/base.img'}
        (root/'topology.json').write_text(json.dumps(value))
        return value

    def release(self, root):
        assets=[]
        for i in range(14):
            name='ultra-install-linux-amd64' if not i else 'fixture-'+str(i)
            raw=('fixture'+str(i)).encode();(root/name).write_bytes(raw)
            assets.append({'name':name,'size':len(raw),'sha256':repair.sha(raw)})
        commit='4'*40
        value={'source_commit':commit,'version':'v0.0.'+str(int(commit,16)),'assets':assets}
        (root/'release-manifest.json').write_text(json.dumps(value))
        return value

    def test_topology_rejects_public_endpoint_or_user_identity_before_ssh(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);value=self.topology(root)
            self.assertTrue(repair.checked_topology(root)['fixture_binding'])
            for change in ({'network_restrict':False},{'identity':'/home/user/.ssh/id_ed25519'},
                           {'nodes':dict(value['nodes'],database='192.0.2.1')}):
                (root/'topology.json').write_text(json.dumps(dict(value,**change)))
                with self.subTest(change=change),self.assertRaises(ValueError):repair.checked_topology(root)

    def test_release_verifies_all_fourteen_actual_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.release(root)
            repair.checked_release(root)
            (root/'fixture-13').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'baseline_asset_changed'):repair.checked_release(root)

    def test_baseline_plan_is_one_static_ca_exit_with_isolated_managed_dns(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);topology=self.topology(root);release=self.release(root)
            plan=repair.baseline_plan(topology,release,root,'age1fixture',root/'fixture-runtime.env',root/'fixture-cloud')
            self.assertEqual(len(plan['exits']),1)
            self.assertEqual(plan['database']['primary_host'],topology['nodes']['database'])
            self.assertEqual(plan['bridge']['address'],topology['nodes']['bridge'])
            self.assertEqual(plan['automation']['dns']['zone'],'fixture.test')
            self.assertEqual(plan['features']['main_exit_domain'],'exit.fixture.test')
            self.assertNotIn('forward_host',plan['automation']['ingress'])
            self.assertEqual({row['provider'] for row in plan['automation']['static_nodes']},{'fixture-b'})
            self.assertNotEqual(plan['automation']['bridge_provider'],plan['automation']['static_nodes'][0]['provider'])

    def test_interrupted_mutating_phase_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);topology=root/'topology';topology.mkdir();release=root/'release';release.mkdir()
            self.topology(topology);self.release(release)
            driver=repair.Driver(root/'driver',topology,release)
            with self.assertRaises(RuntimeError):driver.phase('baseline_apply',lambda:(_ for _ in ()).throw(RuntimeError()))
            called=[]
            with self.assertRaisesRegex(ValueError,'interrupted_phase_requires_observation'):
                driver.phase('baseline_apply',lambda:called.append('redispatch'))
            self.assertEqual(called,[])

    def test_fixture_inputs_retry_is_closed_after_any_apply_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);topology=root/'topology';topology.mkdir();release=root/'release';release.mkdir()
            self.topology(topology);self.release(release)
            driver=repair.Driver(root/'driver',topology,release)
            fail=lambda:(_ for _ in ()).throw(RuntimeError())
            with self.assertRaises(RuntimeError):driver.phase('baseline_inputs',fail,fixture_replay=True)
            with self.assertRaises(RuntimeError):driver.phase('baseline_inputs',fail,fixture_replay=True)
            with self.assertRaises(RuntimeError):driver.phase('baseline_apply',fail)
            called=[]
            with self.assertRaisesRegex(ValueError,'interrupted_phase_requires_observation'):
                driver.phase('baseline_inputs',lambda:called.append('changed'),fixture_replay=True)
            self.assertEqual(called,[])

    def test_primary_checkpoint_uses_only_readonly_query_on_dedicated_primary(self):
        with tempfile.TemporaryDirectory() as temporary:
            topology=self.topology(Path(temporary))
            value={'primary':True,'system_identifier':'fixture','migration_versions':'1,2',
                'routes':[{'address':topology['nodes']['nl'],'tunnel_uuid':'fixture','pin':None}]}
            with patch.object(repair,'ssh',return_value=json.dumps(value).encode()) as ssh:
                self.assertEqual(repair.primary_identity(topology),value)
            self.assertEqual(ssh.call_args.args[1],topology['nodes']['database'])
            query=ssh.call_args.args[2][-1]
            self.assertTrue(query.startswith('BEGIN READ ONLY;'))
            self.assertTrue(query.rstrip().endswith('ROLLBACK;'))
            self.assertNotIn('INSERT ',query)
            self.assertNotIn('UPDATE ',query)


if __name__=='__main__':unittest.main()
