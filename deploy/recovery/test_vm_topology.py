import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import vm_acceptance
import vm_topology


class PreservedTopology(unittest.TestCase):
    def setup_fixture(self, root):
        saved={'synthetic_only':True,'network_restrict':True,'isolation_verified_at':123,
               'nodes':{name:vm_topology.endpoint(index) for index,name in enumerate(vm_topology.NODES)},
               'identity':'synthetic-original','known_hosts':'synthetic-pins','created_at':111}
        (root/'topology.json').write_text(json.dumps(saved))
        for name in vm_topology.NODES:
            node=root/name;node.mkdir()
            (node/'disk.qcow2').write_bytes(b'preserved-disk')
            (node/'seed.img').write_bytes(b'preserved-seed')
        return saved

    def test_resume_preserves_disks_pins_and_creation_clock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);original=self.setup_fixture(root)
            with mock.patch.object(vm_acceptance,'owned_vm_pids',return_value=[]), mock.patch.object(vm_topology,'command'), mock.patch.object(vm_topology.subprocess,'Popen') as launch:
                launch.return_value.pid=345
                vm_topology.resume(argparse.Namespace(workspace=temporary,memory_mb=640))
            saved=json.loads((root/'topology.json').read_text())
            for name in ('identity','known_hosts','created_at','nodes'):
                self.assertEqual(saved[name],original[name])
            self.assertNotIn('isolation_verified_at',saved)
            for name in vm_topology.NODES:
                self.assertEqual((root/name/'disk.qcow2').read_bytes(),b'preserved-disk')
                self.assertEqual((root/name/'seed.img').read_bytes(),b'preserved-seed')
            guests=[call.args[0] for call in launch.call_args_list if call.args[0][0]=='qemu-system-x86_64']
            self.assertEqual(len(guests),4)
            self.assertTrue(all('restrict=on' in args[args.index('-netdev')+1] for args in guests))
            self.assertTrue(all(args[args.index('-m')+1]=='640' for args in guests))

    def test_running_disk_rejected_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.setup_fixture(root)
            before=(root/'topology.json').read_bytes()
            with mock.patch.object(vm_acceptance,'owned_vm_pids',side_effect=[[],[123]]), mock.patch.object(vm_topology,'command') as command, mock.patch.object(vm_topology.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ValueError,'still_running'):
                    vm_topology.resume(argparse.Namespace(workspace=temporary,memory_mb=640))
                command.assert_not_called();launch.assert_not_called()
            self.assertEqual((root/'topology.json').read_bytes(),before)

    def test_missing_disk_rejected_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.setup_fixture(root)
            (root/'replacement'/'disk.qcow2').unlink()
            with mock.patch.object(vm_acceptance,'owned_vm_pids',return_value=[]), mock.patch.object(vm_topology.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ValueError,'preserved_synthetic_disks'):
                    vm_topology.resume(argparse.Namespace(workspace=temporary,memory_mb=640))
                launch.assert_not_called()

    def test_recorded_memory_cannot_be_changed_on_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);saved=self.setup_fixture(root);saved['memory_mb']=640
            (root/'topology.json').write_text(json.dumps(saved))
            with mock.patch.object(vm_topology.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ValueError,'memory_change_forbidden'):
                    vm_topology.resume(argparse.Namespace(workspace=temporary,memory_mb=1024))
                launch.assert_not_called()

    def test_old_receipt_requires_original_memory_explicitly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.setup_fixture(root)
            with mock.patch.object(vm_topology.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ValueError,'original_synthetic_memory'):
                    vm_topology.resume(argparse.Namespace(workspace=temporary,memory_mb=None))
                launch.assert_not_called()
