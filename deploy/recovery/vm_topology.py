#!/usr/bin/env python3
"""Synthetic QEMU acceptance topology; run inside a dedicated disposable container.

Creates six independent Ubuntu systemd guests and pinned SSH endpoints. It never
loads operator recovery keys, production bundles, or production configuration.
The base must be an official Ubuntu 24.04 cloud image. All guest networking uses
QEMU restrict=on and explicit forwards to this container's loopback listeners.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

NODES = ('bridge', 'nl', 'us', 'replacement', 'database', 'database_restore')
PORTS = (22, 80, 443, 8444, 24443, 15432, 8443, 18080)


def command(args, data=None, timeout=120):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise ValueError('topology_command_failed:' + Path(args[0]).name)
    return result.stdout


def endpoint(index):
    return '198.18.0.' + str(10 + index)


def forwarded(index, port):
    return 22000 + index * 100 + PORTS.index(port)


def topology_arguments(index):
    # Every VM sees the same synthetic public IPs; TCP streams reach only the
    # corresponding VM's host-forwarded endpoint, never the Internet.
    options = ['user,id=net0,net=198.18.0.0/24,host=198.18.0.2,dhcpstart=198.18.0.100,restrict=on',
               'guestfwd=tcp:198.18.0.4:3128-cmd:socat STDIO TCP:127.0.0.1:3128',
               'guestfwd=tcp:198.18.0.20:443-cmd:socat STDIO TCP:127.0.0.1:' + str(18443 + index)]
    for port in PORTS:
        options.append('hostfwd=tcp:127.0.0.1:' + str(forwarded(index, port)) + '-:' + str(port))
    for peer in range(len(NODES)):
        for port in PORTS:
            options.append('guestfwd=tcp:' + endpoint(peer) + ':' + str(port) + '-cmd:socat STDIO TCP:127.0.0.1:' + str(forwarded(peer, port)))
    return ','.join(options)


def generate_seed(directory, index, public_key):
    name = NODES[index]
    node = directory / name
    node.mkdir(mode=0o700)
    key = node / 'ssh_host_ed25519_key'
    command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    # These credentials are newly generated fixture credentials, unrelated to
    # the operator identity or any real deployed node.
    hosts = '127.0.0.1 localhost\n' + '\n'.join(endpoint(i) + ' ' + n for i, n in enumerate(NODES)) + '\n198.18.0.11 vpn.fixture.test\n'
    data = {'ssh_pwauth': False, 'disable_root': False, 'ssh_authorized_keys': [public_key],
            'users': [{'name': 'root', 'ssh_authorized_keys': [public_key]}],
            'ssh_keys': {'ed25519_private': key.read_text(), 'ed25519_public': key.with_suffix('.pub').read_text()},
            'write_files': [{'path': '/etc/hosts', 'content': hosts},
                            {'path': '/etc/environment', 'content': 'http_proxy=http://198.18.0.4:3128\nhttps_proxy=http://198.18.0.4:3128\nHTTP_PROXY=http://198.18.0.4:3128\nHTTPS_PROXY=http://198.18.0.4:3128\nno_proxy=localhost,127.0.0.1,198.18.0.0/24,vpn.fixture.test\n'},
                            {'path': '/etc/apt/apt.conf.d/99-fixture-download-proxy', 'content': 'Acquire::http::Proxy "http://198.18.0.4:3128";\nAcquire::https::Proxy "http://198.18.0.4:3128";\n'},
                            {'path': '/etc/ssh/sshd_config.d/99-fixture.conf', 'content': 'PermitRootLogin prohibit-password\nPasswordAuthentication no\n'}],
            'runcmd': [['systemctl', 'restart', 'ssh']]}
    (node / 'user-data').write_text('#cloud-config\n' + json.dumps(data))
    (node / 'meta-data').write_text(json.dumps({'instance-id': 'ultra-synthetic-' + name, 'local-hostname': name}))
    command(['cloud-localds', str(node / 'seed.img'), str(node / 'user-data'), str(node / 'meta-data')])
    return key.with_suffix('.pub').read_text().strip()


def create(args):
    os.umask(0o077)
    directory = Path(args.workspace).resolve()
    if directory.exists():
        raise ValueError('new_topology_workspace_required')
    directory.mkdir(parents=True, mode=0o700)
    base = Path(args.base_image).resolve()
    if not base.is_file():
        raise ValueError('official_ubuntu_cloud_image_required')
    key = directory / 'synthetic_operator_key'
    command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    public = key.with_suffix('.pub').read_text().strip()
    pins = []
    processes = []
    qemu_pids = {}
    memory_mb=args.memory_mb or 1024
    for index, name in enumerate(NODES):
        host_key = generate_seed(directory, index, public)
        pins.append(endpoint(index) + ' ' + host_key)
        node = directory / name
        command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(node / 'disk.qcow2'), '12G'])
        # Dedicated container owns these loopback aliases. No host network mode.
        command(['ip', 'address', 'add', endpoint(index) + '/32', 'dev', 'lo'])
        for port in PORTS:
            log = (node / ('forward-' + str(port) + '.log')).open('wb')
            process = subprocess.Popen(['socat', 'TCP-LISTEN:' + str(port) + ',bind=' + endpoint(index) + ',reuseaddr,fork',
                                        'TCP:127.0.0.1:' + str(forwarded(index, port))], stdout=log, stderr=log)
            processes.append(process.pid); log.close()
        log = (node / 'qemu.log').open('wb')
        process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'tcg,tb-size=32', '-cpu', 'max', '-m', str(memory_mb),
                                    '-smp', '2', '-nographic', '-monitor', 'none', '-serial', 'file:' + str(node / 'serial.log'),
                                    '-drive', 'file=' + str(node / 'disk.qcow2') + ',if=virtio,format=qcow2',
                                    '-drive', 'file=' + str(node / 'seed.img') + ',if=virtio,format=raw,readonly=on',
                                    '-netdev', topology_arguments(index), '-device', 'virtio-net-pci,netdev=net0'], stdout=log, stderr=log)
        processes.append(process.pid);qemu_pids[name] = process.pid;log.close()
    (directory / 'known_hosts').write_text('\n'.join(pins) + '\n')
    receipt = {'synthetic_only': True, 'network_restrict': True, 'nodes': {name: endpoint(i) for i, name in enumerate(NODES)},
               'processes': processes, 'qemu_pids': qemu_pids, 'base_image': str(base), 'created_at': int(time.time()),
               'identity': str(key), 'known_hosts': str(directory / 'known_hosts'), 'memory_mb':memory_mb}
    (directory / 'topology.json').write_text(json.dumps(receipt))
    print(json.dumps({'topology_created': True, 'nodes': receipt['nodes'], 'network_restrict': True}))


def verify(args):
    directory = Path(args.workspace).resolve()
    saved = json.loads((directory / 'topology.json').read_text())
    deadline = time.monotonic() + 600
    for name, address in saved['nodes'].items():
        while True:
            try:
                output = command(['ssh', '-F', '/dev/null', '-i', saved['identity'], '-o', 'BatchMode=yes',
                                  '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + saved['known_hosts'],
                                  '-o', 'ConnectTimeout=3', 'root@' + address,
                                  "python3 -c " + shlex.quote("import socket,json; s=socket.socket(); s.settimeout(2); result=s.connect_ex(('9.9.9.9',443)); print(json.dumps({'external_blocked':result!=0}))")], timeout=10)
                if json.loads(output)['external_blocked'] is not True:
                    raise ValueError('external_egress_available')
                break
            except (ValueError, subprocess.SubprocessError):
                if time.monotonic() >= deadline:
                    raise ValueError('guest_readiness_or_isolation_failed:' + name)
                time.sleep(3)
    saved['isolation_verified_at'] = int(time.time())
    (directory / 'topology.json').write_text(json.dumps(saved))
    print(json.dumps({'all_guests_ready': True, 'external_tcp_blocked': True}))


def resume(args):
    """Restart a stopped fixture without regenerating disks, pins or credentials."""
    from vm_acceptance import owned_vm_pids
    directory=Path(args.workspace).resolve()
    saved=json.loads((directory/'topology.json').read_text())
    expected={name:endpoint(index) for index,name in enumerate(NODES)}
    if (not saved.get('synthetic_only') or not saved.get('network_restrict')
            or saved.get('nodes')!=expected):
        raise ValueError('isolated_synthetic_topology_required')
    memory_mb=saved.get('memory_mb') or args.memory_mb
    if not isinstance(memory_mb,int) or memory_mb<256:
        raise ValueError('original_synthetic_memory_required')
    if saved.get('memory_mb') and args.memory_mb and args.memory_mb!=memory_mb:
        raise ValueError('synthetic_memory_change_forbidden')
    # Validate all disks before starting any process. A partial/live topology
    # requires inspection rather than starting duplicate guests or forwards.
    for name in NODES:
        node=directory/name
        if not all((node/file).is_file() for file in ('disk.qcow2','seed.img')):
            raise ValueError('preserved_synthetic_disks_required')
        if owned_vm_pids(node/'disk.qcow2'):
            raise ValueError('synthetic_topology_still_running')
    processes=[];pids={}
    for index,name in enumerate(NODES):
        node=directory/name
        command(['ip','address','replace',endpoint(index)+'/32','dev','lo'])
        for port in PORTS:
            with (node/('forward-'+str(port)+'.log')).open('ab') as log:
                process=subprocess.Popen(['socat','TCP-LISTEN:'+str(port)+',bind='+endpoint(index)+',reuseaddr,fork',
                    'TCP:127.0.0.1:'+str(forwarded(index,port))],stdout=log,stderr=log)
                processes.append(process.pid)
        with (node/'qemu.log').open('ab') as log:
            process=subprocess.Popen(['qemu-system-x86_64','-accel','tcg,tb-size=32','-cpu','max','-m',str(memory_mb),
                '-smp','2','-nographic','-monitor','none','-chardev','file,id=fixture-serial,path='+str(node/'serial.log')+',append=on','-serial','chardev:fixture-serial',
                '-drive','file='+str(node/'disk.qcow2')+',if=virtio,format=qcow2',
                '-drive','file='+str(node/'seed.img')+',if=virtio,format=raw,readonly=on',
                '-netdev',topology_arguments(index),'-device','virtio-net-pci,netdev=net0'],stdout=log,stderr=log)
            processes.append(process.pid);pids[name]=process.pid
    saved.update(processes=processes,qemu_pids=pids,last_resumed_at=int(time.time()),memory_mb=memory_mb)
    # Isolation must be measured again after a process restart.
    saved.pop('isolation_verified_at',None)
    (directory/'topology.json').write_text(json.dumps(saved))
    print(json.dumps({'topology_resumed':True,'nodes':expected,'network_restrict':True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('create', 'verify', 'resume'))
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--base-image')
    parser.add_argument('--memory-mb', type=int, help='creation defaults to 1024; resume preserves recorded size or requires original size')
    args = parser.parse_args()
    {'create':create,'verify':verify,'resume':resume}[args.action](args)


if __name__ == '__main__':
    main()
