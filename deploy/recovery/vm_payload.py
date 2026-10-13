#!/usr/bin/env python3
"""Five-account payload and emergency journal proof on a synthetic restored VM."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, '/opt/ultra-recovery')
from restore_host import unit_environment, sql, database_spec, literal


def run(args, data=None, timeout=90):
    result=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if result.returncode:raise ValueError('synthetic_payload_command_failed')
    return result.stdout


def api(path, value=None):
    _,env=unit_environment('ultra-relay.service')
    request=urllib.request.Request('http://127.0.0.1:8443'+path,data=None if value is None else json.dumps(value).encode(),headers={'Authorization':'Bearer '+env['ULTRA_RELAY_ADMIN_TOKEN'],'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)


def ready(mode):
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        try:
            state=api('/v1/hardening')['runtime']
            if state['mode']==mode and state['revision']==state['applied_revision'] and not state.get('error'):return state
        except (OSError,ValueError,KeyError):pass
        time.sleep(2)
    raise ValueError('synthetic_runtime_not_ready')


def database():
    return database_spec(json.loads(Path('/etc/ultra-relay/spec.json').read_text()))[0]


def seed():
    if not Path('/etc/ultra-fixture-marker').is_file():raise ValueError('synthetic_target_required')
    name=database()
    for index in range(5):
        label='acceptance-fixture-'+str(index)
        if sql('SELECT count(*) FROM users WHERE name='+literal(label),name)=='0':api('/v1/users',{'name':label,'kind':'vless'})
    if sql("SELECT count(*)=2 AND bool_and(b.source='manual' AND b.monthly_bytes=107374182400 AND b.is_fallback=(n.address='198.18.0.11')) FROM exit_nodes n JOIN exit_traffic_budgets b ON b.exit_id=n.id WHERE n.enabled",name)!='t':
        raise ValueError('installer_static_budgets_missing')
    run(['systemctl','restart','ultra-relay'])
    ready('online')
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        if int(sql("SELECT count(DISTINCT u.uuid) FROM users u JOIN user_exit_quotas q ON q.user_uuid=u.uuid WHERE u.name LIKE 'acceptance-fixture-%' AND NOT q.blocked AND q.limit_bytes>1048576",name))==5:return {'five_ordinary_accounts_ready':True}
        time.sleep(3)
    raise ValueError('synthetic_quotas_not_ready')


def receive(channel,count):
    result=b''
    while len(result)<count:
        part=channel.recv(count-len(result))
        if not part:raise ValueError('truncated_socks_response')
        result+=part
    return result


def udp(port):
    with socket.create_connection(('127.0.0.1',port),timeout=10) as control:
        control.sendall(b'\x05\x01\x00')
        if receive(control,2)!=b'\x05\x00':raise ValueError('socks_greeting')
        control.sendall(b'\x05\x03\x00\x01'+b'\x00'*6)
        head=receive(control,4)
        if head!=b'\x05\x00\x00\x01':raise ValueError('socks_udp_associate')
        address=receive(control,6);target=(socket.inet_ntoa(address[:4]),struct.unpack('!H',address[4:])[0])
        payload=b'ultra-synthetic-acceptance-udp'
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as channel:
            channel.settimeout(15)
            channel.sendto(b'\x00\x00\x00\x01'+socket.inet_aton('8.8.8.8')+struct.pack('!H',19444)+payload,target)
            if channel.recv(65535)[10:]!=payload:raise ValueError('udp_payload_mismatch')


def payload(port, expected_egress=None, timeout_seconds=90):
    until=time.monotonic()+timeout_seconds
    while True:
        try:
            data=run(['env','-u','http_proxy','-u','https_proxy','-u','HTTP_PROXY','-u','HTTPS_PROXY','-u','ALL_PROXY','curl','--fail','--silent','--max-time','15','--socks5-hostname','127.0.0.1:'+str(port),'--noproxy','','https://8.8.8.8:19443/payload'])
            if data!=b'x'*65536:raise ValueError('tcp_payload_mismatch')
            udp(port)
            if expected_egress:
                trace=run(['env','-u','http_proxy','-u','https_proxy','-u','HTTP_PROXY','-u','HTTPS_PROXY','-u','ALL_PROXY','curl','--fail','--silent','--max-time','15','--socks5-hostname','127.0.0.1:'+str(port),'--noproxy','','https://www.cloudflare.com/cdn-cgi/trace']).decode()
                if 'ip='+expected_egress not in trace.splitlines():raise ValueError('unexpected_failover_egress')
            return
        except (ValueError,OSError):
            if time.monotonic()>=until:raise
            time.sleep(2)


def clients():
    users=json.loads(sql("SELECT json_agg(uuid ORDER BY name) FROM users WHERE name LIKE 'acceptance-fixture-%' AND is_active",database()))
    if len(users)!=5:raise ValueError('five_fixture_accounts_required')
    root=Path('/var/lib/ultra-acceptance');root.mkdir(mode=0o700,exist_ok=True)
    processes=[]
    for index,uid in enumerate(users):
        profile=api('/v1/users/'+uid+'/client');file=root/('client-'+str(index)+'.json');file.write_text(json.dumps(profile));file.chmod(0o600)
        # Test the published TLS profile when installed, else the published REALITY profile.
        names=[entry['id'] for entry in profile.get('profiles',[])]
        selected='primary_xhttp_tls' if 'primary_xhttp_tls' in names else 'fast_tcp_reality'
        port=19808+index*2
        log=(root/('client-'+str(index)+'.log')).open('ab')
        processes.append(subprocess.Popen(['/usr/local/bin/ultra-acceptance-client','-config',str(file),'-profile',selected,'-socks','127.0.0.1:'+str(port),'-http','127.0.0.1:'+str(port+1)],stdout=log,stderr=log));log.close()
    return processes


def five_payloads(expected_egress=None, timeout_seconds=90):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:list(pool.map(lambda port:payload(port,expected_egress,timeout_seconds),[19808+i*2 for i in range(5)]))


def during_backup():
    status=Path('/var/lib/ultra-recovery/last-success.json')
    before=json.loads(status.read_text())['backup_name']
    active=threading.Event();stop=threading.Event();barrier=threading.Barrier(6)
    counts=[0]*5
    def load(index):
        payload(19808+index*2);barrier.wait(timeout=120)
        while not stop.is_set():
            payload(19808+index*2)
            if active.is_set():counts[index]+=1
            time.sleep(0.2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        jobs=[pool.submit(load,index) for index in range(5)]
        try:
            barrier.wait(timeout=120);active.set()
            run(['systemctl','start','ultra-recovery-backup.service'],timeout=240)
        finally:
            active.clear();stop.set()
        for job in jobs:job.result()
    if any(count==0 for count in counts) or json.loads(status.read_text())['backup_name']==before:
        raise ValueError('five_client_copy_overlap_unproved')
    return counts


def failover():
    import reconcile
    config=reconcile.read_config('/etc/ultra-recovery/reconcile.json')
    nodes,_=reconcile.desired_nodes(config,reconcile.discover(config))
    node=next(node for node in nodes if node['address']=='198.18.0.11')
    # This helper is fixture-only; never signal a node from a real configuration.
    if any(node['address'] not in ('198.18.0.11','198.18.0.12') for node in nodes):
        raise ValueError('synthetic_peer_addresses_required')
    five_payloads('198.18.0.11')
    try:
        reconcile.execute(config,node,['systemctl','stop','ultra-relay.service'],stdout=subprocess.DEVNULL,timeout=60)
        stopped_at=time.monotonic()
        # All five were just observed on NL; fresh payloads must leave through US.
        five_payloads('198.18.0.12',timeout_seconds=60)
        elapsed=time.monotonic()-stopped_at
        if elapsed>60:raise ValueError('five_client_failover_exceeded_sixty_seconds')
    finally:
        reconcile.execute(config,node,['systemctl','start','ultra-relay.service'],stdout=subprocess.DEVNULL,timeout=60)
    ready('online')
    return round(elapsed,3)


def verify():
    if not Path('/etc/ultra-fixture-marker').is_file():raise ValueError('synthetic_target_required')
    online=ready('online');name=database()
    emergency=Path('/usr/local/libexec/ultra-relay-emergency')
    manifest=json.loads(Path('/usr/local/libexec/ultra-emergency-manifest.json').read_text())
    schema=int(sql('SELECT max(version) FROM schema_migrations',name))
    checksum=hashlib.sha256(emergency.read_bytes()).hexdigest()
    asset=next(item for item in manifest['assets'] if item['name']=='ultra-relay-linux-amd64')
    if 'service-access-v1' not in manifest.get('capabilities',[]) or not manifest['database_schema_min']<=schema<=manifest['database_schema_max'] or checksum!=asset['sha256']:
        raise ValueError('verified_compatible_emergency_release_required')
    distinct=checksum!=hashlib.sha256(Path('/usr/local/bin/ultra-relay').read_bytes()).hexdigest()
    query="SELECT COALESCE(SUM(uplink_bytes+downlink_bytes),0) FROM account_exit_usage a JOIN users u ON u.account_id=a.account_id WHERE u.name LIKE 'acceptance-fixture-%'"
    before=int(sql(query,name));processes=clients();dropin=Path('/etc/systemd/system/ultra-relay.service.d/zzzzzz-synthetic-cache-only.conf')
    try:
        five_payloads()
        deadline=time.monotonic()+90
        while time.monotonic()<deadline and int(sql(query,name))<=before:time.sleep(3)
        after=int(sql(query,name))
        if after<=before:raise ValueError('five_account_usage_not_persisted')
        copy_counts=during_backup()
        failover_seconds=failover()
        online=ready('online')
        run(['systemctl','stop','ultra-relay'])
        baseline=Path('/var/lib/ultra-acceptance/allowances.json')
        if baseline.exists():baseline.unlink()
        stopped=json.loads(run(['/usr/local/bin/ultra-acceptance-state','-state','/var/lib/ultra-relay/runtime.db','-baseline',str(baseline)]))
        dropin.write_text('[Service]\nExecStart=\nExecStart=/usr/local/libexec/ultra-relay-emergency -cache-only -spec /etc/ultra-relay/spec.json\n');dropin.chmod(0o600)
        run(['systemctl','daemon-reload']);run(['systemctl','start','ultra-relay'])
        cached=ready('cache_only')
        if any(cached[key]!=stopped[key] for key in ('confirmed_at','expires_at')):raise ValueError('emergency_lease_changed')
        five_payloads();run(['systemctl','stop','ultra-relay'])
        run(['/usr/local/bin/ultra-acceptance-state','-state','/var/lib/ultra-relay/runtime.db','-baseline',str(baseline),'-compare'])
        return {'five_simultaneous_tcp_udp':True,'persisted_usage_increased':True,'five_client_payloads_during_copy':copy_counts,'five_client_initial_nl':True,'five_client_single_exit_failover':True,'five_client_us_failover_seconds':failover_seconds,'compatible_emergency_tcp_udp':True,'distinct_emergency_binary':distinct,'cache_only_preserved_lease':True,'cache_only_no_quota_refund':True,'emergency_release_version':manifest['version']}
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        dropin.unlink(missing_ok=True)
        run(['systemctl','daemon-reload']);run(['systemctl','restart','ultra-relay']);ready('online')


if __name__=='__main__':
    import os
    os.umask(0o077)
    print(json.dumps((seed if sys.argv[1]=='seed' else verify)()))
