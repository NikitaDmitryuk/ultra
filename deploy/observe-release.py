#!/usr/bin/env python3
"""Bounded, read-only release observation. Summary contains no access credentials."""
import argparse
import datetime
import json
import os
import pathlib
import subprocess
import time
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('--hours', type=float, default=24)
p.add_argument('--output', required=True)
p.add_argument('--public-url', required=True)
args = p.parse_args()
if not 0 < args.hours <= 24:
    raise SystemExit('duration must be in (0,24] hours')
from urllib.parse import urlsplit
origin = urlsplit(args.public_url)
if origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.path not in ('','/') or origin.query or origin.fragment:
    raise SystemExit('HTTPS origin required')
P=pathlib.Path
spec=json.loads(P('/etc/ultra-relay/spec.json').read_text())
env={}
for line in P('/etc/ultra-relay/environment').read_text().splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        key,value=line.split('=',1);env[key]=value.strip().strip('"\'')

def api(path):
    request=urllib.request.Request('http://'+spec.get('admin_listen','127.0.0.1:8443')+path,headers={'Authorization':'Bearer '+env['ULTRA_RELAY_ADMIN_TOKEN']})
    return json.load(urllib.request.urlopen(request,timeout=10))

started=time.time();deadline=started+args.hours*3600
summary={'started_at':started,'deadline':deadline,'samples':0,'failures':0,'completed':False,'error_counts':{}}
last=started
while True:
    now=time.time();summary['samples']+=1;summary['updated_at']=now
    try:
        state=api('/v1/hardening')['reload']
        summary.setdefault('reload_start',state['count']);summary['reload_last']=state['count']
        nodes=api('/v1/cloud/quotas')['nodes'];summary['ready_exits']=sum(bool(n['ready'] and n['enabled']) for n in nodes)
        with urllib.request.urlopen(args.public_url.rstrip('/')+'/happ',timeout=15) as response:
            summary['public_http_status']=response.status
        healthy=not state.get('error') and summary['ready_exits']>0 and summary['public_http_status']==200
        summary.pop('last_error_type',None)
        summary['last_ok']=healthy
        if not healthy:summary['failures']+=1
    except Exception as error:
        summary['failures']+=1;summary['last_ok']=False;summary['last_error_type']=type(error).__name__
    try:
        raw=subprocess.check_output(['journalctl','-u','ultra-relay','-u','ultra-bot','--since','@'+str(last),'--until','@'+str(now),'-o','json'],text=True,stderr=subprocess.DEVNULL,timeout=15)
        for line in raw.splitlines():
            message=json.loads(line).get('MESSAGE','').lower()
            for marker in ['route application failed','quota evaluation failed','quota provider refresh failed','failed to record traffic','slow subscription response','panic:','fatal error:']:
                if marker in message:
                    summary['error_counts'][marker]=summary['error_counts'].get(marker,0)+1
        last=now
    except Exception:
        summary['log_read_failures']=summary.get('log_read_failures',0)+1
    summary['completed']=time.time()>=deadline
    target=P(args.output);temp=target.with_suffix('.next');temp.write_text(json.dumps(summary));temp.chmod(0o600);os.replace(temp,target)
    if summary['completed']:break
    time.sleep(min(60,max(0,deadline-time.time())))
