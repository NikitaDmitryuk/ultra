#!/usr/bin/env python3
"""Domain-publication identity and full TLS probe contracts, independent of host installation."""
import base64
import copy
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import urllib.parse


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def candidate_spec(before, target):
    after = copy.deepcopy(before)
    old = before.get('primary_xhttp', {})
    if not old or old.get('published', True) is not True or old.get('port') != 443:
        raise ValueError('cutover_requires_published_primary')
    if old['path'] != target['path'] or old['backend_port'] != target['backend_port']:
        raise ValueError('cutover_cannot_change_transport')
    primary = after['primary_xhttp']
    primary['host'] = target['public_host']
    primary['server_name'] = target['domain']
    for descriptor in after.get('subscription_bridges', []):
        if descriptor.get('security') != 'tls':
            continue
        if (descriptor.get('host'), descriptor.get('server_name'), descriptor.get('port'), descriptor.get('path')) != (old['host'], old['server_name'], old['port'], old['path']):
            raise ValueError('cutover_unknown_tls_publication')
        descriptor['host'] = target['public_host']
        descriptor['server_name'] = target['domain']
    return after


def single_alias_probe(profile, old, target, bridge_ip):
    matches = []
    for outbound in profile.get('outbounds', []):
        stream = outbound.get('streamSettings', {})
        destinations = outbound.get('settings', {}).get('vnext', [])
        if (outbound.get('protocol') == 'vless' and stream.get('security') == 'tls'
                and stream.get('network') == 'xhttp' and stream.get('tlsSettings', {}).get('serverName') == old['server_name']
                and len(destinations) == 1 and destinations[0]['address'] == old['host'] and destinations[0]['port'] == 443):
            matches.append(copy.deepcopy(outbound))
    if not matches:
        raise ValueError('cutover_monitor_tls_route_missing')
    selected = matches[0]
    selected['tag'] = 'cutover-edge-only'
    selected['settings']['vnext'][0]['address'] = bridge_ip
    selected['streamSettings']['tlsSettings']['serverName'] = target['domain']
    selected['streamSettings']['tlsSettings'].pop('allowInsecure', None)
    if selected['streamSettings'].get('xhttpSettings', {}).get('downloadSettings'):
        raise ValueError('cutover_split_download_requires_explicit_plan')
    return {'outbounds': [selected]}


def subscription_documents(raw):
    document = json.loads(raw)
    if isinstance(document, dict):
        return [document]
    if isinstance(document, list) and all(isinstance(profile, dict) for profile in document):
        return document
    raise ValueError('cutover_subscription_invalid_json')


def subscription_shape(raw):
    try:
        documents = subscription_documents(raw)
    except ValueError:
        try:
            text = base64.b64decode(raw + b'='*((-len(raw))%4), validate=True).decode()
        except (ValueError, UnicodeError):
            text = raw.decode()
        uris = [line for line in text.splitlines() if line.startswith('vless://')]
        if not uris:
            raise ValueError('cutover_subscription_missing_vless')
        credentials = sorted(urllib.parse.urlsplit(uri).username for uri in uris)
    else:
        if any(not isinstance(document.get('outbounds'), list) for document in documents):
            raise ValueError('cutover_subscription_invalid_json')
        credentials = sorted(user['id'] for document in documents for row in document['outbounds']
                             if row.get('protocol') == 'vless'
                             for destination in row.get('settings', {}).get('vnext', [])
                             for user in destination.get('users', []))
        if not credentials:
            raise ValueError('cutover_subscription_missing_credentials')
    return {'credential_digest': digest(json.dumps(credentials).encode()), 'routes': len(credentials)}


def shape_failure_stage(prefix, error):
    known = {
        'cutover_subscription_missing_vless': 'missing_vless',
        'cutover_subscription_invalid_json': 'invalid_json',
        'cutover_subscription_missing_credentials': 'missing_credentials',
    }
    return prefix + '_' + known.get(str(error), 'invalid')


def subscription_tls_endpoints(raw):
    try:
        documents=subscription_documents(raw)
    except ValueError:
        try:text=base64.b64decode(raw+b'='*((-len(raw))%4),validate=True).decode()
        except (ValueError,UnicodeError):text=raw.decode()
        endpoints=[]
        for line in text.splitlines():
            if not line.startswith('vless://'):continue
            parsed=urllib.parse.urlsplit(line);query=urllib.parse.parse_qs(parsed.query)
            if query.get('security')==['tls']:endpoints.append((parsed.hostname,query.get('sni',[''])[0]))
        return set(endpoints)
    endpoints=set()
    for doc in documents:
        for outbound in doc.get('outbounds',[]):
            stream=outbound.get('streamSettings',{})
            if stream.get('security')!='tls':continue
            for destination in outbound.get('settings',{}).get('vnext',[]):
                endpoints.add((destination['address'],stream.get('tlsSettings',{}).get('serverName','')))
    return endpoints


def https(host, address, port, request_path):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((address, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.sendall(('GET ' + request_path + ' HTTP/1.1\r\nHost: ' + host + '\r\nUser-Agent: Happ/4.7.1/Android/cutover-check\r\nConnection: close\r\n\r\n').encode())
            response = http.client.HTTPResponse(connection)
            response.begin()
            data = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(data) > 1024 * 1024:
                raise ValueError('cutover_https_failed')
            return data
