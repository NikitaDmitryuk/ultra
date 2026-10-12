#!/usr/bin/env python3
"""Restore drill entrypoint. ONLY disposable, externally isolated Ubuntu 24.04 VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def run(args, data=None):
    Path('/var/lib/ultra-drill-phase').write_text(Path(args[0]).name + ('/' + args[4] if args[0] == 'runuser' and len(args) > 4 else '') + '\n')
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    if p.returncode:
        raise RuntimeError('command failed: ' + Path(args[0]).name)
    return p.stdout


def sql(text, database='ultra_drill'):
    return run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database], text.encode()).decode().strip()


def write(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(mode)


def restore(stage):
    if os.geteuid() or not Path('/var/lib/ultra-drill-ready').exists():
        raise RuntimeError('prepared disposable drill VM required')
    # Additional guest boundary; SSH replies are the only non-loopback output.
    run(['iptables', '-I', 'OUTPUT', '1', '-o', 'lo', '-j', 'ACCEPT'])
    run(['iptables', '-I', 'OUTPUT', '2', '-p', 'tcp', '--sport', '22', '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT'])
    run(['iptables', '-A', 'OUTPUT', '-j', 'REJECT'])
    run(['ip6tables', '-A', 'OUTPUT', '!', '-o', 'lo', '-j', 'REJECT'])
    started = time.monotonic()
    stage = Path(stage)
    manifest = json.loads((stage / 'manifest.json').read_text())
    artifacts = json.loads((stage / 'artifacts/manifest.json').read_text())
    if manifest.get('kind') != 'backup' or artifacts.get('kind') != 'artifact':
        raise RuntimeError('verified recovery stage required')
    # Enforce manifest hashes again at guest boundary, before installing anything.
    for root, entries in [(stage, manifest['files']), (stage / 'artifacts', artifacts['files'])]:
        for name, row in entries.items():
            content = (root / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != row['sha256']:
                raise RuntimeError('staging checksum mismatch')
    for source in [stage / 'state', stage / 'artifacts']:
        for path in source.rglob('*'):
            if not path.is_file() or path.name == 'manifest.json':
                continue
            target = Path('/') / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            name = path.relative_to(source).as_posix()
            row = artifacts['files'][name] if source.name == 'artifacts' else manifest['files']['state/' + name]
            target.chmod(row['mode'])
    run(['systemctl', 'stop', 'nginx'])
    # No restored EnvironmentFile is executed; real credentials remain inert.
    write('/etc/ultra-relay/environment', 'ULTRA_RELAY_ADMIN_TOKEN=drill-admin-token\n')
    write('/etc/ultra-relay/bot.env', 'TELEGRAM_BOT_TOKEN=123456789:drill-unused-token\nULTRA_RELAY_ADMIN_TOKEN=drill-admin-token\n')
    run(['systemctl', 'start', 'postgresql'])
    sql("CREATE ROLE ultra_drill LOGIN PASSWORD 'isolated-drill-password';", 'postgres')
    run(['runuser', '-u', 'postgres', '--', 'createdb', '-O', 'ultra_drill', 'ultra_drill'])
    run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '--role=ultra_drill', '-d', 'ultra_drill'], (stage / 'database.dump').read_bytes())
    sql("GRANT ALL ON SCHEMA public TO ultra_drill; GRANT ALL ON ALL TABLES IN SCHEMA public TO ultra_drill; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ultra_drill;")
    tables = json.loads(sql("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'"))
    # Compare restored rows with a second independent restore, without disclosing rows.
    run(['runuser', '-u', 'postgres', '--', 'createdb', 'ultra_drill_reference'])
    run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '-d', 'ultra_drill_reference'], (stage / 'database.dump').read_bytes())
    checked = []
    for table in tables:
        if sql("SELECT to_regclass('" + table + "') IS NOT NULL") != 't':
            continue
        query = 'SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,\'[]\') FROM ' + '"' + table.replace('"', '""') + '" t'
        if sql(query) != sql(query, 'ultra_drill_reference'):
            raise RuntimeError('restore data mismatch')
        checked.append(table)
    if sql('SELECT max(version) FROM schema_migrations') != '23':
        raise RuntimeError('schema version mismatch')
    spec_path = Path('/etc/ultra-relay/spec.json')
    spec = json.loads(spec_path.read_text())
    spec['database']['dsn'] = 'postgres://ultra_drill:isolated-drill-password@127.0.0.1:5432/ultra_drill?sslmode=disable'
    spec['public_host'] = '127.0.0.1'
    spec['primary_xhttp']['host'] = '127.0.0.1'
    spec['exit']['address'] = '127.0.0.1'
    spec['exit']['port'] = 16443
    spec['split_routing'] = False
    spec['experimental_profile_file'] = ''
    spec['anti_censor']['disable_doh'] = True
    spec['probe_urls'] = ['https://8.8.8.8:19443/probe-a', 'https://8.8.8.8:19443/probe-b']
    # Public-shaped address exists ONLY on guest lo; Xray blocks private targets.
    run(['ip', 'address', 'replace', '8.8.8.8/32', 'dev', 'lo'])
    fixture = Path('/etc/ultra-drill')
    fixture.mkdir(mode=0o700, exist_ok=True)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:8.8.8.8', '-keyout', str(fixture / 'key.pem'), '-out', str(fixture / 'cert.pem')])
    shutil.copyfile(fixture / 'cert.pem', '/usr/local/share/ca-certificates/ultra-drill.crt')
    run(['update-ca-certificates'])
    cert_der = run(['openssl', 'x509', '-in', str(fixture / 'cert.pem'), '-outform', 'DER'])
    pin = hashlib.sha256(cert_der).hexdigest()
    node = json.loads(sql("SELECT row_to_json(t) FROM (SELECT tunnel_uuid FROM exit_nodes WHERE enabled ORDER BY priority LIMIT 1) t"))
    sql("UPDATE exit_nodes SET address='127.0.0.1', port=16443, pinned_peer_cert_sha256='" + pin + "' WHERE enabled;")
    spec['exit']['tunnel_uuid'] = node['tunnel_uuid']
    spec['exit']['pinned_peer_cert_sha256'] = pin
    spec['splithttp_tls']['server_name'] = 'localhost'
    spec['splithttp_tls']['omit_sni'] = False
    spec['tunnel_tls_provision'] = 'self_signed'
    exit_spec = {key: spec[key] for key in ['schema_version', 'mimic_preset', 'splithttp_tls', 'splithttp_host', 'splithttp_path', 'tunnel_transport'] if key in spec}
    exit_spec.update({'role': 'exit', 'listen_address': '127.0.0.1', 'vless_port': 16443, 'exit': {'tunnel_uuid': node['tunnel_uuid']}, 'anti_censor': {'disable_doh': True, 'exit_fallback_host': '8.8.8.8:19443'}})
    exit_spec['exit_cert'] = {'cert_file': str(fixture / 'cert.pem'), 'key_file': str(fixture / 'key.pem')}
    write(fixture / 'exit.json', json.dumps(exit_spec))
    write('/etc/systemd/system/ultra-drill-exit.service', '[Service]\nExecStart=/usr/local/bin/ultra-relay -spec /etc/ultra-drill/exit.json -log-level error\n')
    write('/etc/systemd/system/ultra-drill-target.service', '[Service]\nExecStart=/usr/bin/python3 /opt/ultra-drill/vm_fixture.py --cert /etc/ultra-drill/cert.pem --key /etc/ultra-drill/key.pem\n')
    write(spec_path, json.dumps(spec))
    if subprocess.run(['id', 'ultra-relay'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(['useradd', '--system', '--no-create-home', 'ultra-relay'])
    run(['chown', '-R', 'ultra-relay:ultra-relay', '/etc/ultra-relay', '/var/lib/ultra-relay'])
    run(['chmod', '700', '/var/lib/ultra-relay'])
    # Override start commands explicitly and remove all restored supplementary units.
    shutil.rmtree('/etc/systemd/system/ultra-relay.service.d', ignore_errors=True)
    write('/etc/systemd/system/ultra-relay.service.d/drill.conf', '[Service]\nExecStart=\nExecStart=/usr/local/bin/ultra-relay -spec /etc/ultra-relay/spec.json -log-level error\n')
    write('/etc/systemd/system/ultra-bot.service.d/drill.conf', '[Service]\nExecStart=\nExecStart=/usr/local/bin/ultra-bot -spec /etc/ultra-relay/spec.json -dev -port 18444 -log-level error\n')
    Path('/var/www/ultra-acme/.well-known/acme-challenge').mkdir(parents=True, exist_ok=True)
    write('/var/www/ultra-acme/.well-known/acme-challenge/ultra-drill', 'ultra-drill', 0o644)
    # Discard stale task-only include. Production Nginx TLS location is preserved.
    nginx = Path('/etc/nginx/conf.d/ultra-vpn.conf')
    nginx.write_text('\n'.join(line for line in nginx.read_text().splitlines() if '/ultra-android-test-locations/' not in line) + '\n')
    run(['nginx', '-t'])
    run(['/usr/local/bin/ultra-relay', '-check', '-spec', str(spec_path), '-log-level', 'error'])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', 'ultra-drill-target', 'ultra-drill-exit', 'ultra-relay', 'ultra-bot', 'nginx'])
    run(['curl', '--fail', '--silent', '--header', 'Host: ' + spec['primary_xhttp']['server_name'], 'http://127.0.0.1/.well-known/acme-challenge/ultra-drill'])
    # Return only non-sensitive proof, further VPN fixtures are a separate phase.
    result = {'schema': 23, 'restored_tables_equal': checked, 'vm_restore_seconds': round(time.monotonic() - started, 2), 'services_started': True, 'network_output_isolated': True, 'from_stage_creation_seconds': round(time.time() - int(run(['stat', '-c', '%W', str(stage)]).decode().strip()), 2)}
    write('/var/lib/ultra-drill-result.json', json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True)
    args = parser.parse_args()
    try:
        restore(args.stage)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('isolated VM drill failed; sensitive details suppressed')
