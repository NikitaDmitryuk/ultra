#!/usr/bin/env python3
"""Capture and independently restore a new encrypted generation inside a drill VM."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from recovery import collect, encrypt, pack
from vm_guest import run, sql, write


def generation():
    if not Path('/var/lib/ultra-drill-result.json').exists():
        raise RuntimeError('restored drill required')
    # Compare one quiescent confirmed SQL state, not concurrently changing rows.
    run(['systemctl', 'stop', 'ultra-relay', 'ultra-bot'])
    with tempfile.TemporaryDirectory(prefix='ultra-drill-generation-') as temporary:
        directory = Path(temporary)
        identity = directory / 'identity.txt'
        run(['age-keygen', '-o', str(identity)])
        identity.chmod(0o600)
        recipient = run(['age-keygen', '-y', str(identity)]).decode().strip()
        config = json.loads(Path('/etc/ultra-recovery/backup.json').read_text())
        selected = config['state_paths'] + ['/etc/ultra-drill/cert.pem', '/etc/ultra-drill/key.pem']
        state = collect(selected, config['artifact_paths'])
        artifacts = collect(config['artifact_paths'])
        artifact_plain = directory / 'artifact.tar.gz'
        manifest = pack(artifact_plain, {'kind': 'artifact', 'source': 'drill'}, {name: Path('/') / name for name in artifacts})
        artifact_id = hashlib.sha256(json.dumps(manifest['files'], sort_keys=True).encode()).hexdigest()
        artifact = directory / ('artifact-' + artifact_id + '.age')
        encrypt(artifact_plain, artifact, recipient)
        dump = directory / 'database.dump'
        dump.write_bytes(run(['runuser', '-u', 'postgres', '--', 'pg_dump', '-Fc', '--no-owner', '--no-acl', 'ultra_drill']))
        files = {'state/' + name: Path('/') / name for name in state}
        files['database.dump'] = dump
        plain = directory / 'backup.tar.gz'
        now = int(time.time())
        pack(plain, {'kind': 'backup', 'source': 'drill', 'snapshot_at': now, 'artifact': artifact.name, 'database': 'ultra_drill'}, files)
        backup = directory / ('backup-' + str(now) + '-' + uuid.uuid4().hex + '.age')
        encrypt(plain, backup, recipient)
        target = directory / 'second-stage'
        run(['python3', '/opt/ultra-drill/recovery.py', 'verify', '--bundle', str(backup), '--identity', str(identity), '--test-stage', '--target', str(target)])
        name = 'ultra_drill_generation_' + uuid.uuid4().hex
        try:
            run(['runuser', '-u', 'postgres', '--', 'createdb', name])
            run(['runuser', '-u', 'postgres', '--', 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '-d', name], (target / 'database.dump').read_bytes())
            tables = json.loads(sql("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'"))
            for table in tables:
                query = 'SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,\'[]\') FROM ' + '"' + table.replace('"', '""') + '" t'
                if sql(query) != sql(query, name):
                    raise RuntimeError('new generation data mismatch')
        finally:
            run(['runuser', '-u', 'postgres', '--', 'dropdb', '--if-exists', name])
    path = Path('/var/lib/ultra-drill-result.json')
    result = json.loads(path.read_text())
    result['new_encrypted_generation_restored'] = True
    result['total_drill_seconds'] = round(time.time() - int(run(['stat', '-c', '%W', '/root/ultra-drill-stage']).decode().strip()), 2)
    write(path, json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        generation()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('isolated generation drill failed; sensitive details suppressed')
