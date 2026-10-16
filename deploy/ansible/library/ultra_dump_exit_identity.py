#!/usr/bin/python3
"""Rebind only explicitly matched imported exits before fresh bridge activation."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import uuid

RECEIPT = Path('/var/lib/ultra-db-import-state/receipt.json')
SQL_FAILURE_CODES = (
    'database_import_identity_mismatch',
    'dump_exit_identity_binding_mismatch',
    'dump_exit_identity_mapping_not_unique',
    'dump_exit_identity_route_disabled',
    'dump_exit_identity_membership_changed',
    'dump_exit_identity_changed',
)
SAFE_FAILURE_CODES = {
    'invalid_dump_exit_identity_input',
    'database_import_receipt_mismatch',
    'invalid_dump_exit_identity_route',
    'invalid_dump_exit_identity_pin',
    'duplicate_dump_exit_identity_route',
    *SQL_FAILURE_CODES,
    'database_reconciliation_timeout',
    'database_reconciliation_failed',
}


def safe_failure_code(error):
    """Return a fixed, non-sensitive category; never expose SQL or subprocess output."""
    if isinstance(error, ValueError) and str(error) in SAFE_FAILURE_CODES:
        return str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return 'database_reconciliation_timeout'
    if isinstance(error, subprocess.CalledProcessError):
        stderr = error.stderr if isinstance(error.stderr, str) else ''
        for code in SQL_FAILURE_CODES:
            if code in stderr:
                return code
    return 'database_reconciliation_failed'


def payload(database, user, archive_sha256, entries, tls_policy, receipt):
    if (not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', database)
            or not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', user)
            or not re.fullmatch(r'[a-f0-9]{64}', archive_sha256)
            or tls_policy not in ('pin', 'ca')
            or not isinstance(entries, list) or not 0 < len(entries) <= 64):
        raise ValueError('invalid_dump_exit_identity_input')
    expected = {'database': database, 'user': user, 'sha256': archive_sha256}
    if (not isinstance(receipt, dict) or set(receipt) != set(expected) | {'system_identifier', 'database_oid'}
            or any(receipt.get(k) != v for k, v in expected.items())
            or any(not re.fullmatch(r'[0-9]+', str(receipt[k])) for k in ('system_identifier', 'database_oid'))):
        raise ValueError('database_import_receipt_mismatch')
    routes = []
    endpoints, identities = set(), set()
    for entry in entries:
        address, port = entry['address'], entry['port']
        # Validate IP syntax without normalizing: matching is exact, including IPv6 spelling.
        ipaddress.ip_address(address)
        identity = entry['tunnel_uuid']
        if str(uuid.UUID(identity)) != identity or type(port) is not int or not 0 < port <= 65535:
            raise ValueError('invalid_dump_exit_identity_route')
        pin = entry.get('pinned_peer_cert_sha256', '')
        if tls_policy == 'ca':
            pin = ''
        elif not isinstance(pin, str) or not re.fullmatch(r'[a-f0-9]{64}', pin):
            raise ValueError('invalid_dump_exit_identity_pin')
        if (address, port) in endpoints or identity in identities:
            raise ValueError('duplicate_dump_exit_identity_route')
        endpoints.add((address, port))
        identities.add(identity)
        routes.append({'address': address, 'port': port, 'tunnel_uuid': identity, 'pin': pin})
    routes.sort(key=lambda r: (r['address'], r['port']))
    value = {'receipt': receipt, 'routes': routes, 'tls_policy': tls_policy, 'version': 1}
    value['binding'] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return value


def statement(value):
    # Hex contains no SQL metacharacters; archive/route text is never interpolated as SQL.
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode().hex()
    return """BEGIN;
SET LOCAL statement_timeout='15s';
SELECT pg_advisory_xact_lock(817365010);
LOCK TABLE public.exit_nodes IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE IF NOT EXISTS public.ultra_dump_exit_identity (
 target text PRIMARY KEY, binding text NOT NULL, matches jsonb NOT NULL
);
DO $identity$
DECLARE
 p jsonb := convert_from(decode('""" + encoded + """','hex'),'UTF8')::jsonb;
 target_identity text := (p->'receipt'->>'system_identifier') || ':' || (p->'receipt'->>'database_oid');
 route jsonb;
 matched uuid;
active boolean;
 amount integer;
 matches jsonb := '[]'::jsonb;
 saved public.ultra_dump_exit_identity%ROWTYPE;
BEGIN
 IF (SELECT system_identifier::text FROM pg_control_system()) <> p->'receipt'->>'system_identifier'
    OR (SELECT oid::text FROM pg_database WHERE datname=current_database()) <> p->'receipt'->>'database_oid'
    OR current_database() <> p->'receipt'->>'database' THEN
   RAISE EXCEPTION 'database_import_identity_mismatch';
 END IF;
 SELECT * INTO saved FROM public.ultra_dump_exit_identity WHERE target=target_identity;
 IF FOUND AND saved.binding <> p->>'binding' THEN
   RAISE EXCEPTION 'dump_exit_identity_binding_mismatch';
 END IF;
 FOR route IN SELECT * FROM jsonb_array_elements(p->'routes') LOOP
   SELECT count(*) INTO amount FROM public.exit_nodes
    WHERE address=route->>'address' AND port=(route->>'port')::integer;
   IF amount <> 1 THEN
     RAISE EXCEPTION 'dump_exit_identity_mapping_not_unique';
   END IF;
   SELECT id, enabled INTO matched, active FROM public.exit_nodes
    WHERE address=route->>'address' AND port=(route->>'port')::integer;
   IF active IS DISTINCT FROM true THEN
     RAISE EXCEPTION 'dump_exit_identity_route_disabled';
   END IF;
   matches := matches || jsonb_build_array(jsonb_build_object('id',matched,'route',route));
 END LOOP;
 IF saved.binding IS NOT NULL THEN
   IF saved.matches <> matches THEN
     RAISE EXCEPTION 'dump_exit_identity_membership_changed';
   END IF;
   FOR route IN SELECT * FROM jsonb_array_elements(matches) LOOP
     IF NOT EXISTS (SELECT 1 FROM public.exit_nodes WHERE id=(route->>'id')::uuid
        AND tunnel_uuid=route->'route'->>'tunnel_uuid'
        AND pinned_peer_cert_sha256=route->'route'->>'pin') THEN
       RAISE EXCEPTION 'dump_exit_identity_changed';
     END IF;
   END LOOP;
 ELSE
   FOR route IN SELECT * FROM jsonb_array_elements(matches) LOOP
     UPDATE public.exit_nodes SET tunnel_uuid=route->'route'->>'tunnel_uuid',
       pinned_peer_cert_sha256=route->'route'->>'pin' WHERE id=(route->>'id')::uuid;
   END LOOP;
   INSERT INTO public.ultra_dump_exit_identity VALUES (target_identity,p->>'binding',matches);
   PERFORM set_config('ultra.dump_exit_changed','true',true);
 END IF;
END $identity$;
SELECT coalesce(current_setting('ultra.dump_exit_changed',true),'false');
COMMIT;
"""


def reconcile(database, user, password, archive_sha256, entries, tls_policy,
              read_receipt=lambda: json.loads(RECEIPT.read_text()), call=subprocess.run):
    value = payload(database, user, archive_sha256, entries, tls_policy, read_receipt())
    # A fixed environment avoids inheriting PGOPTIONS/service settings; credentials never enter argv/output.
    result = call(['psql', '--no-psqlrc', '--no-password', '--host', '127.0.0.1',
                   '--username', user, '--dbname', database, '--quiet', '--tuples-only', '--no-align', '--set', 'ON_ERROR_STOP=1'],
                  input=statement(value), text=True, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, check=True, timeout=30,
                  env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'PGCONNECT_TIMEOUT': '5', 'PGPASSWORD': password})
    return result.stdout.strip().splitlines()[-1] == 'true'


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'database': {'type': 'str', 'required': True, 'no_log': True},
        'user': {'type': 'str', 'required': True, 'no_log': True},
        'password': {'type': 'str', 'required': True, 'no_log': True},
        'archive_sha256': {'type': 'str', 'required': True, 'no_log': True},
        'entries': {'type': 'list', 'elements': 'dict', 'required': True, 'no_log': True},
        'tls_policy': {'type': 'str', 'choices': ['pin', 'ca'], 'required': True, 'no_log': True},
    }, supports_check_mode=False)
    try:
        changed = reconcile(**module.params)
        module.exit_json(changed=changed, verified=True)
    except Exception as error:
        module.fail_json(msg='dump_exit_identity_reconciliation_failed',
                         ultra_safe_failure_code=safe_failure_code(error))


if __name__ == '__main__':
    main()
