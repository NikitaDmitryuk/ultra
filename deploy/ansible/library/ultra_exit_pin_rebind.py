#!/usr/bin/python3
"""Snapshot existing enabled exits, then CAS only their TLS pins after OS reimage.

Store the snapshot BEFORE reimage in trusted operator storage. Its SHA-256 binds
canonical JSON, not provenance: the caller must retain the original snapshot.
No tunnel credentials are returned: tunnel_uuid is represented by its SHA-256.
Snapshots use PostgreSQL UTC timestamp JSON representations. No migrations run.
"""
import hashlib
import ipaddress
import json
import re
import subprocess
import uuid

MAX_ROUTES = 64
FIELDS = {'id', 'name', 'address', 'port', 'priority', 'enabled', 'created_at',
          'updated_at', 'country_code', 'country_name', 'city', 'display_name',
          'pinned_peer_cert_sha256', 'tunnel_uuid_sha256'}
PROJECTION = "(to_jsonb(n) - 'tunnel_uuid') || jsonb_build_object('tunnel_uuid_sha256', encode(sha256(convert_to(n.tunnel_uuid,'UTF8')),'hex'))"
INHERITANCE_GUARD = """DO $inheritance$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_inherits
    WHERE inhparent='public.exit_nodes'::regclass OR inhrelid='public.exit_nodes'::regclass) THEN
   RAISE EXCEPTION 'exit_pin_topology_ambiguous';
 END IF;
END $inheritance$;
"""
ERRORS = {'exit_pin_identity_mismatch', 'exit_pin_topology_changed',
          'exit_pin_topology_ambiguous', 'exit_pin_compare_failed',
          'exit_pin_invalid_input', 'exit_pin_database_failed', 'exit_pin_database_timeout'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def topology_hash(routes):
    return hashlib.sha256(canonical(sorted(routes, key=lambda r: r['id'])).encode()).hexdigest()


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_snapshot(snapshot):
    try:
        if not isinstance(snapshot, dict) or set(snapshot) != {'version', 'database', 'system_identifier', 'database_oid', 'routes', 'topology_sha256'}:
            raise ValueError()
        if type(snapshot['version']) is not int or snapshot['version'] != 1:
            raise ValueError()
        for key in ('system_identifier', 'database_oid'):
            if not isinstance(snapshot[key], str) or not re.fullmatch('[1-9][0-9]{0,19}', snapshot[key]):
                raise ValueError()
        if not isinstance(snapshot['database'], str) or not re.fullmatch('[a-z_][a-z0-9_]{0,62}', snapshot['database']):
            raise ValueError()
        routes = snapshot['routes']
        if not isinstance(routes, list) or not 0 < len(routes) <= MAX_ROUTES:
            raise ValueError()
        ids, endpoints, tunnels, names = set(), set(), set(), set()
        for row in routes:
            if not isinstance(row, dict) or set(row) != FIELDS or row['enabled'] is not True:
                raise ValueError()
            if str(uuid.UUID(row['id'])) != row['id'] or type(row['port']) is not int or not 0 < row['port'] <= 65535 or type(row['priority']) is not int:
                raise ValueError()
            address = str(ipaddress.ip_address(row['address']))
            for key in FIELDS - {'id', 'port', 'priority', 'enabled'}:
                if not isinstance(row[key], str) or len(row[key]) > 1024:
                    raise ValueError()
            if not valid_hash(row['pinned_peer_cert_sha256']) or not valid_hash(row['tunnel_uuid_sha256']):
                raise ValueError()
            for seen, value in ((ids, row['id']), (endpoints, (address, row['port'])),
                                (tunnels, row['tunnel_uuid_sha256']), (names, row['name'])):
                if value in seen:
                    raise ValueError()
                seen.add(value)
        if not valid_hash(snapshot['topology_sha256']) or topology_hash(routes) != snapshot['topology_sha256']:
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError('exit_pin_invalid_input') from None
    return snapshot


def payload(database, snapshot, new_pins):
    validate_snapshot(snapshot)
    if database != snapshot['database'] or not isinstance(new_pins, list) or len(new_pins) != len(snapshot['routes']):
        raise ValueError('exit_pin_invalid_input')
    pins = {}
    for item in new_pins:
        if (not isinstance(item, dict) or set(item) != {'id', 'pinned_peer_cert_sha256'}
                or not isinstance(item['id'], str) or item['id'] in pins
                or not valid_hash(item['pinned_peer_cert_sha256'])):
            raise ValueError('exit_pin_invalid_input')
        pins[item['id']] = item['pinned_peer_cert_sha256']
    if set(pins) != {r['id'] for r in snapshot['routes']}:
        raise ValueError('exit_pin_invalid_input')
    return {'snapshot': snapshot, 'pins': pins}


def statement(value):
    # Only hexadecimal data enters SQL; no input is interpreted as SQL syntax.
    encoded = canonical(value).encode().hex()
    return """BEGIN;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='5s';
SET LOCAL timezone='UTC';
SET LOCAL row_security=off;
LOCK TABLE public.exit_nodes IN SHARE ROW EXCLUSIVE MODE;
""" + INHERITANCE_GUARD + """DO $rebind$
DECLARE
 p jsonb := convert_from(decode('""" + encoded + """','hex'),'UTF8')::jsonb;
 actual jsonb;
 wanted jsonb;
 route jsonb;
 amount integer;
BEGIN
 IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.exit_nodes'::regclass AND NOT tgisinternal)
    OR EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class='public.exit_nodes'::regclass)
    OR NOT EXISTS (SELECT 1 FROM pg_class WHERE oid='public.exit_nodes'::regclass AND relkind='r') THEN
   RAISE EXCEPTION 'exit_pin_topology_ambiguous';
 END IF;
 IF pg_is_in_recovery()
    OR (SELECT system_identifier::text FROM pg_control_system()) IS DISTINCT FROM p->'snapshot'->>'system_identifier'
    OR (SELECT oid::text FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM p->'snapshot'->>'database_oid'
    OR current_database() IS DISTINCT FROM p->'snapshot'->>'database' THEN
   RAISE EXCEPTION 'exit_pin_identity_mismatch';
 END IF;
 SELECT coalesce(jsonb_agg(""" + PROJECTION + """ ORDER BY n.id),'[]'::jsonb)
 INTO actual FROM ONLY public.exit_nodes n WHERE n.enabled;
 SELECT jsonb_agg(r || jsonb_build_object('pinned_peer_cert_sha256',p->'pins'->>(r->>'id')) ORDER BY r->>'id')
 INTO wanted FROM jsonb_array_elements(p->'snapshot'->'routes') r;
 IF actual IS DISTINCT FROM p->'snapshot'->'routes' AND actual IS DISTINCT FROM wanted THEN
   RAISE EXCEPTION 'exit_pin_topology_changed';
 END IF;
 -- Reject disabled aliases too: a reimage must not silently select one of two nodes.
 IF EXISTS (SELECT 1 FROM ONLY public.exit_nodes n JOIN public.exit_nodes other ON n.id<>other.id
    AND (n.tunnel_uuid=other.tunnel_uuid OR (n.address=other.address AND n.port=other.port) OR n.name=other.name)
    WHERE n.enabled) THEN
   RAISE EXCEPTION 'exit_pin_topology_ambiguous';
 END IF;
 IF actual IS DISTINCT FROM wanted THEN
   FOR route IN SELECT * FROM jsonb_array_elements(p->'snapshot'->'routes') LOOP
     UPDATE ONLY public.exit_nodes SET pinned_peer_cert_sha256=p->'pins'->>(route->>'id')
     WHERE id=(route->>'id')::uuid AND enabled
       AND pinned_peer_cert_sha256=route->>'pinned_peer_cert_sha256';
     GET DIAGNOSTICS amount = ROW_COUNT;
     IF amount <> 1 THEN RAISE EXCEPTION 'exit_pin_compare_failed'; END IF;
   END LOOP;
   SELECT jsonb_agg(""" + PROJECTION + """ ORDER BY n.id) INTO actual FROM ONLY public.exit_nodes n WHERE n.enabled;
   IF actual IS DISTINCT FROM wanted THEN RAISE EXCEPTION 'exit_pin_compare_failed'; END IF;
   PERFORM set_config('ultra.exit_pin_changed','true',true);
 END IF;
END $rebind$;
SELECT coalesce(current_setting('ultra.exit_pin_changed',true),'false');
COMMIT;
"""


SNAPSHOT_SQL = """BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s';
SET LOCAL timezone='UTC';
SET LOCAL row_security=off;
LOCK TABLE public.exit_nodes IN ACCESS SHARE MODE;
""" + INHERITANCE_GUARD + """WITH captured AS (SELECT jsonb_build_object('version',1,'database',current_database(),
 'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
 'database_oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'primary', NOT pg_is_in_recovery(), 'routes',
 (SELECT coalesce(jsonb_agg(route ORDER BY id),'[]'::jsonb) FROM
 (SELECT n.id,""" + PROJECTION + """ AS route FROM ONLY public.exit_nodes n WHERE n.enabled ORDER BY n.id LIMIT 65) rows)) AS snapshot)
SELECT CASE WHEN octet_length(snapshot::text)<=262144 THEN snapshot::text ELSE '{}' END FROM captured;
COMMIT;
"""


def run_sql(database, user, password, sql, call=subprocess.run):
    if any(not isinstance(v, str) or not re.fullmatch('[a-z_][a-z0-9_]{0,62}', v) for v in (database, user)):
        raise ValueError('exit_pin_invalid_input')
    result = call(['psql', '--no-psqlrc', '--no-password', '--host', '127.0.0.1',
                   '--username', user, '--dbname', database, '--quiet', '--tuples-only',
                   '--no-align', '--set', 'ON_ERROR_STOP=1'], input=sql, text=True,
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
                  env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'PGCONNECT_TIMEOUT': '5', 'PGPASSWORD': password})
    return result.stdout.strip()


def execute(mode, database, user, password, snapshot=None, new_pins=None, call=subprocess.run):
    if mode == 'snapshot':
        if snapshot is not None or new_pins is not None:
            raise ValueError('exit_pin_invalid_input')
        value = json.loads(run_sql(database, user, password, SNAPSHOT_SQL, call))
        if not value:
            raise ValueError('exit_pin_invalid_input')
        if value.pop('primary') is not True:
            raise ValueError('exit_pin_identity_mismatch')
        value['routes'].sort(key=lambda r: r['id'])
        value['topology_sha256'] = topology_hash(value['routes'])
        validate_snapshot(value)
        return {'changed': False, 'snapshot': value}
    if mode != 'apply':
        raise ValueError('exit_pin_invalid_input')
    value = payload(database, snapshot, new_pins)
    # PostgreSQL JSONB array equality is ordered; snapshot order is canonicalized.
    value = json.loads(canonical(value))
    value['snapshot']['routes'].sort(key=lambda r: r['id'])
    output = run_sql(database, user, password, statement(value), call)
    if output not in ('true', 'false'):
        raise ValueError('exit_pin_database_failed')
    return {'changed': output == 'true', 'verified': True}


def safe_failure_code(error):
    if isinstance(error, ValueError) and str(error) in ERRORS:
        return str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return 'exit_pin_database_timeout'
    # Do not echo SQL, exception text, subprocess output or connection information.
    return 'exit_pin_database_failed'


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'mode': {'type': 'str', 'choices': ['snapshot', 'apply'], 'required': True},
        'database': {'type': 'str', 'required': True},
        'user': {'type': 'str', 'required': True, 'no_log': True},
        'password': {'type': 'str', 'required': True, 'no_log': True},
        'snapshot': {'type': 'dict', 'default': None},
        'new_pins': {'type': 'list', 'elements': 'dict', 'default': None},
    }, supports_check_mode=False)
    try:
        result = execute(**module.params)
    except Exception as error:
        module.fail_json(msg='exit_pin_rebind_failed', reason_code=safe_failure_code(error))
    module.exit_json(**result)


if __name__ == '__main__':
    main()
