"""Validation shared by the operator and prepared-VM recovery installer."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time

from recovery import private, safe_name

AUTOMATION_UNITS = (
    'ultra-recovery-backup.service', 'ultra-recovery-backup.timer',
    'ultra-recovery-prune.service', 'ultra-recovery-prune.timer',
    'ultra-recovery-reconcile.service', 'ultra-recovery-reconcile.timer',
    'ultra-monitor.service', 'ultra-monitor.timer', 'ultra-monitor-probe.service',
    'certbot.service', 'certbot.timer',
    'ultra-ansible-controller.service', 'ultra-auto-upgrade.service', 'ultra-auto-upgrade.timer',
)
APP_UNITS = ('ultra-relay.service', 'ultra-bot.service')
PHASES = ('prepare', 'install', 'database', 'peer_reseed', 'activate', 'ingress', 'automation', 'ready')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def migration_identity(value):
    fields={'source_machine_id','target_machine_id','source_ssh_endpoint','target_ssh_endpoint'}
    if not isinstance(value,dict) or set(value)!=fields:
        raise ValueError('invalid_migration_identity')
    for name in ('source_machine_id','target_machine_id'):
        if not isinstance(value[name],str) or not re.fullmatch(r'[a-f0-9]{32}',value[name]):
            raise ValueError('invalid_migration_identity')
    for name in ('source_ssh_endpoint','target_ssh_endpoint'):
        if not isinstance(value[name],str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]+',value[name]) or value[name].startswith('-'):
            raise ValueError('invalid_migration_identity')
    if value['source_machine_id']==value['target_machine_id'] or value['source_ssh_endpoint']==value['target_ssh_endpoint']:
        raise ValueError('distinct_migration_machines_required')
    return value


def fence(value, source, target_host, old_address, now=None, migration=None):
    now = time.time() if now is None else now
    age = now - value.get('confirmed_at', 0)
    if (value.get('source') != source or value.get('confirmed_offline') is not True
            or value.get('target_host') != target_host or value.get('source_address') != old_address
            or not 0 <= age <= 3600):
        raise ValueError('fresh_target_bound_fencing_required')
    if migration is not None:
        migration_identity(migration)
        if value.get('migration_identity') != migration or migration['target_ssh_endpoint'] != target_host:
            raise ValueError('migration_identity_fence_mismatch')
    return value


def endpoint(value):
    if not isinstance(value, dict) or not re.fullmatch(r'[A-Za-z0-9_.:@-]+', value.get('host', '')) or value['host'].startswith('-'):
        raise ValueError('invalid_ssh_target')
    if not isinstance(value.get('port', 22), int) or not 1 <= value.get('port', 22) <= 65535:
        raise ValueError('invalid_ssh_port')
    for key in ('identity', 'known_hosts'):
        if not Path(value[key]).is_absolute():
            raise ValueError('absolute_ssh_files_required')
    return value


def configuration(value):
    if value.get('format') != 1 or value.get('source', 'bridge') != 'bridge':
        raise ValueError('unsupported_restore_plan')
    value = dict(value, source='bridge')
    if not isinstance(value.get('new_bridge_provider'), str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', value['new_bridge_provider']):
        raise ValueError('explicit_new_bridge_provider_required')
    value['new_bridge_provider'] = value['new_bridge_provider'].lower()
    endpoint(value['target'])
    value.setdefault('ingress_mode', 'forward')
    if value['ingress_mode'] not in ('forward', 'direct'):
        raise ValueError('unsupported_ingress_mode')
    if value['ingress_mode'] == 'forward':
        endpoint(value['ingress'])
        if value['target']['host'] == value['ingress']['host']:
            raise ValueError('ingress_must_be_separate')
    for key in ('bundle', 'identity', 'fence_file', 'state_dir'):
        path = Path(value[key])
        if not path.is_absolute() or '..' in path.parts or path == Path('/'):
            raise ValueError('absolute_private_restore_paths_required')
    for key in ('old_bridge_address', 'new_bridge_address'):
        address = ipaddress.IPv4Address(value[key])
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValueError('invalid_bridge_address')
    if value.get('migration_identity') is not None:
        migration_identity(value['migration_identity'])
        if value['migration_identity']['target_ssh_endpoint'] != value['target']['host']:
            raise ValueError('migration_target_endpoint_mismatch')
    if value['old_bridge_address'] == value['new_bridge_address'] and value.get('migration_identity') is None:
        raise ValueError('new_bridge_address_must_differ')
    for key in ('public_host', 'subscription_domain'):
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value[key]):
            raise ValueError('invalid_public_name')
    if not 30 <= value.get('readiness_timeout', 900) <= 1800:
        raise ValueError('invalid_readiness_timeout')
    return value


def plan_id(config, bundle_sha):
    # Fresh fence timestamps and local filesystem locations can change on resume;
    # destinations and the selected immutable generation cannot.
    identity = {key: config[key] for key in ('source', 'old_bridge_address', 'new_bridge_address',
                                            'public_host', 'subscription_domain', 'new_bridge_provider')}
    identity['ingress_mode'] = config.get('ingress_mode', 'forward')
    if config.get('migration_identity') is not None:
        identity['migration_identity'] = migration_identity(config['migration_identity'])
    identity.update(bundle_sha256=bundle_sha,
                    target={key: config['target'].get(key, 22) for key in ('host', 'port')},
                    ingress={key: config['ingress'].get(key, 22) for key in ('host', 'port')} if config.get('ingress_mode', 'forward') == 'forward' else None)
    return hashlib.sha256(canonical(identity)).hexdigest()


def system_unit(name):
    parts = Path(name).parts
    if parts and parts[0] == '/':
        parts = parts[1:]
    return len(parts) > 3 and parts[:3] == ('etc', 'systemd', 'system')


def destination(name):
    safe_name(name)
    path = Path('/') / name
    blocked = ('etc/ssh/', 'etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow',
               'etc/sudoers', 'root/.ssh/authorized_keys', 'var/lib/postgresql/')
    if (len(path.parts) < 4 or path.parts[1] not in ('etc', 'var', 'opt', 'usr', 'root', 'srv')
            or name.startswith(blocked) or path.name == 'runtime.db'):
        raise ValueError('unsupported_restore_destination')
    return path


def safe_target(root, name):
    destination(name)
    target = Path(root) / name
    for path in (target, *target.parents):
        if path == Path(root):
            break
        if path.is_symlink():
            raise ValueError('restore_destination_symlink')
    return target


def stage_manifests(stage):
    stage = Path(stage)
    state = json.loads((stage / 'manifest.json').read_text())
    artifacts = json.loads((stage / 'artifacts/manifest.json').read_text())
    if state.get('kind') != 'backup' or state.get('source') != 'bridge' or artifacts.get('kind') != 'artifact' or artifacts.get('source') != 'bridge':
        raise ValueError('bridge_manifests_required')
    for root, manifest in ((stage, state), (stage / 'artifacts', artifacts)):
        for name, row in manifest['files'].items():
            safe_name(name)
            path = safe_target(root, name) if root.name == 'artifacts' else root / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
                raise ValueError('staged_manifest_mismatch')
            if root == stage and name != 'database.dump':
                if not name.startswith('state/'):
                    raise ValueError('invalid_state_inventory')
                destination(name.removeprefix('state/'))
    files = artifacts['files']
    for name in ('usr/local/bin/ultra-relay', 'usr/local/bin/ultra-bot'):
        if name not in files:
            raise ValueError('application_artifact_missing')
    for name in ('state/etc/ultra-relay/spec.json', 'database.dump',
                 'state/etc/ultra-recovery/backup.json', 'state/etc/ultra-recovery/reconcile.json'):
        if name not in state['files']:
            raise ValueError('required_restore_state_missing')
    release_name = 'opt/ultra-recovery/release-manifest.json'
    if release_name not in files:
        raise ValueError('versioned_release_manifest_required')
    release = json.loads((stage / 'artifacts' / release_name).read_text())
    if 'service-access-v1' not in release.get('capabilities', []):
        raise ValueError('service_access_capable_release_required')
    if not isinstance(release.get('database_schema_min'), int) or not isinstance(release.get('database_schema_max'), int):
        raise ValueError('release_schema_bounds_required')
    return state, artifacts


def read_private(path):
    if Path(path).stat().st_size > 65536:
        raise ValueError('configuration_too_large')
    return json.loads(private(path).read_text())


# Only these literal invariant codes may cross the private execution boundary.
SAFE_ERROR_CODES = frozenset((
    'authenticated_offline_runtime_missing', 'authenticated_offline_runtime_member_invalid',
    'authenticated_offline_runtime_changed', 'authenticated_offline_runtime_exceeds_bounds',
    'offline_recovery_runtime_failed', 'offline_recovery_runtime_invalid', 'offline_recovery_runtime_not_prepared',
    'absolute_runtime_release_required', 'foreign_replica_seed_marker', 'retired_seed_conflict',

    'certbot_lineage_invalid',
    'certbot_lineage_state_incomplete',
    'certbot_lineage_state_changed',
    'certbot_lineage_version_limit',
    'dns_api_request_failed',
    'dns_conflicting_records',
    'dns_duplicate_roles',
    'dns_foreign_record',
    'dns_invalid_address',
    'dns_invalid_credential',
    'dns_invalid_label',
    'dns_invalid_pending',
    'dns_invalid_policy',
    'dns_invalid_receipt',
    'dns_invalid_record',
    'dns_invalid_record_id',
    'dns_invalid_record_name',
    'dns_invalid_records',
    'dns_owned_name_change_requires_migration',
    'dns_pagination_limit',
    'dns_pagination_loop',
    'dns_pending_conflict',
    'dns_pending_create_unconfirmed',
    'dns_pending_policy_changed',
    'dns_private_file_permissions',
    'dns_private_file_required',
    'dns_propagation_timeout',
    'dns_receipt_policy_mismatch',
    'dns_receipt_symlink',
    'dns_reconcile_incomplete',
    'dns_record_drift',
    'dns_response_limit',
    'dns_untrusted_api_url',
    'dns_untrusted_pagination',
    'dns_write_unconfirmed',
    'absolute_private_restore_paths_required',
    'absolute_ssh_files_required',
    'application_artifact_missing',
    'application_database_password_required',
    'backup_monitor_replica_readiness_timeout',
    'bridge_manifests_required',
    'checksum',
    'configuration_too_large',
    'database_intent_changed',
    'database_not_created_by_this_restore',
    'database_restore_requires_inactive_apps',
    'empty_postgres_16_primary_required',
    'explicit_new_bridge_provider_required',
    'external_tablespaces_unsupported',
    'filesystem_error',
    'foreign_unit_symlink',
    'fresh_target_bound_fencing_required',
    'host_command_failed',
    'ingress_must_be_separate',
    'installed_artifact_changed',
    'invalid_bridge_address',
    'invalid_host_phase',
    'invalid_input',
    'invalid_public_name',
    'invalid_readiness_timeout',
    'invalid_restore_directory',
    'invalid_service_user',
    'invalid_ssh_port',
    'invalid_ssh_target',
    'invalid_stage_archive',
    'invalid_state_inventory',
    'local_postgres_uri_required',
    'loopback_admin_api_required',
    'machine_identity_required',
    'new_bridge_address_must_differ',
    'pinned_remote_action_failed',
    'prepared_postgres_16_required',
    'prepared_target_tools_missing',
    'private_state_directory_required',
    'public_ingress_not_ready',
    'referenced_certificate_missing_from_generation',
    'release_incompatible_with_restored_schema',
    'release_schema_bounds_required',
    'replication_automation_state_required',
    'required_restore_state_missing',
    'restore_destination_symlink',
    'restore_marker_conflict',
    'restore_phase_order',
    'restore_receipt_conflict',
    'restored_database_identity_changed',
    'restored_database_schema_changed',
    'restored_public_endpoint_changed',
    'restored_service_resource_missing',
    'restored_table_mismatch',
    'root_target_required',
    'runtime_readiness_timeout',
    'separate_bot_database_unsupported',
    'service_access_capable_release_required',
    'stage_archive_exceeds_bounds',
    'stage_symlink_rejected',
    'stage_transport_checksum_mismatch',
    'staged_manifest_mismatch',
    'subprocess_failed',
    'supported_linux_release_required',
    'symlink',
    'target_already_contains_ultra',
    'target_contains_application_databases',
    'target_disk_insufficient',
    'target_generation_architecture_mismatch',
    'target_machine_changed',
    'target_owned_by_another_restore',
    'timeout',
    'trusted_known_hosts_required',
    'ubuntu_24_04_target_required',
    'unexpected_failure',
    'unique_persisted_exit_tunnel_required',
    'unsupported_database_identifier',
    'unsupported_environment_file',
    'unsupported_environment_syntax',
    'unsupported_environment_value',
    'unsupported_primary_repository',
    'unsupported_replication_credentials',
    'unsupported_restore_destination',
    'unsupported_restore_plan',
    'unsupported_ingress_mode',
    'restored_dns_policy_required',
    'restored_dns_policy_mismatch',
    'verified_public_ingress_required',
    'versioned_release_manifest_required',
    'write_symlink_rejected',
))

def safe_error_code(error):
    if type(error) is ValueError and str(error) in SAFE_ERROR_CODES:
        return str(error)
    import subprocess
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(error, OSError):
        return "filesystem_error"
    if isinstance(error, subprocess.SubprocessError):
        return "subprocess_failed"
    if isinstance(error, (ValueError, KeyError, TypeError)):
        return "invalid_input"
    return "unexpected_failure"
