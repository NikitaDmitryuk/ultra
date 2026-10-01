#!/usr/bin/env bash
# Planned bridge migration between two SSH-accessible Linux hosts.
# Yandex Cloud networking is deliberately out of scope: the cloud owner switches
# the public address/DNS between `freeze` and `activate`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_BIN="${ULTRA_MIGRATE_SSH_BIN:-ssh}"
KNOWN_HOSTS="${HOME}/.ssh/known_hosts"
SOURCE_HOST=""
SOURCE_USER="root"
SOURCE_IDENTITY=""
TARGET_HOST=""
TARGET_USER="root"
TARGET_IDENTITY=""
NEW_PUBLIC_HOST=""
NEW_BRIDGE_IP=""
VERIFY_IP_URL=""
EXPECTED_EXIT_IP=""
VERIFY_USER_UUID=""
TARGET_PUBLIC_IP=""
MINIAPP_INGRESS_IP=""
PAIR_ID=""
FREEZE_GUARD=false
ACTIVATE_GUARD=false
STAGE_GUARD=false
REMOTE_IMPORT_WORK=""
CONFIRM=""
NETWORK_READY=false
NETWORK_RESTORED=false
SKIP_CLIENT_TEST=false
ALLOW_POST_ACTIVATE_DATA_LOSS=false

usage() {
	cat <<'EOF'
Usage:
  scripts/migrate-bridge.sh COMMAND [options]

Commands:
  preflight   Read-only compatibility, sizing and port report.
  stage       Prepare target, stream service state and restore a preliminary DB dump.
  freeze      Stop source writes and restore the final DB dump on target.
  activate    Patch host-dependent settings and start target relay, then bot.
  verify      Check services/API and run the existing end-to-end client probe.
  rollback    Stop target; with --network-restored, start source again.

Required options:
  --source-host HOST              Stable old bridge SSH address or ~/.ssh/config alias.
  --target-host HOST              Stable new bridge SSH address or ~/.ssh/config alias.

SSH options:
  --source-user USER              Default: root.
  --source-identity FILE          Optional source SSH private key.
  --target-user USER              Default: root.
  --target-identity FILE          Optional target SSH private key.
  --known-hosts FILE              Default: ~/.ssh/known_hosts; strict checking is mandatory.

Cutover options:
  --new-public-host HOST          New spec.public_host; omit when preserving the old address.
  --new-bridge-ip IPv4            New ULTRA_VULTR_BRIDGE_IP; required for Vultr automation after IP change.
  --network-ready                 Owner confirms that IP/DNS now routes to target.
  --network-restored              Owner confirms that IP/DNS routes back to source.
  --verify-ip-url HTTPS_URL       Required by verify unless --skip-client-test is explicit.
  --expected-exit-ip IP           Required exit egress IP for the client probe.
  --verify-user-uuid UUID          Optional active VLESS test user.
  --target-public-ip IP           Required target backend IP with Mini App.
  --miniapp-ingress-ip IP         Expected separate public ingress IP.
  --skip-client-test              Diagnostic only, not migration acceptance.
  --allow-post-activate-data-loss Permit rollback after activation; only traffic written during acceptance may be lost.
  --confirm FREEZE|ACTIVATE|ROLLBACK

The script never invokes Yandex Cloud APIs and never prints service secrets.
Both SSH host keys must already be verified in --known-hosts.
SSH endpoints must remain reachable after the service public IP is moved.
EOF
}

log() { printf 'bridge-migration: %s\n' "$*"; }
warn() { printf 'bridge-migration: WARNING: %s\n' "$*" >&2; }
die() { printf 'bridge-migration: ERROR: %s\n' "$*" >&2; exit 1; }

need_local_command() {
	command -v "$1" >/dev/null 2>&1 || die "required local command is missing: $1"
}

shell_quote() {
	printf "'%s'" "${1//\'/\'\"\'\"\'}"
}

parse_args() {
	[[ $# -ge 1 ]] || { usage >&2; exit 2; }
	COMMAND=$1
	shift
	if [[ "$COMMAND" == -h || "$COMMAND" == --help ]]; then usage; exit 0; fi
	case "$COMMAND" in
	preflight | stage | freeze | activate | verify | rollback | help) ;;
	*) usage >&2; die "unknown command: $COMMAND" ;;
	esac
	[[ "$COMMAND" != help ]] || { usage; exit 0; }

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--source-host) SOURCE_HOST=${2:-}; shift 2 ;;
		--source-user) SOURCE_USER=${2:-}; shift 2 ;;
		--source-identity) SOURCE_IDENTITY=${2:-}; shift 2 ;;
		--target-host) TARGET_HOST=${2:-}; shift 2 ;;
		--target-user) TARGET_USER=${2:-}; shift 2 ;;
		--target-identity) TARGET_IDENTITY=${2:-}; shift 2 ;;
		--known-hosts) KNOWN_HOSTS=${2:-}; shift 2 ;;
		--new-public-host) NEW_PUBLIC_HOST=${2:-}; shift 2 ;;
		--new-bridge-ip) NEW_BRIDGE_IP=${2:-}; shift 2 ;;
		--verify-ip-url) VERIFY_IP_URL=${2:-}; shift 2 ;;
		--expected-exit-ip) EXPECTED_EXIT_IP=${2:-}; shift 2 ;;
		--verify-user-uuid) VERIFY_USER_UUID=${2:-}; shift 2 ;;
		--target-public-ip) TARGET_PUBLIC_IP=${2:-}; shift 2 ;;
		--miniapp-ingress-ip) MINIAPP_INGRESS_IP=${2:-}; shift 2 ;;
		--confirm) CONFIRM=${2:-}; shift 2 ;;
		--network-ready) NETWORK_READY=true; shift ;;
		--network-restored) NETWORK_RESTORED=true; shift ;;
		--skip-client-test) SKIP_CLIENT_TEST=true; shift ;;
		--allow-post-activate-data-loss) ALLOW_POST_ACTIVATE_DATA_LOSS=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "unknown option: $1" ;;
		esac
	done

	for value in "$SOURCE_HOST" "$TARGET_HOST" "$SOURCE_USER" "$TARGET_USER" "$NEW_PUBLIC_HOST"; do
		[[ "$value" != -* && "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *" "* ]] || die "invalid host/user input"
	done
	python3 - "$NEW_BRIDGE_IP" "$EXPECTED_EXIT_IP" "$TARGET_PUBLIC_IP" "$MINIAPP_INGRESS_IP" "$VERIFY_IP_URL" <<'PY' || die "invalid probe or IP option"
import ipaddress,sys,urllib.parse
for v in sys.argv[1:5]:
    if v: ipaddress.ip_address(v)
u=urllib.parse.urlsplit(sys.argv[5])
if sys.argv[5] and (u.scheme != "https" or not u.hostname or u.username or u.password or "\n" in sys.argv[5] or "\r" in sys.argv[5]): raise SystemExit(1)
PY
	[[ -n "$SOURCE_HOST" && -n "$TARGET_HOST" ]] || die "--source-host and --target-host are required"
	[[ "$SOURCE_HOST" != "$TARGET_HOST" ]] || die "source and target must differ"
	[[ -r "$KNOWN_HOSTS" ]] || die "known_hosts is not readable: $KNOWN_HOSTS"
	[[ -z "$SOURCE_IDENTITY" || -r "$SOURCE_IDENTITY" ]] || die "source identity is not readable"
	[[ -z "$TARGET_IDENTITY" || -r "$TARGET_IDENTITY" ]] || die "target identity is not readable"
}

ssh_role() {
	local role=$1
	shift
	local host user identity
	case "$role" in
	source) host=$SOURCE_HOST; user=$SOURCE_USER; identity=$SOURCE_IDENTITY ;;
	target) host=$TARGET_HOST; user=$TARGET_USER; identity=$TARGET_IDENTITY ;;
	*) die "internal: invalid SSH role $role" ;;
	esac
	local -a args=(
		-o BatchMode=yes
		-o ConnectTimeout="${ULTRA_SSH_CONNECT_TIMEOUT:-10}"
		-o StrictHostKeyChecking=yes
		-o UserKnownHostsFile="$KNOWN_HOSTS"
	)
	[[ -z "$identity" ]] || args+=(-i "$identity" -o IdentitiesOnly=yes)
	"$SSH_BIN" "${args[@]}" "${user}@${host}" "$@"
}

ssh_effective_port() {
	local role=$1 host user identity out port
	case "$role" in
	source) host=$SOURCE_HOST; user=$SOURCE_USER; identity=$SOURCE_IDENTITY ;;
	target) host=$TARGET_HOST; user=$TARGET_USER; identity=$TARGET_IDENTITY ;;
	*) die "internal: invalid SSH role $role" ;;
	esac
	local -a args=(-G -o "User=$user")
	[[ -z "$identity" ]] || args+=(-i "$identity")
	out=$("$SSH_BIN" "${args[@]}" "$host" 2>/dev/null || true)
	port=$(printf '%s\n' "$out" | awk '$1 == "port" {print $2; exit}')
	printf '%s\n' "${port:-22}"
}

remote_root() {
	local role=$1
	shift
	local quoted="" arg
	for arg in "$@"; do quoted+=" $(shell_quote "$arg")"; done
	# shellcheck disable=SC2029
	ssh_role "$role" "if [ \"\$(id -u)\" -eq 0 ]; then exec bash -s --$quoted; else exec sudo -n bash -s --$quoted; fi"
}

check_connections() {
	ssh_role source true
	ssh_role target true
	remote_root source <<'EOS'
set -eu
true
EOS
	remote_root target <<'EOS'
set -eu
true
EOS
}

kv_get() {
	local data=$1 key=$2
	printf '%s\n' "$data" | awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}'
}

remote_helper() {
	local role=$1
	shift
	{
		printf '%s\n' 'set -euo pipefail' 'umask 077' "python3 - \"\$@\" <<'ULTRA_MIGRATE_HELPER'"
		cat "$SCRIPT_DIR/bridge-migration-state.py"
		printf '\n%s\n' 'ULTRA_MIGRATE_HELPER'
	} | remote_root "$role" "$@"
}

remote_env_prefix() {
	# Secret values are evaluated only on the server, never sent to the operator.
	printf '%s\n' "settings=\$(python3 - env <<'ULTRA_MIGRATE_HELPER'"
	cat "$SCRIPT_DIR/bridge-migration-state.py"
	# Expanded by the remote shell, not the operator.
# shellcheck disable=SC2016
	printf '\n%s\n' 'ULTRA_MIGRATE_HELPER' ')' 'eval "$settings"'
}

source_inventory() {
	remote_root source <<'EOS'
# ULTRA_MIGRATE_SOURCE_INVENTORY
set -euo pipefail
spec=/etc/ultra-relay/spec.json
env_file=/etc/ultra-relay/environment
[[ -r "$spec" ]] || { echo 'missing source spec' >&2; exit 20; }
[[ -r "$env_file" ]] || { echo 'missing source environment' >&2; exit 20; }
[[ -x /usr/local/bin/ultra-relay ]] || { echo 'missing source relay binary' >&2; exit 20; }
command -v python3 >/dev/null
python3 -c 'import sys; assert sys.version_info >= (3,8)'
command -v pg_dump >/dev/null
command -v psql >/dev/null
. /etc/os-release
printf 'OS_ID=%s\n' "${ID:-unknown}"
printf 'OS_VERSION=%s\n' "${VERSION_ID:-unknown}"
printf 'ARCH=%s\n' "$(uname -m)"
printf 'MACHINE_ID=%s\n' "$(cat /etc/machine-id)"
printf 'CPU_COUNT=%s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
printf 'MEM_BYTES=%s\n' "$(awk '/MemTotal/ {printf "%.0f\\n", $2 * 1024}' /proc/meminfo)"
python3 - "$spec" <<'PY'
import json, sys, urllib.parse
d=json.load(open(sys.argv[1], encoding='utf-8'))
db=urllib.parse.urlparse((d.get('database') or {}).get('dsn',''))
host=(db.hostname or '').lower()
local=host in ('', '127.0.0.1', 'localhost', '::1')
ports=[d.get('vless_port')]
anti=d.get('anti_censor') or {}
if anti.get('public_xhttp_port'): ports.append(anti['public_xhttp_port'])
socks=d.get('socks5') or {}
if socks.get('enabled') and socks.get('listen_address','').startswith(('0.0.0.0:', '[::]:')): ports.append(socks.get('port'))
admin=d.get('admin_listen','')
print('DB_LOCAL=' + ('yes' if local else 'no'))
print('DB_NAME=' + urllib.parse.unquote(db.path.lstrip('/')))
print('DB_USER=' + urllib.parse.unquote(db.username or ''))
print('PUBLIC_HOST=' + str(d.get('public_host','')))
print('PUBLIC_PORTS=' + ','.join(str(x) for x in ports if isinstance(x,int) and x>0))
print('ADMIN_LOOPBACK=' + ('yes' if admin.startswith(('127.0.0.1:', 'localhost:')) else 'no'))
PY
db_name=$(python3 - "$spec" <<'PY'
import json,sys,urllib.parse
d=json.load(open(sys.argv[1], encoding='utf-8'))
print(urllib.parse.unquote(urllib.parse.urlparse(d['database']['dsn']).path.lstrip('/')))
PY
)
[[ "$db_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo 'unsafe database name' >&2; exit 21; }
db_bytes=$(runuser -u postgres -- psql -Atq -d postgres -v ON_ERROR_STOP=1 -c "SELECT pg_database_size('$db_name')")
state_paths=(/etc/ultra-relay /var/lib/ultra-relay /usr/local/bin/ultra-relay)
[[ ! -e /var/lib/ultra-bot ]] || state_paths+=(/var/lib/ultra-bot)
[[ ! -e /usr/local/bin/ultra-bot ]] || state_paths+=(/usr/local/bin/ultra-bot)
state_bytes=$(du -sb "${state_paths[@]}" | awk '{s+=$1} END {print s+0}')
start=$(date +%s)
dump_bytes=$(runuser -u postgres -- pg_dump -Fc --no-owner --no-acl "$db_name" | wc -c)
elapsed=$(( $(date +%s) - start ))
printf 'DB_BYTES=%s\n' "$db_bytes"
printf 'STATE_BYTES=%s\n' "$state_bytes"
printf 'DUMP_BYTES=%s\n' "$dump_bytes"
printf 'DUMP_SECONDS=%s\n' "$elapsed"
printf 'PG_MAJOR=%s\n' "$(runuser -u postgres -- psql -Atq -d postgres -c 'SHOW server_version_num' | cut -c1-2)"
bot_domain=$(sed -n 's/^ULTRA_BOT_DOMAIN=//p' "$env_file" | head -1)
bot_port=$(sed -n 's/^ULTRA_BOT_PORT=//p' "$env_file" | head -1)
printf 'BOT_ENABLED=%s\n' "$([[ -x /usr/local/bin/ultra-bot && -n "$bot_domain" ]] && echo yes || echo no)"
printf 'BOT_DOMAIN=%s\n' "$bot_domain"
printf 'BOT_PORT=%s\n' "$bot_port"
printf 'HAS_VULTR=%s\n' "$(grep -q '^ULTRA_VULTR_KEY_FILE=' "$env_file" && echo yes || echo no)"
printf 'HAS_SOCKS_USERS=%s\n' "$(runuser -u postgres -- psql -Atq -d "$db_name" -c "SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE kind='socks5' AND is_active) THEN 'yes' ELSE 'no' END" 2>/dev/null || echo unknown)"
[[ -f /etc/systemd/system/ultra-relay.service ]] || { echo 'missing source relay systemd unit' >&2; exit 22; }
while IFS='=' read -r key value; do
	case "$key" in ULTRA_*_KEY_FILE) ;; *) continue ;; esac
	value=${value%$'\r'}; value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
	[[ "$value" != /* || -r "$value" ]] || { echo "unreadable configured key file: $key" >&2; exit 22; }
done <"$env_file"
while IFS= read -r value; do [[ -r "$value" ]] || { echo 'unreadable public XHTTP TLS file' >&2; exit 22; }; done < <(python3 - "$spec" <<'PY'
import json,sys
t=(json.load(open(sys.argv[1], encoding='utf-8')).get('public_xhttp_tls') or {})
for key in ('certificate_file','key_file'):
    value=t.get(key)
    if isinstance(value,str) and value.startswith('/'): print(value)
PY
)
if [[ -n "$bot_domain" ]]; then
	command -v certbot >/dev/null
	[[ -x /usr/local/bin/ultra-bot && -f /etc/systemd/system/ultra-bot.service && -r /etc/ultra-relay/bot.env ]] || { echo 'incomplete bot installation' >&2; exit 22; }
	[[ -r "/etc/letsencrypt/live/$bot_domain/fullchain.pem" && -r "/etc/letsencrypt/live/$bot_domain/privkey.pem" ]] || { echo 'missing active bot certificate' >&2; exit 22; }
	[[ -r "/etc/letsencrypt/renewal/$bot_domain.conf" && -x /etc/letsencrypt/renewal-hooks/deploy/ultra-bot ]] || { echo 'missing bot certificate renewal config or hook' >&2; exit 22; }
fi
EOS
}

target_inventory() {
	local source_db=$1
	remote_root target "$SOURCE_HOST" "$source_db" "$2" "$3" <<'EOS'
# ULTRA_MIGRATE_TARGET_INVENTORY
set -euo pipefail
source_host=$1
source_db=$2
command -v python3 >/dev/null
python3 -c 'import sys; assert sys.version_info >= (3,8)'
for renewal in /etc/letsencrypt/renewal/*.conf; do
	[[ ! -e "$renewal" || "$renewal" == "/etc/letsencrypt/renewal/$4.conf" ]] || { echo 'target has unrelated certificates; use a dedicated VM' >&2; exit 1; }
done
if id postgres >/dev/null 2>&1 && command -v psql >/dev/null 2>&1; then
	other=$(runuser -u postgres -- psql -XAtq -d postgres -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','${source_db//\'/\'\'}')" 2>/dev/null) || { echo 'cannot inspect target PostgreSQL cluster' >&2; exit 1; }
	[[ "$other" == 0 ]] || { echo 'target has unrelated PostgreSQL databases; use a dedicated VM' >&2; exit 1; }
fi
. /etc/os-release
printf 'OS_ID=%s\n' "${ID:-unknown}"
printf 'OS_VERSION=%s\n' "${VERSION_ID:-unknown}"
printf 'ARCH=%s\n' "$(uname -m)"
printf 'MACHINE_ID=%s\n' "$(cat /etc/machine-id)"
printf 'CPU_COUNT=%s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
printf 'MEM_BYTES=%s\n' "$(awk '/MemTotal/ {printf "%.0f\\n", $2 * 1024}' /proc/meminfo)"
python3 - "$3" <<'PY'
import json,pathlib,shutil,sys
locations=json.loads(sys.argv[1])+['/var/lib/postgresql','/var/tmp','/var/backups','/etc','/usr/local']
free=[]
for location in locations:
    p=pathlib.Path(location)
    while not p.exists(): p=p.parent
    free.append(shutil.disk_usage(p).free)
print('FREE_BYTES='+str(min(free)))
PY
marker=/var/lib/ultra-relay/bridge-migration/source
if [[ -r "$marker" && "$(cat "$marker")" == "$source_host" ]]; then
	echo 'TARGET_STATE=staged'
else
	occupied=false
	for p in /etc/ultra-relay /var/lib/ultra-relay /var/lib/ultra-bot \
		/usr/local/bin/ultra-relay /usr/local/bin/ultra-bot \
		/etc/systemd/system/ultra-relay.service /etc/systemd/system/ultra-bot.service; do
		[[ ! -e "$p" ]] || occupied=true
	done
	if id postgres >/dev/null 2>&1 && command -v psql >/dev/null 2>&1 && \
		[[ "$(runuser -u postgres -- psql -Atq -d postgres -v ON_ERROR_STOP=1 -c "SELECT 1 FROM pg_database WHERE datname='${source_db//\'/\'\'}'" 2>/dev/null || true)" == 1 ]]; then
		occupied=true
	fi
	$occupied && echo 'TARGET_STATE=foreign' || echo 'TARGET_STATE=empty'
fi
printf 'PG_MAJOR=%s\n' "$(psql --version 2>/dev/null | sed -E 's/.* ([0-9]+).*/\1/' || true)"
EOS
}

preflight_core() {
	need_local_command "$SSH_BIN"
	need_local_command awk
	check_connections
	local src dst extra
	extra=$(remote_helper source validate) || die "unsupported source state, renewal or database configuration"
	src=$(source_inventory) || die "source inventory failed"
	dst=$(target_inventory "$(kv_get "$src" DB_NAME)" "$(kv_get "$extra" LOCATIONS)" "$(kv_get "$extra" BOT_DOMAIN)") || die "target inventory failed"

	local src_os src_arch dst_os dst_arch target_state
	src_os=$(kv_get "$src" OS_ID)
	dst_os=$(kv_get "$dst" OS_ID)
	src_arch=$(kv_get "$src" ARCH)
	dst_arch=$(kv_get "$dst" ARCH)
	target_state=$(kv_get "$dst" TARGET_STATE)
	[[ "$src_os" =~ ^(ubuntu|debian)$ && "$dst_os" =~ ^(ubuntu|debian)$ ]] || die "only Debian/Ubuntu hosts are supported"
	[[ "$src_arch" == x86_64 ]] || die "only Linux/amd64 bridge migration is supported (source=$src_arch)"
	[[ "$src_arch" == "$dst_arch" ]] || die "architecture mismatch: source=$src_arch target=$dst_arch"
	[[ -n "$(kv_get "$src" MACHINE_ID)" && "$(kv_get "$src" MACHINE_ID)" != "$(kv_get "$dst" MACHINE_ID)" ]] || die "source and target resolve to the same machine"
	[[ "$(kv_get "$src" DB_LOCAL)" == yes ]] || die "source PostgreSQL is not co-located with bridge"
	[[ "$(kv_get "$src" ADMIN_LOOPBACK)" == yes ]] || die "source Admin API is not loopback-only"
	[[ "$target_state" != foreign ]] || die "target already contains unrelated Ultra state"

	PAIR_ID="$(kv_get "$src" MACHINE_ID):$(kv_get "$dst" MACHINE_ID)"
	local source_pg target_pg
	source_pg=$(kv_get "$src" PG_MAJOR); target_pg=$(kv_get "$dst" PG_MAJOR)
	[[ -z "$target_pg" || "$target_pg" == "$source_pg" ]] || die "target PostgreSQL major must match source"
	local required free src_cpu dst_cpu src_mem dst_mem
	[[ "$(kv_get "$extra" EXTRA_STATE_BYTES)" =~ ^[0-9]+$ ]] || die "invalid source state size"
	required=$(( $(kv_get "$src" DB_BYTES) * 3 + $(kv_get "$extra" EXTRA_STATE_BYTES) * 3 + $(kv_get "$src" DUMP_BYTES) * 2 + 1073741824 ))
	free=$(kv_get "$dst" FREE_BYTES)
	(( free >= required )) || die "insufficient target disk: need at least $required bytes, have $free"
	src_cpu=$(kv_get "$src" CPU_COUNT); dst_cpu=$(kv_get "$dst" CPU_COUNT)
	src_mem=$(kv_get "$src" MEM_BYTES); dst_mem=$(kv_get "$dst" MEM_BYTES)
	(( dst_cpu >= src_cpu )) || die "target has fewer CPUs ($dst_cpu < $src_cpu)"
	(( dst_mem >= src_mem )) || die "target has less RAM ($dst_mem < $src_mem)"

	log "preflight OK"
	log "source: ${src_os} $(kv_get "$src" OS_VERSION), ${src_arch}, PostgreSQL $(kv_get "$src" PG_MAJOR)"
	log "database: $(kv_get "$src" DB_BYTES) bytes; compressed test dump: $(kv_get "$src" DUMP_BYTES) bytes in $(kv_get "$src" DUMP_SECONDS)s"
	log "target free space: ${free} bytes; required reserve: ${required} bytes; state: ${target_state}"
	log "public host: $(kv_get "$src" PUBLIC_HOST)"
	local ports bot_port
	ports=$(kv_get "$src" PUBLIC_PORTS)
	bot_port=$(kv_get "$extra" BOT_PORT)
	[[ -z "$bot_port" ]] || ports="${ports}${ports:+,}${bot_port},80"
	[[ "$(kv_get "$src" HAS_SOCKS_USERS)" != yes ]] || ports="${ports},10810-10899"
	log "owner security-group ingress: TCP $(ssh_effective_port target) from operator CIDR; TCP ${ports} from clients; never expose PostgreSQL"
	[[ "$(kv_get "$src" HAS_VULTR)" != yes || -n "$NEW_BRIDGE_IP" || -z "$NEW_PUBLIC_HOST" ]] || die "Vultr automation is configured: supply --new-bridge-ip when changing public_host"

	PREFLIGHT_SOURCE=$src
	PREFLIGHT_BOT_ENABLED=$(kv_get "$extra" BOT_ENABLED)
}

install_target_dependencies() {
	remote_root target "$(kv_get "$PREFLIGHT_SOURCE" PG_MAJOR)" <<'EOS'
set -euo pipefail
. /etc/os-release
[[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || exit 31
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-cache show "postgresql-$1" >/dev/null 2>&1 || { echo 'matching PostgreSQL packages unavailable; prepare target repository' >&2; exit 31; }
apt-get install -y -q "postgresql-$1" curl python3 ca-certificates tar gzip certbot
systemctl enable --now postgresql
systemctl disable --now certbot.timer
systemctl mask certbot.service
id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay
for unit in ultra-bot ultra-relay; do
	if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; systemctl disable "$unit"; fi
done
EOS
	local source_pg target_pg
	source_pg=$(kv_get "$PREFLIGHT_SOURCE" PG_MAJOR)
	target_pg=$(remote_root target <<'EOS'
runuser -u postgres -- psql -Atq -d postgres -c 'SHOW server_version_num' | cut -c1-2
EOS
)
	[[ "$source_pg" =~ ^[0-9]+$ && "$target_pg" =~ ^[0-9]+$ ]] || die "cannot determine PostgreSQL versions"
	[[ "$target_pg" == "$source_pg" ]] || die "target PostgreSQL major must match source"
}

stream_state() {
	log "streaming selected service state; target retains a root-only backup"
	local work import_cmd rc=0
	work=$(remote_root target <<'EOS'
# ULTRA_MIGRATE_IMPORT_TEMP
set -euo pipefail
umask 077
mktemp -d /var/tmp/ultra-migrate-import.XXXXXX
EOS
	) || return 1
	[[ "$work" == /var/tmp/ultra-migrate-import.* && "$work" != *$'\n'* ]] || return 1
	REMOTE_IMPORT_WORK=$work
	{
		printf '%s\n' 'set -euo pipefail' 'umask 077' "tee \"\$1/state.py\" >/dev/null <<'ULTRA_MIGRATE_HELPER'"
		cat "$SCRIPT_DIR/bridge-migration-state.py"
		printf '\n%s\n' 'ULTRA_MIGRATE_HELPER'
	} | remote_root target "$work" || rc=1
	import_cmd="if [ \"\$(id -u)\" -eq 0 ]; then exec python3 $(shell_quote "$work/state.py") import; else exec sudo -n python3 $(shell_quote "$work/state.py") import; fi"
	if [[ "$rc" == 0 ]]; then
		remote_helper source export | ssh_role target "$import_cmd" || rc=1
	fi
	remote_root target "$work" <<'EOS' || rc=1
set -euo pipefail
[[ "$1" == /var/tmp/ultra-migrate-import.* ]]
rm -f -- "$1/state.py"
rmdir -- "$1"
EOS
	[[ "$rc" == 0 ]] || return 1
	REMOTE_IMPORT_WORK=""
	{
		printf '%s\n' 'set -euo pipefail' 'umask 077'
		remote_env_prefix
		cat <<'EOS'
set -euo pipefail
umask 077
printf '%s' "${ULTRA_REPLICATION_KEY_FILE:-}" >/var/lib/ultra-relay/bridge-migration/recovery-path
install -d -m 700 /etc/systemd/system/ultra-relay.service.d
cat >/etc/systemd/system/ultra-relay.service.d/zzzz-bridge-migration.conf <<'UNIT'
[Service]
EnvironmentFile=/var/lib/ultra-relay/bridge-migration/paused.env
UNIT
printf '%s\n' 'ULTRA_REPLICATION_KEY_FILE=' 'ULTRA_VULTR_KEY_FILE=' >/var/lib/ultra-relay/bridge-migration/paused.env
chown -R root:root /var/lib/ultra-relay/bridge-migration
systemctl daemon-reload
EOS
	} | remote_root target
	{
		printf '%s\n' 'set -euo pipefail'
		remote_env_prefix
		# Deliberately evaluated on target.
# shellcheck disable=SC2016
		printf '%s\n' '[[ -z "${ULTRA_REPLICATION_KEY_FILE:-}" && -z "${ULTRA_VULTR_KEY_FILE:-}" ]]'
	} | remote_root target
}

prepare_renewal() {
	# No ACME requests: check the installed runtime and selected renewal config only.
	local version
	version=$(remote_root source <<'EOS'
set -euo pipefail
[[ ! -x /usr/local/bin/ultra-bot ]] || certbot --version 2>/dev/null
EOS
	) || return 1
	{
		printf '%s\n' 'set -euo pipefail' '[[ -x /usr/local/bin/ultra-bot ]] || exit 0'
		printf '%s\n' "settings=\$(python3 - env ultra-bot.service <<'ULTRA_MIGRATE_HELPER'"
		cat "$SCRIPT_DIR/bridge-migration-state.py"
		# Evaluated on target only.
		# shellcheck disable=SC2016
		printf '\n%s\n' 'ULTRA_MIGRATE_HELPER' ')' 'eval "$settings"'
		cat <<'EOS'
# ULTRA_MIGRATE_RENEWAL_PREPARE
python3 - "$1" <<'PY'
import re,subprocess,sys
def version(value):
    match=re.search(r'certbot ([0-9]+(?:\.[0-9]+)+)',value)
    if not match: raise SystemExit('cannot determine Certbot version')
    return tuple(map(int,match.group(1).split('.')))
result=subprocess.run(['certbot','--version'],text=True,capture_output=True,check=True)
if version(result.stdout)<version(sys.argv[1]): raise SystemExit('target Certbot is older; prepare a compatible runtime before cutover')
PY
certbot certificates --cert-name "$ULTRA_BOT_DOMAIN" >/dev/null 2>&1
systemctl cat certbot.timer >/dev/null
EOS
	} | remote_root target "$version"
}

prepare_recovery() {
	{
		cat <<'EOS'
# ULTRA_MIGRATE_PREPARE_RECOVERY
set -euo pipefail
path=$(cat /var/lib/ultra-relay/bridge-migration/recovery-path)
[[ -n "$path" ]] || exit 0
[[ -r "$path" ]] || exit 1
export ULTRA_RECOVERY_CONFIG_FILE="$path" ULTRA_RECOVERY_DB_ONLY=1 ULTRA_RECOVERY_ALLOW_RESTART=1
EOS
		cat "$SCRIPT_DIR/../internal/install/scripts/recovery-primary.sh"
	} | remote_root target
}

compare_database() {
	local src dst
	src=$(remote_helper source database-fingerprint) || return 1
	dst=$(remote_helper target database-fingerprint) || return 1
	[[ -n "$src" && "$src" == "$dst" ]] || { warn "restored database content differs"; return 1; }
	log "frozen database contents match"
}

prepare_target_database() {
	remote_root target "$1" <<'EOS'
set -euo pipefail
mode=$1
spec=/etc/ultra-relay/spec.json
backup_root=/var/backups/ultra-bridge-migration
install -d -m 700 "$backup_root"
python3 - "$spec" "$mode" "$backup_root" <<'PY'
import json, os, subprocess, sys, urllib.parse, tempfile, datetime
spec, mode, backup_root=sys.argv[1:]
dsn=(json.load(open(spec, encoding='utf-8')).get('database') or {}).get('dsn','')
u=urllib.parse.urlparse(dsn)
host=(u.hostname or '').lower()
if host not in ('', '127.0.0.1', 'localhost', '::1'):
    raise SystemExit('database DSN is not local')
role=urllib.parse.unquote(u.username or '')
password=urllib.parse.unquote(u.password or '')
dbname=urllib.parse.unquote(u.path.lstrip('/'))
if not role or not password or not dbname or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for c in role+dbname):
    raise SystemExit('invalid local database DSN')
def sql_ident(v): return '"'+v.replace('"','""')+'"'
def sql_literal(v): return "'"+v.replace("'", "''")+"'"
def run(*args, input=None):
    result=subprocess.run(args, input=input, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode: raise SystemExit('target PostgreSQL command failed; diagnostics suppressed')
psql=['runuser','-u','postgres','--','psql','-X','-v','ON_ERROR_STOP=1','-d','postgres']
run(*psql, input="ALTER SYSTEM SET timezone='UTC'; ALTER SYSTEM SET log_timezone='UTC'; ALTER SYSTEM SET listen_addresses='localhost';\n")
exists=subprocess.run(psql+['-Atq','-c',"SELECT 1 FROM pg_roles WHERE rolname="+sql_literal(role)], text=True, capture_output=True, check=True).stdout.strip()
if not exists:
    run(*psql, input=f'CREATE ROLE {sql_ident(role)} LOGIN PASSWORD {sql_literal(password)};\n')
else:
    run(*psql, input=f'ALTER ROLE {sql_ident(role)} PASSWORD {sql_literal(password)};\n')
db_exists=subprocess.run(psql+['-Atq','-c',"SELECT 1 FROM pg_database WHERE datname="+sql_literal(dbname)], text=True, capture_output=True, check=True).stdout.strip()
if db_exists and mode == 'reset':
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    fd,backup=tempfile.mkstemp(prefix='target-before-restore-'+stamp+'-',suffix='.dump',dir=backup_root)
    with os.fdopen(fd,'wb') as output:
        result=subprocess.run(['runuser','-u','postgres','--','pg_dump','-Fc','--no-owner','--no-acl',dbname],stdout=output,stderr=subprocess.PIPE)
    if result.returncode: raise SystemExit('target database backup failed; original database retained')
    run(*psql, input=f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname={sql_literal(dbname)} AND pid<>pg_backend_pid();\n")
    run('runuser','-u','postgres','--','dropdb',dbname)
    db_exists=''
if not db_exists:
    run('runuser','-u','postgres','--','createdb','--owner',role,dbname)
run(*psql, input="SELECT pg_reload_conf();\n")
run('systemctl','restart','postgresql')
print(dbname+'\t'+role)
PY
EOS
}

stream_database() {
	local mode=$1 db_info db_name db_user start
	db_info=$(prepare_target_database "$mode") || return 1
	IFS=$'\t' read -r db_name db_user <<<"$db_info"
	[[ "$db_name" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
	[[ "$db_user" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
	log "streaming PostgreSQL logical dump"
	start=$SECONDS
	local source_cmd target_cmd
	source_cmd="if [ \"\$(id -u)\" -eq 0 ]; then exec runuser -u postgres -- pg_dump -Fc --no-owner --no-acl $(shell_quote "$db_name") 2>/dev/null; else exec sudo -n -u postgres pg_dump -Fc --no-owner --no-acl $(shell_quote "$db_name") 2>/dev/null; fi"
	target_cmd="if [ \"\$(id -u)\" -eq 0 ]; then exec runuser -u postgres -- pg_restore --exit-on-error --no-owner --no-acl --role=$(shell_quote "$db_user") -d $(shell_quote "$db_name") 2>/dev/null; else exec sudo -n -u postgres pg_restore --exit-on-error --no-owner --no-acl --role=$(shell_quote "$db_user") -d $(shell_quote "$db_name") 2>/dev/null; fi"
	# pipefail is inherited: a failed dump or restore fails the phase.
	ssh_role source "$source_cmd" | ssh_role target "$target_cmd" || return 1
	log "logical dump/restore completed in $((SECONDS - start))s"
}

set_marker() {
	remote_root target "$1" "$PAIR_ID" "$SOURCE_HOST" <<'EOS'
# ULTRA_MIGRATE_SET_MARKER
set -euo pipefail
umask 077
dir=/var/lib/ultra-relay/bridge-migration
install -d -m 700 "$dir"
chown root:root "$dir"
for entry in "pair:$2" "source:$3" "state:$1"; do
	key=${entry%%:*}; value=${entry#*:}
	tmp=$(mktemp "$dir/.marker.XXXXXX")
	printf '%s' "$value" >"$tmp"
	chmod 600 "$tmp"
	mv "$tmp" "$dir/$key"
done
EOS
}

marker_state() {
	remote_root target "$PAIR_ID" <<'EOS'
# ULTRA_MIGRATE_MARKER_STATE
set -euo pipefail
dir=/var/lib/ultra-relay/bridge-migration
[[ ! -f "$dir/state" ]] || {
	[[ -s "$dir/pair" && "$(cat "$dir/pair")" == "$1" ]] || { echo 'migration pair mismatch' >&2; exit 1; }
	cat "$dir/state"
}
EOS
}

identify_pair() {
	local src dst
	src=$(remote_root source <<'EOS'
cat /etc/machine-id
EOS
	) || return 1
	dst=$(remote_root target <<'EOS'
cat /etc/machine-id
EOS
	) || return 1
	[[ -n "$src" && -n "$dst" && "$src" != "$dst" ]] || return 1
	PAIR_ID="$src:$dst"
}

stop_target() {
	remote_root target <<'EOS'
# ULTRA_MIGRATE_STOP_TARGET
set -euo pipefail
if systemctl cat certbot.service >/dev/null 2>&1; then
	systemctl disable --now certbot.timer
	systemctl stop certbot.service
	systemctl mask certbot.service
fi
for unit in ultra-bot ultra-relay ultra-migrate-probe; do
	if systemctl cat "$unit" >/dev/null 2>&1; then
		systemctl stop "$unit"
		systemctl disable "$unit"
		if systemctl is-active --quiet "$unit"; then exit 1; fi
	fi
done
EOS
}

source_stopped() {
	remote_root source <<'EOS'
# ULTRA_MIGRATE_SOURCE_STOPPED
set -euo pipefail
for unit in ultra-relay ultra-bot certbot.service certbot.timer; do
	if systemctl is-active --quiet "$unit"; then exit 1; fi
done
EOS
}

phase_cleanup() {
	local rc=$?
	trap - EXIT INT TERM
	if [[ -n "$REMOTE_IMPORT_WORK" ]]; then
		remote_root target "$REMOTE_IMPORT_WORK" <<'EOS' || warn "could not remove remote importer; remove restricted temp directory manually"
set -euo pipefail
[[ "$1" == /var/tmp/ultra-migrate-import.* ]]
rm -f -- "$1/state.py"
rmdir -- "$1"
EOS
	fi
	if [[ "$STAGE_GUARD" == true && "$rc" != 0 ]]; then
		stop_target || warn "staged target stop unconfirmed"
		set_marker stage_failed || warn "could not record failed stage"
	fi
	if [[ "$FREEZE_GUARD" == true ]]; then
		if stop_target; then
			if restart_source; then
				set_marker stage_failed || warn "could not record failed freeze"
				warn "freeze failed; original source services restored"
			else warn "source recovery failed; manual intervention required"; fi
		else warn "target stop unconfirmed; source NOT restarted to prevent two primaries"; fi
	fi
	if [[ "$ACTIVATE_GUARD" == true ]]; then
		if stop_target; then set_marker activation_failed || warn "could not record failed activation"
		else warn "target stop unconfirmed; do not start source"; fi
	fi
	exit "$rc"
}

stage_relay_probe() {
	{
		printf '%s\n' 'set -euo pipefail' 'umask 077'
		remote_env_prefix
		cat <<'EOS'
# ULTRA_MIGRATE_STAGE_PROBE
unit=/run/systemd/system/ultra-migrate-probe.service
tmp=$(mktemp -d /var/tmp/ultra-migrate-probe.XXXXXX)
cleanup() {
	systemctl stop ultra-migrate-probe || return 1
	if systemctl is-active --quiet ultra-migrate-probe; then return 1; fi
	rm -f "$unit" "$tmp/hardening.json"
	rmdir "$tmp"
	systemctl daemon-reload
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
systemctl cat ultra-relay >"$unit"
printf '\n[Service]\nRestart=no\nEnvironmentFile=/var/lib/ultra-relay/bridge-migration/paused.env\n' >>"$unit"
systemctl daemon-reload
systemctl start ultra-migrate-probe
for _ in $(seq 1 60); do
	if curl -fsS -H "Authorization: Bearer $ULTRA_RELAY_ADMIN_TOKEN" "$ADMIN_URL/v1/hardening" >"$tmp/hardening.json" 2>/dev/null &&
		python3 - "$tmp/hardening.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])).get('reload') or {}
raise SystemExit(0 if not r.get('error') and int(r.get('count') or 0)>0 else 1)
PY
	then exit 0; fi
	systemctl is-active --quiet ultra-migrate-probe || exit 42
	sleep 1
done
echo 'staged relay readiness failed; inspect server logs locally' >&2
exit 43
EOS
	} | remote_root target
}

stage() {
	preflight_core
	local state
	state=$(marker_state) || die "cannot verify migration pair/state"
	case "$state" in ""|staging|staged|stage_failed) ;; *) die "stage is forbidden after freeze or activation" ;; esac
	set_marker staging
	STAGE_GUARD=true
	if [[ "$PREFLIGHT_BOT_ENABLED" == yes && -z "$TARGET_PUBLIC_IP" ]]; then
		warn "supply --target-public-ip at activation for direct Mini App backend verification"
	fi
	install_target_dependencies
	stream_state
	prepare_renewal
	stream_database reset
	prepare_recovery
	stage_relay_probe
	set_marker staged
	STAGE_GUARD=false
	log "stage complete; target relay and bot are stopped"
}

restart_source() {
	local active
	active=$(remote_root source <<'EOS'
# ULTRA_MIGRATE_RESTART_SOURCE
set -euo pipefail
saved=/var/lib/ultra-relay/bridge-migration-source/services
[[ -s "$saved" ]] || exit 1
while read -r unit enabled active; do
	if [[ "$enabled" == enabled ]]; then systemctl enable "$unit"; fi
	if [[ "$unit" == ultra-relay && "$active" == active ]]; then systemctl start "$unit"; systemctl is-active --quiet "$unit"; echo yes; fi
done <"$saved"
EOS
	) || return 1
	if [[ "$active" == *yes* ]]; then target_api_check source || return 1; fi
	remote_root source <<'EOS'
set -euo pipefail
if systemctl cat certbot.service >/dev/null 2>&1; then systemctl unmask certbot.service; fi
while read -r unit enabled active; do
	if [[ "$unit" == ultra-bot && "$active" == active ]]; then systemctl start "$unit"; systemctl is-active --quiet "$unit"; fi
done </var/lib/ultra-relay/bridge-migration-source/services
while read -r unit enabled active; do
	if [[ "$unit" == certbot.* && "$active" == active ]]; then systemctl start "$unit"; fi
done </var/lib/ultra-relay/bridge-migration-source/services
EOS
}

freeze() {
	[[ "$CONFIRM" == FREEZE ]] || die "freeze requires --confirm FREEZE"
	identify_pair || die "cannot identify migration pair"
	[[ "$(marker_state)" == staged ]] || die "target must be successfully staged first"
	preflight_core
	stop_target
	FREEZE_GUARD=true
	trap phase_cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	remote_root source <<'EOS'
# ULTRA_MIGRATE_FREEZE_SOURCE
set -euo pipefail
umask 077
dir=/var/lib/ultra-relay/bridge-migration-source
install -d -m 700 "$dir"
tmp=$(mktemp "$dir/.services.XXXXXX")
for unit in ultra-relay ultra-bot certbot.service certbot.timer; do
	if systemctl cat "$unit" >/dev/null 2>&1; then
		enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
		active=$(systemctl is-active "$unit" 2>/dev/null || true)
		[[ "$enabled" == enabled || "$enabled" == disabled || "$enabled" == static ]] || { echo 'unsupported source enable state' >&2; exit 1; }
		printf '%s %s %s\n' "$unit" "$enabled" "$active" >>"$tmp"
	fi
done
mv "$tmp" "$dir/services"
if systemctl cat certbot.service >/dev/null 2>&1; then
	systemctl disable --now certbot.timer
	systemctl stop certbot.service
	systemctl mask certbot.service
fi
for unit in ultra-bot ultra-relay; do
	if systemctl cat "$unit" >/dev/null 2>&1; then
		systemctl disable "$unit"
		systemctl stop "$unit"
		if systemctl is-active --quiet "$unit"; then exit 51; fi
	fi
done
EOS
	source_stopped
	set_marker freezing
	stream_state
	prepare_renewal
	stream_database reset
	prepare_recovery
	remote_helper target check
	compare_database
	source_stopped
	set_marker frozen
	FREEZE_GUARD=false
	trap - EXIT INT TERM
	log "source frozen; final files and database verified; ask owner to switch IP/DNS"
}

patch_target_host() {
	remote_root target "$NEW_PUBLIC_HOST" "$NEW_BRIDGE_IP" <<'EOS'
set -euo pipefail
new_public=$1
new_ip=$2
spec=/etc/ultra-relay/spec.json
env_file=/etc/ultra-relay/environment
if [[ -n "$new_public" ]]; then
	python3 - "$spec" "$new_public" <<'PY'
import json, os, sys, tempfile
path,value=sys.argv[1:]
d=json.load(open(path, encoding='utf-8'))
d['public_host']=value
fd,tmp=tempfile.mkstemp(prefix='.spec.', dir=os.path.dirname(path))
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(d,f,ensure_ascii=False,indent=2); f.write('\n')
    os.chmod(tmp,0o600); os.replace(tmp,path)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
fi
if [[ -n "$new_ip" ]]; then
	tmp=$(mktemp /etc/ultra-relay/.environment.XXXXXX)
	grep -v '^ULTRA_VULTR_BRIDGE_IP=' "$env_file" >"$tmp" || true
	printf 'ULTRA_VULTR_BRIDGE_IP=%s\n' "$new_ip" >>"$tmp"
	chmod 600 "$tmp"; chown ultra-relay:ultra-relay "$tmp"; mv "$tmp" "$env_file"
fi
chown ultra-relay:ultra-relay "$spec" "$env_file"
EOS
}

configure_target_firewall() {
	remote_root target <<'EOS'
set -euo pipefail
command -v ufw >/dev/null 2>&1 || exit 0
ufw status 2>/dev/null | grep -q '^Status: active' || exit 0
python3 - /etc/ultra-relay/spec.json /etc/ultra-relay/environment <<'PY' | while read -r port; do ufw allow "$port/tcp" >/dev/null; done
import json,sys
d=json.load(open(sys.argv[1], encoding='utf-8'))
ports={d.get('vless_port')}
a=d.get('anti_censor') or {}
if a.get('public_xhttp_port'): ports.add(a['public_xhttp_port'])
env={}
for line in open(sys.argv[2], encoding='utf-8'):
    if '=' in line and not line.lstrip().startswith('#'):
        k,v=line.rstrip('\n').split('=',1); env[k]=v
if env.get('ULTRA_BOT_DOMAIN'):
    ports.add(80)
    try: ports.add(int(env.get('ULTRA_BOT_PORT','8444')))
    except ValueError: pass
for p in sorted(x for x in ports if isinstance(x,int) and 0<x<65536): print(p)
PY
EOS
}

target_api_check() {
	local role=${1:-target}
	{
		printf '%s\n' 'set -euo pipefail'
		remote_env_prefix
		cat <<'EOS'
# ULTRA_MIGRATE_API_CHECK
[[ -n "$ULTRA_RELAY_ADMIN_TOKEN" ]]
for _ in $(seq 1 90); do
	if health=$(curl -fsS -H "Authorization: Bearer $ULTRA_RELAY_ADMIN_TOKEN" "$ADMIN_URL/v1/health" 2>/dev/null) &&
	   hardening=$(curl -fsS -H "Authorization: Bearer $ULTRA_RELAY_ADMIN_TOKEN" "$ADMIN_URL/v1/hardening" 2>/dev/null); then
		if HEALTH="$health" HARDENING="$hardening" python3 - <<'PY'
import json,os
h=json.loads(os.environ['HEALTH']); d=json.loads(os.environ['HARDENING'])
r=d.get('reload') or {}
if r.get('error') or int(r.get('count') or 0)<1: raise SystemExit(1)
if not h.get('active_exit_id') or not (h.get('bridge') or {}).get('reachable'): raise SystemExit(1)
PY
		then exit 0; fi
	fi
	sleep 1
done
echo 'relay readiness failed; inspect restricted server logs locally' >&2
exit 61
EOS
	} | remote_root "$role"
}

activate() {
	[[ "$CONFIRM" == ACTIVATE ]] || die "activate requires --confirm ACTIVATE"
	[[ "$NETWORK_READY" == true ]] || die "activate requires --network-ready after owner switches IP/DNS"
	identify_pair || die "cannot identify migration pair"
	[[ "$(marker_state)" == frozen ]] || die "target must have the final frozen state"
	[[ "$SKIP_CLIENT_TEST" == false && -n "$EXPECTED_EXIT_IP" && -n "$VERIFY_IP_URL" ]] || die "activation requires a real client probe with --verify-ip-url and --expected-exit-ip"
	source_stopped
	remote_root target "$TARGET_PUBLIC_IP" <<'EOS'
set -euo pipefail
[[ ! -x /usr/local/bin/ultra-bot || -n "$1" ]] || { echo 'bot activation requires --target-public-ip' >&2; exit 1; }
EOS
	remote_helper target check
	ACTIVATE_GUARD=true
	trap phase_cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	set_marker activating
	patch_target_host
	configure_target_firewall
	remote_root target <<'EOS'
# ULTRA_MIGRATE_START_RELAY
set -euo pipefail
systemctl daemon-reload
systemctl enable ultra-relay
systemctl restart ultra-relay
EOS
	target_api_check
	client_probe
	remote_root target <<'EOS'
# ULTRA_MIGRATE_START_BOT
set -euo pipefail
if [[ -x /usr/local/bin/ultra-bot && -f /etc/systemd/system/ultra-bot.service ]]; then
	systemctl enable ultra-bot
	systemctl restart ultra-bot
	systemctl is-active --quiet ultra-bot
	systemctl unmask certbot.service
	systemctl enable --now certbot.timer
fi
EOS
	verify_miniapp
	source_stopped
	set_marker activated
	ACTIVATE_GUARD=false
	trap - EXIT INT TERM
	log "target activated; source stopped; replication/provisioning workers remain paused"
}

verify_remote() {
	remote_root target <<'EOS'
set -euo pipefail
systemctl is-active --quiet ultra-relay
if [[ -x /usr/local/bin/ultra-bot ]]; then systemctl is-active --quiet ultra-bot; fi
runuser -u postgres -- psql -XAtq -d postgres -v ON_ERROR_STOP=1 -c 'SELECT 1' >/dev/null
EOS
}

verify_miniapp() {
	local info domain port public_url
	info=$({
		printf '%s\n' 'set -euo pipefail' '[[ -x /usr/local/bin/ultra-bot ]] || exit 0'
		# Bot public URL may come from any drop-in, not only public-url.conf.
		printf '%s\n' "settings=\$(python3 - env ultra-bot.service <<'ULTRA_MIGRATE_HELPER'"
		cat "$SCRIPT_DIR/bridge-migration-state.py"
		# Remote environment stays on target.
# shellcheck disable=SC2016
		printf '\n%s\n' 'ULTRA_MIGRATE_HELPER' ')' 'eval "$settings"'
		# Return only public bot addresses.
# shellcheck disable=SC2016
		printf '%s\n' 'printf "%s\t%s\t%s\n" "$ULTRA_BOT_DOMAIN" "${ULTRA_BOT_PORT:-8444}" "${ULTRA_BOT_PUBLIC_URL:-}"'
	} | remote_root target) || return 1
	[[ -n "$info" ]] || return 0
	[[ -n "$TARGET_PUBLIC_IP" ]] || { warn "Mini App requires --target-public-ip (not SSH alias)"; return 1; }
	IFS=$'\t' read -r domain port public_url <<<"$info"
	python3 "$SCRIPT_DIR/verify-miniapp.py" "$TARGET_PUBLIC_IP" "$domain" "$port" "$public_url" "$MINIAPP_INGRESS_IP"
}

client_probe() {
	[[ -n "$EXPECTED_EXIT_IP" && "$VERIFY_IP_URL" == https://* ]] || return 1
	local -a args=()
	[[ -z "$TARGET_IDENTITY" ]] || args+=(-i "$TARGET_IDENTITY")
	args+=(-u "$TARGET_USER" "$TARGET_HOST" "$TARGET_HOST")
	VERIFY_IP_URL="$VERIFY_IP_URL" VERIFY_EXPECTED_EXIT_IP="$EXPECTED_EXIT_IP" VERIFY_USER_UUID="$VERIFY_USER_UUID" \
		VERIFY_SPLIT_ROUTING=n VERIFY_SSH_SUDO=yes VERIFY_SSH_STRICT_HOST_KEY=yes VERIFY_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
		"$SCRIPT_DIR/verify-relay.sh" "${args[@]}"
}

verify() {
	identify_pair || die "cannot identify migration pair"
	[[ "$(marker_state)" == activated ]] || die "target is not activated"
	source_stopped
	target_api_check
	verify_remote
	verify_miniapp
	local src_hash dst_hash
	src_hash=$(remote_root source <<'EOS'
sha256sum /usr/local/bin/ultra-relay
if [[ ! -x /usr/local/bin/ultra-bot ]]; then exit 0; fi
sha256sum /usr/local/bin/ultra-bot
EOS
	)
	dst_hash=$(remote_root target <<'EOS'
sha256sum /usr/local/bin/ultra-relay
if [[ ! -x /usr/local/bin/ultra-bot ]]; then exit 0; fi
sha256sum /usr/local/bin/ultra-bot
EOS
	)
	[[ "$src_hash" == "$dst_hash" ]] || die "binary checksums differ"
	if [[ "$SKIP_CLIENT_TEST" == true ]]; then
		warn "client probe skipped; diagnostic checks passed, migration NOT accepted"
		return 0
	fi
	client_probe
	log "verification passed; retain old VM; replication/provisioning remain paused"
}

rollback() {
	[[ "$CONFIRM" == ROLLBACK ]] || die "rollback requires --confirm ROLLBACK"
	local state
	identify_pair || die "cannot identify migration pair"
	state=$(marker_state)
	case "$state" in staged | freezing | frozen | activating | activation_failed | activated | rollback_pending) ;; *) die "nothing to roll back (state=$state)" ;; esac
	if [[ "$state" =~ ^(activated|activating|activation_failed|rollback_pending)$ && "$ALLOW_POST_ACTIVATE_DATA_LOSS" != true ]]; then
		die "post-activation rollback may lose acceptance-window writes; add --allow-post-activate-data-loss after confirming no admin changes"
	fi
	stop_target
	if [[ "$state" == staged ]]; then
		set_marker rolled_back
		log "staged target stopped; source was never frozen"
		return 0
	fi
	set_marker rollback_pending
	if [[ "$NETWORK_RESTORED" != true ]]; then
		log "target stopped; restore old IP/DNS, then rerun rollback with --network-restored --confirm ROLLBACK"
		return 0
	fi
	restart_source
	set_marker rolled_back
	log "source restarted; target remains stopped"
}

main() {
	parse_args "$@"
	trap phase_cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	case "$COMMAND" in
	preflight) preflight_core ;;
	stage) stage ;;
	freeze) freeze ;;
	activate) activate ;;
	verify) verify ;;
	rollback) rollback ;;
	esac
}

main "$@"
