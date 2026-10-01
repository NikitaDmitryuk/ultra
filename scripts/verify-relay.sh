#!/usr/bin/env bash
# Интеграционная проверка: по SSH на bridge читается Admin API, локально поднимается клиент ядра (SOCKS inbound),
# затем HTTPS GET на VERIFY_IP_URL и по умолчанию доп. зонд exit (scripts/verify-split-routing.sh).
#
# Зависимости на машине оператора: ssh, curl, бинарник совместимый с go.mod (в PATH как xray), base64.
# JSON: jq (предпочтительно) или python3.
# Версию клиента ориентируйте по github.com/xtls/xray-core в go.mod репозитория.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-config.sh
source "$SCRIPT_DIR/install-config.sh"

SOCKS_PORT="${VERIFY_SOCKS_PORT:-10808}"

usage() {
	echo "Использование:" >&2
	echo "  $0 [-i identity] [-u ssh_user] [-p socks_port] BRIDGE_HOST EXIT_HOST" >&2
	echo "  $0 [-c install.config] [-i …] [-u …] [-p …]   # хосты из файла (EXIT не используется)" >&2
	echo "  $0 [-i …] [-u …] [-p …]   # без аргументов: корневой install.config, если есть" >&2
	echo "Переменные: VERIFY_USER_UUID, VERIFY_SOCKS_PORT, VERIFY_IP_URL (обязательно — HTTPS URL для первого GET)" >&2
	echo "  VERIFY_SPLIT_ROUTING=n|0 — не вызывать scripts/verify-split-routing.sh (по умолчанию вызывается)" >&2
	echo "  VERIFY_EXPECTED_EXIT_IP — требовать plain-IP ответ и совпадение с выбранным exit" >&2
	echo "  VERIFY_SSH_SUDO=yes — читать серверные настройки через passwordless sudo" >&2
	echo "  VERIFY_PROBE_EXIT_URL / VERIFY_PROBE_EXIT_PLAIN_URL — зонды exit для split (см. verify-split-routing.sh)" >&2
	echo "  VERIFY_SPEC_PATH — путь к spec.json на bridge (по умолчанию /etc/ultra-relay/spec.json; для routing_mode в verify-split)" >&2
	echo "Пример: VERIFY_IP_URL=https://… $0 -c install.config" >&2
	exit 2
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

json_users_first_uuid() {
	if have_cmd jq; then
		jq -r '[.[] | select(.is_active != false and (.kind == "vless" or .kind == null or .kind == ""))][0].uuid // empty' "$1"
	else
		python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); print(next((u["uuid"] for u in a if u.get("is_active",True) and u.get("kind","vless") in ("vless","")), ""))' "$1"
	fi
}

json_client_b64() {
	if have_cmd jq; then
		jq -r '.full_xray_config_base64 // empty' "$1"
	else
		python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("full_xray_config_base64") or "")' "$1"
	fi
}

patch_socks_port() {
	local f=$1
	local p=$2
	if have_cmd jq; then
		jq --argjson port "$p" '(.inbounds |= map(if (.protocol == "socks") then .port = $port else . end))' "$f" >"${f}.tmp"
		mv "${f}.tmp" "$f"
	else
		python3 -c "
import json, sys
p = int(sys.argv[2])
with open(sys.argv[1], 'r') as fp:
    cfg = json.load(fp)
for ib in cfg.get('inbounds', []):
    if ib.get('protocol') == 'socks':
        ib['port'] = p
with open(sys.argv[1], 'w') as fp:
    json.dump(cfg, fp, indent=2)
" "$f" "$p"
	fi
}

port_open() {
	local host=$1
	local port=$2
	if have_cmd nc; then
		nc -z "$host" "$port" 2>/dev/null
		return $?
	fi
	# bash /dev/tcp
	if echo 2>/dev/null >/dev/tcp/"$host"/"$port"; then
		return 0
	fi
	return 1
}

CONFIG_FILE=""
SSH_EXTRA=()
SSH_USER=root

while getopts "c:i:u:p:h" opt; do
	case "$opt" in
	c) CONFIG_FILE=$OPTARG ;;
	i) SSH_EXTRA=(-i "$OPTARG") ;;
	u) SSH_USER="$OPTARG" ;;
	p) SOCKS_PORT="$OPTARG" ;;
	h) usage ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

BRIDGE=""
EXIT=""

if [[ $# -eq 2 ]]; then
	BRIDGE="$1"
	EXIT="$2"
elif [[ -n "$CONFIG_FILE" ]]; then
	if [[ ! -f "$CONFIG_FILE" ]]; then
		echo "Файл конфига не найден: $CONFIG_FILE" >&2
		exit 1
	fi
	load_install_config "$CONFIG_FILE"
	BRIDGE="${BRIDGE:-${FRONT:-}}"
	EXIT="${EXIT:-${BACK:-}}"
	SSH_USER=${SSH_USER:-root}
elif [[ $# -eq 0 ]]; then
	def="$(install_config_default_path)"
	if [[ -f "$def" ]]; then
		load_install_config "$def"
		BRIDGE="${BRIDGE:-${FRONT:-}}"
		EXIT="${EXIT:-${BACK:-}}"
		SSH_USER=${SSH_USER:-root}
	fi
else
	usage
fi

if [[ -z "${BRIDGE// }" || -z "${EXIT// }" ]]; then
	echo "Не заданы BRIDGE и EXIT: укажите два хоста или файл install.config (-c или $(install_config_default_path))." >&2
	usage
fi

IP_URL="${VERIFY_IP_URL:-}"
if [[ -z "${IP_URL// }" ]]; then
	echo "relay-check: задайте VERIFY_IP_URL (HTTPS URL для тестового GET через SOCKS)." >&2
	exit 1
fi

if [[ -n "${IDENTITY:-}" && ${#SSH_EXTRA[@]} -eq 0 ]]; then
	id="$IDENTITY"
	if [[ "$id" == ~/* ]]; then
		id="$HOME/${id#~/}"
	fi
	SSH_EXTRA=(-i "$id")
fi

for x in ssh curl xray; do
	if ! have_cmd "$x"; then
		echo "Требуется команда в PATH: $x" >&2
		if [[ "$x" == xray ]]; then
			echo "Нужен клиент ядра в PATH как «xray» (версию ориентируйте по go.mod: github.com/xtls/xray-core)." >&2
		fi
		exit 1
	fi
done

if ! have_cmd jq && ! have_cmd python3; then
	echo "Нужен jq или python3 для разбора JSON ответа Admin API." >&2
	exit 1
fi

SSH_STRICT_HOST_KEY="${VERIFY_SSH_STRICT_HOST_KEY:-accept-new}"
ssh_opts=(-o BatchMode=yes -o "StrictHostKeyChecking=${SSH_STRICT_HOST_KEY}")
[[ ${#SSH_EXTRA[@]} -eq 0 ]] || ssh_opts+=(-o IdentitiesOnly=yes)
if [[ -n "${VERIFY_SSH_KNOWN_HOSTS:-}" ]]; then
	ssh_opts+=(-o "UserKnownHostsFile=${VERIFY_SSH_KNOWN_HOSTS}")
fi
# shellcheck disable=SC2206
ssh_base=(ssh "${ssh_opts[@]}" "${SSH_EXTRA[@]}" "${SSH_USER}@${BRIDGE}")

remote_curl_api() {
	local command
	command="bash -s -- $(printf '%q' "$1")"
	if [[ "${VERIFY_SSH_SUDO:-no}" == yes ]]; then
		command="if [ \"\$(id -u)\" -eq 0 ]; then exec $command; else exec sudo -n $command; fi"
	fi
	{
		printf '%s\n' 'set -euo pipefail' "settings=\$(python3 - env <<'ULTRA_VERIFY_HELPER'"
		cat "$SCRIPT_DIR/bridge-migration-state.py"
		# Evaluated only by remote root/sudo shell.
# shellcheck disable=SC2016
		printf '\n%s\n' 'ULTRA_VERIFY_HELPER' ')' 'eval "$settings"'
		cat <<'EOS'
[[ -n "${ULTRA_RELAY_ADMIN_TOKEN:-}" ]] || exit 3
exec curl -fsS -g -H "Authorization: Bearer $ULTRA_RELAY_ADMIN_TOKEN" "$ADMIN_URL${1:?}" 2>/dev/null
EOS
	} | "${ssh_base[@]}" "$command"
}

TMPDIR_VERIFY=""
XRAY_PID=""
# Invoked through trap.
# shellcheck disable=SC2329
cleanup() {
	if [[ -n "${XRAY_PID:-}" ]] && kill -0 "$XRAY_PID" 2>/dev/null; then
		kill "$XRAY_PID" 2>/dev/null || true
		wait "$XRAY_PID" 2>/dev/null || true
	fi
	if [[ -n "${TMPDIR_VERIFY:-}" && -d "$TMPDIR_VERIFY" ]]; then
		rm -rf "$TMPDIR_VERIFY"
	fi
}
trap cleanup EXIT INT TERM

echo "=== relay-check: bridge=${BRIDGE} (Admin API по SSH; поле EXIT в конфиге не используется) ==="

REMOTE_SPEC="${VERIFY_SPEC_PATH:-/etc/ultra-relay/spec.json}"
ULTRA_ROUTING_MODE="blocklist"
qspec=$(printf '%q' "$REMOTE_SPEC")
spec_command="python3 -c $(printf '%q' 'import json,sys; print(json.load(open(sys.argv[1])).get("routing_mode","blocklist"))') $qspec"
if [[ "${VERIFY_SSH_SUDO:-no}" == yes ]]; then spec_command="sudo -n $spec_command"; fi
if mode=$("${ssh_base[@]}" "$spec_command" 2>/dev/null); then
	[[ "$mode" == blocklist || "$mode" == ru_direct ]] && ULTRA_ROUTING_MODE="$mode"
fi
echo "relay-check: routing_mode=${ULTRA_ROUTING_MODE} (spec на bridge: ${REMOTE_SPEC})"
export ULTRA_ROUTING_MODE

TMPDIR_VERIFY=$(mktemp -d)
USERS_JSON="${TMPDIR_VERIFY}/users.json"

if ! remote_curl_api "/v1/users" >"$USERS_JSON"; then
	echo "relay-check: не удалось запросить /v1/users (SSH или curl на bridge)." >&2
	exit 1
fi

if [[ -s "$USERS_JSON" ]] && head -c 300 "$USERS_JSON" | grep -qiE 'unauthorized|401'; then
	echo "relay-check: Admin API ответил 401 — проверьте ULTRA_RELAY_ADMIN_TOKEN на bridge." >&2
	exit 1
fi

UUID="${VERIFY_USER_UUID:-}"
if [[ -z "$UUID" ]]; then
	UUID="$(json_users_first_uuid "$USERS_JSON")"
fi
if [[ -z "$UUID" ]]; then
	echo "relay-check: пустой users.json — создайте запись через POST /v1/users или админку." >&2
	exit 1
fi
[[ "$UUID" =~ ^[A-Za-z0-9-]+$ ]] || { echo "relay-check: invalid test user ID" >&2; exit 1; }

CLIENT_JSON="${TMPDIR_VERIFY}/client.json.raw"
if ! remote_curl_api "/v1/users/${UUID}/client" >"$CLIENT_JSON"; then
	echo "relay-check: не удалось запросить /v1/users/${UUID}/client." >&2
	exit 1
fi

if head -c 400 "$CLIENT_JSON" | grep -qiE 'not found'; then
	echo "relay-check: запись не найдена на сервере." >&2
	exit 1
fi

B64="$(json_client_b64 "$CLIENT_JSON")"
if [[ -z "$B64" ]]; then
	echo "relay-check: в ответе нет full_xray_config_base64." >&2
	exit 1
fi

CFG="${TMPDIR_VERIFY}/client.json"
if ! printf '%s' "$B64" | base64 -d >"$CFG" 2>/dev/null; then
	if ! printf '%s' "$B64" | base64 --decode >"$CFG" 2>/dev/null; then
		printf '%s' "$B64" | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.standard_b64decode(sys.stdin.buffer.read()))' >"$CFG"
	fi
fi
chmod 600 "$CFG"

DEFAULT_SOCKS=10808
if [[ "$SOCKS_PORT" != "$DEFAULT_SOCKS" ]]; then
	patch_socks_port "$CFG" "$SOCKS_PORT"
	echo "relay-check: inbound SOCKS порт изменён на $SOCKS_PORT"
fi

if port_open 127.0.0.1 "$SOCKS_PORT"; then
	echo "relay-check: порт $SOCKS_PORT уже занят — задайте VERIFY_SOCKS_PORT или флаг -p." >&2
	exit 1
fi

echo "relay-check: локальный клиент (SOCKS 127.0.0.1:${SOCKS_PORT})…"
xray run -c "$CFG" >"${TMPDIR_VERIFY}/client.log" 2>&1 &
XRAY_PID=$!

ready=0
for _ in $(seq 1 50); do
	if port_open 127.0.0.1 "$SOCKS_PORT"; then
		ready=1
		break
	fi
	if ! kill -0 "$XRAY_PID" 2>/dev/null; then
		echo "relay-check: клиент завершился до готовности SOCKS — проверьте конфиг и версию бинарника." >&2
		exit 1
	fi
	sleep 0.2
done

if [[ "$ready" -eq 0 ]]; then
	echo "relay-check: таймаут ожидания SOCKS на 127.0.0.1:${SOCKS_PORT}." >&2
	exit 1
fi

echo "relay-check: GET ${IP_URL} через SOCKS…"
PROBE_BODY=""
if ! PROBE_BODY=$(curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -fsS --max-time 40 "$IP_URL" 2>/dev/null); then
	echo "relay-check: curl через SOCKS завершился с ошибкой." >&2
	exit 1
fi

if [[ -n "${VERIFY_EXPECTED_EXIT_IP:-}" ]]; then
	PROBE_BODY="$PROBE_BODY" python3 - "$VERIFY_EXPECTED_EXIT_IP" <<'PY'
import ipaddress,os,sys
try:
    actual=ipaddress.ip_address(os.environ['PROBE_BODY'].strip())
    expected=ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit('relay-check: probe must return a plain IP address')
if actual != expected: raise SystemExit('relay-check: external IP does not match expected exit')
PY
	echo "relay-check: expected exit IP confirmed"
else
	[[ -n "$PROBE_BODY" ]] || { echo "relay-check: empty probe response" >&2; exit 1; }
	echo "relay-check: successful HTTP response (exit IP not checked)"
fi

skip_split=0
case "${VERIFY_SPLIT_ROUTING:-y}" in
n | N | no | NO | false | FALSE | 0) skip_split=1 ;;
esac

if [[ "$skip_split" -eq 0 ]]; then
	echo "relay-check: split-routing — зонд exit, SOCKS 127.0.0.1:${SOCKS_PORT}…"
	export ULTRA_SOCKS5="127.0.0.1:${SOCKS_PORT}"
	if [[ -n "${VERIFY_PROBE_EXIT_URL:-}" ]]; then
		export SPLIT_PROBE_EXIT_URL="$VERIFY_PROBE_EXIT_URL"
	fi
	if [[ -n "${VERIFY_PROBE_EXIT_PLAIN_URL:-}" ]]; then
		export SPLIT_PROBE_EXIT_PLAIN_URL="$VERIFY_PROBE_EXIT_PLAIN_URL"
	fi
	if ! "$SCRIPT_DIR/verify-split-routing.sh"; then
		echo "relay-check: verify-split-routing.sh завершился с ошибкой." >&2
		exit 1
	fi
fi

echo "=== relay-check: OK ==="
exit 0
