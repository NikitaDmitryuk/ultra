#!/usr/bin/env bash
# Интеграционная проверка: по SSH на bridge читается Admin API, локально поднимается Xray (SOCKS inbound),
# затем HTTPS GET на VERIFY_IP_URL и по умолчанию два зонда split-routing (IP direct на bridge vs через exit).
#
# Зависимости на машине оператора: ssh, curl, xray (в PATH), base64.
# JSON: jq (предпочтительно) или python3.
# Версию Xray ориентируйте по github.com/xtls/xray-core в go.mod репозитория.
set -euo pipefail

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
	echo "  VERIFY_SPLIT_STRICT=0 — при совпадении обоих IP только предупреждение (по умолчанию 1 — ошибка)" >&2
	echo "  VERIFY_PROBE_DIRECT_URL / VERIFY_PROBE_EXIT_URL — зонды для split (см. verify-split-routing.sh)" >&2
	echo "Пример: VERIFY_IP_URL=https://… $0 -c install.config" >&2
	exit 2
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

json_users_first_uuid() {
	if have_cmd jq; then
		jq -r '.[0].uuid // empty' "$1"
	else
		python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); print(a[0]["uuid"] if a else "")' "$1"
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
			echo "Установите Xray (версию смотрите в go.mod: github.com/xtls/xray-core)." >&2
		fi
		exit 1
	fi
done

if ! have_cmd jq && ! have_cmd python3; then
	echo "Нужен jq или python3 для разбора JSON ответа Admin API." >&2
	exit 1
fi

# shellcheck disable=SC2206
ssh_base=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${SSH_EXTRA[@]}" "${SSH_USER}@${BRIDGE}")

remote_curl_api() {
	local api_path=$1
	local out
	# shellcheck disable=SC2029
	if ! out=$("${ssh_base[@]}" bash -s "$api_path" <<'EOS'
set -euo pipefail
path=${1:?}
ENV=/etc/ultra-relay/environment
if [[ ! -f "$ENV" ]]; then
	echo "relay-check: нет файла $ENV" >&2
	exit 3
fi
line=$(grep -E '^ULTRA_RELAY_ADMIN_TOKEN=' "$ENV" | head -1 || true)
if [[ -z "$line" ]]; then
	echo "relay-check: в $ENV нет ULTRA_RELAY_ADMIN_TOKEN (Admin API выключен)." >&2
	exit 3
fi
tok=${line#ULTRA_RELAY_ADMIN_TOKEN=}
if [[ -z "$tok" ]]; then
	echo "relay-check: пустой ULTRA_RELAY_ADMIN_TOKEN." >&2
	exit 3
fi
exec curl -sS -g -H "Authorization: Bearer ${tok}" "http://127.0.0.1:8443${path}"
EOS
	); then
		return 1
	fi
	printf '%s' "$out"
}

TMPDIR_VERIFY=""
XRAY_PID=""
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
echo "relay-check: UUID=$UUID"

CLIENT_JSON="${TMPDIR_VERIFY}/client.json.raw"
if ! remote_curl_api "/v1/users/${UUID}/client" >"$CLIENT_JSON"; then
	echo "relay-check: не удалось запросить /v1/users/${UUID}/client." >&2
	exit 1
fi

if head -c 400 "$CLIENT_JSON" | grep -qiE 'not found|404'; then
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

echo "relay-check: локальный xray (SOCKS 127.0.0.1:${SOCKS_PORT})…"
xray run -c "$CFG" &
XRAY_PID=$!

ready=0
for _ in $(seq 1 50); do
	if port_open 127.0.0.1 "$SOCKS_PORT"; then
		ready=1
		break
	fi
	if ! kill -0 "$XRAY_PID" 2>/dev/null; then
		echo "relay-check: xray завершился до готовности SOCKS — проверьте конфиг и версию xray." >&2
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
if ! PROBE_BODY=$(curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -sS --max-time 40 "$IP_URL"); then
	echo "relay-check: curl через SOCKS завершился с ошибкой." >&2
	exit 1
fi

PROBE_BODY="$(echo "$PROBE_BODY" | tr -d '\r\n' | head -c 256)"
if [[ -z "$PROBE_BODY" ]]; then
	echo "relay-check: пустой ответ от ${IP_URL}." >&2
	exit 1
fi

echo "probe_response=${PROBE_BODY}"

skip_split=0
case "${VERIFY_SPLIT_ROUTING:-y}" in
n | N | no | NO | false | FALSE | 0) skip_split=1 ;;
esac

if [[ "$skip_split" -eq 0 ]]; then
	echo "relay-check: split-routing — два зонда (direct на bridge и через exit), SOCKS 127.0.0.1:${SOCKS_PORT}…"
	export ULTRA_SOCKS5="127.0.0.1:${SOCKS_PORT}"
	export SPLIT_STRICT="${VERIFY_SPLIT_STRICT:-1}"
	if [[ -n "${VERIFY_PROBE_DIRECT_URL:-}" ]]; then
		export SPLIT_PROBE_DIRECT_URL="$VERIFY_PROBE_DIRECT_URL"
	fi
	if [[ -n "${VERIFY_PROBE_EXIT_URL:-}" ]]; then
		export SPLIT_PROBE_EXIT_URL="$VERIFY_PROBE_EXIT_URL"
	fi
	if ! "$SCRIPT_DIR/verify-split-routing.sh"; then
		echo "relay-check: verify-split-routing.sh завершился с ошибкой." >&2
		exit 1
	fi
fi

echo "=== relay-check: OK ==="
exit 0
