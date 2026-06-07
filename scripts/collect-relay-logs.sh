#!/usr/bin/env bash
# Собрать journalctl ultra-relay с bridge и exit-нод (EXIT, EXIT2 из install.config).
# Недоступные хосты пропускаются с предупреждением; exit 1 только если недоступен bridge.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-config.sh
source "$SCRIPT_DIR/install-config.sh"

usage() {
	echo "Использование:" >&2
	echo "  $0 [-c install.config] [-i identity] [-u ssh_user] [-n lines] [-s] [BRIDGE [EXIT [EXIT2]]]" >&2
	echo "  $0 [-i …] [-u …] [-n …] [-s]   # без аргументов: install.config в корне репозитория" >&2
	echo "  -s  журнал с момента последнего запуска ultra-relay; иначе — последние -n строк" >&2
	echo "Хосты EXIT/EXIT2 опциональны: при ошибке SSH выводится предупреждение, сбор продолжается." >&2
	exit 2
}

CONFIG_FILE=""
SSH_EXTRA=()
SSH_USER=root
LINES=400
SINCE_RESTART=0
while getopts "c:i:u:n:sh" opt; do
	case "$opt" in
	c) CONFIG_FILE=$OPTARG ;;
	i) SSH_EXTRA=(-i "$OPTARG") ;;
	u) SSH_USER="$OPTARG" ;;
	n) LINES="$OPTARG" ;;
	s) SINCE_RESTART=1 ;;
	h) usage ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

BRIDGE=""
EXIT=""
EXIT2=""

load_config_hosts() {
	local f="${1:-}"
	[[ -n "$f" ]] || return 0
	load_install_config "$f" || return 0
	BRIDGE="${BRIDGE:-${FRONT:-}}"
	EXIT="${EXIT:-${BACK:-}}"
	EXIT2="${EXIT2:-}"
	SSH_USER=${SSH_USER:-root}
}

if [[ -n "$CONFIG_FILE" ]]; then
	if [[ ! -f "$CONFIG_FILE" ]]; then
		echo "Файл конфига не найден: $CONFIG_FILE" >&2
		exit 1
	fi
	load_config_hosts "$CONFIG_FILE"
fi

case $# in
0)
	if [[ -z "$CONFIG_FILE" ]]; then
		def="$(install_config_default_path)"
		[[ -f "$def" ]] && load_config_hosts "$def"
	fi
	;;
1) BRIDGE="$1" ;;
2) BRIDGE="$1" EXIT="$2" ;;
3) BRIDGE="$1" EXIT="$2" EXIT2="$3" ;;
*) usage ;;
esac

EXIT2="${EXIT2:-}"

if [[ -z "${BRIDGE// }" ]]; then
	echo "Не задан BRIDGE: укажите хост или install.config (-c)." >&2
	usage
fi

if [[ -n "${IDENTITY:-}" && ${#SSH_EXTRA[@]} -eq 0 ]]; then
	id="$IDENTITY"
	if [[ "$id" == ~/* ]]; then
		id="$HOME/${id#~/}"
	fi
	SSH_EXTRA=(-i "$id")
fi

SSH_CONNECT_TIMEOUT="${ULTRA_SSH_CONNECT_TIMEOUT:-15}"
SSH_OPTS=(
	-o BatchMode=yes
	-o StrictHostKeyChecking=accept-new
	-o ConnectTimeout="$SSH_CONNECT_TIMEOUT"
)

FAILED=()
SKIPPED=()

run_host() {
	local label=$1
	local host=$2
	[[ -n "${host// }" ]] || return 0
	echo "========== $label ($host) =========="
	if [[ "$SINCE_RESTART" -eq 1 ]]; then
		if ! ssh "${SSH_OPTS[@]}" "${SSH_EXTRA[@]}" "${SSH_USER}@${host}" bash -s "$LINES" <<'REMOTE'
set -euo pipefail
LINES=${1:?}
ts=$(systemctl show ultra-relay -p ActiveEnterTimestamp --value 2>/dev/null | head -1 || true)
if [[ -n "$ts" && "$ts" != "n/a" ]]; then
	journalctl -u ultra-relay --no-pager -o short-iso --since "$ts"
else
	journalctl -u ultra-relay -n "$LINES" --no-pager -o short-iso
fi
REMOTE
		then
			echo "WARNING: $label ($host): SSH или journalctl недоступны" >&2
			FAILED+=("$label ($host)")
		fi
	else
		if ! ssh "${SSH_OPTS[@]}" "${SSH_EXTRA[@]}" "${SSH_USER}@${host}" \
			"journalctl -u ultra-relay -n ${LINES} --no-pager -o short-iso"; then
			echo "WARNING: $label ($host): SSH или journalctl недоступны" >&2
			FAILED+=("$label ($host)")
		fi
	fi
	echo
}

# Dedupe hosts (bridge may coincide with db host; exit2 must not repeat exit).
declare -A SEEN=()
add_host() {
	local label=$1
	local host=$2
	[[ -n "${host// }" ]] || return 0
	if [[ -n "${SEEN[$host]+x}" ]]; then
		SKIPPED+=("$label ($host) — уже собран")
		return 0
	fi
	SEEN[$host]=1
	run_host "$label" "$host"
}

add_host bridge "$BRIDGE"
add_host exit "$EXIT"
add_host exit2 "$EXIT2"

if [[ ${#FAILED[@]} -gt 0 ]]; then
	echo "========== Недоступные хосты ==========" >&2
	for h in "${FAILED[@]}"; do
		echo " • $h" >&2
	done
fi

# Bridge обязателен; exit-ноды могут быть offline.
bridge_failed=0
for h in "${FAILED[@]}"; do
	if [[ "$h" == bridge* ]]; then
		bridge_failed=1
		break
	fi
done

if [[ "$bridge_failed" -eq 1 ]]; then
	exit 1
fi
exit 0
