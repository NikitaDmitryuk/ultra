#!/usr/bin/env bash
# Собрать последние строки journalctl с bridge и exit (для отладки).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-config.sh
source "$SCRIPT_DIR/install-config.sh"

usage() {
	echo "Использование:" >&2
	echo "  $0 [-i identity] [-u ssh_user] [-n lines] BRIDGE_HOST EXIT_HOST" >&2
	echo "  $0 [-c install.config] [-i …] [-u …] [-n …]   # хосты из файла" >&2
	echo "  $0 [-i …] [-u …] [-n …]   # без аргументов: корневой install.config, если есть" >&2
	echo "Пример: $0 -i ~/.ssh/key 158.160.x.x 94.103.x.x" >&2
	exit 2
}

CONFIG_FILE=""
SSH_EXTRA=()
SSH_USER=root
LINES=400
while getopts "c:i:u:n:h" opt; do
	case "$opt" in
	c) CONFIG_FILE=$OPTARG ;;
	i) SSH_EXTRA=(-i "$OPTARG") ;;
	u) SSH_USER="$OPTARG" ;;
	n) LINES="$OPTARG" ;;
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
	echo "Не заданы BRIDGE и EXIT: укажите два хоста или файл install.config (-c или $SCRIPT_DIR/../install.config)." >&2
	usage
fi

if [[ -n "${IDENTITY:-}" && ${#SSH_EXTRA[@]} -eq 0 ]]; then
	id="$IDENTITY"
	if [[ "$id" == ~/* ]]; then
		id="$HOME/${id#~/}"
	fi
	SSH_EXTRA=(-i "$id")
fi

run() {
	local label=$1
	local host=$2
	echo "========== $label ($host) =========="
	ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${SSH_EXTRA[@]}" "${SSH_USER}@${host}" \
		"journalctl -u ultra-relay -n ${LINES} --no-pager -o short-iso"
	echo
}

run bridge "$BRIDGE"
run exit "$EXIT"
