# shellcheck shell=bash
# Разбор install.config: только строки VAR=value (комментарии #, пустые строки).
# Использование: source "$(dirname "$0")/install-config.sh"
#   install_config_default_path
#   load_install_config [путь]

install_config_default_path() {
	local here root
	here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	root="$(cd "$here/.." && pwd)"
	echo "${ULTRA_INSTALL_CONFIG:-$root/install.config}"
}

# Загружает переменные в текущую оболочку. Возврат 0 если файл прочитан, 1 если файла нет.
load_install_config() {
	local f="${1:-}"
	if [[ -z "$f" ]]; then
		f="$(install_config_default_path)"
	fi
	[[ -f "$f" ]] || return 1
	while IFS= read -r line || [[ -n "$line" ]]; do
		[[ "$line" =~ ^[[:space:]]*# ]] && continue
		line="${line%%#*}"
		[[ -z "${line// }" ]] && continue
		if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
			local key="${BASH_REMATCH[1]}"
			local val="${BASH_REMATCH[2]}"
			val="${val#"${val%%[![:space:]]*}"}"
			val="${val%"${val##*[![:space:]]}"}"
			if [[ "$val" =~ ^\".*\"$ ]]; then
				val="${val#\"}"
				val="${val%\"}"
			elif [[ "$val" =~ ^\'.*\'$ ]]; then
				val="${val#\'}"
				val="${val%\'}"
			fi
			printf -v "$key" '%s' "$val"
		fi
	done <"$f"
	return 0
}
