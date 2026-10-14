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

# The Go adapter owns parsing; NUL pairs avoid eval and shell execution.
load_install_config() {
 local f="${1:-$(install_config_default_path)}" executable values key val
 [[ -f "$f" ]] || return 1
 executable="${ULTRA_INSTALL_BIN:-$(dirname "${BASH_SOURCE[0]}")/../ultra-install}"
 if [[ ! -x "$executable" ]]; then
  executable="$(command -v ultra-install || true)"
 fi
 [[ -n "$executable" && -x "$executable" ]] || { echo "Build or install ultra-install first" >&2; return 1; }
 values="$(mktemp)" || return 1
 chmod 600 "$values"
 if ! "$executable" config-values --config "$f" >"$values"; then
  rm -f "$values"
  return 1
 fi
 while IFS= read -r -d '' key && IFS= read -r -d '' val; do
  printf -v "$key" '%s' "$val"
 done <"$values"
 rm -f "$values"
}
