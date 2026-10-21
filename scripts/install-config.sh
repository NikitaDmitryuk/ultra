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
  # config-values exposes only the canonical external keys. Map them to the
  # long-standing shell variable names used internally by these diagnostics.
  case "$key" in
   BRIDGE_IP) printf -v BRIDGE '%s' "$val" ;;
   BRIDGE_SSH_KEY) printf -v BRIDGE_SSH_IDENTITY '%s' "$val" ;;
   MAIN_EXIT_IP) printf -v EXIT '%s' "$val" ;;
   MAIN_EXIT_SSH_KEY) printf -v EXIT_SSH_IDENTITY '%s' "$val" ;;
   DATABASE_IP) printf -v DATABASE '%s' "$val" ;;
   DATABASE_SSH_KEY) printf -v DATABASE_SSH_IDENTITY '%s' "$val" ;;
   BRIDGE|BRIDGE_SSH_HOST|BRIDGE_SSH_IDENTITY|EXIT|EXIT_SSH_IDENTITY|EXIT2|EXIT2_SSH_IDENTITY|DB_HOST|IDENTITY|FRONT|BACK)
    echo "Deprecated install.config key rejected: $key" >&2
    rm -f "$values"
    return 1
    ;;
   *) printf -v "$key" '%s' "$val" ;;
  esac
 done <"$values"
 rm -f "$values"
}

# Paths are non-secret references; the SSH client opens the selected key.
install_identity_for_host() {
	local host=$1
 local selected=
 if [[ "$host" == "${BRIDGE:-}" ]]; then
  selected=${BRIDGE_SSH_IDENTITY:-}
 elif [[ "$host" == "${EXIT:-}" ]]; then
  selected=${EXIT_SSH_IDENTITY:-}
 elif [[ "$host" == "${DATABASE:-}" ]]; then
  selected=${DATABASE_SSH_IDENTITY:-}
	fi
	if [[ "$selected" == ~/* ]]; then
		selected="$HOME/${selected#~/}"
	fi
	printf '%s' "$selected"
}
