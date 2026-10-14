#!/usr/bin/env bash
# Compatibility loader; all server changes use the shared Ansible lifecycle.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${ULTRA_INSTALL_CONFIG:-$ROOT/install.config}"
if [[ -n "${SPEC_LOCAL:-}" || -n "${SERVICE_NAME:-}" || -n "${BIN_LOCAL:-}" ]]; then
    echo 'Legacy raw spec/binary/service overrides are unsupported; configure the verified release in install.config.' >&2
    exit 1
fi
[[ -x "$ROOT/ultra-install" ]] || { echo 'Build ultra-install first with make build-install.' >&2; exit 1; }
exec "$ROOT/ultra-install" bootstrap --config "$CONFIG" "$@"
