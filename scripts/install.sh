#!/usr/bin/env bash
# Compatibility entrypoint; configuration parsing and application live in Go.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${ULTRA_INSTALL_CONFIG:-$ROOT/install.config}"
if [[ ! -x "$ROOT/ultra-install" ]]; then
    echo 'Build ultra-install first with make build-install.' >&2
    exit 1
fi
exec "$ROOT/ultra-install" apply --config "$CONFIG" "$@"
