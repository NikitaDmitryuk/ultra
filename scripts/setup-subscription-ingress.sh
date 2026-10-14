#!/usr/bin/env bash
# Compatibility alias: one native role owns subscription and transport ingress.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${ULTRA_INSTALL_CONFIG:-$ROOT/install.config}"
[[ -x "$ROOT/ultra-install" ]] || { echo 'Build ultra-install first with make build-install.' >&2; exit 1; }
exec "$ROOT/ultra-install" ingress --config "$CONFIG" --action activate "$@"
