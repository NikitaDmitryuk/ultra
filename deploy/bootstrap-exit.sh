#!/usr/bin/env bash
# Compatibility loader; the common CLI applies the native configure-exit role.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -n "${SPEC_LOCAL:-}" || -n "${SERVICE_NAME:-}" ]]; then
    echo 'Raw remote spec/service overrides are unsupported; use the common configure-exit CLI.' >&2
    exit 1
fi
: "${BRIDGE_IP:?set the existing BRIDGE_IP}"
: "${EXIT_IP:?set the existing EXIT_IP}"
: "${TUNNEL_UUID:?set the registered TUNNEL_UUID from the bridge deployment hints}"
[[ -x "$ROOT/ultra-install" ]] || { echo 'Build ultra-install first with make build-install.' >&2; exit 1; }
args=(-exit-only -bridge "$BRIDGE_IP" -exit "$EXIT_IP" -tunnel-uuid "$TUNNEL_UUID" -ssh-user "${SSH_USER:-root}" -binary "${BIN_LOCAL:-$ROOT/ultra-relay-linux-amd64}")
if [[ -n "${SSH_IDENTITY:-}" ]]; then args+=(-identity "$SSH_IDENTITY"); fi
exec "$ROOT/ultra-install" "${args[@]}" "$@"
