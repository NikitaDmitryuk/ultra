#!/usr/bin/env bash
# Remote bootstrap for the bridge VPS: installs binary, dirs, systemd, optional admin token.
# Requires SSH key auth (BatchMode); do not rely on root passwords in scripts.
#
# Usage (from your laptop):
#   BRIDGE_IP=1.2.3.4 SSH_USER=root ./deploy/bootstrap-bridge.sh
# Optional: SSH_IDENTITY=~/.ssh/id_ed25519
set -euo pipefail

: "${BRIDGE_IP:?set BRIDGE_IP}"
SSH_USER="${SSH_USER:-root}"
SSH_IDENTITY="${SSH_IDENTITY:-}"
REMOTE_DIR="${REMOTE_DIR:-/etc/ultra-relay}"
SERVICE_NAME="${SERVICE_NAME:-ultra-relay}"

# Match ultra-install: ULTRA_INSTALL_SSH_STRICT_HOST_KEY=yes requires pre-populated known_hosts.
SSH_STRICT="${ULTRA_INSTALL_SSH_STRICT_HOST_KEY:-}"
if [[ "$SSH_STRICT" == "1" || "$SSH_STRICT" == "yes" || "$SSH_STRICT" == "true" || "$SSH_STRICT" == "strict" ]]; then
  _SSH_CHK=yes
else
  _SSH_CHK=accept-new
fi
ssh_base=(ssh -o BatchMode=yes -o "StrictHostKeyChecking=${_SSH_CHK}")
scp_base=(scp -o BatchMode=yes -o "StrictHostKeyChecking=${_SSH_CHK}")
if [[ -n "$SSH_IDENTITY" ]]; then
  ssh_base+=(-i "$SSH_IDENTITY")
  scp_base+=(-i "$SSH_IDENTITY")
fi

BIN_LOCAL="${BIN_LOCAL:-./ultra-relay-linux-amd64}"
if [[ ! -f "$BIN_LOCAL" ]]; then
  echo "Build first: make build-linux-amd64" >&2
  exit 1
fi

TOKEN="${ULTRA_RELAY_ADMIN_TOKEN:-$(openssl rand -hex 32)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC_LOCAL="${SPEC_LOCAL:-$ROOT/deploy/spec.bridge.example.json}"

ENV_LOCAL="$(mktemp)"
trap 'rm -f "$ENV_LOCAL"' EXIT
printf 'ULTRA_RELAY_ADMIN_TOKEN=%s\n' "$TOKEN" >"$ENV_LOCAL"
chmod 600 "$ENV_LOCAL"

"${ssh_base[@]}" "${SSH_USER}@${BRIDGE_IP}" "mkdir -p '${REMOTE_DIR}' && chmod 700 '${REMOTE_DIR}'"
"${scp_base[@]}" "$BIN_LOCAL" "${SSH_USER}@${BRIDGE_IP}:/tmp/ultra-relay"
"${scp_base[@]}" "$SPEC_LOCAL" "${SSH_USER}@${BRIDGE_IP}:${REMOTE_DIR}/spec.json"
"${scp_base[@]}" "$ENV_LOCAL" "${SSH_USER}@${BRIDGE_IP}:${REMOTE_DIR}/environment.tmp"
if "${ssh_base[@]}" "${SSH_USER}@${BRIDGE_IP}" "test ! -f '${REMOTE_DIR}/users.json'"; then
  "${scp_base[@]}" "$ROOT/users.json.sample" "${SSH_USER}@${BRIDGE_IP}:${REMOTE_DIR}/users.json"
fi

"${ssh_base[@]}" "${SSH_USER}@${BRIDGE_IP}" bash -s <<REMOTE
set -euo pipefail
REMOTE_DIR='${REMOTE_DIR}'
if ! id -u ultra-relay >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay
fi
install -m 755 /tmp/ultra-relay /usr/local/bin/ultra-relay
rm -f /tmp/ultra-relay
install -m 600 "\${REMOTE_DIR}/environment.tmp" /etc/ultra-relay/environment
rm -f "\${REMOTE_DIR}/environment.tmp"
chown -R ultra-relay:ultra-relay "\$REMOTE_DIR"
chmod 700 "\$REMOTE_DIR"
chmod 600 "\$REMOTE_DIR/spec.json" || true
chmod 600 "\$REMOTE_DIR/users.json" 2>/dev/null || true
chmod 600 /etc/ultra-relay/environment
REMOTE

"${scp_base[@]}" "$ROOT/deploy/systemd/ultra-relay.service" "${SSH_USER}@${BRIDGE_IP}:/tmp/ultra-relay.service"
"${ssh_base[@]}" "${SSH_USER}@${BRIDGE_IP}" "mv /tmp/ultra-relay.service /etc/systemd/system/${SERVICE_NAME}.service && systemctl daemon-reload && systemctl enable ${SERVICE_NAME} && systemctl restart ${SERVICE_NAME}"

echo "Done. Admin token (save securely): ${TOKEN}"
echo "Access admin API: ssh -L 8443:127.0.0.1:8443 ${SSH_USER}@${BRIDGE_IP}"
echo "Then: curl -sS -H \"Authorization: Bearer \${ULTRA_RELAY_ADMIN_TOKEN}\" http://127.0.0.1:8443/v1/users/..."
