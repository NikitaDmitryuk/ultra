#!/usr/bin/env bash
# Remote bootstrap for the exit VPS (TLS cert paths must exist on the server unless you generate them first).
# Requires SSH key auth (BatchMode).
#
# Usage:
#   EXIT_IP=1.2.3.4 SSH_USER=root ./deploy/bootstrap-exit.sh
set -euo pipefail

: "${EXIT_IP:?set EXIT_IP}"
SSH_USER="${SSH_USER:-root}"
SSH_IDENTITY="${SSH_IDENTITY:-}"
REMOTE_DIR="${REMOTE_DIR:-/etc/ultra-relay}"
SERVICE_NAME="${SERVICE_NAME:-ultra-relay}"

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

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC_LOCAL="${SPEC_LOCAL:-$ROOT/deploy/spec.exit.example.json}"

"${ssh_base[@]}" "${SSH_USER}@${EXIT_IP}" "mkdir -p '${REMOTE_DIR}' && chmod 700 '${REMOTE_DIR}'"
"${scp_base[@]}" "$BIN_LOCAL" "${SSH_USER}@${EXIT_IP}:/tmp/ultra-relay"
"${scp_base[@]}" "$SPEC_LOCAL" "${SSH_USER}@${EXIT_IP}:${REMOTE_DIR}/spec.json"

"${ssh_base[@]}" "${SSH_USER}@${EXIT_IP}" bash -s <<REMOTE
set -euo pipefail
REMOTE_DIR='${REMOTE_DIR}'
if ! id -u ultra-relay >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay
fi
install -m 755 /tmp/ultra-relay /usr/local/bin/ultra-relay
rm -f /tmp/ultra-relay
chown -R ultra-relay:ultra-relay "\$REMOTE_DIR"
chmod 700 "\$REMOTE_DIR"
chmod 600 "\$REMOTE_DIR/spec.json" || true
chmod 600 "\$REMOTE_DIR/fullchain.pem" 2>/dev/null || true
chmod 600 "\$REMOTE_DIR/privkey.pem" 2>/dev/null || true
REMOTE

"${scp_base[@]}" "$ROOT/deploy/systemd/ultra-relay.service" "${SSH_USER}@${EXIT_IP}:/tmp/ultra-relay.service"
"${ssh_base[@]}" "${SSH_USER}@${EXIT_IP}" "mv /tmp/ultra-relay.service /etc/systemd/system/${SERVICE_NAME}.service && systemctl daemon-reload && systemctl enable ${SERVICE_NAME} && systemctl restart ${SERVICE_NAME}"

echo "Ensure TLS files in spec exist under ${REMOTE_DIR} (see deploy/TLS.md)."
