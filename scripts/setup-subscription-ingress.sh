#!/usr/bin/env bash
# Run locally; only public settings and the HAProxy template are sent to bridge.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/install-config.sh"
load_install_config "${ULTRA_INSTALL_CONFIG:-$(install_config_default_path)}"
: "${BOT_INGRESS_IP:?Set BOT_INGRESS_IP}"
BRIDGE="${BRIDGE:-${FRONT:-}}"
: "${BRIDGE:?Set BRIDGE}"
args=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8)
if [[ -n "${IDENTITY:-}" ]]; then args+=(-i "${IDENTITY/#\~/$HOME}"); fi
mode="${BOT_INGRESS_MODE:-vultr}"
if [[ "$mode" = ssh ]]; then
  : "${BOT_DOMAIN:?Set BOT_DOMAIN}"
  python3 - "$ROOT" "$BRIDGE" "$BOT_DOMAIN" "$BOT_INGRESS_IP" <<'PYSSH' | ssh "${args[@]}" "${SSH_USER:-root}@${BOT_INGRESS_IP}" 'python3 -'
import pathlib,sys,ipaddress
root,bridge,domain,ingress=sys.argv[1:]
ipaddress.IPv4Address(bridge);ipaddress.IPv4Address(ingress)
print('settings = '+repr({'bridge':bridge,'domain':domain}))
print((pathlib.Path(root)/'deploy/setup-subscription-ingress-ssh.py').read_text())
PYSSH
  exit
fi
[[ "$mode" = vultr ]] || { echo "Invalid BOT_INGRESS_MODE" >&2; exit 1; }
python3 - "$ROOT" "$BRIDGE" "$BOT_INGRESS_IP" "${BOT_INGRESS_INSTANCE_ID:-}" <<'PY' | ssh "${args[@]}" "${SSH_USER:-root}@${BRIDGE}" 'python3 -'
import pathlib,sys,ipaddress,json
root,bridge,ingress,instance=sys.argv[1:]
ipaddress.IPv4Address(bridge);ipaddress.IPv4Address(ingress)
p=pathlib.Path(root)
print('settings = '+repr({'bridge':bridge,'ingress':ingress,'instance':instance,'config':(p/'deploy/subscription-ingress.cfg').read_text().replace('BRIDGE_IP',bridge),'hook':(p/'deploy/renew-ultra-bot.sh').read_text()}))
print((p/'deploy/setup-subscription-ingress.py').read_text())
PY
