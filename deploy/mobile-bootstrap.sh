#!/usr/bin/env bash
# Bootstrap ultra from a GitHub Release on a fresh VPS.
#
# Intended for mobile/SSH controllers:
#   1. Upload install-plan JSON to the server (for example /tmp/ultra-plan.json).
#   2. Run this script over SSH.
#   3. Read ultra-install JSONL progress from stdout.
set -euo pipefail

REPO="NikitaDmitryuk/ultra"
RELEASE="latest"
PLAN="/tmp/ultra-plan.json"
SECRETS=""
SSH_IDENTITY=""
FORMAT="jsonl"
INSTALL_ROOT="/opt/ultra"
MINISIGN_PUBKEY=""
REQUIRE_SIGNATURE="yes"
WORK=""

usage() {
  cat <<EOF
Usage: mobile-bootstrap.sh [options]

Options:
  --repo OWNER/REPO       GitHub repository (default: ${REPO})
  --release TAG|latest    GitHub release tag or latest (default: latest)
  --plan PATH             install-plan JSON already uploaded to this server
  --secrets PATH          secrets env file already uploaded to this server
  --ssh-identity PATH     temporary SSH private key already uploaded to this server
  --format human|jsonl    ultra-install event output format (default: jsonl)
  --install-root PATH     release install root (default: /opt/ultra)
  --minisign-pubkey KEY   minisign public key for checksums.txt.minisig
  --require-signature MODE  auto, yes, or no (default: yes)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="${2:?}"; shift 2 ;;
    --release) RELEASE="${2:?}"; shift 2 ;;
    --plan) PLAN="${2:?}"; shift 2 ;;
    --secrets) SECRETS="${2:?}"; shift 2 ;;
    --ssh-identity) SSH_IDENTITY="${2:?}"; shift 2 ;;
    --format) FORMAT="${2:?}"; shift 2 ;;
    --install-root) INSTALL_ROOT="${2:?}"; shift 2 ;;
    --minisign-pubkey) MINISIGN_PUBKEY="${2:?}"; shift 2 ;;
    --require-signature) REQUIRE_SIGNATURE="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

cleanup() {
  if [[ -n "${WORK:-}" ]]; then
    rm -rf "$WORK"
  fi
  rm -f -- "$PLAN"
  if [[ -n "$SECRETS" ]]; then
    rm -f -- "$SECRETS"
  fi
  if [[ -n "$SSH_IDENTITY" ]]; then
    rm -f -- "$SSH_IDENTITY"
  fi
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "mobile-bootstrap: run as root (or connect with a root SSH user)" >&2
  exit 1
fi
if [[ ! -f "$PLAN" ]]; then
  echo "mobile-bootstrap: plan file not found: $PLAN" >&2
  exit 1
fi
if [[ -n "$SECRETS" && ! -f "$SECRETS" ]]; then
  echo "mobile-bootstrap: secrets file not found: $SECRETS" >&2
  exit 1
fi
if [[ -n "$SSH_IDENTITY" ]]; then
  if [[ ! -f "$SSH_IDENTITY" ]]; then
    echo "mobile-bootstrap: ssh identity file not found: $SSH_IDENTITY" >&2
    exit 1
  fi
  chmod 600 "$SSH_IDENTITY"
fi
case "$REQUIRE_SIGNATURE" in
  auto|yes|no) ;;
  *) echo "mobile-bootstrap: --require-signature must be auto, yes, or no" >&2; exit 2 ;;
esac
if [[ "$REQUIRE_SIGNATURE" == "yes" && -z "$MINISIGN_PUBKEY" ]]; then
  echo 'mobile-bootstrap: trusted minisign public key required' >&2
  exit 2
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "mobile-bootstrap: required command not found: $1" >&2
    exit 1
  fi
}

need curl
need sha256sum
need install
need python3

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "mobile-bootstrap: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

case "$RELEASE" in
  latest) BASE_URL="https://github.com/${REPO}/releases/latest/download"; RELEASE_DIR_NAME="latest" ;;
  *) BASE_URL="https://github.com/${REPO}/releases/download/${RELEASE}"; RELEASE_DIR_NAME="${RELEASE}" ;;
esac

WORK="$(mktemp -d)"

download() {
  local name="$1"
  curl -fL --retry 3 --connect-timeout 10 -o "${WORK}/${name}" "${BASE_URL}/${name}"
}

download checksums.txt
download release-manifest.json
if [[ "$REQUIRE_SIGNATURE" != "no" ]] && [[ -n "$MINISIGN_PUBKEY" || "$REQUIRE_SIGNATURE" == "yes" ]]; then
  if download checksums.txt.minisig; then
    if ! command -v minisign >/dev/null 2>&1; then
      if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q minisign
      fi
    fi
    if ! command -v minisign >/dev/null 2>&1; then
        echo "mobile-bootstrap: minisign is required for signature verification" >&2
        echo "mobile-bootstrap: install minisign or use --require-signature no" >&2
        exit 1
    fi
    if [[ -z "$MINISIGN_PUBKEY" ]]; then
      echo "mobile-bootstrap: --minisign-pubkey is required when verifying checksums.txt.minisig" >&2
      exit 1
    fi
    minisign -Vm "${WORK}/checksums.txt" -x "${WORK}/checksums.txt.minisig" -P "$MINISIGN_PUBKEY"
    download release-manifest.json.minisig
    minisign -Vm "${WORK}/release-manifest.json" -x "${WORK}/release-manifest.json.minisig" -P "$MINISIGN_PUBKEY"
  elif [[ "$REQUIRE_SIGNATURE" == "yes" ]]; then
    echo "mobile-bootstrap: checksums.txt.minisig is required but was not found" >&2
    exit 1
  fi
fi
# The loader fetches a complete immutable bundle; all server setup is Ansible.
python3 - "$WORK/release-manifest.json" "$WORK/assets" "$WORK/version" <<'PY_MANIFEST'
import json,re,sys
from pathlib import Path
manifest=json.loads(Path(sys.argv[1]).read_text())
version=manifest.get('version','')
if not re.fullmatch(r'v[0-9]+[.][0-9]+[.][0-9]+(?:[-+][A-Za-z0-9.-]+)?',version):
 raise SystemExit('invalid immutable release version')
required={f'ultra-{app}-linux-{arch}' for app in ('install','relay','bot','client') for arch in ('amd64','arm64')}
required.update({'ultra-recovery.tar.gz','ultra-ansible.tar.gz','ultra-ansible-runtime-linux-amd64.tar.gz','ultra-ansible-runtime-linux-arm64.tar.gz'})
names=[]
for asset in manifest.get('assets',[]):
 name=asset.get('name','')
 if name not in required|{'checksums.txt','mobile-bootstrap.sh'} or name in names or not re.fullmatch('[a-f0-9]{64}',asset.get('sha256','')) or type(asset.get('size')) is not int or not 0<asset['size']<512*1024*1024:
  raise SystemExit('invalid release asset')
 names.append(name)
if not required<=set(names):raise SystemExit('incomplete Ansible release')
Path(sys.argv[2]).write_text('\n'.join(names)+'\n')
Path(sys.argv[3]).write_text(version)
PY_MANIFEST
RELEASE_DIR_NAME="$(cat "$WORK/version")"
BASE_URL="https://github.com/${REPO}/releases/download/${RELEASE_DIR_NAME}"
while IFS= read -r asset; do
 [[ "$asset" == checksums.txt ]] || download "$asset"
done <"$WORK/assets"
python3 - "$WORK" <<'PY_VERIFY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])
for asset in json.loads((root/'release-manifest.json').read_text())['assets']:
 file=root/asset['name']
 if not file.is_file() or file.stat().st_size!=asset['size'] or hashlib.sha256(file.read_bytes()).hexdigest()!=asset['sha256']:
  raise SystemExit('release integrity mismatch')
PY_VERIFY
RELEASE_DIR="${INSTALL_ROOT}/releases/${RELEASE_DIR_NAME}-${ARCH}"
install -d -m 700 "$RELEASE_DIR"
for metadata in release-manifest.json checksums.txt.minisig release-manifest.json.minisig; do
 if [[ -f "$WORK/$metadata" && -e "$RELEASE_DIR/$metadata" ]] && ! cmp -s "$WORK/$metadata" "$RELEASE_DIR/$metadata"; then
  echo 'mobile-bootstrap: immutable release metadata conflict' >&2; exit 1
 fi
done
while IFS= read -r asset; do
 if [[ -e "$RELEASE_DIR/$asset" ]] && ! cmp -s "$WORK/$asset" "$RELEASE_DIR/$asset"; then
  echo 'mobile-bootstrap: immutable release conflict' >&2; exit 1
 fi
 mode=600
 [[ "$asset" == ultra-*-linux-* && "$asset" != *.tar.gz ]] && mode=755
 install -m "$mode" "$WORK/$asset" "$RELEASE_DIR/$asset"
done <"$WORK/assets"
install -m 600 "$WORK/release-manifest.json" "$RELEASE_DIR/release-manifest.json"
for signature in checksums.txt.minisig release-manifest.json.minisig; do
 [[ ! -f "$WORK/$signature" ]] || install -m 600 "$WORK/$signature" "$RELEASE_DIR/$signature"
done
for app in install relay bot; do
 ln -sfn "ultra-${app}-linux-${ARCH}" "$RELEASE_DIR/ultra-${app}"
done
# This pointer refers only to bootstrap artifacts, not an activated service.
ln -sfn "$RELEASE_DIR" "${INSTALL_ROOT}/current"

APPLY_ARGS=(
  apply-remote
  -plan "$PLAN"
  -release-dir "$RELEASE_DIR"
  -format "$FORMAT"
)
if [[ -n "$SECRETS" ]]; then
  APPLY_ARGS+=(-secrets "$SECRETS")
fi
if [[ -n "$SSH_IDENTITY" ]]; then
  APPLY_ARGS+=(-ssh-identity "$SSH_IDENTITY")
fi

"${RELEASE_DIR}/ultra-install" "${APPLY_ARGS[@]}"
