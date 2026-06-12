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
FORMAT="jsonl"
INSTALL_ROOT="/opt/ultra"
MINISIGN_PUBKEY=""
REQUIRE_SIGNATURE="auto"

usage() {
  cat <<EOF
Usage: mobile-bootstrap.sh [options]

Options:
  --repo OWNER/REPO       GitHub repository (default: ${REPO})
  --release TAG|latest    GitHub release tag or latest (default: latest)
  --plan PATH             install-plan JSON already uploaded to this server
  --secrets PATH          secrets env file already uploaded to this server
  --format human|jsonl    ultra-install event output format (default: jsonl)
  --install-root PATH     release install root (default: /opt/ultra)
  --minisign-pubkey KEY   minisign public key for checksums.txt.minisig
  --require-signature MODE  auto, yes, or no (default: auto)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="${2:?}"; shift 2 ;;
    --release) RELEASE="${2:?}"; shift 2 ;;
    --plan) PLAN="${2:?}"; shift 2 ;;
    --secrets) SECRETS="${2:?}"; shift 2 ;;
    --format) FORMAT="${2:?}"; shift 2 ;;
    --install-root) INSTALL_ROOT="${2:?}"; shift 2 ;;
    --minisign-pubkey) MINISIGN_PUBKEY="${2:?}"; shift 2 ;;
    --require-signature) REQUIRE_SIGNATURE="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

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
case "$REQUIRE_SIGNATURE" in
  auto|yes|no) ;;
  *) echo "mobile-bootstrap: --require-signature must be auto, yes, or no" >&2; exit 2 ;;
esac

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "mobile-bootstrap: required command not found: $1" >&2
    exit 1
  fi
}

need curl
need sha256sum
need install

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
trap 'rm -rf "$WORK"' EXIT

download() {
  local name="$1"
  curl -fL --retry 3 --connect-timeout 10 -o "${WORK}/${name}" "${BASE_URL}/${name}"
}

INSTALL_ASSET="ultra-install-linux-${ARCH}"
RELAY_ASSET="ultra-relay-linux-${ARCH}"
BOT_ASSET="ultra-bot-linux-${ARCH}"

download checksums.txt
download release-manifest.json || true
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
  elif [[ "$REQUIRE_SIGNATURE" == "yes" ]]; then
    echo "mobile-bootstrap: checksums.txt.minisig is required but was not found" >&2
    exit 1
  fi
fi
download "$INSTALL_ASSET"
download "$RELAY_ASSET"
download "$BOT_ASSET"

(
  cd "$WORK"
  grep -E " (${INSTALL_ASSET}|${RELAY_ASSET}|${BOT_ASSET})$" checksums.txt | sha256sum -c -
)

RELEASE_DIR="${INSTALL_ROOT}/releases/${RELEASE_DIR_NAME}-${ARCH}"
install -d -m 755 "$RELEASE_DIR"
install -m 755 "${WORK}/${INSTALL_ASSET}" "${RELEASE_DIR}/ultra-install"
install -m 755 "${WORK}/${RELAY_ASSET}" "${RELEASE_DIR}/ultra-relay"
install -m 755 "${WORK}/${BOT_ASSET}" "${RELEASE_DIR}/ultra-bot"
ln -sfn "$RELEASE_DIR" "${INSTALL_ROOT}/current"

APPLY_ARGS=(
  apply-remote
  -plan "$PLAN"
  -release-dir "${INSTALL_ROOT}/current"
  -format "$FORMAT"
)
if [[ -n "$SECRETS" ]]; then
  APPLY_ARGS+=(-secrets "$SECRETS")
fi

exec "${INSTALL_ROOT}/current/ultra-install" "${APPLY_ARGS[@]}"
