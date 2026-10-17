#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"
VERSION="${2:-}"
SOURCE_COMMIT="$(git rev-parse HEAD)"
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid source commit" >&2; exit 1; }

if [[ ! -d "$DIST_DIR" ]]; then
  echo "release manifest: dist dir not found: $DIST_DIR" >&2
  exit 1
fi

json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

sha_for() {
  local file="$1"
  sha256sum "$file" | awk '{print $1}'
}

size_for() {
  wc -c <"$1" | tr -d ' '
}

manifest="${DIST_DIR}/release-manifest.json"
tmp="${manifest}.tmp"

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "version": "%s",\n' "$(json_escape "$VERSION")"
  printf '  "source_commit": "%s",\n' "$SOURCE_COMMIT"
  printf '  "capabilities": ["service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"],\n'
  printf '  "database_schema_min": 24,\n'
  printf '  "database_schema_max": 25,\n'
  printf '  "assets": [\n'
  first=1
  for file in \
    ultra-install-linux-amd64 \
    ultra-install-linux-arm64 \
    ultra-relay-linux-amd64 \
    ultra-relay-linux-arm64 \
    ultra-bot-linux-amd64 \
    ultra-bot-linux-arm64 \
    ultra-client-linux-amd64 \
    ultra-client-linux-arm64 \
    ultra-recovery.tar.gz \
    ultra-ansible.tar.gz \
    ultra-ansible-runtime-linux-amd64.tar.gz \
    ultra-ansible-runtime-linux-arm64.tar.gz \
    mobile-bootstrap.sh \
    checksums.txt; do
    path="${DIST_DIR}/${file}"
    [[ -f "$path" && -s "$path" ]] || { echo "release manifest: missing or empty asset: $file" >&2; rm -f "$tmp"; exit 1; }
    if [[ "$first" -eq 0 ]]; then
      printf ',\n'
    fi
    first=0
    printf '    {"name":"%s","sha256":"%s","size":%s}' \
      "$(json_escape "$file")" "$(sha_for "$path")" "$(size_for "$path")"
  done
  printf '\n  ]\n'
  printf '}\n'
} >"$tmp"
mv "$tmp" "$manifest"
