#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"
VERSION="${2:-}"

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
  printf '  "assets": [\n'
  first=1
  for file in \
    ultra-install-linux-amd64 \
    ultra-install-linux-arm64 \
    ultra-relay-linux-amd64 \
    ultra-relay-linux-arm64 \
    ultra-bot-linux-amd64 \
    ultra-bot-linux-arm64 \
    mobile-bootstrap.sh \
    checksums.txt; do
    path="${DIST_DIR}/${file}"
    [[ -f "$path" ]] || continue
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

