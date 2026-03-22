#!/usr/bin/env bash
# update-geo-assets.sh — fetch geoip.dat + geosite.dat from a pinned GitHub release
# into spec.geo_assets_dir (XRAY_LOCATION_ASSET). Typical path after install: .../geo under the relay config dir.
#
# Usage:
#   ./scripts/update-geo-assets.sh /var/lib/ultra/geo
#   ./scripts/update-geo-assets.sh /var/lib/ultra/geo 202603220955
#
# Optional: GITHUB_TOKEN reduces GitHub API rate limits when resolving "latest".
#
# After a successful update, reload embedded Xray on the Linux bridge:
#   kill -USR1 "$(pidof ultra-relay)"
#
# cron (example, twice daily):
#   15 */6 * * * /path/to/ultra/scripts/update-geo-assets.sh /var/lib/ultra/geo && kill -USR1 "$(pidof ultra-relay)"
#
set -euo pipefail

GEO_DIR="${1:-}"
TAG="${2:-}"

if [[ -z "$GEO_DIR" ]]; then
  echo "usage: $0 <geo_assets_dir> [release_tag]" >&2
  exit 2
fi

GEO_DIR="$(cd "$GEO_DIR" && pwd)"
REPO="runetfreedom/russia-v2ray-rules-dat"
BASE="https://github.com/${REPO}/releases/download"

mkdir -p "$GEO_DIR"
TMP="$(mktemp -d "${GEO_DIR%/}/.geo-update.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

curl_opts=(-fsSL)
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  curl_opts+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

if [[ -z "$TAG" ]]; then
  TAG="$(
    curl "${curl_opts[@]}" "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -1
  )"
fi
if [[ -z "$TAG" ]]; then
  echo "failed to resolve release tag (set GITHUB_TOKEN if API rate-limited)" >&2
  exit 1
fi

verify_sha256() {
  local file="$1" sumfile="$2"
  local want got
  want="$(awk '{print $1}' "$sumfile")"
  got="$(openssl dgst -sha256 -r "$file" | awk '{print $1}')"
  if [[ "$got" != "$want" ]]; then
    echo "checksum mismatch for $(basename "$file") (expected $want got $got)" >&2
    exit 1
  fi
}

for name in geoip.dat geosite.dat; do
  curl "${curl_opts[@]}" "${BASE}/${TAG}/${name}" -o "${TMP}/${name}"
  curl "${curl_opts[@]}" "${BASE}/${TAG}/${name}.sha256sum" -o "${TMP}/${name}.sha256sum"
  verify_sha256 "${TMP}/${name}" "${TMP}/${name}.sha256sum"
done

mv -f "${TMP}/geoip.dat" "${GEO_DIR}/geoip.dat"
mv -f "${TMP}/geosite.dat" "${GEO_DIR}/geosite.dat"
rm -rf "$TMP"
trap - EXIT

echo "updated ${REPO}@${TAG} -> ${GEO_DIR}"
