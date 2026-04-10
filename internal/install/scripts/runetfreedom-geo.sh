#!/bin/bash
# Template processed by fmt.Sprintf — see RunetfreedomGeoRemoteScript in runetfreedom_geo.go.
set -euo pipefail
GEO_DIR=%s
mkdir -p "$GEO_DIR"
TMP="$(mktemp -d "$GEO_DIR/.geo-init.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
REPO="runetfreedom/russia-v2ray-rules-dat"
BASE="https://github.com/${REPO}/releases/download"
%s
if [[ -z "$TAG" ]]; then echo "runetfreedom geo: failed to resolve release tag" >&2; exit 1; fi
verify_sha256() {
  local file="$1" sumfile="$2"
  local want got
  want="$(awk '{print $1}' "$sumfile")"
  got="$(openssl dgst -sha256 -r "$file" | awk '{print $1}')"
  if [[ "$got" != "$want" ]]; then
    echo "runetfreedom geo: checksum mismatch for $(basename "$file")" >&2
    exit 1
  fi
}
for n in geoip.dat geosite.dat; do
  curl -fsSL "${BASE}/${TAG}/${n}" -o "${TMP}/${n}"
  curl -fsSL "${BASE}/${TAG}/${n}.sha256sum" -o "${TMP}/${n}.sha256sum"
  verify_sha256 "${TMP}/${n}" "${TMP}/${n}.sha256sum"
done
mv -f "${TMP}/geoip.dat" "$GEO_DIR/geoip.dat"
mv -f "${TMP}/geosite.dat" "$GEO_DIR/geosite.dat"
trap - EXIT
cleanup
chown -R ultra-relay:ultra-relay "$GEO_DIR"
chmod 755 "$GEO_DIR"
chmod 644 "$GEO_DIR/geoip.dat" "$GEO_DIR/geosite.dat"
