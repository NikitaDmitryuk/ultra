#!/bin/sh
# Build the reviewed provider transport without changing ultra's Go module.
set -eu
arch=${1:-amd64}
out=${2:?usage: tools/build-olcrtc.sh amd64|arm64 /absolute/output-directory [existing-source-repository]}
case "$arch" in amd64|arm64) ;; *) echo 'unsupported architecture' >&2; exit 1;; esac
case "$out" in /*) ;; *) echo 'output directory must be absolute' >&2; exit 1;; esac
commit=189d16c093c4f721376afb5eaa0213d132a11242
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
if [ $# -ge 3 ]; then
    git -C "$3" archive "$commit" | tar -x -C "$work"
else
    git -C "$work" init -q
    git -C "$work" remote add origin https://github.com/openlibrecommunity/olcrtc.git
    git -C "$work" fetch --depth 1 origin "$commit"
    git -C "$work" checkout --detach FETCH_HEAD
fi
cp "$repo/testdata/olcrtc/ultra_failclosed_test.go" "$work/internal/server/ultra_failclosed_test.go"
cp "$repo/testdata/olcrtc/ultra_config_test.go" "$work/internal/config/ultra_config_test.go"
(cd "$work" && go test ./internal/config ./internal/server -run 'TestUltra|TestDialProxyError' -count=1)
mkdir -p "$out"
(cd "$work" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$out/olcrtc-linux-$arch" ./cmd/olcrtc)
python3 - "$out/olcrtc-linux-$arch" "$commit" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
manifest={'binary':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'source_commit':sys.argv[2]}
p.with_suffix('.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Built binary and rtc_deployment manifest:',p)
PY
