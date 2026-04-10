package install

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed scripts/runetfreedom-geo.sh
var runetfreedomGeoScriptTmpl string

// RunetfreedomGeoRemoteScript returns a bash script run on the bridge host: downloads geoip.dat and
// geosite.dat from a fixed upstream rules release into geoDir, verifies sha256, sets owner to ultra-relay.
// releaseTag empty means resolve latest via GitHub API (needs curl, openssl on the server).
func RunetfreedomGeoRemoteScript(geoDir, releaseTag string) string {
	q := func(s string) string {
		return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
	}
	geoQ := q(geoDir)
	tagSetup := ""
	if strings.TrimSpace(releaseTag) != "" {
		tagSetup = fmt.Sprintf("TAG=%s\n", q(strings.TrimSpace(releaseTag)))
	} else {
		tagSetup = `TAG="$(curl -fsSL https://api.github.com/repos/runetfreedom/russia-v2ray-rules-dat/releases/latest | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
`
	}
	return fmt.Sprintf(runetfreedomGeoScriptTmpl, geoQ, tagSetup)
}
