package installplan

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func LoadLegacyEnvConfig(path string) (*InstallPlan, error) {
	values, err := parseLegacyEnvFile(path)
	if err != nil {
		return nil, err
	}
	return LegacyValuesToPlan(values), nil
}

func LegacyValuesToPlan(v map[string]string) *InstallPlan {
	sshUser := valueDefault(v, "SSH_USER", "root")
	bridgeHost := firstValue(v, "BRIDGE", "FRONT")
	exitHost := firstValue(v, "EXIT", "BACK")
	publicHost := valueDefault(v, "PUBLIC_HOST", bridgeHost)
	vlessPort := intDefault(v, "VLESS_PORT", 443)
	tunnelPort := intDefault(v, "TUNNEL_PORT", vlessPort)

	p := &InstallPlan{
		SchemaVersion: CurrentSchemaVersion,
		SSH: SSHConfig{
			User:              sshUser,
			Identity:          v["IDENTITY"],
			StrictHostKey:     boolValue(v, "ULTRA_INSTALL_SSH_STRICT_HOST_KEY", false),
			ConnectTimeoutSec: intDefault(v, "ULTRA_SSH_CONNECT_TIMEOUT", 10),
		},
		Bridge: BridgeConfig{
			SSHHost:     bridgeHost,
			PublicHost:  publicHost,
			VLESSPort:   vlessPort,
			TunnelPort:  tunnelPort,
			RealityDest: v["REALITY_DEST"],
			RealitySNI:  v["REALITY_SNI"],
			ReuseSpec:   boolValue(v, "REUSE_BRIDGE_SPEC", true),
			RemoteDir:   valueDefault(v, "REMOTE_DIR", "/etc/ultra-relay"),
			BotDomain:   v["BOT_DOMAIN"],
			BotPort:     intDefault(v, "BOT_PORT", 8444),
			AdminListen: "127.0.0.1:8443",
		},
		Features: FeatureConfig{
			Preset:                 valueDefault(v, "PRESET", "apijson"),
			Transport:              valueDefault(v, "TRANSPORT", "splithttp"),
			RoutingMode:            v["ROUTING_MODE"],
			LogLevel:               valueDefault(v, "LOG_LEVEL", "info"),
			GenerateExitTLS:        boolValue(v, "GENERATE_EXIT_TLS", true),
			SkipGeoDownload:        boolValue(v, "SKIP_GEO_DOWNLOAD", boolValue(v, "SKIP_RUNETFREEDOM_GEO", false)),
			GeoReleaseTag:          v["GEO_RELEASE_TAG"],
			WARP:                   boolValue(v, "WARP_ENABLE", false),
			WARPPort:               intDefault(v, "WARP_PORT", 40000),
			DisableDOH:             boolValue(v, "DOH_DISABLE", false),
			DisableVLESSFlow:       boolValue(v, "DISABLE_VLESS_FLOW", false),
			VLESSFlow:              valueDefault(v, "VLESS_FLOW", "xtls-rprx-vision"),
			AntiCensorProfile:      v["ANTI_CENSOR_PROFILE"],
			PublicXHTTPPort:        intDefault(v, "PUBLIC_XHTTP_PORT", 0),
			DisableFragment:        boolValue(v, "FRAGMENT_DISABLE", false),
			SplitHTTPPadding:       v["SPLITHTTP_PADDING"],
			SplitHTTPMaxChunkKB:    intDefault(v, "SPLITHTTP_MAX_CHUNK_KB", 0),
			RealityFingerprintsCSV: v["REALITY_FINGERPRINTS"],
			GeositeBlockTags:       v["GEOSITE_BLOCK_TAGS"],
			DomainDirect:           v["DOMAIN_DIRECT"],
			SplitHTTPHost:          v["SPLITHTTP_HOST"],
			SplitHTTPPath:          v["SPLITHTTP_PATH"],
		},
		Database: DatabaseConfig{
			Enabled:     boolValue(v, "DB_ENABLE", false),
			PrimaryHost: v["DB_HOST"],
			ReplicaHost: v["DB_REPLICA"],
			SSHUser:     v["DB_SSH_USER"],
			Name:        valueDefault(v, "DB_NAME", "ultra_db"),
			User:        valueDefault(v, "DB_USER", "ultra"),
		},
		Bot: BotConfig{
			Enabled: boolValue(v, "BOT_ENABLE", false),
			Domain:  v["BOT_DOMAIN"],
			Port:    intDefault(v, "BOT_PORT", 8444),
			EnvFile: valueDefault(v, "BOT_ENV_FILE", ".env"),
		},
		Secrets: SecretsConfig{
			EnvFile: valueDefault(v, "BOT_ENV_FILE", ".env"),
		},
		Verification: Verification{
			Enabled:           boolValue(v, "VERIFY_AFTER_INSTALL", false),
			IPURL:             v["VERIFY_IP_URL"],
			SOCKSPort:         intDefault(v, "VERIFY_SOCKS_PORT", 0),
			UserUUID:          v["VERIFY_USER_UUID"],
			FailLogLines:      intDefault(v, "VERIFY_FAIL_LOG_LINES", 400),
			SplitRouting:      v["VERIFY_SPLIT_ROUTING"],
			ProbeExitURL:      v["VERIFY_PROBE_EXIT_URL"],
			ProbeExitPlainURL: v["VERIFY_PROBE_EXIT_PLAIN_URL"],
		},
		Artifacts: ArtifactConfig{
			ProjectRoot: ".",
			RelayBinary: "ultra-relay-linux-amd64",
			BotBinary:   "ultra-bot-linux-amd64",
		},
		Execution: ExecutionConfig{
			Mode:    "local",
			Release: valueDefault(v, "ULTRA_RELEASE", "latest"),
			Channel: valueDefault(v, "ULTRA_CHANNEL", "stable"),
		},
	}

	if exitHost != "" {
		p.Exits = append(p.Exits, ExitNode{
			Name:     "primary",
			SSHHost:  exitHost,
			DialAddr: valueDefault(v, "EXIT_DIAL", exitHost),
			Port:     tunnelPort,
			Priority: 100,
		})
	}
	if exit2 := strings.TrimSpace(v["EXIT2"]); exit2 != "" && exit2 != exitHost {
		p.Exits = append(p.Exits, ExitNode{
			Name:     valueDefault(v, "EXIT2_NAME", "backup"),
			SSHHost:  exit2,
			DialAddr: valueDefault(v, "EXIT2_DIAL", exit2),
			Port:     tunnelPort,
			Priority: intDefault(v, "EXIT2_PRIORITY", 200),
		})
	}
	return p
}

func parseLegacyEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	values := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = stripInlineComment(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		values[key] = unquote(strings.TrimSpace(val))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read legacy config: %w", err)
	}
	return values, nil
}

func stripInlineComment(s string) string {
	var quote rune
	for i, r := range s {
		switch r {
		case '\'', '"':
			switch quote {
			case 0:
				quote = r
			case r:
				quote = 0
			}
		case '#':
			if quote == 0 {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return strings.TrimSpace(s)
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func firstValue(v map[string]string, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(v[k]); s != "" {
			return s
		}
	}
	return ""
}

func valueDefault(v map[string]string, key, def string) string {
	if s := strings.TrimSpace(v[key]); s != "" {
		return s
	}
	return def
}

func intDefault(v map[string]string, key string, def int) int {
	s := strings.TrimSpace(v[key])
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func boolValue(v map[string]string, key string, def bool) bool {
	s := strings.ToLower(strings.TrimSpace(v[key]))
	if s == "" {
		return def
	}
	switch s {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}
