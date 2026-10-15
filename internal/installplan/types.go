package installplan

import "time"

const CurrentSchemaVersion = 2

type InstallPlan struct {
	ControllerLocalTarget string `json:"-"`
	// Native execution location is attested and frozen by the operator process, never config.
	ControllerLocal *bool             `json:"-"`
	SourceValues    map[string]string `json:"-"`
	Automation      *AutomationConfig `json:"automation,omitempty"`
	BridgeNative    bool              `json:"bridge_native,omitempty"`
	AdoptRuntime    bool              `json:"adopt_runtime,omitempty"`
	SchemaVersion   int               `json:"schema_version"`
	SSH             SSHConfig         `json:"ssh"`
	Bridge          BridgeConfig      `json:"bridge"`
	Exits           []ExitNode        `json:"exits"`
	Database        DatabaseConfig    `json:"database,omitempty"`
	Bot             BotConfig         `json:"bot,omitempty"`
	Secrets         SecretsConfig     `json:"secrets,omitempty"`
	Features        FeatureConfig     `json:"features,omitempty"`
	Verification    Verification      `json:"verification,omitempty"`
	Artifacts       ArtifactConfig    `json:"artifacts,omitempty"`
	Execution       ExecutionConfig   `json:"execution,omitempty"`
}

type SSHConfig struct {
	User              string `json:"user,omitempty"`
	Identity          string `json:"identity,omitempty"`
	StrictHostKey     bool   `json:"strict_host_key,omitempty"`
	ConnectTimeoutSec int    `json:"connect_timeout_sec,omitempty"`
}

type BridgeConfig struct {
	SSHIdentity string `json:"ssh_identity,omitempty"`
	Address     string `json:"address,omitempty"`
	SSHHost     string `json:"ssh_host"`
	PublicHost  string `json:"public_host,omitempty"`
	VLESSPort   int    `json:"vless_port,omitempty"`
	TunnelPort  int    `json:"tunnel_port,omitempty"`
	RealityDest string `json:"reality_dest,omitempty"`
	RealitySNI  string `json:"reality_sni,omitempty"`
	ReuseSpec   bool   `json:"reuse_spec,omitempty"`
	RemoteDir   string `json:"remote_dir,omitempty"`
	BotDomain   string `json:"bot_domain,omitempty"`
	BotPort     int    `json:"bot_port,omitempty"`
	AdminListen string `json:"admin_listen,omitempty"`
}

type ExitNode struct {
	SSHIdentity string `json:"ssh_identity,omitempty"`
	Name        string `json:"name"`
	SSHHost     string `json:"ssh_host"`
	DialAddr    string `json:"dial_addr,omitempty"`
	Port        int    `json:"port,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
	TunnelUUID  string `json:"tunnel_uuid,omitempty"`
}

type DatabaseConfig struct {
	Enabled     bool   `json:"enabled,omitempty"`
	PrimaryHost string `json:"primary_host,omitempty"`
	ReplicaHost string `json:"replica_host,omitempty"`
	SSHUser     string `json:"ssh_user,omitempty"`
	SSHIdentity string `json:"ssh_identity,omitempty"`
	Name        string `json:"name,omitempty"`
	User        string `json:"user,omitempty"`
}

type BotConfig struct {
	SubscriptionDomain string `json:"subscription_domain,omitempty"`
	Enabled            bool   `json:"enabled,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Port               int    `json:"port,omitempty"`
	// EnvFile is kept for backward compatibility. New callers should use secrets.env_file.
	EnvFile string `json:"env_file,omitempty"`
}

type SecretsConfig struct {
	DatabaseDumpFile        string `json:"database_dump_file,omitempty"`
	DatabaseDumpSHA256      string `json:"database_dump_sha256,omitempty"`
	DatabaseCredentialsFile string `json:"database_credentials_file,omitempty"`
	EnvFile                 string `json:"env_file,omitempty"`
}

type FeatureConfig struct {
	BotTelegramProxy       bool   `json:"bot_telegram_proxy,omitempty"`
	Preset                 string `json:"preset,omitempty"`
	Transport              string `json:"transport,omitempty"`
	RoutingMode            string `json:"routing_mode,omitempty"`
	LogLevel               string `json:"log_level,omitempty"`
	GenerateExitTLS        bool   `json:"generate_exit_tls,omitempty"`
	SkipGeoDownload        bool   `json:"skip_geo_download,omitempty"`
	GeoReleaseTag          string `json:"geo_release_tag,omitempty"`
	WARP                   bool   `json:"warp,omitempty"`
	WARPPort               int    `json:"warp_port,omitempty"`
	DisableDOH             bool   `json:"disable_doh,omitempty"`
	DisableVLESSFlow       bool   `json:"disable_vless_flow,omitempty"`
	VLESSFlow              string `json:"vless_flow,omitempty"`
	AntiCensorProfile      string `json:"anti_censor_profile,omitempty"`
	PublicXHTTPPort        int    `json:"public_xhttp_port,omitempty"`
	DisableFragment        bool   `json:"disable_fragment,omitempty"`
	SplitHTTPPadding       string `json:"splithttp_padding,omitempty"`
	SplitHTTPMaxChunkKB    int    `json:"splithttp_max_chunk_kb,omitempty"`
	RealityFingerprintsCSV string `json:"reality_fingerprints,omitempty"`
	GeositeBlockTags       string `json:"geosite_block_tags,omitempty"`
	DomainDirect           string `json:"domain_direct,omitempty"`
	SplitHTTPHost          string `json:"splithttp_host,omitempty"`
	SplitHTTPPath          string `json:"splithttp_path,omitempty"`
}

type Verification struct {
	Enabled           bool   `json:"enabled,omitempty"`
	IPURL             string `json:"ip_url,omitempty"`
	SOCKSPort         int    `json:"socks_port,omitempty"`
	UserUUID          string `json:"user_uuid,omitempty"`
	FailLogLines      int    `json:"fail_log_lines,omitempty"`
	SplitRouting      string `json:"split_routing,omitempty"`
	ProbeExitURL      string `json:"probe_exit_url,omitempty"`
	ProbeExitPlainURL string `json:"probe_exit_plain_url,omitempty"`
}

type ArtifactConfig struct {
	ProjectRoot string `json:"project_root,omitempty"`
	RelayBinary string `json:"relay_binary,omitempty"`
	BotBinary   string `json:"bot_binary,omitempty"`
}

type ExecutionConfig struct {
	Mode    string `json:"mode,omitempty"`    // local, remote_bootstrap
	Release string `json:"release,omitempty"` // latest or a tag like v1.2.3
	Channel string `json:"channel,omitempty"` // stable, beta, dev
}

type InstallResult struct {
	DeployedNodes []NodeResult `json:"deployed_nodes,omitempty"`
	SkippedNodes  []NodeResult `json:"skipped_nodes,omitempty"`
	AdminToken    string       `json:"admin_token,omitempty"`
	Warnings      []Issue      `json:"warnings,omitempty"`
}

type NodeResult struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Role    string `json:"role"`
	CertPin string `json:"cert_pin,omitempty"`
	Message string `json:"message,omitempty"`
}

type EventKind string

const (
	EventStep     EventKind = "step"
	EventProgress EventKind = "progress"
	EventLog      EventKind = "log"
	EventWarning  EventKind = "warning"
	EventError    EventKind = "error"
)

type InstallEvent struct {
	Time    time.Time `json:"time"`
	Kind    EventKind `json:"kind"`
	Code    string    `json:"code,omitempty"`
	Message string    `json:"message"`
	Node    string    `json:"node,omitempty"`
}

type IssueSeverity string

const (
	SeverityInfo    IssueSeverity = "info"
	SeverityWarning IssueSeverity = "warning"
	SeverityError   IssueSeverity = "error"
)

const (
	CodeSSHUnreachable             = "SSH_UNREACHABLE"
	CodeDNSMismatch                = "DNS_MISMATCH"
	CodePortBlocked                = "PORT_BLOCKED"
	CodeMissingBotToken            = "MISSING_BOT_TOKEN"
	CodeRemotePackageInstallFailed = "REMOTE_PACKAGE_INSTALL_FAILED"
	CodeNoExitDeployed             = "NO_EXIT_DEPLOYED"
	CodeCertbotFailed              = "CERTBOT_FAILED"
	CodeInvalidPlan                = "INVALID_PLAN"
	CodeUnsupportedOS              = "UNSUPPORTED_OS"
	CodeUnsupportedArch            = "UNSUPPORTED_ARCH"
	CodeMissingSystemd             = "MISSING_SYSTEMD"
	CodeGitHubUnreachable          = "GITHUB_UNREACHABLE"
)

type Issue struct {
	Severity IssueSeverity `json:"severity"`
	Code     string        `json:"code"`
	Message  string        `json:"message"`
	Node     string        `json:"node,omitempty"`
}

type DoctorReport struct {
	OK     bool    `json:"ok"`
	Issues []Issue `json:"issues,omitempty"`
}

// AutomationConfig contains references and public deployment policy, never secret values.
// A v2 plan requires automation; v1 plans retain their legacy deployment semantics.
type AutomationConfig struct {
	DNS                 *AutomationDNS     `json:"dns,omitempty"`
	Ingress             *AutomationIngress `json:"ingress,omitempty"`
	AdminTelegramID     int64              `json:"admin_telegram_id,omitempty"`
	ReleaseDir          string             `json:"release_dir"`
	Version             string             `json:"version"`
	AgeRecipient        string             `json:"age_recipient"`
	BridgeProvider      string             `json:"bridge_provider"`
	BridgeIPv4          string             `json:"bridge_ipv4"`
	BridgeURL           string             `json:"bridge_url"`
	CloudKeyFile        string             `json:"cloud_key_file,omitempty"`
	KnownHostsFile      string             `json:"known_hosts_file"`
	StaticNodes         []AutomationNode   `json:"static_nodes"`
	StatePaths          []string           `json:"state_paths,omitempty"`
	ArtifactPaths       []string           `json:"artifact_paths,omitempty"`
	ReadinessTimeoutSec int                `json:"readiness_timeout_sec,omitempty"`
}
type StaticBudget struct {
	MonthlyBytes int64 `json:"monthly_bytes"`
	IsFallback   bool  `json:"is_fallback"`
}

type AutomationNode struct {
	Budget   *StaticBudget `json:"budget,omitempty"`
	Name     string        `json:"name"`
	Address  string        `json:"address"`
	Provider string        `json:"provider"`
}

func (p *InstallPlan) FullAutomation() bool { return p.SchemaVersion >= 2 || p.Automation != nil }

type AutomationIngress struct {
	Domain           string `json:"domain"`
	Email            string `json:"email"`
	Path             string `json:"path"`
	ForwardHost      string `json:"forward_host,omitempty"`
	PublicHost       string `json:"public_host,omitempty"`
	BackendPort      int    `json:"backend_port"`
	GatewayPort      int    `json:"gateway_port"`
	StatusPort       int    `json:"status_port"`
	ExperimentalPort int    `json:"experimental_port"`
	StagingPort      int    `json:"staging_port"`
}

// AutomationDNS describes owned records. APIKeyFile is a derived runtime reference, never a token.
type AutomationDNS struct {
	Provider         string `json:"provider"`
	Zone             string `json:"zone"`
	TTL              int    `json:"ttl"`
	SubscriptionName string `json:"subscription_name"`
	VPNName          string `json:"vpn_name"`
	APIKeyFile       string `json:"api_key_file,omitempty"`
}

// PublicSubscriptionDomain is independent of the bot's backend TLS certificate name.
func (p *InstallPlan) PublicSubscriptionDomain() string {
	if p.Bot.SubscriptionDomain != "" {
		return p.Bot.SubscriptionDomain
	}
	return p.Bot.Domain
}

// Role-specific keys override the shared legacy identity without changing it.
func (p *InstallPlan) BridgeSSHIdentity() string {
	if p.Bridge.SSHIdentity != "" {
		return p.Bridge.SSHIdentity
	}
	return p.SSH.Identity
}
func (p *InstallPlan) ExitSSHIdentity(node ExitNode) string {
	if node.SSHIdentity != "" {
		return node.SSHIdentity
	}
	return p.SSH.Identity
}
