package main

type upgradeDomainEvidence struct {
	BridgeURL             string `json:"bridge_url"`
	BridgeIPv4            string `json:"bridge_ipv4"`
	Zone                  string `json:"zone"`
	DNSTTL                int    `json:"dns_ttl"`
	ACMEEmailMatches      bool   `json:"acme_email_matches"`
	IngressModeMatches    bool   `json:"ingress_mode_matches"`
	ForwardHostMatches    bool   `json:"forward_host_matches"`
	StagingPortMatches    bool   `json:"staging_port_matches"`
	StagingPortUnrecorded bool   `json:"staging_port_unrecorded"`
	StatusPortMatches     bool   `json:"status_port_matches"`
	ExperimentalPortMatch bool   `json:"experimental_port_matches"`
	AgeRecipientMatches   bool   `json:"age_recipient_matches"`
	BridgeProviderMatches bool   `json:"bridge_provider_matches"`
	StaticNodesMatch      bool   `json:"static_nodes_match"`
	AdminIDMatches        bool   `json:"admin_id_matches"`
	StatePathsMatch       bool   `json:"state_paths_match"`
	ArtifactPathsMatch    bool   `json:"artifact_paths_match"`
	Verified              bool   `json:"verified"`
	Subscription          string `json:"subscription"`
	Backend               string `json:"backend"`
	VPN                   string `json:"vpn"`
	PublicHost            string `json:"public_host"`
	Path                  string `json:"path"`
	BackendPort           int    `json:"backend_port"`
	BotPort               int    `json:"bot_port"`
	GatewayPort           int    `json:"gateway_port"`
	Fingerprint           string `json:"fingerprint"`
}
