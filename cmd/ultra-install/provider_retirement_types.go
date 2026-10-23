package main

type retainedPrimaryIdentity struct {
	RouteSHA256       string `json:"route_sha256,omitempty"`
	SystemIdentifier  string `json:"system_identifier"`
	Database          string `json:"database"`
	DatabaseOID       uint32 `json:"database_oid"`
	MigrationsSHA256  string `json:"migrations_sha256"`
	MigrationVersions string `json:"migration_versions"`
}

type retainedPrimaryRebuildInput struct {
	ExecutionTimeoutSeconds    int64               `json:",omitempty"`
	BackupSnapshotUTC          string              `json:",omitempty"`
	BackupSHA256               string              `json:",omitempty"`
	BackupMaxAgeSeconds        float64             `json:",omitempty"`
	BridgeOnly                 bool                `json:",omitempty"`
	RetainedExit               *retainedBridgeExit `json:",omitempty"`
	Inventory                  map[string]any
	Variables                  map[string]any
	JournalSHA256              string
	ConfigSHA256               string
	ManifestSHA256             string
	CandidateMigrationsSHA256  string
	CandidateMigrationVersions string
	FenceEvidenceSHA256        string
	Primary                    retainedPrimaryIdentity
	Directory                  string
	Python                     string
	Executable                 string
}
