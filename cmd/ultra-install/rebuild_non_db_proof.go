package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This is an offline evidence intake protocol, not an execution authorization.
// There is no trusted fleet collector or signer delegation in the current
// deployment contract. Even a structurally valid envelope remains unverified.
const rebuildPreflightProtocol = "ultra-rebuild-non-db-preflight-v1"

type rebuildEnvelope struct {
	Protocol  string `json:"protocol"`
	SignerID  string `json:"signer_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type rebuildCensus struct {
	Provider           string `json:"provider"`
	AccountSHA         string `json:"account_sha256"`
	InventorySHA       string `json:"inventory_sha256"`
	ObservedAt         int64  `json:"observed_at_unix"`
	PaginationComplete bool   `json:"pagination_complete"`
	TargetCount        int    `json:"target_count"`
}

type rebuildTarget struct {
	ID             string `json:"id"`
	Role           string `json:"role"`
	Provider       string `json:"provider"`
	AccountSHA     string `json:"account_sha256"`
	InstanceID     string `json:"instance_id"`
	SSHIdentitySHA string `json:"ssh_identity_sha256"`
	ObservationSHA string `json:"observation_sha256"`
	ObservedAt     int64  `json:"observed_at_unix"`
	WorkersFenced  bool   `json:"workers_fenced"`
}

type rebuildPrimary struct {
	Provider         string `json:"provider"`
	AccountSHA       string `json:"account_sha256"`
	InstanceID       string `json:"instance_id"`
	SSHIdentitySHA   string `json:"ssh_identity_sha256"`
	SystemIdentifier string `json:"system_identifier"`
	Database         string `json:"database"`
	DatabaseOID      uint32 `json:"database_oid"`
	Primary          bool   `json:"primary"`
	MigrationsSHA    string `json:"migrations_sha256"`
	DSNBindingSHA    string `json:"dsn_binding_sha256"`
	ObservationSHA   string `json:"observation_sha256"`
	ObservedAt       int64  `json:"observed_at_unix"`
	WorkersFenced    bool   `json:"workers_fenced"`
	ActiveClients    int    `json:"active_clients"`
	AccessPolicy     string `json:"access_policy"`
	AuthorizationSHA string `json:"authorization_sha256"`
}

type rebuildStep struct {
	Operation string   `json:"operation"`
	Targets   []string `json:"targets"`
}

type rebuildEvidence struct {
	Protocol       string          `json:"protocol"`
	OperationID    string          `json:"operation_id"`
	Nonce          string          `json:"nonce"`
	IssuedAt       int64           `json:"issued_at_unix"`
	ExpiresAt      int64           `json:"expires_at_unix"`
	JournalSHA     string          `json:"journal_sha256"`
	ConfigSHA      string          `json:"config_sha256"`
	ManifestSHA    string          `json:"manifest_sha256"`
	Complete       bool            `json:"complete_fleet"`
	Censuses       []rebuildCensus `json:"censuses"`
	Targets        []rebuildTarget `json:"targets"`
	Primary        rebuildPrimary  `json:"retained_primary"`
	OldLifecycleID string          `json:"old_lifecycle_id"`
	OldGateSHA     string          `json:"old_gate_sha256"`
	Steps          []rebuildStep   `json:"mutation_plan"`
}

var rebuildSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var rebuildID = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
var rebuildLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)

// Reject duplicate keys as well as unknown fields. Otherwise different parsers
// could assign different meanings to the same signed JSON bytes.
func rebuildDecode(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("rebuild_evidence_size_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("rebuild_json_depth_invalid")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return errors.New("rebuild_json_duplicate_or_invalid_key")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("rebuild_json_invalid")
			}
		case json.Delim('['):
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("rebuild_json_invalid")
			}
		case json.Delim('}'), json.Delim(']'):
			return errors.New("rebuild_json_invalid")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("rebuild_json_trailing_data")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("rebuild_evidence_schema_invalid")
	}
	return rebuildRequiredFields(raw, reflect.TypeOf(destination).Elem())
}

func rebuildRequiredFields(raw json.RawMessage, kind reflect.Type) error {
	fail := errors.New("rebuild_evidence_required_field_missing")
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fail
	}
	switch kind.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return fail
		}
		tags := make(map[string]reflect.StructField, kind.NumField())
		for index := 0; index < kind.NumField(); index++ {
			field := kind.Field(index)
			tag := field.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			tags[name] = field
		}
		for name := range fields {
			if _, found := tags[name]; !found {
				return errors.New("rebuild_evidence_schema_invalid")
			}
		}
		for name, field := range tags {
			value, found := fields[name]
			if !found {
				return fail
			}
			if err := rebuildRequiredFields(value, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if kind.Elem().Kind() != reflect.Uint8 {
			var values []json.RawMessage
			if json.Unmarshal(raw, &values) != nil {
				return fail
			}
			for _, value := range values {
				if err := rebuildRequiredFields(value, kind.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateRebuildEvidence(raw []byte, now time.Time, journalSHA, configSHA, manifestSHA string) (rebuildEvidence, error) {
	var envelope rebuildEnvelope
	var proof rebuildEvidence
	fail := errors.New("rebuild_evidence_invalid")
	if rebuildDecode(raw, &envelope) != nil || envelope.Protocol != rebuildPreflightProtocol ||
		!rebuildSHA.MatchString(envelope.SignerID) || len(envelope.Signature) != 64 ||
		rebuildDecode(envelope.Payload, &proof) != nil {
		return proof, fail
	}
	if proof.Protocol != rebuildPreflightProtocol || !rebuildID.MatchString(proof.OperationID) ||
		!rebuildID.MatchString(proof.OldLifecycleID) || proof.OldLifecycleID == proof.OperationID ||
		!rebuildSHA.MatchString(proof.Nonce) || !rebuildSHA.MatchString(proof.OldGateSHA) ||
		!rebuildSHA.MatchString(proof.JournalSHA) || !rebuildSHA.MatchString(proof.ConfigSHA) ||
		!rebuildSHA.MatchString(proof.ManifestSHA) || proof.JournalSHA != journalSHA ||
		proof.ConfigSHA != configSHA || proof.ManifestSHA != manifestSHA {
		return proof, errors.New("rebuild_input_binding_invalid")
	}
	// All arithmetic is bounded before subtraction; future or stale claims fail.
	stamp := now.Unix()
	if proof.IssuedAt <= 0 || proof.IssuedAt > stamp || proof.ExpiresAt <= stamp ||
		proof.ExpiresAt <= proof.IssuedAt || proof.ExpiresAt-proof.IssuedAt > 300 {
		return proof, errors.New("rebuild_evidence_expired_or_future")
	}
	fresh := func(at int64) bool { return at >= proof.IssuedAt && at <= stamp }
	if !proof.Complete || len(proof.Censuses) == 0 || len(proof.Censuses) > 64 ||
		len(proof.Targets) < 2 || len(proof.Targets) > 1024 {
		return proof, errors.New("rebuild_complete_fleet_claim_required")
	}
	censuses := map[string]rebuildCensus{}
	for _, census := range proof.Censuses {
		key := census.Provider + "/" + census.AccountSHA
		if !rebuildLabel.MatchString(census.Provider) || !rebuildSHA.MatchString(census.AccountSHA) ||
			!rebuildSHA.MatchString(census.InventorySHA) || !fresh(census.ObservedAt) ||
			!census.PaginationComplete || census.TargetCount < 1 || census.TargetCount > 1024 {
			return proof, errors.New("rebuild_census_claim_invalid")
		}
		if _, found := censuses[key]; found {
			return proof, errors.New("rebuild_duplicate_census")
		}
		censuses[key] = census
	}
	primary := proof.Primary
	systemID, err := strconv.ParseUint(primary.SystemIdentifier, 10, 64)
	if err != nil || systemID == 0 || strconv.FormatUint(systemID, 10) != primary.SystemIdentifier ||
		!primary.Primary || primary.DatabaseOID == 0 || !rebuildLabel.MatchString(primary.Database) ||
		!rebuildLabel.MatchString(primary.Provider) || !rebuildLabel.MatchString(primary.InstanceID) ||
		!rebuildSHA.MatchString(primary.AccountSHA) || !rebuildSHA.MatchString(primary.SSHIdentitySHA) ||
		!rebuildSHA.MatchString(primary.MigrationsSHA) || !rebuildSHA.MatchString(primary.DSNBindingSHA) ||
		!rebuildSHA.MatchString(primary.ObservationSHA) || !fresh(primary.ObservedAt) ||
		!primary.WorkersFenced || primary.ActiveClients != 0 ||
		primary.AccessPolicy != "reuse-existing-authorization" || !rebuildSHA.MatchString(primary.AuthorizationSHA) {
		return proof, errors.New("rebuild_retained_primary_claim_invalid")
	}
	roles := map[string]string{}
	instances := map[string]bool{}
	identities := map[string]bool{}
	counts := map[string]int{}
	bridgeCount := 0
	for _, target := range proof.Targets {
		key := target.Provider + "/" + target.AccountSHA
		instance := key + "/" + target.InstanceID
		_, censusFound := censuses[key]
		if !censusFound || !rebuildLabel.MatchString(target.ID) || !rebuildLabel.MatchString(target.InstanceID) ||
			(target.Role != "bridge" && target.Role != "exit") || roles[target.ID] != "" || instances[instance] ||
			!rebuildSHA.MatchString(target.SSHIdentitySHA) || identities[target.SSHIdentitySHA] ||
			!rebuildSHA.MatchString(target.ObservationSHA) || !fresh(target.ObservedAt) || !target.WorkersFenced ||
			(target.Provider == primary.Provider && target.InstanceID == primary.InstanceID) ||
			target.SSHIdentitySHA == primary.SSHIdentitySHA {
			return proof, errors.New("rebuild_target_claim_invalid")
		}
		roles[target.ID], instances[instance], identities[target.SSHIdentitySHA] = target.Role, true, true
		counts[key]++
		if target.Role == "bridge" {
			bridgeCount++
		}
	}
	if bridgeCount != 1 {
		return proof, errors.New("rebuild_bridge_identity_ambiguous")
	}
	for key, census := range censuses {
		if counts[key] != census.TargetCount {
			return proof, errors.New("rebuild_census_target_count_mismatch")
		}
	}
	// These are fixed *proposed* stage identities, never executable playbook
	// names. No arbitrary variables, hosts, delegates or DB access changes exist.
	operations := []string{"rebuild-exits", "rebuild-bridge", "activate-bot"}
	if len(proof.Steps) != len(operations) {
		return proof, errors.New("rebuild_mutation_scope_invalid")
	}
	for index, step := range proof.Steps {
		wantedRole := "bridge"
		if index == 0 {
			wantedRole = "exit"
		}
		seen := map[string]bool{}
		if step.Operation != operations[index] {
			return proof, errors.New("rebuild_mutation_scope_invalid")
		}
		for _, target := range step.Targets {
			if seen[target] || roles[target] != wantedRole {
				return proof, errors.New("rebuild_mutation_scope_invalid")
			}
			seen[target] = true
		}
		for target, role := range roles {
			if role == wantedRole && !seen[target] {
				return proof, errors.New("rebuild_mutation_scope_incomplete")
			}
		}
	}
	return proof, nil
}
