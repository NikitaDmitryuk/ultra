package main

// A reimaged bridge loses its private ownership receipt while the provider keeps
// the records it created, and the DNS application then refuses those rows as
// foreign forever. One explicit operator attestation, re-read from the provider,
// is the only way to adopt them again; nothing here is inferred.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const dnsAttestationProtocol = "ultra-owned-dns-attestation-v1"

type dnsAttestedRecord struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

type dnsAttestation struct {
	Protocol string                       `json:"protocol"`
	Zone     string                       `json:"zone"`
	Records  map[string]dnsAttestedRecord `json:"records"`
}

// dnsRecordFetch reads the provider's view of one zone. It never writes.
type dnsRecordFetch func(zone string) ([]dnsAttestedRecord, error)

// The attestation lives beside the canonical configuration it describes.
func dnsAttestationPath(config, requested string) string {
	if requested != "" {
		return requested
	}
	return filepath.Join(filepath.Dir(config), "dns-attestation.json")
}

// prepareAnsibleDNSAttested adds the ownership seed when the operator attested
// the rows that already exist for this exact plan, and confirms each one with the
// provider before any variable is set. Without an attestation it changes nothing.
func prepareAnsibleDNSAttested(
	p *installplan.InstallPlan,
	variables map[string]any,
	config, requested string,
	fetch dnsRecordFetch,
) error {
	path := dnsAttestationPath(config, requested)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return prepareAnsibleDNS(p, variables)
	}
	raw, err := readRebuildInput(path, true)
	if err != nil {
		return errors.New("dns_attestation_unavailable")
	}
	var attestation dnsAttestation
	if decodeRetainedReconcile(raw, &attestation) != nil || attestation.Protocol != dnsAttestationProtocol {
		return errors.New("dns_attestation_invalid")
	}
	if err = validateDNSAttestation(attestation, p); err != nil {
		return err
	}
	if err = prepareAnsibleDNS(p, variables); err != nil {
		return err
	}
	if fetch == nil {
		key, _ := variables["ultra_dns_api_key"].(string)
		if key == "" {
			return errors.New("dns_attestation_provider_credential_required")
		}
		fetch = vultrRecordFetch(key, nil)
	}
	if err = verifyDNSAttestationOnline(attestation, fetch); err != nil {
		return err
	}
	variables["ultra_dns_receipt_seed"] = dnsAttestationSeed(attestation)
	variables["ultra_dns_attestation_sha256"] = dnsAttestedFingerprint(attestation)
	return nil
}

// dnsAttestationDesired derives the only rows this plan may ever own. Both the
// attestation check and the attestation writer read it from the same place.
func dnsAttestationDesired(p *installplan.InstallPlan) (map[string]dnsAttestedRecord, error) {
	if p.Automation == nil || p.Automation.DNS == nil || len(p.Exits) != 1 {
		return nil, errors.New("dns_attestation_requires_managed_dns")
	}
	policy := *p.Automation.DNS
	want := map[string]dnsAttestedRecord{
		"subscription": {Type: "A", Name: policy.SubscriptionName, Data: p.Automation.BridgeIPv4},
		"vpn":          {Type: "A", Name: policy.VPNName, Data: p.Automation.BridgeIPv4},
	}
	if p.Features.MainExitDomain != "" {
		want["tunnel"] = dnsAttestedRecord{
			Type: "A",
			Name: strings.TrimSuffix(p.Features.MainExitDomain, "."+policy.Zone),
			Data: p.Exits[0].DialAddr,
		}
	}
	return want, nil
}

// validateDNSAttestation binds every attested row to this plan, so an attestation
// written for another host, zone or role set can never seed this bridge.
func validateDNSAttestation(a dnsAttestation, p *installplan.InstallPlan) error {
	want, err := dnsAttestationDesired(p)
	if err != nil {
		return err
	}
	if a.Zone != p.Automation.DNS.Zone {
		return errors.New("dns_attestation_zone_mismatch")
	}
	if len(a.Records) != len(want) {
		return errors.New("dns_attestation_roles_mismatch")
	}
	for role, expected := range want {
		record, ok := a.Records[role]
		if !ok || record.Type != expected.Type || record.Name != expected.Name ||
			record.Data != expected.Data || record.TTL < 120 || record.TTL > 86400 ||
			!dnsAttestedIdentityValid(record) {
			return errors.New("dns_attestation_record_mismatch")
		}
	}
	return nil
}

// The application re-validates the seed; this only rejects obvious garbage early.
func dnsAttestedIdentityValid(record dnsAttestedRecord) bool {
	if record.ID == "" || len(record.ID) > 64 || strings.ContainsAny(record.ID, " \t\n/") {
		return false
	}
	if record.Name == "" || len(record.Name) > 63 || strings.Contains(record.Name, ".") {
		return false
	}
	return record.Data != "" && len(record.Data) <= 45
}

func dnsAttestationSeed(a dnsAttestation) map[string]any {
	records := map[string]any{}
	for role, record := range a.Records {
		records[role] = map[string]any{
			"id": record.ID, "type": record.Type, "name": record.Name,
			"data": record.Data, "ttl": record.TTL,
		}
	}
	return map[string]any{"version": 1, "zone": a.Zone, "records": records}
}

// The fingerprint records which exact attestation authorized adoption.
func dnsAttestedFingerprint(a dnsAttestation) string {
	raw, err := json.Marshal(dnsAttestationSeed(a))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// verifyDNSAttestationOnline rejects every attested row the provider does not
// confirm, so an attestation can only describe what is really published.
func verifyDNSAttestationOnline(a dnsAttestation, fetch dnsRecordFetch) error {
	published, err := fetch(a.Zone)
	if err != nil {
		return err
	}
	byID := map[string]dnsAttestedRecord{}
	for _, record := range published {
		byID[record.ID] = record
	}
	for _, attested := range a.Records {
		if live, ok := byID[attested.ID]; !ok || live != attested {
			return errors.New("dns_attestation_provider_mismatch")
		}
	}
	return nil
}

// vultrRecordFetch only reads. The credential stays in the request header and no
// provider payload ever reaches an error message.
func vultrRecordFetch(apiKey string, client *http.Client) dnsRecordFetch {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return func(zone string) ([]dnsAttestedRecord, error) {
		endpoint := "https://api.vultr.com/v2/domains/" + url.PathEscape(zone) + "/records?per_page=500"
		request, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, errors.New("dns_attestation_provider_unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+apiKey)
		response, err := client.Do(request)
		if err != nil {
			return nil, errors.New("dns_attestation_provider_unavailable")
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
			return nil, errors.New("dns_attestation_provider_unavailable")
		}
		var body struct {
			Records []dnsAttestedRecord `json:"records"`
		}
		if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil {
			return nil, errors.New("dns_attestation_provider_unavailable")
		}
		return body.Records, nil
	}
}
