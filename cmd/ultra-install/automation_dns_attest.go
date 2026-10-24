package main

// The attestation is the operator's decision, but transcribing record ids by hand
// invites exactly the drift the DNS application then refuses. This action reads
// the provider once and writes the attestation only for the rows this plan
// already declares, so it can never authorize anything else.
import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runDNSAttestCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("dns-attest", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "canonical operator config")
	output := f.String("output", "", "private attestation file to create")
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" || *output == "" {
		return errors.New("dns_attest_config_and_output_required")
	}
	for _, path := range []string{*config, *output} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("dns_attest_absolute_paths_required")
		}
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil {
		return errors.New("dns_attest_config_invalid")
	}
	want, err := dnsAttestationDesired(p)
	if err != nil {
		return err
	}
	variables := map[string]any{}
	if err = prepareAnsibleDNS(p, variables); err != nil {
		return err
	}
	key, _ := variables["ultra_dns_api_key"].(string)
	if key == "" {
		return errors.New("dns_attestation_provider_credential_required")
	}
	zone := p.Automation.DNS.Zone
	published, err := vultrRecordFetch(key, nil)(zone)
	if err != nil {
		return err
	}
	records := make(map[string]dnsAttestedRecord, len(want))
	for role, expected := range want {
		var matched []dnsAttestedRecord
		for _, record := range published {
			if record.Type == expected.Type && record.Name == expected.Name && record.Data == expected.Data {
				matched = append(matched, record)
			}
		}
		// Two identical rows would make ownership ambiguous, which no attestation
		// can resolve; the operator has to remove one at the provider first.
		if len(matched) != 1 {
			return fmt.Errorf("dns_attest_record_not_unique: %s", role)
		}
		records[role] = matched[0]
	}
	attestation := dnsAttestation{Protocol: dnsAttestationProtocol, Zone: zone, Records: records}
	// The writer and the reader share one validator, so a file this action emits
	// is accepted by the deploy by construction.
	if err = validateDNSAttestation(attestation, p); err != nil {
		return err
	}
	raw, err := json.Marshal(attestation)
	if err != nil {
		return errors.New("dns_attest_unencodable")
	}
	if err = writeDNSAttestation(*output, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"owned DNS attestation written; zone=%s; roles=%d; attestation_sha256=%s\n",
		zone, len(records), dnsAttestedFingerprint(attestation),
	)
	return err
}

// Refusing an existing file keeps a stale attestation from being mistaken for a
// fresh confirmation of the provider's current state.
func writeDNSAttestation(path string, raw []byte) error {
	if rebuildNoSymlinkAncestors(filepath.Dir(path)) != nil {
		return errors.New("dns_attest_output_unsafe")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return errors.New("dns_attest_output_unsafe")
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("dns_attest_output_unsafe")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("dns_attest_output_exists")
	}
	if err != nil {
		return errors.New("dns_attest_output_unavailable")
	}
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		return errors.New("dns_attest_output_unavailable")
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("dns_attest_output_unavailable")
	}
	if err = file.Close(); err != nil {
		return errors.New("dns_attest_output_unavailable")
	}
	return nil
}
