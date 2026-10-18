package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"golang.org/x/sys/unix"
)

type rebuildInstanceReader interface {
	Instances(context.Context) ([]cloud.Instance, error)
}

type rebuildInstanceMapping struct {
	ID         string
	InstanceID string
	Address    string
	Role       string
	OwnerTag   string
	RoleTag    string
}

// collectRebuildProviderInventory consumes the existing paginated read-only
// provider API. It proves exact mapping only within the supplied account. It
// does not prove that this account covers the historic fleet, authenticate SSH
// hosts, prove workers stopped or establish retained-primary database identity.
// It is not wired to CLI credentials until those independent contracts exist.
func collectRebuildProviderInventory(
	ctx context.Context,
	provider rebuildInstanceReader,
	mapping []rebuildInstanceMapping,
) ([]cloud.Instance, error) {
	if provider == nil || len(mapping) < 3 || len(mapping) > 1025 {
		return nil, errors.New("rebuild_provider_mapping_invalid")
	}
	byInstance := map[string]rebuildInstanceMapping{}
	ids, addresses := map[string]bool{}, map[string]bool{}
	bridges, primaries, exits := 0, 0, 0
	for _, entry := range mapping {
		if !rebuildLabel.MatchString(entry.ID) || !rebuildLabel.MatchString(entry.InstanceID) ||
			!rebuildLabel.MatchString(entry.OwnerTag) || net.ParseIP(entry.Address) == nil ||
			byInstance[entry.InstanceID].ID != "" || ids[entry.ID] || addresses[net.ParseIP(entry.Address).String()] {
			return nil, errors.New("rebuild_provider_mapping_invalid")
		}
		switch entry.Role {
		case "bridge":
			bridges++
		case "exit":
			exits++
		case "primary":
			primaries++
		default:
			return nil, errors.New("rebuild_provider_mapping_invalid")
		}
		byInstance[entry.InstanceID], ids[entry.ID], addresses[net.ParseIP(entry.Address).String()] = entry, true, true
	}
	if bridges != 1 || primaries != 1 || exits == 0 {
		return nil, errors.New("rebuild_provider_mapping_invalid")
	}
	instances, err := provider.Instances(ctx)
	if err != nil {
		return nil, errors.New("rebuild_provider_inventory_unavailable")
	}
	if len(instances) != len(mapping) {
		return nil, errors.New("rebuild_provider_inventory_incomplete_or_unknown")
	}
	seen := map[string]bool{}
	seenAddresses := map[string]bool{}
	for _, instance := range instances {
		entry, found := byInstance[instance.ID]
		owned := false
		roleMatched := entry.RoleTag == ""
		for _, tag := range instance.Tags {
			if tag == entry.OwnerTag {
				owned = true
			}
			if tag == entry.RoleTag {
				roleMatched = true
			}
		}
		ip := net.ParseIP(instance.IP)
		if !found || ip == nil || seen[instance.ID] || !ip.Equal(net.ParseIP(entry.Address)) || !owned || !roleMatched ||
			instance.Status != "active" || instance.ServerStatus != "ok" || instance.PowerStatus != "running" {
			return nil, errors.New("rebuild_provider_identity_unverified")
		}
		if seenAddresses[ip.String()] {
			return nil, errors.New("rebuild_provider_identity_unverified")
		}
		seenAddresses[ip.String()] = true
		seen[instance.ID] = true
	}
	return instances, nil
}

// This transport audits the existing cloud client's pagination without adding
// any provider mutation capability. Raw API responses and credentials never
// enter receipts or errors. total is required: a missing final page must not
// silently become a successful census.
type rebuildInventoryTransport struct {
	base                http.RoundTripper
	pages, count, total int
	finished            bool
	secret              string
}

func (t *rebuildInventoryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	fail := errors.New("rebuild_provider_page_invalid")
	if request.Method != http.MethodGet || request.URL.Scheme != "https" ||
		request.URL.Host != "api.vultr.com" || request.URL.Path != "/v2/instances" ||
		request.URL.Query().Get("per_page") != "500" || t.finished || t.pages >= 1026 {
		return nil, fail
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, fail
	}
	if response == nil || response.Body == nil {
		return nil, fail
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return nil, fail
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 || (t.secret != "" && bytes.Contains(raw, []byte(t.secret))) {
		return nil, fail
	}
	var fields map[string]json.RawMessage
	if rebuildDecode(raw, &fields) != nil {
		return nil, fail
	}
	var page []cloud.Instance
	var meta struct {
		Total *int                       `json:"total"`
		Links map[string]json.RawMessage `json:"links"`
	}
	if json.Unmarshal(fields["instances"], &page) != nil || bytes.Equal(bytes.TrimSpace(fields["instances"]), []byte("null")) ||
		json.Unmarshal(fields["meta"], &meta) != nil || meta.Total == nil || *meta.Total < 3 || *meta.Total > 1025 {
		return nil, fail
	}
	nextRaw, exists := meta.Links["next"]
	var next string
	if !exists || json.Unmarshal(nextRaw, &next) != nil {
		return nil, fail
	}
	if t.pages == 0 {
		t.total = *meta.Total
	}
	if t.total != *meta.Total || len(page) == 0 || len(page) > 500 {
		return nil, fail
	}
	t.pages++
	t.count += len(page)
	if t.count > t.total || (next == "" && t.count != t.total) || (next != "" && t.count >= t.total) {
		return nil, fail
	}
	t.finished = next == ""
	copy := *response
	copy.Body = io.NopCloser(bytes.NewReader(raw))
	copy.ContentLength = int64(len(raw))
	return &copy, nil
}

type rebuildProviderReceipt struct {
	Protocol        string                   `json:"protocol"`
	Authority       string                   `json:"authority"`
	RequestSHA      string                   `json:"request_sha256"`
	ConfigSHA       string                   `json:"config_sha256"`
	MappingSHA      string                   `json:"mapping_sha256"`
	InventorySHA    string                   `json:"inventory_sha256"`
	ObservedAt      int64                    `json:"observed_at_unix"`
	Pages           int                      `json:"pages"`
	Inventory       []cloud.Instance         `json:"inventory"`
	Targets         []rebuildInstanceMapping `json:"non_db_targets"`
	RetainedPrimary rebuildInstanceMapping   `json:"excluded_retained_primary"`
}

// collectRebuildVultrReceipt accepts only the actual provider client, never an
// inventory JSON input. Mapping remains a claim until an independently trusted
// historical account/fleet binding exists in the provisioning contract. A digest
// protects content identity; it is not a signature or execution authorization.
func collectRebuildVultrReceipt(ctx context.Context, provider *cloud.Vultr, mapping []rebuildInstanceMapping,
	requestSHA, configSHA string, now time.Time) (rebuildProviderReceipt, error) {
	var receipt rebuildProviderReceipt
	if provider == nil || provider.HTTP == nil || provider.Key == "" || provider.BaseURL != "https://api.vultr.com/v2" ||
		!rebuildSHA.MatchString(requestSHA) || !rebuildSHA.MatchString(configSHA) || now.Unix() <= 0 {
		return receipt, errors.New("rebuild_provider_request_invalid")
	}
	// A role is checked against a distinct provider tag, rather than trusting
	// the role label supplied by the mapping itself.
	for _, entry := range mapping {
		if !rebuildLabel.MatchString(entry.RoleTag) || entry.RoleTag == entry.OwnerTag {
			return receipt, errors.New("rebuild_provider_role_binding_required")
		}
	}
	mappingRaw, _ := json.Marshal(mapping)
	if strings.TrimSpace(provider.Key) != provider.Key || strings.ContainsAny(provider.Key, "\r\n\x00") || bytes.Contains(mappingRaw, []byte(provider.Key)) {
		return receipt, errors.New("rebuild_provider_request_invalid")
	}
	base := provider.HTTP.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	audit := &rebuildInventoryTransport{base: base, secret: provider.Key}
	client := *provider.HTTP
	client.Transport = audit
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clone := *provider
	clone.HTTP = &client
	instances, err := collectRebuildProviderInventory(ctx, &clone, mapping)
	if err != nil || !audit.finished {
		return receipt, errors.New("rebuild_provider_collection_failed")
	}
	instances = append([]cloud.Instance(nil), instances...)
	for i := range instances {
		instances[i].Tags = append([]string(nil), instances[i].Tags...)
		sort.Strings(instances[i].Tags)
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
	mapping = append([]rebuildInstanceMapping(nil), mapping...)
	sort.Slice(mapping, func(i, j int) bool { return mapping[i].InstanceID < mapping[j].InstanceID })
	mapRaw, _ := json.Marshal(mapping)
	inventoryRaw, _ := json.Marshal(instances)
	receipt = rebuildProviderReceipt{Protocol: "ultra-rebuild-provider-observation-v1", Authority: "account-scope-unbound",
		RequestSHA: requestSHA, ConfigSHA: configSHA, MappingSHA: digestSHA256(mapRaw), InventorySHA: digestSHA256(inventoryRaw),
		ObservedAt: now.Unix(), Pages: audit.pages, Inventory: instances}
	for _, entry := range mapping {
		if entry.Role == "primary" {
			receipt.RetainedPrimary = entry
		} else {
			receipt.Targets = append(receipt.Targets, entry)
		}
	}
	return receipt, nil
}

// Persist an observation exclusively, with fsync before and after publication.
// A pending artifact after a crash blocks reuse; existing receipts are never
// overwritten. This is independent of the blocked preflight journal.
func persistRebuildProviderReceipt(directory string, receipt rebuildProviderReceipt) error {
	fail := errors.New("rebuild_provider_receipt_publication_failed")
	if receipt.Protocol != "ultra-rebuild-provider-observation-v1" || receipt.Authority != "account-scope-unbound" ||
		!rebuildSHA.MatchString(receipt.RequestSHA) || operatorPrivate(directory, true) != nil || rebuildNoSymlinkAncestors(directory) != nil {
		return fail
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return fail
	}
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail
	}
	dir := os.NewFile(uintptr(fd), directory)
	defer dir.Close() //nolint:errcheck
	const pending = ".rebuild-provider-observation-pending"
	fileFD, err := syscall.Openat(fd, pending, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fail
	}
	file := os.NewFile(uintptr(fileFD), pending)
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fail
	}
	if unix.Renameat2(fd, pending, fd, "rebuild-provider-observation.json", unix.RENAME_NOREPLACE) != nil || dir.Sync() != nil {
		return fail
	}
	return nil
}
