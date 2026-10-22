package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type censusProvider interface {
	Instances(context.Context) ([]cloud.Instance, error)
	Get(context.Context, string) (cloud.Instance, error)
}

type providerCensusInstance struct {
	ID      string `json:"id"`
	Address string `json:"address,omitempty"`
	Present bool   `json:"present"`
}

type providerCensusReceipt struct {
	Protocol        string                   `json:"protocol"`
	ObservedAt      int64                    `json:"observed_at"`
	RequestedSHA256 string                   `json:"requested_sha256"`
	Instances       []providerCensusInstance `json:"instances"`
	Requested       []providerCensusInstance `json:"requested"`
}

var providerCensusID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

func providerCensusError(stage string, err error) error {
	code := "unavailable"
	var api cloud.APIError
	if errors.As(err, &api) {
		if api.Status >= 100 && api.Status <= 599 {
			code = fmt.Sprintf("http_%d", api.Status)
		} else if api.Code == "provider_timeout" || api.Code == "provider_unreachable" {
			code = api.Code
		}
	}
	return errors.New("provider_census_" + stage + "_" + code)
}

func collectProviderCensus(ctx context.Context, api censusProvider, ids []string, requestedSHA string) (providerCensusReceipt, error) {
	fail := errors.New("provider_census_unverified")
	r := providerCensusReceipt{
		Protocol:        "ultra-provider-census-v1",
		RequestedSHA256: requestedSHA,
		Instances:       []providerCensusInstance{},
		Requested:       []providerCensusInstance{},
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !providerCensusID.MatchString(id) || seen[id] {
			return r, fail
		}
		seen[id] = true
	}
	if len(ids) == 0 || len(ids) > 10000 || !runtimeHostValidDigest(requestedSHA) {
		return r, fail
	}
	rows, err := api.Instances(ctx) // The existing client consumes every page.
	if err != nil {
		return r, providerCensusError("list", err)
	}
	present := map[string]string{}
	for _, row := range rows {
		if !providerCensusID.MatchString(row.ID) || net.ParseIP(row.IP) == nil {
			return r, errors.New("provider_census_list_identity_invalid")
		}
		if _, exists := present[row.ID]; exists {
			return r, errors.New("provider_census_list_duplicate")
		}
		present[row.ID] = row.IP
		r.Instances = append(r.Instances, providerCensusInstance{row.ID, row.IP, true})
	}
	for _, id := range ids {
		row, getErr := api.Get(ctx, id)
		address, listed := present[id]
		if getErr != nil {
			var providerErr cloud.APIError
			if !errors.As(getErr, &providerErr) || providerErr.Status != 404 {
				return r, providerCensusError("get", getErr)
			}
			if listed {
				return r, errors.New("provider_census_inventory_changed")
			}
			r.Requested = append(r.Requested, providerCensusInstance{ID: id, Present: false})
			continue
		}
		if !listed || row.ID != id || row.IP != address {
			return r, errors.New("provider_census_inventory_changed")
		}
		r.Requested = append(r.Requested, providerCensusInstance{id, address, true})
	}
	sort.Slice(r.Instances, func(i, j int) bool { return r.Instances[i].ID < r.Instances[j].ID })
	sort.Slice(r.Requested, func(i, j int) bool { return r.Requested[i].ID < r.Requested[j].ID })
	r.ObservedAt = time.Now().Unix()
	return r, nil
}

// Read-only provider evidence. The normal secret resolver is used internally;
// neither credentials, labels, tags nor provider response bodies are emitted.
func runProviderCensus(args []string, out io.Writer) error {
	f := flag.NewFlagSet("provider-census", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "canonical config")
	idsFile := f.String("instance-ids-file", "", "private JSON array of known provider instance IDs")
	receipt := f.String("receipt", "", "new private census receipt")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("provider_census_arguments_invalid")
	}
	for _, path := range []string{*config, *idsFile, *receipt} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("provider_census_absolute_paths_required")
		}
	}
	raw, err := readRebuildInput(*idsFile, true)
	var ids []string
	if err != nil || decodeRetainedReconcile(raw, &ids) != nil {
		return errors.New("provider_census_ids_invalid")
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil || p.Automation == nil {
		return errors.New("provider_census_config_invalid")
	}
	values, err := readProviderSecretValues(p)
	if err != nil {
		return errors.New("provider_census_credential_unavailable")
	}
	key := strings.TrimSpace(values["ULTRA_VULTR_API_KEY"])
	if key == "" && p.Automation.CloudKeyFile != "" {
		secret, e := readRebuildInput(p.Automation.CloudKeyFile, true)
		if e != nil {
			return errors.New("provider_census_credential_unavailable")
		}
		key = strings.TrimSpace(string(secret))
	}
	if key == "" || strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("provider_census_credential_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, err := collectProviderCensus(ctx, cloud.NewVultr(key), ids, digestSHA256(raw))
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(r)
	if _, err = os.Lstat(*receipt); !os.IsNotExist(err) {
		return errors.New("provider_census_new_receipt_required")
	}
	if err = publishRetainedReconcile(*receipt, encoded); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"provider census verified; listed=%d requested=%d receipt_sha256=%s\n",
		len(r.Instances),
		len(r.Requested),
		digestSHA256(encoded),
	)
	return err
}
