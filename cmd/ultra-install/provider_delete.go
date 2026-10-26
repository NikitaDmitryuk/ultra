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
	"strings"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type deleteCensusProvider interface {
	censusProvider
	Delete(context.Context, string) error
}

type providerDeleteIntent struct {
	Protocol     string `json:"protocol"`
	InstanceID   string `json:"instance_id"`
	Address      string `json:"address"`
	ConfigSHA256 string `json:"config_sha256"`
	CensusSHA256 string `json:"census_sha256"`
}
type providerDeleteReceipt struct {
	Intent     providerDeleteIntent `json:"intent"`
	Result     string               `json:"result"`
	ObservedAt int64                `json:"observed_at"`
}

func providerInstanceAbsent(err error) bool {
	var e cloud.APIError
	return errors.As(err, &e) && e.Status == 404
}

func observeDeletedProviderInstance(ctx context.Context, api censusProvider, id string) error {
	_, err := api.Get(ctx, id)
	if err == nil {
		return errors.New("provider_delete_still_present")
	}
	if !providerInstanceAbsent(err) {
		return providerCensusError("delete_observation", err)
	}
	rows, err := api.Instances(ctx)
	if err != nil {
		return providerCensusError("delete_list", err)
	}
	for _, row := range rows {
		if row.ID == id {
			return errors.New("provider_delete_list_still_present")
		}
	}
	return nil
}

// Persist intent before calling this function. A prior uncertain dispatch is
// observation-only; an acknowledgment loss must never create a second target.
func deleteObservedProviderInstance(ctx context.Context, api deleteCensusProvider, intent providerDeleteIntent, resume bool) error {
	if resume {
		return observeDeletedProviderInstance(ctx, api, intent.InstanceID)
	}
	row, err := api.Get(ctx, intent.InstanceID)
	if err != nil {
		return providerCensusError("delete_preflight", err)
	}
	if row.ID != intent.InstanceID || row.IP != intent.Address {
		return errors.New("provider_delete_target_changed")
	}
	if err = api.Delete(ctx, intent.InstanceID); err != nil {
		return providerCensusError("delete_dispatch", err)
	}
	// A successful DELETE acknowledgment is not yet an absence proof.
	return observeDeletedProviderInstance(ctx, api, intent.InstanceID)
}

func runProviderDelete(args []string, out io.Writer) error {
	return runProviderDeleteWithProvider(args, out, func(key string) deleteCensusProvider { return cloud.NewVultr(key) })
}

func runProviderDeleteWithProvider(args []string, out io.Writer, provider func(string) deleteCensusProvider) error {
	f := flag.NewFlagSet("provider-delete", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "canonical config")
	censusPath := f.String("census", "", "successful private provider census")
	idPath := f.String("instance-id-file", "", "private single-element JSON array naming the authorized instance")
	address := f.String("expected-address", "", "explicitly authorized instance address")
	receiptPath := f.String("receipt", "", "private result path; adjacent intent persists before dispatch")
	execute := f.Bool("execute", false, "explicitly delete this exact independently observed provider instance")
	if f.Parse(args) != nil || f.NArg() != 0 || !*execute || net.ParseIP(*address) == nil {
		return errors.New("provider_delete_explicit_target_required")
	}
	for _, path := range []string{*config, *censusPath, *idPath, *receiptPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("provider_delete_absolute_paths_required")
		}
	}
	lock, err := os.OpenFile(*receiptPath+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("provider_delete_lock_unavailable")
	}
	defer func() { _ = lock.Close() }()
	if err = operatorPrivate(*receiptPath+".lock", false); err != nil {
		return err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("provider_delete_busy")
	}
	configRaw, err := readRebuildInput(*config, true)
	if err != nil {
		return err
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil || p.Automation == nil {
		return errors.New("provider_delete_config_invalid")
	}
	protected := []string{p.Bridge.Address, p.Bridge.SSHHost, p.Database.PrimaryHost}
	for _, exit := range p.Exits {
		protected = append(protected, exit.SSHHost, exit.DialAddr)
	}
	for _, host := range protected {
		if host == *address {
			return errors.New("provider_delete_static_target_forbidden")
		}
	}
	idRaw, err := readRebuildInput(*idPath, true)
	var ids []string
	if err != nil || decodeRetainedReconcile(idRaw, &ids) != nil || len(ids) != 1 || !providerCensusID.MatchString(ids[0]) {
		return errors.New("provider_delete_id_invalid")
	}
	id := ids[0]
	censusRaw, err := readRebuildInput(*censusPath, true)
	var census providerCensusReceipt
	if err != nil || decodeRetainedReconcile(censusRaw, &census) != nil || census.Protocol != "ultra-provider-census-v1" {
		return errors.New("provider_delete_census_invalid")
	}
	found := 0
	for _, row := range census.Requested {
		if row.ID == id && row.Present && row.Address == *address {
			found++
		}
	}
	if found != 1 {
		return errors.New("provider_delete_target_not_observed")
	}
	intent := providerDeleteIntent{"ultra-provider-delete-intent-v1", id, *address, digestSHA256(configRaw), digestSHA256(censusRaw)}
	intentRaw, _ := json.Marshal(intent)
	intentPath := *receiptPath + ".intent.json"
	_, statErr := os.Lstat(intentPath)
	resume := !os.IsNotExist(statErr)
	if !resume {
		age := time.Now().Unix() - census.ObservedAt
		if age < 0 || age > 3600 {
			return errors.New("provider_delete_fresh_census_required")
		}
	}
	values, err := readProviderSecretValues(p)
	if err != nil {
		return errors.New("provider_delete_credential_unavailable")
	}
	key := strings.TrimSpace(values["ULTRA_VULTR_API_KEY"])
	if key == "" && p.Automation.CloudKeyFile != "" {
		raw, e := readRebuildInput(p.Automation.CloudKeyFile, true)
		if e != nil {
			return errors.New("provider_delete_credential_unavailable")
		}
		key = strings.TrimSpace(string(raw))
	}
	if key == "" || strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("provider_delete_credential_unavailable")
	}
	if err = publishRetainedReconcile(intentPath, intentRaw); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = deleteObservedProviderInstance(ctx, provider(key), intent, resume); err != nil {
		return err
	}
	if _, e := os.Lstat(*receiptPath); e == nil {
		raw, readErr := readRebuildInput(*receiptPath, true)
		if readErr != nil {
			return readErr
		}
		var saved providerDeleteReceipt
		if decodeRetainedReconcile(raw, &saved) != nil || saved.Intent != intent || saved.Result != "provider-instance-absent" {
			return errors.New("provider_delete_receipt_changed")
		}
	} else {
		if !os.IsNotExist(e) {
			return e
		}
		raw, _ := json.Marshal(providerDeleteReceipt{intent, "provider-instance-absent", time.Now().Unix()})
		if err = publishRetainedReconcile(*receiptPath, raw); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, "provider deletion verified by GET 404 and complete inventory absence; database and firewall unchanged")
	return err
}
