package main

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/google/uuid"
)

const preservePrimarySourceKey = "_BOOTSTRAP_PRESERVE_PRIMARY_BACKUP_SHA256"
const preservePrimarySnapshotKey = "_BOOTSTRAP_PRESERVE_PRIMARY_BACKUP_SNAPSHOT_UNIX"

func preservingBootstrapPrimary(p *installplan.InstallPlan) bool {
	return p.SourceValues[preservePrimarySourceKey] != ""
}

// This mode reinstalls application components only. It does not retire an old
// operation or establish executor quiescence, and must retain those gates.
func authorizePreservedPrimaryBootstrap(p *installplan.InstallPlan, backup, backupSHA string) error {
	if !p.FullAutomation() || !p.Database.Enabled || p.AdoptRuntime || p.Database.PrimaryHost == "" ||
		samePreservedPrimaryHost(p.Database.PrimaryHost, p.Bridge.Address) || samePreservedPrimaryHost(p.Database.PrimaryHost, p.Bridge.SSHHost) {
		return errors.New("bootstrap_preserved_primary_separate_database_required")
	}
	for _, exit := range p.Exits {
		if samePreservedPrimaryHost(p.Database.PrimaryHost, exit.SSHHost) || samePreservedPrimaryHost(p.Database.PrimaryHost, exit.DialAddr) {
			return errors.New("bootstrap_preserved_primary_database_in_application_targets")
		}
	}
	if _, err := retainedExistingDatabaseCredentials(p); err != nil {
		return err
	}
	if p.Secrets.DatabaseDumpFile != "" {
		return errors.New("bootstrap_preserved_primary_import_forbidden")
	}
	metadata, err := verifyRetainedBackupBundle(backup, backupSHA, p.SourceValues["ULTRA_OPERATOR_AGE_IDENTITY_FILE"],
		retainedSourceSHA256(p.Database.PrimaryHost, p.Database.Name), p.Database.Name, 30*time.Minute, time.Now())
	if err != nil {
		return err
	}
	if p.SourceValues == nil {
		p.SourceValues = map[string]string{}
	}
	p.SourceValues[preservePrimarySourceKey] = backupSHA
	p.SourceValues[preservePrimarySnapshotKey] = strconv.FormatInt(metadata.SnapshotStarted.Unix(), 10)
	return nil
}

func samePreservedPrimaryHost(a, b string) bool {
	return a == b || (net.ParseIP(a) != nil && net.ParseIP(a).Equal(net.ParseIP(b)))
}

func preservedPrimaryBootstrapRoutes(p *installplan.InstallPlan, inspection map[string]bootstrapInspection) ([]exits.BootstrapEntry, error) {
	raw, err := inspection["bridge"].file(exits.BootstrapFileName)
	var routes []exits.BootstrapEntry
	if err != nil || retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &routes) != nil || len(routes) == 0 {
		return nil, errors.New("bootstrap_preserved_primary_existing_routes_required")
	}
	return managedPreservedPrimaryRoutes(p, routes)
}

func managedPreservedPrimaryRoutes(p *installplan.InstallPlan, routes []exits.BootstrapEntry) ([]exits.BootstrapEntry, error) {
	if p == nil || len(p.Exits) == 0 || len(routes) == 0 {
		return nil, errors.New("bootstrap_preserved_primary_route_scope_changed")
	}
	managed := make([]exits.BootstrapEntry, 0, len(p.Exits))
	seen := map[string]bool{}
	for _, exit := range p.Exits {
		var match *exits.BootstrapEntry
		for _, route := range routes {
			if route.Name == exit.Name && route.Address == exit.DialAddr && route.Port == exit.Port &&
				uuid.Validate(route.TunnelUUID) == nil &&
				(exit.TunnelUUID == "" || exit.TunnelUUID == route.TunnelUUID) {
				if match != nil {
					return nil, errors.New("bootstrap_preserved_primary_route_scope_changed")
				}
				copy := route
				match = &copy
			}
		}
		if match == nil || seen[exit.Name] {
			return nil, errors.New("bootstrap_preserved_primary_route_scope_changed")
		}
		seen[exit.Name] = true
		managed = append(managed, *match)
	}
	return managed, nil
}

func preparePreservedPrimaryDesired(p *installplan.InstallPlan, ds *installplan.DesiredState, inventory map[string]any, directory string, prior []exits.BootstrapEntry) error {
	credentialDSN, err := retainedExistingDatabaseCredentials(p)
	if err != nil || ds.DBDSN != credentialDSN {
		return errors.New("bootstrap_preserved_primary_credentials_changed")
	}
	if err := comparePreservedRouteIdentities(ds.Bootstrap, prior); err != nil {
		return err
	}
	ds.PostgresConfig = nil
	common := inventory["all"].(map[string]any)["vars"].(map[string]any)
	common["ultra_preserve_primary"] = true
	common["ultra_preserved_primary_database"] = p.Database.Name
	common["ultra_preserved_primary_host"] = p.Database.PrimaryHost
	common["ultra_preserved_primary_identity_file"] = filepath.Join(directory, "preserved-primary-identity.json")
	common["ultra_preserved_primary_backup_sha256"] = p.SourceValues[preservePrimarySourceKey]
	common["ultra_preserved_primary_backup_snapshot_unix"] = p.SourceValues[preservePrimarySnapshotKey]
	common["ultra_generate_exit_tls"] = false
	// Pin preservation is verified against the actual post-install certificate by
	// the bridge playbook before it writes or activates bootstrap routes.
	common["ultra_preserved_primary_routes"] = append([]exits.BootstrapEntry(nil), prior...)
	return nil
}

func comparePreservedRouteIdentities(desired, prior []exits.BootstrapEntry) error {
	fail := errors.New("bootstrap_preserved_primary_route_scope_changed")
	if len(desired) != len(prior) {
		return fail
	}
	key := func(r exits.BootstrapEntry) string {
		return r.Name + "\x00" + r.Address + "\x00" + strconv.Itoa(r.Port)
	}
	old := map[string]string{}
	for _, route := range prior {
		k := key(route)
		if _, ok := old[k]; ok || uuid.Validate(route.TunnelUUID) != nil {
			return fail
		}
		old[k] = route.TunnelUUID
	}
	for _, route := range desired {
		k := key(route)
		if old[k] != route.TunnelUUID || route.TunnelUUID == "" {
			return fail
		}
		delete(old, k)
	}
	if len(old) != 0 {
		return fail
	}
	return nil
}

func validatePreservedPrimaryFrozenMode(p *installplan.InstallPlan, inventory map[string]any) error {
	common := inventory["all"].(map[string]any)["vars"].(map[string]any)
	preserved, _ := common["ultra_preserve_primary"].(bool)
	if preserved != preservingBootstrapPrimary(p) || (preserved &&
		common["ultra_preserved_primary_backup_sha256"] != p.SourceValues[preservePrimarySourceKey]) {
		return errors.New("bootstrap_preserved_primary_frozen_mode_changed")
	}
	return nil
}
