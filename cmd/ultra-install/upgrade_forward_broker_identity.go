package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
)

type forwardBrokerIdentity struct {
	Directory    string `json:"directory"`
	InstallerSHA string `json:"installer_sha256"`
	RuntimeSHA   string `json:"runtime_sha256"`
	UnitSHA      string `json:"unit_sha256"`
}

// forwardBrokerPredecessor identifies the independently managed controller
// that inspection found before the predecessor upgrade. Its release assets
// are verified on the bridge against retained operator input before recovery
// accepts it; this record deliberately does not assert binary hashes itself.
type forwardBrokerPredecessor struct {
	Directory string `json:"directory"`
	UnitSHA   string `json:"unit_sha256"`
}

// forwardBrokerVariables derives the only controller identities that may be
// running before broker recovery: the predecessor request's fully verifiable
// previous controller or its target controller. It also returns the exact identity for
// the candidate whose signed runtime is about to be installed.
func forwardBrokerVariables(old forwardOldOperation, target *automationRelease) (map[string]any, error) {
	fail := errors.New("upgrade_forward_broker_identity_unverified")
	if old.Directory == "" || old.ID == "" || target == nil {
		return nil, fail
	}
	raw, err := readForwardEvidence(filepath.Join(old.Directory, "activate", "request.json"))
	if err != nil {
		return nil, fail
	}
	var request struct {
		Variables map[string]json.RawMessage `json:"variables"`
		Inventory struct {
			All struct {
				Children struct {
					Bridge struct {
						Hosts map[string]map[string]json.RawMessage `json:"hosts"`
					} `json:"bridge"`
				} `json:"children"`
			} `json:"all"`
		} `json:"inventory"`
	}
	if json.Unmarshal(raw, &request) != nil || request.Variables == nil {
		return nil, fail
	}
	// ansibleUpgrade freezes controller identities as bridge host variables;
	// lifecycle and release manifests remain operation-wide request variables.
	bridge := request.Inventory.All.Children.Bridge.Hosts["bridge"]
	if len(request.Inventory.All.Children.Bridge.Hosts) != 1 || bridge == nil {
		return nil, fail
	}
	requestSHA := digestSHA256(raw)
	for _, name := range []string{"job.json", "receipt.json"} {
		evidence, readErr := readForwardEvidence(filepath.Join(old.Directory, "activate", name))
		var proof struct {
			Schema     int    `json:"schema_version"`
			Operation  string `json:"operation"`
			RequestSHA string `json:"request_sha256"`
			BinarySHA  string `json:"binary_sha256"`
		}
		if readErr != nil || json.Unmarshal(evidence, &proof) != nil || proof.Schema != 1 ||
			proof.Operation != "upgrade" || proof.RequestSHA != requestSHA || proof.BinarySHA != requestSHA {
			return nil, fail
		}
	}
	readField := func(fields map[string]json.RawMessage, key string) (string, error) {
		var value string
		err := json.Unmarshal(fields[key], &value)
		if err != nil || value == "" {
			return "", fail
		}
		return value, nil
	}
	readString := func(key string) (string, error) { return readField(request.Variables, key) }
	readBridgeString := func(key string) (string, error) { return readField(bridge, key) }
	readManifest := func(key string) (*automationRelease, error) {
		var manifest automationRelease
		if err := json.Unmarshal(request.Variables[key], &manifest); err != nil || !validAutomationVersion(manifest.Version) {
			return nil, fail
		}
		return &manifest, nil
	}
	architecture, err := readBridgeString("ultra_architecture")
	if err != nil || (architecture != "amd64" && architecture != "arm64") {
		return nil, fail
	}
	oldID, err := readString("ultra_lifecycle_id")
	if err != nil || oldID != old.ID || old.ID != lifecycleID(old.Directory) {
		return nil, fail
	}
	previous, err := readManifest("ultra_previous_manifest")
	if err != nil {
		return nil, fail
	}
	oldTarget, err := readManifest("ultra_release_manifest")
	if err != nil || oldTarget.Version != oldTargetVersion(old.Directory) ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(oldTarget.SourceCommit) {
		return nil, fail
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(target.SourceCommit) ||
		!validAutomationVersion(target.Version) {
		return nil, fail
	}
	previousManifestSHA, err := readString("ultra_previous_manifest_sha256")
	if err != nil || !sha256DigestPattern.MatchString(previousManifestSHA) {
		return nil, fail
	}
	oldManifestSHA, err := readString("ultra_release_manifest_sha256")
	if err != nil || !sha256DigestPattern.MatchString(oldManifestSHA) {
		return nil, fail
	}
	releaseSource, err := readString("ultra_release_source")
	if err != nil || !filepath.IsAbs(releaseSource) || filepath.Clean(releaseSource) != releaseSource ||
		operatorPrivate(releaseSource, true) != nil {
		return nil, fail
	}
	manifestRaw, err := readForwardEvidence(filepath.Join(releaseSource, "release-manifest.json"))
	var sourceManifest automationRelease
	if err != nil || digestSHA256(manifestRaw) != oldManifestSHA || json.Unmarshal(manifestRaw, &sourceManifest) != nil ||
		!reflect.DeepEqual(sourceManifest, *oldTarget) {
		return nil, fail
	}
	oldTargetDirectory, err := readBridgeString("ultra_controller_directory")
	if err != nil || oldTargetDirectory != managedControllerDirectory(oldTarget.Version) {
		return nil, fail
	}
	oldTargetUnitSHA, err := readBridgeString("ultra_target_controller_unit_sha256")
	if err != nil || !sha256DigestPattern.MatchString(oldTargetUnitSHA) {
		return nil, fail
	}
	oldTargetInstallerSHA, err := readBridgeString("ultra_install_sha256")
	if err != nil || !sha256DigestPattern.MatchString(oldTargetInstallerSHA) {
		return nil, fail
	}
	oldTargetRuntimeSHA, err := readBridgeString("ultra_controller_runtime_sha256")
	if err != nil || !sha256DigestPattern.MatchString(oldTargetRuntimeSHA) {
		return nil, fail
	}

	oldTargetInstaller, err := upgradeAsset(oldTarget, "ultra-install-linux-"+architecture)
	if err != nil || oldTargetInstaller.SHA != oldTargetInstallerSHA {
		return nil, fail
	}
	oldTargetRuntime, err := upgradeAsset(oldTarget, "ultra-ansible-runtime-linux-"+architecture+".tar.gz")
	if err != nil || oldTargetRuntime.SHA != oldTargetRuntimeSHA {
		return nil, fail
	}

	oldTargetIdentity := forwardBrokerIdentity{
		Directory: oldTargetDirectory, InstallerSHA: oldTargetInstaller.SHA,
		RuntimeSHA: oldTargetRuntime.SHA, UnitSHA: oldTargetUnitSHA,
	}
	// Legacy baselines can lack the signed runtime, source commit, or managed
	// controller path needed to prove their broker identity. Omit that identity
	// rather than guessing any field or blocking the verified target identities.
	// The live guard must still match one complete identity before mutation.
	allowed := []forwardBrokerIdentity{}
	previousDirectory, directoryErr := readBridgeString("ultra_previous_controller_directory")
	previousUnitSHA, unitErr := readBridgeString("ultra_previous_controller_unit_sha256")
	previousInstaller, installerErr := upgradeAsset(previous, "ultra-install-linux-"+architecture)
	previousRuntime, runtimeErr := upgradeAsset(previous, "ultra-ansible-runtime-linux-"+architecture+".tar.gz")
	if regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(previous.SourceCommit) &&
		directoryErr == nil && previousDirectory == managedControllerDirectory(previous.Version) &&
		unitErr == nil && sha256DigestPattern.MatchString(previousUnitSHA) &&
		installerErr == nil && sha256DigestPattern.MatchString(previousInstaller.SHA) &&
		runtimeErr == nil && sha256DigestPattern.MatchString(previousRuntime.SHA) {
		allowed = append(allowed, forwardBrokerIdentity{
			Directory: previousDirectory, InstallerSHA: previousInstaller.SHA,
			RuntimeSHA: previousRuntime.SHA, UnitSHA: previousUnitSHA,
		})
	}
	if !containsForwardBrokerIdentity(allowed, oldTargetIdentity) {
		allowed = append(allowed, oldTargetIdentity)
	}

	targetInstaller, err := upgradeAsset(target, "ultra-install-linux-"+architecture)
	if err != nil || !sha256DigestPattern.MatchString(targetInstaller.SHA) {
		return nil, fail
	}
	targetRuntime, err := upgradeAsset(target, "ultra-ansible-runtime-linux-"+architecture+".tar.gz")
	if err != nil || !sha256DigestPattern.MatchString(targetRuntime.SHA) {
		return nil, fail
	}
	unitTemplate, err := ansibleassets.Bundle.ReadFile("roles/controller/templates/ultra-ansible-controller.service.j2")
	if err != nil {
		return nil, fail
	}
	targetDirectory := managedControllerDirectory(target.Version)
	unit := strings.ReplaceAll(string(unitTemplate), "{{ ultra_controller_directory }}", targetDirectory)
	unitDigest := sha256.Sum256([]byte(unit))
	targetIdentity := forwardBrokerIdentity{
		Directory: targetDirectory, InstallerSHA: targetInstaller.SHA,
		RuntimeSHA: targetRuntime.SHA, UnitSHA: hex.EncodeToString(unitDigest[:]),
	}
	// A prior bootstrap attempt may already have switched current and restarted
	// the service before the operator process failed. Accept the exact signed
	// candidate identity on retry while the predecessor lifecycle remains gated.
	if !containsForwardBrokerIdentity(allowed, targetIdentity) {
		allowed = append(allowed, targetIdentity)
	}
	variables := map[string]any{
		"ultra_forward_expected_brokers": allowed,
		"ultra_forward_target_broker":    targetIdentity,
	}
	previousDirectory, directoryErr = readBridgeString("ultra_previous_controller_directory")
	previousUnitSHA, unitErr = readBridgeString("ultra_previous_controller_unit_sha256")
	if directoryErr == nil && unitErr == nil &&
		regexp.MustCompile(`^/opt/ultra-ansible/releases/managed-v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`).
			MatchString(previousDirectory) &&
		sha256DigestPattern.MatchString(previousUnitSHA) {
		variables["ultra_forward_previous_broker"] = forwardBrokerPredecessor{
			Directory: previousDirectory,
			UnitSHA:   previousUnitSHA,
		}
	}
	return variables, nil
}

func containsForwardBrokerIdentity(values []forwardBrokerIdentity, target forwardBrokerIdentity) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

var sha256DigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func oldTargetVersion(directory string) string {
	base := filepath.Base(directory)
	if !strings.HasPrefix(base, "upgrade-") {
		return ""
	}
	return strings.TrimPrefix(base, "upgrade-")
}
