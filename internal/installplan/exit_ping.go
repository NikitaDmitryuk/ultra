package installplan

import (
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

// An omitted feature preserves an installed bridge's publication policy;
// explicit false or an empty provider ID permits a deliberate rollback.
func optionalBoolValue(values map[string]string, key string) *bool {
	raw, ok := values[key]
	if !ok {
		return nil
	}
	value, _ := strconv.ParseBool(raw) // Canonical parsing rejects malformed values.
	return &value
}

func optionalStringValue(values map[string]string, key string) *string {
	value, ok := values[key]
	if !ok {
		return nil
	}
	return &value
}

func applyExitPingFeatures(spec *config.Spec, features FeatureConfig) {
	if features.ExitPing != nil {
		spec.ExitPing = *features.ExitPing
	}
	if features.HappExitPing != nil {
		spec.HappExitPing = *features.HappExitPing
	}
	if features.HappProviderID != nil {
		spec.HappProviderID = *features.HappProviderID
	}
}

func validateExitPingFeatures(features FeatureConfig) error {
	// Omitted fields may come from the existing bridge. Validate the complete
	// effective policy again in Spec.Validate after the reuse overlay is applied.
	spec := &config.Spec{Role: config.RoleBridge, ExitPing: true, HappProviderID: "pending-reuse"}
	applyExitPingFeatures(spec, features)
	return spec.ValidateExitPing()
}
