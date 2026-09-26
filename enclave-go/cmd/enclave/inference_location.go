package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Match the winning endpoint, not the initial provider or a failed fallback.
// Geography can identify a private backing route, so it follows redaction too.
func selectedInferenceLocation(auth *trustedrouter.Authorization, endpoint, provider, model string) *trustedrouter.InferenceLocationMetadata {
	if auth == nil || hidesPublicRouteMetadata(auth) || auth.CustomModel != nil {
		return nil
	}
	var location *trustedrouter.InferenceLocationMetadata
	if endpoint != "" && endpoint == auth.EndpointID && provider == auth.Provider && model == auth.Model {
		location = auth.InferenceLocation
	} else {
		for _, candidate := range auth.RouteCandidates {
			if endpoint != "" && endpoint == candidate.EndpointID && provider == candidate.Provider && model == candidate.Model {
				location = candidate.InferenceLocation
				break
			}
		}
	}
	if location == nil {
		return nil // Older control planes have no geography contract.
	}
	out := *location
	// No supported adapter currently verifies a serving-region receipt or
	// enforces a provider region pin. Catalog data must never claim otherwise.
	out.ServingRegion = nil
	out.ServingRegionStatus = "not_reported"
	out.RegionPinningEnforced = false
	return &out
}

func annotateInferenceLocation(usage map[string]any, auth *trustedrouter.Authorization, endpoint, provider, model string) {
	if usage == nil {
		return
	}
	delete(usage, "inference_location") // Never trust an upstream's TR extension.
	if location := selectedInferenceLocation(auth, endpoint, provider, model); location != nil {
		usage["inference_location"] = location
	}
}

// Decorate Emit so existing settlement hooks run unchanged before metadata is
// appended. The receipt hook then covers the same bytes sent to the caller.
func withInferenceLocation(control *adapter.StreamControl, auth *trustedrouter.Authorization, selected *selectedRouteTracker) *adapter.StreamControl {
	if auth == nil || selected == nil || hidesPublicRouteMetadata(auth) || auth.CustomModel != nil {
		return control
	}
	if control == nil {
		control = &adapter.StreamControl{}
	}
	control.ExposeResponsesUsage = true
	before := control.BeforeTerminal
	control.BeforeTerminal = func(terminal adapter.StreamTerminal) error {
		emit := terminal.Emit
		terminal.Emit = func() error {
			annotateInferenceLocation(terminal.UsageFields, auth, selected.Endpoint("", auth), selected.Provider("", auth), selected.Model("", auth))
			return emit()
		}
		if before != nil {
			return before(terminal)
		}
		return terminal.Emit()
	}
	return control
}
