package main

import (
	"fmt"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// validateAuthorizationRouting is defense in depth around the control-plane
// contract. With fallbacks disabled, the enclave accepts one route for the
// requested model and nothing else. A control-plane regression therefore
// fails before any prompt reaches a provider.
func validateAuthorizationRouting(
	req *types.OpenAIChatRequest,
	authorization *trustedrouter.Authorization,
) error {
	if req == nil || authorization == nil || req.FallbacksAllowed() {
		return nil
	}
	if len(authorization.RouteCandidates) > 1 {
		return fmt.Errorf(
			"fallbacks disabled but authorization returned %d candidates",
			len(authorization.RouteCandidates),
		)
	}
	if authorization.RequestedModel != "" && authorization.RequestedModel != req.Model {
		return fmt.Errorf(
			"authorization requested model %q does not match request %q",
			authorization.RequestedModel,
			req.Model,
		)
	}
	selectedModel := authorization.Model
	if len(authorization.RouteCandidates) == 1 {
		candidateModel := authorization.RouteCandidates[0].Model
		if candidateModel != "" {
			if selectedModel != "" && candidateModel != selectedModel {
				return fmt.Errorf(
					"authorization model %q does not match candidate model %q",
					selectedModel,
					candidateModel,
				)
			}
			selectedModel = candidateModel
		}
	}
	if selectedModel == "" {
		return fmt.Errorf("authorization returned an empty model")
	}
	if !requestedModelAllowsSelection(req.Model, selectedModel) {
		return fmt.Errorf(
			"requested model %q does not match authorized model %q",
			req.Model,
			selectedModel,
		)
	}
	return nil
}

func requestedModelAllowsSelection(requested string, selected string) bool {
	requested = strings.TrimSpace(requested)
	selected = strings.TrimSpace(selected)
	if requested == selected {
		return true
	}
	// Router and workspace-defined aliases intentionally resolve to another
	// catalog model. Their route count is still constrained above.
	if strings.HasPrefix(requested, "trustedrouter/") || isCustomModelID(requested) {
		return true
	}
	for _, suffix := range []string{":nitro", ":floor"} {
		requested = strings.TrimSuffix(requested, suffix)
	}
	requested = stripDatedModelSnapshot(requested)
	if requested == selected {
		return true
	}
	// The public OpenAI-compatible surface accepts bare OpenAI model names.
	if !strings.Contains(requested, "/") && selected == "openai/"+requested {
		return true
	}
	return false
}

func stripDatedModelSnapshot(model string) string {
	if len(model) < len("-2000-01-01") {
		return model
	}
	suffix := model[len(model)-len("-2000-01-01"):]
	for index, char := range suffix {
		if index == 0 || index == 5 || index == 8 {
			if char != '-' {
				return model
			}
			continue
		}
		if char < '0' || char > '9' {
			return model
		}
	}
	return model[:len(model)-len(suffix)]
}
