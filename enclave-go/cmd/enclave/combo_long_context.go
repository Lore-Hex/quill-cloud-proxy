package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Explicit serving routes, not a model-wide context claim. Reviewed against
// provider documentation/catalogs on 2026-09-22. Qwen and MiniMax each need
// two independent 1M providers; their shorter-context hosts are ineligible.
var longContextComboProviders = map[string][]string{
	mimo26ProModel:                    {"xiaomi"},
	"xiaomi/mimo-v2.6-pro-ultraspeed": {"xiaomi"},
	"z-ai/glm-5.3":                    {"zai", "novita"},
	fusionKimiK3:                      {"kimi", "novita", "together"},
	fusionKimiK31Pro:                  {"novita", "fireworks", "baseten"},
	deepSeekV41FlashModel:             {"novita", "together"},
	"minimax/minimax-m3":              {"minimax", "novita"},
	"qwen/qwen3.8-2.4t-a95b":          {"novita", "together"},
	"openai/gpt-6-astra":              {"openai"},
	"anthropic/claude-fable-5.1":      {"anthropic"},
	"google/gemini-3.8-flash":         {"google-ai-studio", "google-vertex"},
	// Liberty 4.0 members, US-headquartered 1M hosts only, reviewed 2026-11-04.
	"meta-models/muse-spark-open":  {"baseten"},
	"reflection/beam-1.0":          {"baseten"},
	"nvidia/nemotron-3.5-super-vl": {"crusoe"},
	// 256K with tools, reviewed 2026-11-07 (Baseten serves only 200K; DeepInfra
	// is excluded from every combo). fusionWithoutOverlongMembers drops it from
	// Liberty requests above that.
	fusionNemotron3Ultra: {"fireworks", "nvidia-nim"},
	// Liberty 4.1's fourth member, reviewed 2026-11-12: Cloudflare Workers AI
	// is US-headquartered and serves it at 1M. Not used: Nebius (not
	// US-headquartered), Thinking Machines' Tinker (256K, and held on TR's key),
	// and DeepInfra, which every combo excludes.
	fusionInkling2Small: {"cloudflare-workers-ai"},
}

func isLongContextCombo(model string) bool {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case trustedRouterPrometheusModel, trustedRouterPrometheus40Model,
		trustedRouterZeusModel, trustedRouterZeus30Model,
		trustedRouterPlatoModel, trustedRouterPlato40Model,
		trustedRouterSocratesModel, trustedRouterSocrates30Model,
		trustedRouterLiberty40Model, trustedRouterLiberty41Model:
		return true
	default:
		return false
	}
}

func constrainLongContextComboRoute(req *types.OpenAIChatRequest) error {
	if !req.InternalLongContextCombo {
		return nil
	}
	providers := longContextComboProviders[req.Model]
	if len(providers) == 0 {
		return &adapter.AdapterError{Status: 400, Message: "model has no reviewed long-context route for this combo", Context: "model"}
	}
	policy := cloneProviderRouting(req.Provider)
	if policy == nil {
		policy = &types.ProviderRouting{}
	}
	only := make(types.StringList, 0, len(providers))
	for _, provider := range providers {
		allowed := len(policy.Only) == 0
		for _, requested := range policy.Only {
			if strings.EqualFold(strings.TrimSpace(requested), provider) {
				allowed = true
			}
		}
		if allowed {
			only = append(only, provider)
		}
	}
	if len(only) == 0 {
		return &adapter.AdapterError{Status: 400, Message: "provider.only excludes all reviewed long-context routes for this combo", Context: "provider.only"}
	}
	// Preserve ignore, privacy, jurisdiction, price and fallback constraints.
	policy.Only = only
	req.Provider = policy
	return nil
}

func validateLongContextComboOptions(req *types.OpenAIChatRequest, options []llm.InvokeOptions) error {
	if !req.InternalLongContextCombo {
		return nil
	}
	if req.Provider == nil || len(req.Provider.Only) == 0 || len(options) == 0 {
		return fmt.Errorf("missing constrained long-context combo routes")
	}
	for _, option := range options {
		if option.Model != req.Model || !slices.Contains(req.Provider.Only, option.Provider) {
			return fmt.Errorf("authorization returned an unreviewed long-context combo route")
		}
	}
	return nil
}
