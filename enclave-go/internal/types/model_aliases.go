package types

import "strings"

// CanonicalRouterModelID rewrites brand spellings, not model versions. Unknown
// names remain unknown so the authoritative control-plane catalog fails closed.
func CanonicalRouterModelID(model string) string {
	if strings.HasPrefix(model, "nyte/") {
		model = "trustedrouter/" + strings.TrimPrefix(model, "nyte/")
	}
	base, variant, hasVariant := strings.Cut(model, ":")
	if base == "trustedrouter/auto-routing" {
		model = "trustedrouter/auto"
		if hasVariant {
			model += ":" + variant
		}
	}
	return model
}

func (r *OpenAIChatRequest) NormalizeRouterModelAliases() {
	r.Model = CanonicalRouterModelID(r.Model)
	for i, model := range r.Models {
		r.Models[i] = CanonicalRouterModelID(model)
	}
}
