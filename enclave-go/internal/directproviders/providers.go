// Package directproviders defines the bounded set of simple, provider-owned
// OpenAI-compatible chat or embedding endpoints that TrustedRouter may call
// with operator keys.
//
// Bootstrap code and inference dispatch both consume this table. Keeping the
// secret coordinate and immutable HTTPS endpoint together prevents a provider
// from being configured in one cloud while remaining unreachable at runtime.
package directproviders

import (
	"fmt"
	"net/url"
	"strings"
)

// Spec is the complete enclave-side contract for one direct provider.
type Spec struct {
	Provider            string
	BaseURL             string
	ChatCompletionsPath string
	MediaOnly           bool
	SecretEnv           string
	SecretName          string
	SecretLabel         string
}

var specs = [...]Spec{
	{Provider: "nextbit", BaseURL: "https://api.nextbit256.com/v1", SecretEnv: "QUILL_NEXTBIT_SECRET", SecretName: "trustedrouter-nextbit-api-key", SecretLabel: "nextbit key"},
	{Provider: "aion-labs", BaseURL: "https://api.aionlabs.ai/v1", SecretEnv: "QUILL_AION_LABS_SECRET", SecretName: "trustedrouter-aion-labs-api-key", SecretLabel: "aion labs key"},
	{Provider: "sambanova", BaseURL: "https://api.sambanova.ai/v1", SecretEnv: "QUILL_SAMBANOVA_SECRET", SecretName: "trustedrouter-sambanova-api-key", SecretLabel: "sambanova key"},
	{Provider: "inception", BaseURL: "https://api.inceptionlabs.ai/v1", SecretEnv: "QUILL_INCEPTION_SECRET", SecretName: "trustedrouter-inception-api-key", SecretLabel: "inception key"},
	{Provider: "akashml", BaseURL: "https://api.akashml.com/v1", SecretEnv: "QUILL_AKASHML_SECRET", SecretName: "trustedrouter-akashml-api-key", SecretLabel: "akashml key"},
	{Provider: "arcee", BaseURL: "https://api.arcee.ai/api/v1", SecretEnv: "QUILL_ARCEE_SECRET", SecretName: "trustedrouter-arcee-api-key", SecretLabel: "arcee key"},
	{Provider: "upstage", BaseURL: "https://api.upstage.ai/v1", SecretEnv: "QUILL_UPSTAGE_SECRET", SecretName: "trustedrouter-upstage-api-key", SecretLabel: "upstage key"},
	{Provider: "reka", BaseURL: "https://api.reka.ai/v1", SecretEnv: "QUILL_REKA_SECRET", SecretName: "trustedrouter-reka-api-key", SecretLabel: "reka key"},
	{Provider: "sail-research", BaseURL: "https://api.sailresearch.com/v1", SecretEnv: "QUILL_SAIL_RESEARCH_SECRET", SecretName: "trustedrouter-sail-research-api-key", SecretLabel: "sail research key"},
	{Provider: "mancer", BaseURL: "https://mancer.tech/oai/v1", SecretEnv: "QUILL_MANCER_SECRET", SecretName: "trustedrouter-mancer-api-key", SecretLabel: "mancer key"},
	{Provider: "io-net", BaseURL: "https://api.intelligence.io.solutions/api/v1", SecretEnv: "QUILL_IO_NET_SECRET", SecretName: "trustedrouter-io-net-api-key", SecretLabel: "io intelligence key"},
	{Provider: "scaleway", BaseURL: "https://api.scaleway.ai/v1", SecretEnv: "QUILL_SCALEWAY_SECRET", SecretName: "trustedrouter-scaleway-api-key", SecretLabel: "scaleway key"},
	{Provider: "featherless", BaseURL: "https://api.featherless.ai/v1", SecretEnv: "QUILL_FEATHERLESS_SECRET", SecretName: "trustedrouter-featherless-api-key", SecretLabel: "featherless key"},
	{Provider: "jina", BaseURL: "https://api.jina.ai/v1", SecretEnv: "QUILL_JINA_SECRET", SecretName: "trustedrouter-jina-api-key", SecretLabel: "jina key"},
	{Provider: "sakana", BaseURL: "https://api.sakana.ai/v1", SecretEnv: "QUILL_SAKANA_SECRET", SecretName: "trustedrouter-sakana-api-key", SecretLabel: "sakana key"},
	{Provider: "nvidia-nim", BaseURL: "https://integrate.api.nvidia.com/v1", SecretEnv: "QUILL_NVIDIA_NIM_SECRET", SecretName: "trustedrouter-nvidia-nim-api-key", SecretLabel: "NVIDIA NIM key"},
	{Provider: "wandb", BaseURL: "https://api.inference.wandb.ai/v1", SecretEnv: "QUILL_WANDB_SECRET", SecretName: "trustedrouter-wandb-api-key", SecretLabel: "W&B Inference key"},
	{Provider: "nscale", BaseURL: "https://inference.api.nscale.com/v1", SecretEnv: "QUILL_NSCALE_SECRET", SecretName: "trustedrouter-nscale-api-key", SecretLabel: "Nscale service token"},
	{Provider: "perplexity", BaseURL: "https://api.perplexity.ai/v1", ChatCompletionsPath: "/sonar", SecretEnv: "QUILL_PERPLEXITY_SECRET", SecretName: "trustedrouter-perplexity-api-key", SecretLabel: "Perplexity key"},
	{Provider: "krea", BaseURL: "https://api.krea.ai", MediaOnly: true, SecretEnv: "QUILL_KREA_SECRET", SecretName: "trustedrouter-krea-api-key", SecretLabel: "Krea key"},
	{Provider: "vultr", BaseURL: "https://api.vultrinference.com/v1", SecretEnv: "QUILL_VULTR_SECRET", SecretName: "trustedrouter-vultr-api-key", SecretLabel: "Vultr inference key"},
	{Provider: "darkbloom", BaseURL: "https://api.darkbloom.dev/v1", SecretEnv: "QUILL_DARKBLOOM_SECRET", SecretName: "trustedrouter-darkbloom-api-key", SecretLabel: "Darkbloom key"},
	{Provider: "baidu", BaseURL: "https://qianfan.baidubce.com/v2", SecretEnv: "QUILL_BAIDU_SECRET", SecretName: "trustedrouter-baidu-api-key", SecretLabel: "Baidu Qianfan key"},
	{Provider: "riverflow", BaseURL: "https://design-api.sourceful.com", MediaOnly: true, SecretEnv: "QUILL_RIVERFLOW_SECRET", SecretName: "trustedrouter-riverflow-api-key", SecretLabel: "Riverflow key"},
}

var byProvider = func() map[string]Spec {
	result := make(map[string]Spec, len(specs))
	for _, spec := range specs {
		result[spec.Provider] = spec
	}
	return result
}()

// All returns a copy so callers cannot mutate the package's security table.
func All() []Spec {
	result := make([]Spec, len(specs))
	copy(result, specs[:])
	return result
}

// Lookup resolves only an exact canonical provider slug.
func Lookup(provider string) (Spec, bool) {
	spec, ok := byProvider[provider]
	return spec, ok
}

// Validate rejects malformed or duplicate entries before bootstrap performs
// any secret-store I/O.
func Validate() error {
	providers := make(map[string]struct{}, len(specs))
	envs := make(map[string]struct{}, len(specs))
	names := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if spec.Provider == "" || spec.BaseURL == "" || spec.SecretEnv == "" || spec.SecretName == "" || spec.SecretLabel == "" {
			return fmt.Errorf("direct providers: malformed provider spec")
		}
		if spec.Provider != strings.TrimSpace(spec.Provider) || spec.Provider != strings.ToLower(spec.Provider) {
			return fmt.Errorf("direct providers: non-canonical provider %q", spec.Provider)
		}
		if _, exists := providers[spec.Provider]; exists {
			return fmt.Errorf("direct providers: duplicate provider %q", spec.Provider)
		}
		if _, exists := envs[spec.SecretEnv]; exists {
			return fmt.Errorf("direct providers: duplicate secret env %q", spec.SecretEnv)
		}
		if _, exists := names[spec.SecretName]; exists {
			return fmt.Errorf("direct providers: duplicate secret name %q", spec.SecretName)
		}
		parsed, err := url.Parse(spec.BaseURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("direct providers: invalid HTTPS base URL for %q", spec.Provider)
		}
		path := spec.ChatCompletionsPath
		if path == "" && !spec.MediaOnly {
			path = "/chat/completions"
		}
		if spec.MediaOnly && spec.ChatCompletionsPath != "" {
			return fmt.Errorf("direct providers: media-only provider %q has a chat path", spec.Provider)
		}
		if (!spec.MediaOnly && !strings.HasPrefix(path, "/")) || strings.Contains(path, "://") {
			return fmt.Errorf("direct providers: invalid chat path for %q", spec.Provider)
		}
		providers[spec.Provider] = struct{}{}
		envs[spec.SecretEnv] = struct{}{}
		names[spec.SecretName] = struct{}{}
	}
	return nil
}

// ChatCompletionsPath returns the provider's compiled inference path.
func (s Spec) ChatPath() string {
	if s.ChatCompletionsPath != "" {
		return s.ChatCompletionsPath
	}
	return "/chat/completions"
}
