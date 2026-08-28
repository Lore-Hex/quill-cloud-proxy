//go:build cloud_azure

// SCOPED TO cloud_azure DELIBERATELY.
//
// On the azure branch this was `cloud_gcp || cloud_azure`, because that branch
// also refactored bootstrap_gcp.go to call into here. Bringing that refactor
// forward would mean rewriting GCP's live secret-loading path — 486 extracted
// lines — against a bootstrap_gcp.go that has since gained 17 more providers.
// Getting it subtly wrong yields an enclave that boots green and 401s at
// runtime.
//
// So GCP keeps its own loader untouched and Azure is self-contained. The cost
// is one duplicated provider list; TestProviderSecretParityAcrossClouds turns
// any drift between the two into a CI failure rather than a silent fork.

// Shared secret-name -> BootstrapData mapping for the two self-fetching clouds.
//
// GCP Confidential Space (bootstrap_gcp.go) and Azure confidential containers
// (bootstrap_azure.go) both fetch their own secrets, from different stores:
//
//	GCP    Google Secret Manager, one HTTPS GET per secret, metadata-server token
//	Azure  ONE Azure Key Vault secret holding an encrypted bundle of all of them
//
// What must NOT differ between them is which secrets exist, what they are
// called, the order they are consulted in, and where their values land in
// BootstrapData. All of that lives here, in ONE implementation, so the two
// adapters cannot drift. A second copy is how "add a provider" turns into "the
// provider works on GCP and 404s on Azure three weeks later".
//
// The clouds meet this file at exactly one seam: a secretResolver, which turns
// a logical secret NAME into its value. Everything above that seam (transport,
// authentication, attestation) is the adapter's business; everything below it
// (names, order, assignment, trimming) is here.
//
// Azure does NOT read Google Secret Manager. It used to — it unwrapped a GCP
// service-account key under attestation and then made ~40 cross-cloud calls to
// secretmanager.googleapis.com — which meant a Google outage took the Azure
// enclave down with it and voided the independence that is the entire reason a
// second cloud exists. Azure now keeps its own copies in Key Vault. Rotation is
// infrequent, so a second copy is an accepted cost; it is the same trade already
// made on AWS, where the provider secrets were replicated into eu-west-3.
//
// (Deliberately detached from the package clause below — the package doc lives
// on whichever per-cloud adapter file the build tag selected.)

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// secretBinding describes one secret: which env var(s) carry its NAME, what it
// is called in an error message, and where its value lands in BootstrapData.
type secretBinding struct {
	// envs holds the env var(s) naming the secret. First non-blank wins, which
	// is how the advisor prompts keep accepting their pre-rename SOCRATES_*
	// spellings.
	envs []string
	// label is the error prefix for this entry, e.g. "openrouter key" ->
	// "bootstrap/azure: openrouter key: not present in the bundle".
	label string
	// provider marks entries that count toward the "at least one provider
	// secret must be configured" guard. Prompt overrides and the control-plane
	// token do not — a deploy with only those set has no LLM backend and must
	// fail loudly rather than boot into a gateway that 500s every request.
	provider bool
	assign   func(*types.BootstrapData, string)
}

// secretBindings is ORDER-SENSITIVE. The assembly loop walks it top to bottom,
// so this order decides which misconfigured secret is reported first when
// several are broken. It reproduces the hand-written sequence bootstrap_gcp.go
// used before this table existed; reordering it changes which error an operator
// sees on a bad deploy.
var secretBindings = func() []secretBinding {
	bindings := []secretBinding{
		{[]string{"QUILL_OPENROUTER_SECRET"}, "openrouter key", true, func(b *types.BootstrapData, v string) { b.OpenRouterAPIKey = v }},
		{[]string{"QUILL_ANTHROPIC_SECRET"}, "anthropic key", true, func(b *types.BootstrapData, v string) { b.AnthropicAPIKey = v }},
		{[]string{"QUILL_OPENAI_SECRET"}, "openai key", true, func(b *types.BootstrapData, v string) { b.OpenAIAPIKey = v }},
		{[]string{"QUILL_GEMINI_SECRET"}, "gemini key", true, func(b *types.BootstrapData, v string) { b.GeminiAPIKey = v }},
		{[]string{"QUILL_CEREBRAS_SECRET"}, "cerebras key", true, func(b *types.BootstrapData, v string) { b.CerebrasAPIKey = v }},
		{[]string{"QUILL_DEEPSEEK_SECRET"}, "deepseek key", true, func(b *types.BootstrapData, v string) { b.DeepSeekAPIKey = v }},
		{[]string{"QUILL_MISTRAL_SECRET"}, "mistral key", true, func(b *types.BootstrapData, v string) { b.MistralAPIKey = v }},
		{[]string{"QUILL_KIMI_SECRET"}, "kimi key", true, func(b *types.BootstrapData, v string) { b.KimiAPIKey = v }},
		{[]string{"QUILL_ZAI_SECRET"}, "zai key", true, func(b *types.BootstrapData, v string) { b.ZAIAPIKey = v }},
		{[]string{"QUILL_TOGETHER_SECRET"}, "together key", true, func(b *types.BootstrapData, v string) { b.TogetherAPIKey = v }},
		{[]string{"QUILL_FIREWORKS_SECRET"}, "fireworks key", true, func(b *types.BootstrapData, v string) { b.FireworksAPIKey = v }},
		{[]string{"QUILL_COHERE_SECRET"}, "cohere key", true, func(b *types.BootstrapData, v string) { b.CohereAPIKey = v }},
		{[]string{"QUILL_VOYAGE_SECRET"}, "voyage key", true, func(b *types.BootstrapData, v string) { b.VoyageAPIKey = v }},
		{[]string{"QUILL_GROK_SECRET"}, "grok key", true, func(b *types.BootstrapData, v string) { b.GrokAPIKey = v }},
		{[]string{"QUILL_NOVITA_SECRET"}, "novita key", true, func(b *types.BootstrapData, v string) { b.NovitaAPIKey = v }},
		{[]string{"QUILL_PHALA_SECRET"}, "phala key", true, func(b *types.BootstrapData, v string) { b.PhalaAPIKey = v }},
		{[]string{"QUILL_SILICONFLOW_SECRET"}, "siliconflow key", true, func(b *types.BootstrapData, v string) { b.SiliconFlowAPIKey = v }},
		{[]string{"QUILL_TINFOIL_SECRET"}, "tinfoil key", true, func(b *types.BootstrapData, v string) { b.TinfoilAPIKey = v }},
		{[]string{"QUILL_NEAR_AI_SECRET"}, "near ai key", true, func(b *types.BootstrapData, v string) { b.NearAIAPIKey = v }},
		{[]string{"QUILL_VENICE_SECRET"}, "venice key", true, func(b *types.BootstrapData, v string) { b.VeniceAPIKey = v }},
		{[]string{"QUILL_PARASAIL_SECRET"}, "parasail key", true, func(b *types.BootstrapData, v string) { b.ParasailAPIKey = v }},
		{[]string{"QUILL_LIGHTNING_SECRET"}, "lightning key", true, func(b *types.BootstrapData, v string) { b.LightningAPIKey = v }},
		{[]string{"QUILL_GMI_SECRET"}, "gmi key", true, func(b *types.BootstrapData, v string) { b.GMIAPIKey = v }},
		{[]string{"QUILL_DEEPINFRA_SECRET"}, "deepinfra key", true, func(b *types.BootstrapData, v string) { b.DeepInfraAPIKey = v }},
		{[]string{"QUILL_FRIENDLI_SECRET"}, "friendli key", true, func(b *types.BootstrapData, v string) { b.FriendliAPIKey = v }},
		{[]string{"QUILL_BASETEN_SECRET"}, "baseten key", true, func(b *types.BootstrapData, v string) { b.BasetenAPIKey = v }},
		{[]string{"QUILL_THINKING_MACHINES_SECRET"}, "thinking machines key", true, func(b *types.BootstrapData, v string) { b.ThinkingMachinesAPIKey = v }},
		{[]string{"QUILL_WAFER_SECRET"}, "wafer key", true, func(b *types.BootstrapData, v string) { b.WaferAPIKey = v }},
		{[]string{"QUILL_CRUSOE_SECRET"}, "crusoe key", true, func(b *types.BootstrapData, v string) { b.CrusoeAPIKey = v }},
		{[]string{"QUILL_MAKORA_SECRET"}, "makora key", true, func(b *types.BootstrapData, v string) { b.MakoraAPIKey = v }},
		{[]string{"QUILL_NEBIUS_SECRET"}, "nebius key", true, func(b *types.BootstrapData, v string) { b.NebiusAPIKey = v }},
		{[]string{"QUILL_MINIMAX_SECRET"}, "minimax key", true, func(b *types.BootstrapData, v string) { b.MiniMaxAPIKey = v }},
		{[]string{"QUILL_XIAOMI_SECRET"}, "xiaomi key", true, func(b *types.BootstrapData, v string) { b.XiaomiAPIKey = v }},
		// Providers added to bootstrap_gcp.go after this file was written. Kept in
		// step by TestProviderSecretParityAcrossClouds, which fails if the two
		// lists ever diverge again.
		{[]string{"QUILL_ALIBABA_SECRET"}, "alibaba key", true, func(b *types.BootstrapData, v string) { b.AlibabaAPIKey = v }},
		{[]string{"QUILL_AZURE_SECRET"}, "azure key", true, func(b *types.BootstrapData, v string) { b.AzureAPIKey = v }},
		{[]string{"QUILL_ATLAS_CLOUD_SECRET"}, "atlas cloud key", true, func(b *types.BootstrapData, v string) { b.AtlasCloudAPIKey = v }},
		{[]string{"QUILL_CHUTES_SECRET"}, "chutes key", true, func(b *types.BootstrapData, v string) { b.ChutesAPIKey = v }},
		{[]string{"QUILL_CLOUDFLARE_WORKERS_AI_SECRET"}, "cloudflare workers ai key", true, func(b *types.BootstrapData, v string) { b.CloudflareWorkersAIAPIKey = v }},
		{[]string{"QUILL_DIGITALOCEAN_SECRET"}, "digitalocean key", true, func(b *types.BootstrapData, v string) { b.DigitalOceanAPIKey = v }},
		{[]string{"QUILL_ENGY_SECRET"}, "engy key", true, func(b *types.BootstrapData, v string) { b.EngyAPIKey = v }},
		{[]string{"QUILL_STEPFUN_SECRET"}, "stepfun key", true, func(b *types.BootstrapData, v string) { b.StepFunAPIKey = v }},
		{[]string{"QUILL_RELACE_SECRET"}, "relace key", true, func(b *types.BootstrapData, v string) { b.RelaceAPIKey = v }},
		{[]string{"QUILL_DECART_SECRET"}, "decart key", true, func(b *types.BootstrapData, v string) { b.DecartAPIKey = v }},
		{[]string{"QUILL_RECRAFT_SECRET"}, "recraft key", true, func(b *types.BootstrapData, v string) { b.RecraftAPIKey = v }},
		{[]string{"QUILL_BFL_SECRET"}, "bfl key", true, func(b *types.BootstrapData, v string) { b.BFLAPIKey = v }},
		{[]string{"QUILL_DATABRICKS_SECRET"}, "databricks token", true, func(b *types.BootstrapData, v string) { b.DatabricksToken = v }},
		{[]string{"QUILL_DATABRICKS_HOST_SECRET"}, "databricks host", false, func(b *types.BootstrapData, v string) { b.DatabricksHost = v }},
		{[]string{"QUILL_EXA_SECRET"}, "exa key", true, func(b *types.BootstrapData, v string) { b.ExaAPIKey = v }},
		{[]string{"QUILL_INCEPTRON_SECRET"}, "inceptron key", true, func(b *types.BootstrapData, v string) { b.InceptronAPIKey = v }},
		{[]string{"QUILL_KLING_SECRET"}, "kling key", true, func(b *types.BootstrapData, v string) { b.KlingAPIKey = v }},
		{[]string{"QUILL_LTX_SECRET"}, "ltx key", true, func(b *types.BootstrapData, v string) { b.LTXAPIKey = v }},
		{[]string{"QUILL_MORPH_SECRET"}, "morph key", true, func(b *types.BootstrapData, v string) { b.MorphAPIKey = v }},
		{[]string{"QUILL_NEUROMETRIC_SECRET"}, "neurometric key", true, func(b *types.BootstrapData, v string) { b.NeurometricAPIKey = v }},
		{[]string{"QUILL_PEARL_SECRET"}, "pearl key", true, func(b *types.BootstrapData, v string) { b.PearlAPIKey = v }},
		{[]string{"QUILL_OPENAI_VIDEO_SECRET"}, "openai video key", true, func(b *types.BootstrapData, v string) { b.OpenAIVideoAPIKey = v }},
		{[]string{"QUILL_RUNWAY_SECRET"}, "runway key", true, func(b *types.BootstrapData, v string) { b.RunwayAPIKey = v }},
		{[]string{"QUILL_STREAMLAKE_SECRET"}, "streamlake key", true, func(b *types.BootstrapData, v string) { b.StreamLakeAPIKey = v }},
		{[]string{"QUILL_TELNYX_SECRET"}, "telnyx key", true, func(b *types.BootstrapData, v string) { b.TelnyxAPIKey = v }},
		{[]string{"QUILL_ZERO_G_SECRET"}, "zero g key", true, func(b *types.BootstrapData, v string) { b.ZeroGAPIKey = v }},
		{[]string{"QUILL_SYNTH_PANEL_PROMPT_SECRET"}, "synth panel prompt", false, func(b *types.BootstrapData, v string) { b.SynthPanelPrompt = v }},
		{[]string{"QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET"}, "synth synthesis prompt", false, func(b *types.BootstrapData, v string) { b.SynthSynthesisPrompt = v }},
		{[]string{"QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET"}, "synth-code panel prompt", false, func(b *types.BootstrapData, v string) { b.SynthCodePanelPrompt = v }},
		{[]string{"QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET"}, "synth-code synthesis prompt", false, func(b *types.BootstrapData, v string) { b.SynthCodeSynthesisPrompt = v }},
		{[]string{"QUILL_ADVISOR_WORKER_PROMPT_SECRET", "QUILL_SOCRATES_WORKER_PROMPT_SECRET"}, "advisor worker prompt", false, func(b *types.BootstrapData, v string) { b.AdvisorWorkerPrompt = v }},
		{[]string{"QUILL_ADVISOR_PROMPT_SECRET", "QUILL_SOCRATES_ADVISOR_PROMPT_SECRET"}, "advisor prompt", false, func(b *types.BootstrapData, v string) { b.AdvisorPrompt = v }},
		{[]string{"QUILL_TRUSTEDROUTER_INTERNAL_SECRET"}, "trustedrouter internal token", false, func(b *types.BootstrapData, v string) { b.TrustedRouterInternalToken = v }},
		// Azure resolves the Stage A issuer manifest for cross-cloud secret
		// parity, but deliberately does not enable SpendLeaseShadow. Design
		// record v8 excludes Azure issuance and soak evidence until its
		// attestation verifier reaches parity with GCP, so the config remains
		// inert here.
		{[]string{"QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET"}, "spend lease issuer config", false, func(b *types.BootstrapData, v string) {
			b.SpendLeaseIssuerConfig = append(json.RawMessage(nil), v...)
		}},
		// "<kid>:<base64url-hmac>" for the fallback ACME CA; one entry so the
		// halves rotate together. Optional: absent simply leaves the fallback
		// CA (if any) registering without EAB.
		{[]string{"QUILL_ACME_FALLBACK_EAB_SECRET"}, "acme fallback eab", false, func(b *types.BootstrapData, v string) { b.ACMEFallbackEAB = v }},
	}
	for _, spec := range directproviders.All() {
		spec := spec
		bindings = append(bindings, secretBinding{
			envs:     []string{spec.SecretEnv},
			label:    spec.SecretLabel,
			provider: true,
			assign: func(data *types.BootstrapData, value string) {
				assignDirectProviderAPIKey(data, spec.Provider, value)
			},
		})
	}
	return bindings
}()

// secretConfig is the resolved, validated environment: everything the assembly
// loop needs, read once so a misconfigured deploy fails before any network I/O.
//
// project is a Google Secret Manager coordinate and is only consulted by the
// GCP adapter; Azure requires it too because a bundle produced from that
// project is what the deploy replicates, and a deploy that cannot say which
// project its copy came from is a deploy nobody can audit.
type secretConfig struct {
	project string
	devices string
	region  string
	trURL   string
	// names is parallel to secretBindings. "" means the deploy did not
	// configure that entry and it is skipped.
	names []string
}

// resolveSecretConfig reads and validates the environment. It performs no I/O
// on purpose: both adapters call it FIRST so a deploy missing
// QUILL_GCP_PROJECT_ID reports exactly that, instead of reporting whatever
// error happens to come out of an unrelated subsystem.
//
// tag is the caller's error prefix ("bootstrap/gcp" / "bootstrap/azure") so the
// message names the cloud whose deploy is broken.
func resolveSecretConfig(tag string) (secretConfig, error) {
	cfg := secretConfig{
		project: os.Getenv("QUILL_GCP_PROJECT_ID"),
		devices: os.Getenv("QUILL_DEVICE_KEYS_SECRET"),
		region:  os.Getenv("QUILL_GCP_REGION"),
		trURL:   os.Getenv("TR_CONTROL_PLANE_BASE_URL"),
		names:   make([]string, len(secretBindings)),
	}
	if err := rejectBlank(tag, "QUILL_GCP_PROJECT_ID", cfg.project); err != nil {
		return secretConfig{}, err
	}
	if err := rejectBlank(tag, "QUILL_DEVICE_KEYS_SECRET", cfg.devices); err != nil {
		return secretConfig{}, err
	}

	// Bootstrap does not know which build target it is serving, so it reads
	// whatever env vars happen to be set: llm_multi sets many, a single-backend
	// build sets exactly one. Literally none is a broken deploy.
	anyProvider := false
	for i, binding := range secretBindings {
		name, err := firstSetEnv(binding.envs)
		if err != nil {
			return secretConfig{}, fmt.Errorf("%s: %s: %w", tag, binding.label, err)
		}
		cfg.names[i] = name
		if binding.provider && name != "" {
			anyProvider = true
		}
	}
	if !anyProvider {
		return secretConfig{}, fmt.Errorf("%s: at least one provider secret env must be set", tag)
	}
	return cfg, nil
}

// rejectBlank distinguishes "not configured" from "configured with whitespace".
// An empty value is the conventional way a container spec says "unset"; a value
// that is non-empty but blank is a broken deploy, and saying so here — before
// any I/O — beats building "projects/   /secrets/..." and reporting a 404.
func rejectBlank(tag, name, value string) error {
	if value == "" {
		return fmt.Errorf("%s: %s not set", tag, name)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s: %s is set to whitespace only (%d chars)", tag, name, len(value))
	}
	return nil
}

// firstSetEnv reads env vars in order and returns the first non-empty VALUE.
// The distinction between the name and the value matters more than it looks:
// passing the names straight in makes every binding appear configured (a name
// is a non-empty constant), which silently turns the "at least one provider
// secret" guard into a no-op and then asks the secret store for a secret
// literally called "QUILL_OPENROUTER_SECRET".
//
// A value that is non-empty but blank is an error, not a skip. Skipping it is
// what an earlier draft did, and it is the one behaviour this file exists to
// prevent: QUILL_ANTHROPIC_SECRET="   " booted a gateway with an empty
// Anthropic key that 401s every Anthropic request at runtime, where the
// pre-refactor GCP code fetched a secret named "   " and died loudly at boot.
// Failing here is louder still — it happens before any network I/O and names
// the variable.
func firstSetEnv(envs []string) (string, error) {
	for _, env := range envs {
		value := os.Getenv(env)
		if value == "" {
			continue
		}
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("%s is set to whitespace only (%d chars); it must name a secret or be unset", env, len(value))
		}
		return value, nil
	}
	return "", nil
}

// secretResolver returns the value of one logical secret by name. It is the ONE
// seam between this shared mapping and a cloud's secret store: GCP hands over a
// closure that GETs Secret Manager, Azure one that reads the decrypted bundle.
//
// It takes a context because the GCP implementation makes a network call per
// name; Azure's ignores it, having already fetched everything in one round trip.
type secretResolver func(ctx context.Context, name string) ([]byte, error)

// assembleBootstrapData resolves every configured secret and assembles
// BootstrapData. This is the only place secret VALUES are mapped onto fields,
// on either cloud.
//
// Every error names which secret failed, because the historically worst
// bootstrap bug in this system was a failure that left the enclave wedged with
// no indication of which step died.
func assembleBootstrapData(ctx context.Context, cfg secretConfig, tag string, resolve secretResolver) (*types.BootstrapData, error) {
	devicesJSON, err := resolve(ctx, cfg.devices)
	if err != nil {
		return nil, fmt.Errorf("%s: device-keys: %w", tag, err)
	}
	var devices []types.DeviceConfig
	if err := json.Unmarshal(devicesJSON, &devices); err != nil {
		return nil, fmt.Errorf("%s: parse device-keys JSON: %w", tag, err)
	}

	data := &types.BootstrapData{
		Devices:              devices,
		Region:               cfg.region,
		TrustedRouterBaseURL: cfg.trURL,
		// Legacy proxy fields unused on the self-fetch clouds — direct egress.
	}
	for i, binding := range secretBindings {
		name := cfg.names[i]
		if name == "" {
			continue
		}
		value, err := resolve(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", tag, binding.label, err)
		}
		// Secret payloads routinely carry a trailing newline (anything created
		// with `printf ... | gcloud secrets create --data-file=-` does). An API
		// key with "\n" on the end produces an unparseable Authorization header
		// and a 401 that looks like a bad key rather than a bad payload.
		trimmed := strings.TrimSpace(string(value))
		// A secret that EXISTS but is empty is a broken deploy, and it has to die
		// here. firstSetEnv above already refuses a blank secret NAME for exactly
		// this reason, but that guard only covers the env var — it says nothing
		// about the value the store hands back, so the hole it was written to
		// close stayed open one level down: an empty payload booted a gateway
		// whose Anthropic key is "" and which 401s every Anthropic request at
		// runtime, hours from its cause.
		//
		// This is likelier on the Azure side than the GCP one, and that asymmetry
		// is the argument for putting the check here rather than in either
		// adapter: the bundle is produced by a mechanical dump, so one provider
		// whose export comes back empty yields `"name": ""` and a silently
		// degraded gateway, where Secret Manager makes an empty payload awkward
		// to create by hand. Azure's own bundle.require applies the same rule to
		// the service-account entry; this makes the other ~40 consistent with it.
		if trimmed == "" {
			return nil, fmt.Errorf("%s: %s: secret %q resolved to an empty value (%d bytes before trimming) — a present-but-empty secret would boot a gateway that fails every request using it", tag, binding.label, name, len(value))
		}
		binding.assign(data, trimmed)
	}
	if err := validateDatabricksBootstrap(data); err != nil {
		return nil, fmt.Errorf("%s: %w", tag, err)
	}
	return data, nil
}
