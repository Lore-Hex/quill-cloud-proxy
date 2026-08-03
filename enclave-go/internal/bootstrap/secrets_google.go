//go:build cloud_gcp || cloud_azure

// Shared Google Secret Manager path.
//
// Two clouds fetch their OWN secrets: GCP Confidential Space
// (bootstrap_gcp.go) and Azure confidential containers (bootstrap_azure.go).
// They differ in exactly one thing — how they obtain a Google OAuth access
// token:
//
//	GCP    metadata server, workload identity federation
//	Azure  SKR-released wrapping key -> decrypt SA key -> JWT-bearer exchange
//
// Everything downstream of that token is cloud-neutral: which secrets exist,
// what they are named, the order they are fetched in, and where their values
// land in BootstrapData. All of that lives here, in ONE implementation, so the
// two adapters cannot drift. A second copy is how "add a provider" turns into
// "the provider works on GCP and 404s on Azure three weeks later".
//
// Why Azure reads Google Secret Manager at all instead of Azure Key Vault:
// the enclave needs Google credentials at runtime regardless (Spanner credit
// ledger, Bigtable generations, the shared ACME cache), and all ~40 provider
// secrets already live in one Google project. Mirroring them into Key Vault
// would create a second copy that silently goes stale — the same failure the
// AWS secret-replication work had to unwind. Azure therefore unlocks a Google
// credential under attestation and reuses this path verbatim.
//
// (Deliberately detached from the package clause below — the package doc lives
// on whichever per-cloud adapter file the build tag selected.)

package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// secretManagerHost is the production endpoint. It is a const so that the
// value cannot be edited away; the var below only exists to be redirected.
const secretManagerHost = "https://secretmanager.googleapis.com"

// secretManagerBaseURL is a var rather than a const purely so tests can point
// the fetch loop at an httptest server (the same "swappable seam" convention
// attestation_azure.go uses for requestToken). Production never rewrites it: it
// is unexported and reachable from no env var, flag, or request path, and
// TestSecretManagerBaseURLDefaultsToProduction fails if it stops equalling
// secretManagerHost.
var secretManagerBaseURL = secretManagerHost

// maxSecretResponseBytes bounds both the Secret Manager error body and the
// success body. Secret Manager caps a payload at 64 KiB, which base64-expands
// to ~88 KiB inside a small JSON wrapper.
const maxSecretResponseBytes = 1 << 20

// secretBinding describes one Secret Manager entry: which env var(s) carry its
// NAME, what it is called in an error message, and where its value lands in
// BootstrapData.
type secretBinding struct {
	// envs holds the env var(s) naming the secret. First non-blank wins, which
	// is how the advisor prompts keep accepting their pre-rename SOCRATES_*
	// spellings.
	envs []string
	// label is the error prefix for this entry, e.g. "openrouter key" ->
	// "bootstrap/azure: openrouter key: secret fetch http 403: ...".
	label string
	// provider marks entries that count toward the "at least one provider
	// secret must be configured" guard. Prompt overrides and the control-plane
	// token do not — a deploy with only those set has no LLM backend and must
	// fail loudly rather than boot into a gateway that 500s every request.
	provider bool
	assign   func(*types.BootstrapData, string)
}

// secretBindings is ORDER-SENSITIVE. The fetch loop walks it top to bottom, so
// this order decides which misconfigured secret is reported first when several
// are broken. It reproduces the hand-written sequence bootstrap_gcp.go used
// before this file existed; reordering it changes which error an operator sees
// on a bad deploy.
var secretBindings = []secretBinding{
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
	{[]string{"QUILL_SYNTH_PANEL_PROMPT_SECRET"}, "synth panel prompt", false, func(b *types.BootstrapData, v string) { b.SynthPanelPrompt = v }},
	{[]string{"QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET"}, "synth synthesis prompt", false, func(b *types.BootstrapData, v string) { b.SynthSynthesisPrompt = v }},
	{[]string{"QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET"}, "synth-code panel prompt", false, func(b *types.BootstrapData, v string) { b.SynthCodePanelPrompt = v }},
	{[]string{"QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET"}, "synth-code synthesis prompt", false, func(b *types.BootstrapData, v string) { b.SynthCodeSynthesisPrompt = v }},
	{[]string{"QUILL_ADVISOR_WORKER_PROMPT_SECRET", "QUILL_SOCRATES_WORKER_PROMPT_SECRET"}, "advisor worker prompt", false, func(b *types.BootstrapData, v string) { b.AdvisorWorkerPrompt = v }},
	{[]string{"QUILL_ADVISOR_PROMPT_SECRET", "QUILL_SOCRATES_ADVISOR_PROMPT_SECRET"}, "advisor prompt", false, func(b *types.BootstrapData, v string) { b.AdvisorPrompt = v }},
	{[]string{"QUILL_TRUSTEDROUTER_INTERNAL_SECRET"}, "trustedrouter internal token", false, func(b *types.BootstrapData, v string) { b.TrustedRouterInternalToken = v }},
}

// secretConfig is the resolved, validated environment: everything the fetch
// loop needs, read once so a misconfigured deploy fails before any network I/O.
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
// token-acquisition error happens to come out of an unrelated subsystem.
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

	// Bootstrap does not know which build target it is serving, so it fetches
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

// fetchBootstrapSecrets pulls every configured secret with the supplied Google
// access token and assembles BootstrapData. The token is the ONLY cloud-
// specific input; how it was obtained is the caller's business.
//
// Every error names which secret failed, because the historically worst
// bootstrap bug in this system was a failure that left the enclave wedged with
// no indication of which step died.
func fetchBootstrapSecrets(ctx context.Context, httpc *http.Client, token string, cfg secretConfig, tag string) (*types.BootstrapData, error) {
	devicesJSON, err := fetchSecret(ctx, httpc, token, cfg.project, cfg.devices)
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
		value, err := fetchSecret(ctx, httpc, token, cfg.project, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", tag, binding.label, err)
		}
		binding.assign(data, strings.TrimSpace(string(value)))
	}
	return data, nil
}

// firstSetEnv reads env vars in order and returns the first non-empty VALUE.
// The distinction between the name and the value matters more than it looks:
// passing the names straight in makes every binding appear configured (a name
// is a non-empty constant), which silently turns the "at least one provider
// secret" guard into a no-op and then asks Secret Manager for a secret
// literally called "QUILL_OPENROUTER_SECRET".
//
// A value that is non-empty but blank is an error, not a skip. Skipping it is
// what an earlier draft did, and it is the one behaviour this whole file exists
// to prevent: QUILL_ANTHROPIC_SECRET="   " booted a gateway with an empty
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

type secretResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"` // base64-encoded
	} `json:"payload"`
}

func fetchSecret(ctx context.Context, c *http.Client, token, project, secretName string) ([]byte, error) {
	url := fmt.Sprintf(
		"%s/v1/projects/%s/secrets/%s/versions/latest:access",
		secretManagerBaseURL, project, secretName,
	)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secret fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// Safe to echo: a non-200 body is Google's error envelope, never the
		// secret. The 200 path below deliberately echoes nothing. Bounded so a
		// misbehaving upstream cannot turn one error into an unbounded
		// allocation on the boot path.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("secret fetch: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("secret fetch http %d: %s", resp.StatusCode, body)
	}
	var sr secretResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSecretResponseBytes)).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(sr.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode secret payload: %w", err)
	}
	return plaintext, nil
}
