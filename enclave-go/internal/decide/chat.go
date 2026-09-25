package decide

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// NativeModel pins how one chat model is driven as a decision model. The
// provider is pinned because strict json_schema support is a property of the
// (model, provider) pair, not of the model: the same weights behind a
// different host may ignore the schema.
type NativeModel struct {
	// Providers is an ORDERED pin: the first is preferred and the rest are the
	// only hosts allowed to stand in for it. Empty pins nothing.
	Providers []string
	// ReasoningEffort is the lowest setting a REASONING model accepts. Empty
	// means the model does not reason, and no reasoning control is sent at
	// all: a plain instruct model behind a strict host rejects the parameter.
	ReasoningEffort string
	Temperature     *float64 // nil where the provider rejects the parameter
	// Format is what the host can enforce at decode time, on top of the
	// prompt's own output skeleton: FormatSchema, FormatObject, or FormatPrompt.
	Format string
	// ExtraTokens is headroom for thinking the model does whether asked or not.
	ExtraTokens int
}

const (
	FormatSchema = "json_schema" // strict schema, enforced by the host
	FormatObject = "json_object" // "valid JSON", shape left to the prompt
	FormatPrompt = "prompt"      // nothing enforced; the prompt carries it all
)

var zeroTemperature = 0.0

// HostedModels are true decision models reached through a provider's own
// decision endpoint. Everything else named on /v1/decide is a chat model and
// takes the native path.
var HostedModels = map[string]bool{
	"typesafe-ai/jev": true,
}

// TrustedRouter's named decision models: one short, stable name per tuned
// configuration, so a caller picks "the fast one" or "the cheap one" without
// tracking which open model and host currently wins. They rhyme with Jev, the
// hosted model they sit beside; the first letter is the family.
//
// TrevModelID is the flagship: the fastest tuned configuration measured.
const (
	TrevModelID = "trustedrouter/trev-1.0" // gpt-oss-120b, on the chain below
	MevModelID  = "trustedrouter/mev-1.0"  // Mercury 2, the fastest native and the cheapest fast one
	ZevModelID  = "trustedrouter/zev-1.0"  // GLM 5.2 Fast
	LevModelID  = "trustedrouter/lev-1.0"  // Llama 3.3 70B, the steadiest tail
	GevModelID  = "trustedrouter/gev-1.0"  // Gemini 3.1 Flash Lite
	DevModelID  = "trustedrouter/dev-1.0"  // DeepSeek V4.1 Flash
	OevModelID  = "trustedrouter/oev-1.0"  // gpt-oss-20b
	// Gemma 4 E4B, the cheapest. It was mev-1.0 for a few hours on 2026-09-20,
	// before Mercury took that name.
	GemmevModelID = "trustedrouter/gemmev-1.0"
)

// TrevProviders is trev-1.0's host chain, fastest first, with the measured
// median for one decision. Slower hosts of the same model were left out
// (DeepInfra 3.7 s, Novita 3.1 s, nscale 7.7 s) and so was Parasail, which
// rate-limited the eval itself.
var TrevProviders = []string{
	"cerebras",  // 353 ms
	"sambanova", // 522 ms
	"fireworks", // 941 ms
	"together",  // 1125 ms
}

// DevProviders is dev-1.0's (and DeepSeek V4.1 Flash's) host chain, fastest
// first. Medians were measured over three passes of the labeled live eval
// through TrustedRouter's decide route with each host pinned: all three hosts
// scored 87/87 checks with 24/24 valid outputs. Like trev, the gateway moves to
// the next host on any upstream error before the first output byte, 429 included.
// Land quill-router's dev-decision-chain first: authorize intersects request
// "only" with its chain, so the old enclave's ["deepinfra"] remains valid.
var DevProviders = []string{
	"wafer",     // 1371 ms p50
	"deepinfra", // 1858 ms p50
	"wandb",     // 1987 ms p50
}

// Each TUNED entry was chosen from a paid live eval
// (internal/llm/decide_live_test.go) scoring judgment on labeled tickets,
// structural validity, latency and cost -- not from a capability table.
//
//   - trev-1.0 is gpt-oss-120b on Cerebras: 353 ms median / 477 ms worst in the
//     eval, against 356 / 553 for the hosted Jev. Cerebras is heavily rate
//     limited, so the pin is a CHAIN (see TrevProviders); the gateway moves to
//     the next host on any error before the first output byte, 429 included,
//     without backing off on the failed one. Every host in the chain scored
//     29/29 with 8/8 valid outputs -- judgment comes from the model, the host
//     only sets the speed. The control plane resolves the name to the concrete
//     model and enforces the same chain; this entry is how it is DRIVEN.
//     Prompt format on purpose: a host-enforced schema is billed as input
//     (766 vs 476 tokens) and was slower.
//   - Gemma 4 E4B is prompt-only because DeepInfra answers HTTP 405 to
//     json_schema for it -- and it scores 29/29 without.
//
// Every pinned host must offer a CREDITS route in the control plane's catalog.
// openai/gpt-5.4-nano passed the eval (27/29, ~1 s) and was still left out: its
// only OpenAI route is bring-your-own-key, so most customers could not call it.
// It remains reachable through GenericNativeModel for a caller with a key.
//
// The three sub-half-second entries after trev, each measured four times
// (8 tickets a run, every output valid):
//
//   - Mercury 2 (mev-1.0) on Inception with reasoning OFF: 275-310 ms median,
//     the cheapest of the fast ones, 28/29 on every run (it over-rates the
//     urgency of one ticket; at "low" effort it is 29/29 in ~600 ms, which a
//     caller can ask for). It was first REJECTED for "3 of 8 outputs cut
//     short". That was this table's mistake, not the model's: Mercury reasons
//     by default, and with no effort set the reasoning ate the token budget.
//   - GLM 5.2 Fast (zev-1.0) on Fireworks 340-468 ms, Baseten 616 ms: 29/29,
//     and about four times trev's price per decision.
//   - Llama 3.3 70B (lev-1.0) on SambaNova 371-450 ms with the tightest tail
//     (worst case 565 ms), then Parasail 927 ms, Together 1576 ms: 29/29. It
//     does not reason, so there is no effort to set. Novita answered 429.
//
// Rejected on the same evidence: openai/gpt-5-nano (hedges at "minimal" effort,
// truncates its JSON at "low" because reasoning eats the token budget),
// google/gemini-2.5-flash-lite (closed to new AI Studio users), and engy as the
// DeepSeek host (5x cheaper, but a 75-second worst case; a caller who wants it
// can ask for it with `provider`). GLM 5.3 Flash cannot turn thinking OFF (Z.ai
// and Fireworks both refuse the request), so a decision takes 2-19 s on every
// host measured: Baseten 2.1 s, Together 4.3 s, Nebius 4.8 s, DeepInfra 18.8 s.
// Qwen 3.8 27B on Cerebras was the fastest native measured (216-301 ms, 29/29)
// and was left out by choice: its other hosts take 4-9 s, so it would have no
// usable fallback behind a heavily rate-limited host.
//
// A NAME and the chat model behind it are driven identically: the name is a
// convenience, and the control plane resolves it to the concrete model and
// enforces its host. One definition serves both, so they cannot drift apart.
// (NativeChatRequest copies the host list for every request it builds.)
//
// The ids here must match NATIVE_DECISION_MODEL_PROVIDERS in the control
// plane's catalog_data.py, which is what /v1/models advertises.
var (
	geminiFlashLite = NativeModel{Providers: []string{"google-ai-studio"}, ReasoningEffort: "none", Temperature: &zeroTemperature, Format: FormatSchema}
	deepSeekFlash   = NativeModel{Providers: DevProviders, Temperature: &zeroTemperature, Format: FormatPrompt}
	gptOSS20B       = NativeModel{Providers: []string{"deepinfra"}, ReasoningEffort: "low", Temperature: &zeroTemperature, Format: FormatSchema}
	gemma4E4B       = NativeModel{Providers: []string{"deepinfra"}, Temperature: &zeroTemperature, Format: FormatPrompt}
	mercury2        = NativeModel{Providers: []string{"inception"}, ReasoningEffort: "none", Temperature: &zeroTemperature, Format: FormatPrompt}
	glm52Fast       = NativeModel{Providers: []string{"fireworks", "baseten"}, ReasoningEffort: "none", Temperature: &zeroTemperature, Format: FormatPrompt}
	llama33         = NativeModel{Providers: []string{"sambanova", "parasail", "together"}, Temperature: &zeroTemperature, Format: FormatPrompt}
)

var NativeModels = map[string]NativeModel{
	TrevModelID: {Providers: TrevProviders, ReasoningEffort: "low", Temperature: &zeroTemperature, Format: FormatPrompt},
	GevModelID:  geminiFlashLite, "google/gemini-3.1-flash-lite": geminiFlashLite,
	DevModelID: deepSeekFlash, "deepseek/deepseek-v4.1-flash": deepSeekFlash,
	OevModelID: gptOSS20B, "openai/gpt-oss-20b": gptOSS20B,
	GemmevModelID: gemma4E4B, "google/gemma-4-e4b-it": gemma4E4B,
	MevModelID: mercury2, "inception/mercury-2": mercury2,
	ZevModelID: glm52Fast, "z-ai/glm-5.2-fast": glm52Fast,
	LevModelID: llama33, "meta-llama/llama-3.3-70b-instruct": llama33,
}

// GenericNativeModel drives ANY other chat model: nothing is assumed about the
// host, so the prompt carries the whole format, no provider is pinned, no
// reasoning control is sent unless the caller asks for one, and there is
// headroom in case the model thinks by default.
var GenericNativeModel = NativeModel{Format: FormatPrompt, ExtraTokens: genericTokenBudget}

// NativeOptions are the caller's per-request overrides.
type NativeOptions struct {
	// Reasoning / ReasoningEffort turn thinking ON for a harder decision. The
	// output contract does not change: the visible answer is still the
	// decision object and still passes Verify.
	Reasoning       any
	ReasoningEffort string
	MaxTokens       *int
	Provider        *types.ProviderRouting // replaces the tuned provider pin
}

// reasoningEfforts are the settings every reasoning host understands. "none"
// is accepted from a caller and means what leaving it out means.
var reasoningEfforts = map[string]bool{"minimal": true, "low": true, "medium": true, "high": true}

// reasoningEffort reduces whatever the caller sent to ONE validated effort
// word, or "" for no reasoning. Two reasons it is not forwarded as given. The
// `reasoning` OBJECT is not portable -- Cerebras answers 400 to it, so
// `"reasoning": {"effort": "high"}` on trev-1.0 failed at the host -- while the
// effort string is understood everywhere. And a value nobody validates is
// rejected by the HOST, which this route must report as its own 502: the
// caller's typo has to be caught here, where it can be a 400 that names it.
//
// The contract, in full: `reasoning_effort` is an effort word. `reasoning` is
// true, false, an effort word, or an object with `effort` and/or `enabled`.
// Every effort word present is validated, whether or not it ends up used. An
// explicit `enabled: false` (or `reasoning: false`) turns reasoning off
// whatever else is said; otherwise `reasoning_effort` wins over
// `reasoning.effort`, and `enabled: true` alone means "medium". A thinking
// TOKEN budget is not part of this route: `max_tokens` raises the whole budget.
func (o NativeOptions) reasoningEffort() (string, error) {
	return RequestedReasoning(o.Reasoning, o.ReasoningEffort)
}

// RequestedReasoning is reasoningEffort for a caller that has not built
// NativeOptions: the route uses it to tell "asks for reasoning" from the many
// ways of writing "does not" (absent, null, false, "", "none").
func RequestedReasoning(reasoning any, reasoningEffort string) (string, error) {
	word := func(param, text string) (string, error) {
		effort := strings.ToLower(strings.TrimSpace(text))
		if effort == "" || effort == "none" || reasoningEfforts[effort] {
			return effort, nil
		}
		return "", bad(param, `reasoning effort must be "minimal", "low", "medium", "high" or "none"`)
	}
	fromField, err := word("reasoning_effort", reasoningEffort)
	if err != nil {
		return "", err
	}
	fromObject, enabled, disabled := "", false, false
	switch requested := reasoning.(type) {
	case nil:
	case bool:
		enabled, disabled = requested, !requested
	case string:
		if fromObject, err = word("reasoning", requested); err != nil {
			return "", err
		}
	case map[string]any:
		// Fixed order, never the map's: a first version ranged over it, so
		// {"enabled":true,"effort":"high"} was "medium" or "high" by chance and
		// a bad effort could go unvalidated.
		unknown := make([]string, 0, len(requested))
		for key := range requested {
			if key != "effort" && key != "enabled" {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return "", bad("reasoning."+unknown[0], `reasoning accepts "effort" and "enabled"`)
		}
		if value, present := requested["effort"]; present && value != nil {
			text, ok := value.(string)
			if !ok {
				return "", bad("reasoning.effort", "reasoning.effort must be a string")
			}
			if fromObject, err = word("reasoning.effort", text); err != nil {
				return "", err
			}
		}
		if value, present := requested["enabled"]; present && value != nil {
			flag, ok := value.(bool)
			if !ok {
				return "", bad("reasoning.enabled", "reasoning.enabled must be true or false")
			}
			enabled, disabled = flag, !flag
		}
	default:
		return "", bad("reasoning", `reasoning must be true, false, an effort word, or {"effort": ..., "enabled": ...}`)
	}
	effort := fromField
	if effort == "" {
		effort = fromObject
	}
	switch {
	case disabled || effort == "none":
		return "", nil
	case effort == "" && enabled:
		return "medium", nil
	}
	return effort, nil
}

const (
	// reasoningTokenBudget is added when the caller turns reasoning on.
	// Without it the thinking eats the budget and the JSON is cut short --
	// observed live with gpt-5-nano.
	reasoningTokenBudget = 8192
	// genericTokenBudget tolerates an untuned model that thinks by default.
	genericTokenBudget = 2048
	maxNativeTokens    = 32768
)

// NativeChatRequest builds the chat completion that stands in for a decision
// model: strict format, and unless the caller asks otherwise, reasoning off.
func NativeChatRequest(model string, state json.RawMessage, specs []Spec, native NativeModel, options NativeOptions) (*types.OpenAIChatRequest, error) {
	schema, err := NativeSchema(specs)
	if err != nil {
		return nil, err
	}
	prompt, err := NativePrompt(state, specs)
	if err != nil {
		return nil, err
	}
	properties := 0
	for _, spec := range specs {
		properties += 1 + len(spec.Options)
	}
	effort, err := options.reasoningEffort()
	if err != nil {
		return nil, err
	}
	maxTokens := 256 + 24*properties + native.ExtraTokens
	if effort != "" {
		maxTokens += reasoningTokenBudget
	}
	// The computed budget obeys the same ceiling as a caller's own max_tokens:
	// a schema near the property limit plus the reasoning allowance would
	// otherwise ask a host for more than this route ever promises to.
	maxTokens = min(maxTokens, maxNativeTokens)
	if options.MaxTokens != nil {
		if *options.MaxTokens < 16 || *options.MaxTokens > maxNativeTokens {
			return nil, bad("max_tokens", "max_tokens must be between 16 and %d", maxNativeTokens)
		}
		maxTokens = *options.MaxTokens
	}
	req := &types.OpenAIChatRequest{
		Model: model,
		Messages: []types.OpenAIChatMessage{
			{Role: "system", Content: NativeSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: native.Temperature,
		MaxTokens:   &maxTokens,
	}
	switch {
	case options.Provider != nil:
		req.Provider = options.Provider
	case len(native.Providers) > 0:
		// Fallback is allowed only AMONG the pinned hosts, in their order.
		// Two separate copies: the tuned table is shared by every request, and
		// Only and Order must not alias each other either.
		fallbacks := len(native.Providers) > 1
		req.Provider = &types.ProviderRouting{
			Only:           types.StringList(append([]string(nil), native.Providers...)),
			Order:          types.StringList(append([]string(nil), native.Providers...)),
			AllowFallbacks: &fallbacks,
		}
	}
	switch {
	case effort != "":
		// The caller turned reasoning on: the one validated word, never the
		// object it may have arrived in.
		req.ReasoningEffort = effort
	case native.ReasoningEffort != "":
		// The effort STRING only. The `reasoning` object is not portable:
		// Cerebras answers HTTP 400 "property 'reasoning' is unsupported", and
		// GLM on wafer thought MORE when sent {"enabled": false}.
		req.ReasoningEffort = native.ReasoningEffort
	}
	switch native.Format {
	case FormatSchema:
		req.ResponseFormat = map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"name": "decision", "strict": true, "schema": schema},
		}
	case FormatObject:
		req.ResponseFormat = map[string]any{"type": "json_object"}
	}
	return req, nil
}
