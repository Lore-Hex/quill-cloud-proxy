// Package types holds the on-the-wire JSON shapes used by the enclave.
// Kept minimal — every type expands the binary's auditable surface.
package types

// DeviceConfig is one entry in the sealed device-key blob.
type DeviceConfig struct {
	KeyHash  string `json:"key_hash"`  // hex sha256 of the bearer
	Owner    string `json:"owner"`     // human-readable identifier
	DeviceID string `json:"device_id"` // opaque ID, used for usage counters
}

// BootstrapData is what the parent hands to the enclave at startup over vsock.
//
// V1 trust caveat: the parent fetches this from S3 + KMS-decrypts on behalf of
// the enclave, then sends plaintext over vsock. V1.1 will switch to KMS-attested
// release so the parent never sees the plaintext bedrock_credentials.
type BootstrapData struct {
	Devices           []DeviceConfig `json:"devices"`
	BedrockAccessKey  string         `json:"bedrock_access_key"`
	BedrockSecretKey  string         `json:"bedrock_secret_key"`
	BedrockSessionTok string         `json:"bedrock_session_token,omitempty"` // present if creds are short-lived
	Region            string         `json:"region"`
	BedrockVsockProxy string         `json:"bedrock_vsock_proxy"` // e.g. "3:8003"

	// OpenRouter (only populated for the openrouter build target). The
	// API key is pulled from KMS-sealed config alongside the device-key
	// blob; same trust posture as the Bedrock creds (parent decrypts and
	// hands plaintext over vsock).
	OpenRouterAPIKey     string `json:"openrouter_api_key,omitempty"`
	OpenRouterVsockProxy string `json:"openrouter_vsock_proxy,omitempty"` // e.g. "3:8004"

	// TrustedRouter control-plane metadata API. The internal token is fetched
	// from Secret Manager inside the attested GCP workload, not injected as
	// plaintext VM metadata.
	TrustedRouterBaseURL       string `json:"trustedrouter_base_url,omitempty"`
	TrustedRouterInternalToken string `json:"trustedrouter_internal_token,omitempty"`

	// Anthropic direct (only populated for the llm_anthropic build target).
	// Same trust posture as the OpenRouter key — pulled from Secret Manager
	// inside the attested workload.
	AnthropicAPIKey string `json:"anthropic_api_key,omitempty"`

	// Additional OpenAI-compatible providers wired into the llm_multi build.
	// Each is independently optional — only the providers compiled in for
	// the running image read these. Same Secret-Manager-fetched-in-workload
	// trust posture as the rest of these credentials.
	OpenAIAPIKey    string `json:"openai_api_key,omitempty"`
	GeminiAPIKey    string `json:"gemini_api_key,omitempty"`
	CerebrasAPIKey  string `json:"cerebras_api_key,omitempty"`
	DeepSeekAPIKey  string `json:"deepseek_api_key,omitempty"`
	MistralAPIKey   string `json:"mistral_api_key,omitempty"`
	KimiAPIKey      string `json:"kimi_api_key,omitempty"`
	ZAIAPIKey       string `json:"zai_api_key,omitempty"`
	TogetherAPIKey  string `json:"together_api_key,omitempty"`
	FireworksAPIKey string `json:"fireworks_api_key,omitempty"`

	// Cohere — embeddings only for now (native /v2/embed). Optional like
	// every other provider key; only the llm_multi build reads it.
	CohereAPIKey string `json:"cohere_api_key,omitempty"`

	// Voyage AI — embeddings only (OpenAI-shaped /v1/embeddings). Optional;
	// only the llm_multi build reads it.
	VoyageAPIKey string `json:"voyage_api_key,omitempty"`

	// 2026-05 — six new backend providers, all OpenAI-compatible.
	// Phala / Tinfoil are TEE-attested; Phala/Tinfoil/Venice are
	// privacy-aligned and reinforce TR's no-logs trust story.
	GrokAPIKey        string `json:"grok_api_key,omitempty"`
	NovitaAPIKey      string `json:"novita_api_key,omitempty"`
	PhalaAPIKey       string `json:"phala_api_key,omitempty"`
	SiliconFlowAPIKey string `json:"siliconflow_api_key,omitempty"`
	TinfoilAPIKey     string `json:"tinfoil_api_key,omitempty"`
	VeniceAPIKey      string `json:"venice_api_key,omitempty"`

	// 2026-05-11 batch — all three serve google/gemma-4 family
	// alongside an open-weight catalog. OpenAI-compatible base URLs:
	//   parasail:  api.parasail.io/v1
	//   lightning: lightning.ai/api/v1
	//   gmi:       api.gmi-serving.com/v1
	ParasailAPIKey  string `json:"parasail_api_key,omitempty"`
	LightningAPIKey string `json:"lightning_api_key,omitempty"`
	GMIAPIKey       string `json:"gmi_api_key,omitempty"`
	DeepInfraAPIKey string `json:"deepinfra_api_key,omitempty"`
	NebiusAPIKey    string `json:"nebius_api_key,omitempty"`
	MiniMaxAPIKey   string `json:"minimax_api_key,omitempty"`

	// Xiaomi MiMo — OpenAI-compatible chat completions at api.xiaomimimo.com/v1.
	XiaomiAPIKey string `json:"xiaomi_api_key,omitempty"`

	// Cross-cloud GCP service-account key (JSON, plaintext).
	//
	// Populated only on the AWS-side enclave path: the parent fetches the
	// AWS-KMS-wrapped ciphertext from `quill/trustedrouter-aws-cross-cloud-sa-key`
	// in AWS Secrets Manager, decrypts via `alias/quill-enclave-cmk`, and
	// ships the plaintext JSON over vsock to the enclave. The enclave
	// writes this to a tmpfs path and points GOOGLE_APPLICATION_CREDENTIALS
	// at it so the GCP client libraries (Spanner, Bigtable, KMS, Secret
	// Manager) authenticate cross-cloud without us mirroring those
	// resources to AWS.
	//
	// V1 trust caveat (parallel to BedrockAccessKey): the parent sees
	// plaintext for ~ms at boot. V1.1 will switch to attestation-gated
	// KMS Decrypt where the parent only forwards still-encrypted bytes
	// and the enclave does the unwrap inside the measured boundary.
	//
	// On GCP-side enclaves this stays empty — Confidential Space uses
	// metadata-server tokens, not an SA key.
	GCPServiceAccountKeyJSON string `json:"gcp_service_account_key_json,omitempty"`

	// Cloudflare DNS API token for the DNS-01 ACME fallback path
	// (enclavetls/dns01.go). Scoped to `Zone:DNS:Edit` on the
	// quillrouter.com zone so the renewer can add/remove the
	// `_acme-challenge.api.quillrouter.com` TXT record during a
	// renewal that can't go through TLS-ALPN-01 (e.g., sustained
	// GCP outage that takes the shared-cache validation path down).
	//
	// Populated on AWS-side and GCP-side both — DNS-01 works the
	// same way regardless of cloud, and having it on GCP gives
	// belt-and-suspenders renewal in case Cloudflare's edge
	// validation route ever has its own issues. Empty disables
	// the renewer goroutine.
	CloudflareAPIToken string `json:"cloudflare_api_token,omitempty"`

	// Cloudflare Zone ID for the DNS-01 ACME fallback. The CF API's
	// DNS-record endpoints are zone-scoped. The zone for
	// quillrouter.com is currently eba5653b08f4483d9c496c41c3a7393b
	// — the parent's bootstrap server reads it from a separate
	// Secret Manager entry (or env) so it can be rotated without
	// re-baking the enclave image.
	CloudflareZoneID string `json:"cloudflare_zone_id,omitempty"`
}

// OpenAIChatMessage is one message in an inbound /v1/chat/completions request.
type OpenAIChatMessage struct {
	Role       string           `json:"role"` // "system" | "user" | "assistant" | "tool"
	Content    any              `json:"content"`
	ToolCalls  []OpenAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	Name       string           `json:"name,omitempty"`
}

type OpenAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type,omitempty"`
	Function OpenAIToolFunction `json:"function"`
}

type OpenAIToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatStreamOptions mirrors OpenAI's chat-completions stream_options
// object. include_usage=true asks for a final usage-bearing chunk
// (choices: []) right before `data: [DONE]`.
type ChatStreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// OpenAIChatRequest is the inbound shape we accept.
type OpenAIChatRequest struct {
	Model           string               `json:"model"`
	Models          []string             `json:"models,omitempty"`
	Messages        []OpenAIChatMessage  `json:"messages"`
	Stream          bool                 `json:"stream,omitempty"`
	StreamOptions   *ChatStreamOptions   `json:"stream_options,omitempty"`
	Temperature     *float64             `json:"temperature,omitempty"`
	TopP            *float64             `json:"top_p,omitempty"`
	MaxTokens       *int                 `json:"max_tokens,omitempty"`
	Reasoning       any                  `json:"reasoning,omitempty"`
	ReasoningEffort string               `json:"reasoning_effort,omitempty"`
	Provider        *ProviderRouting     `json:"provider,omitempty"`
	Metadata        map[string]any       `json:"metadata,omitempty"`
	Trace           map[string]any       `json:"trace,omitempty"`
	User            string               `json:"user,omitempty"`
	SessionID       string               `json:"session_id,omitempty"`
	ResponseFormat  map[string]any       `json:"response_format,omitempty"`
	Tools           []any                `json:"tools,omitempty"`
	Plugins         []any                `json:"plugins,omitempty"`
	ToolChoice      any                  `json:"tool_choice,omitempty"`
	ParallelTools   *bool                `json:"parallel_tool_calls,omitempty"`
	Response        *ResponseRequestMeta `json:"-"`
	IdempotencyKey  string               `json:"-"`
}

// ResponsesInputItem is the text-only subset of the OpenAI Responses input
// item shape that V1 supports.
type ResponsesInputItem struct {
	Role    string             `json:"role,omitempty"`
	Content []ResponsesContent `json:"content,omitempty"`
	Text    string             `json:"text,omitempty"`
	Type    string             `json:"type,omitempty"`
}

// ResponsesContent is one text content part in a Responses input item.
type ResponsesContent struct {
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
}

// ChatContentPart is the canonical multimodal content-part shape carried
// inside the enclave. OpenAI-compatible providers can receive it directly;
// Anthropic-family providers convert image_url parts to base64 inside the
// attested runtime immediately before the upstream request.
type ChatContentPart struct {
	Type     string        `json:"type"`
	Text     string        `json:"text,omitempty"`
	ImageURL *ChatImageURL `json:"image_url,omitempty"`
}

type ChatImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// OpenAIResponsesRequest is the stateless /v1/responses shape accepted by
// the attested gateway. Text and image inputs are supported; stateful and
// hosted-tool fields are validated before this struct is used so callers get
// stable compatibility errors instead of silent no-ops.
type OpenAIResponsesRequest struct {
	Model                string           `json:"model"`
	Models               []string         `json:"models,omitempty"`
	Input                any              `json:"input"`
	Instructions         string           `json:"instructions,omitempty"`
	Stream               bool             `json:"stream,omitempty"`
	Temperature          *float64         `json:"temperature,omitempty"`
	TopP                 *float64         `json:"top_p,omitempty"`
	MaxOutputTokens      *int             `json:"max_output_tokens,omitempty"`
	MaxTokens            *int             `json:"max_tokens,omitempty"`
	Provider             *ProviderRouting `json:"provider,omitempty"`
	Metadata             map[string]any   `json:"metadata,omitempty"`
	Trace                map[string]any   `json:"trace,omitempty"`
	User                 string           `json:"user,omitempty"`
	SessionID            string           `json:"session_id,omitempty"`
	Store                *bool            `json:"store,omitempty"`
	Background           *bool            `json:"background,omitempty"`
	Conversation         any              `json:"conversation,omitempty"`
	Include              []string         `json:"include,omitempty"`
	MaxToolCalls         *int             `json:"max_tool_calls,omitempty"`
	Modalities           []string         `json:"modalities,omitempty"`
	ParallelToolCalls    *bool            `json:"parallel_tool_calls,omitempty"`
	PreviousResponseID   string           `json:"previous_response_id,omitempty"`
	Prompt               any              `json:"prompt,omitempty"`
	PromptCacheKey       string           `json:"prompt_cache_key,omitempty"`
	PromptCacheRetention string           `json:"prompt_cache_retention,omitempty"`
	Reasoning            any              `json:"reasoning,omitempty"`
	SafetyIdentifier     string           `json:"safety_identifier,omitempty"`
	ServiceTier          string           `json:"service_tier,omitempty"`
	StreamOptions        map[string]any   `json:"stream_options,omitempty"`
	Text                 map[string]any   `json:"text,omitempty"`
	ToolChoice           any              `json:"tool_choice,omitempty"`
	Tools                []any            `json:"tools,omitempty"`
	TopLogprobs          *int             `json:"top_logprobs,omitempty"`
	Truncation           string           `json:"truncation,omitempty"`
}

type ResponseRequestMeta struct {
	Include              []string
	Modalities           []string
	InputModalities      []string
	ParallelToolCalls    *bool
	PromptCacheKey       string
	SafetyIdentifier     string
	ServiceTier          string
	StreamOptions        map[string]any
	Text                 map[string]any
	ToolChoice           any
	Tools                []any
	TopLogprobs          *int
	Truncation           string
	MaxOutputTokens      *int
	MaxToolCalls         *int
	PromptCacheRetention string
	Reasoning            any
	Store                bool
}

type ToolCall struct {
	ID        string
	CallID    string
	Name      string
	Arguments string
}

// ProviderRouting mirrors the OpenRouter provider-routing object closely
// enough to preserve caller intent without committing the gateway to every
// future OpenRouter knob. Unknown fields are intentionally ignored at the
// enclave boundary to keep the auditable surface small.
type ProviderRouting struct {
	Order             []string       `json:"order,omitempty"`
	AllowFallbacks    *bool          `json:"allow_fallbacks,omitempty"`
	RequireParameters *bool          `json:"require_parameters,omitempty"`
	DataCollection    string         `json:"data_collection,omitempty"`
	Only              []string       `json:"only,omitempty"`
	Ignore            []string       `json:"ignore,omitempty"`
	Quantizations     []string       `json:"quantizations,omitempty"`
	Sort              any            `json:"sort,omitempty"`
	MaxPrice          map[string]any `json:"max_price,omitempty"`
}

// AnthropicMessage is one user/assistant turn for Bedrock's Anthropic body.
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// AnthropicMessagesRequest is the body we POST to Bedrock's
// InvokeModelWithResponseStream endpoint. Bedrock's body is identical to
// native Anthropic; we just include the bedrock-specific anthropic_version.
type AnthropicMessagesRequest struct {
	AnthropicVersion string               `json:"anthropic_version"`
	System           string               `json:"system,omitempty"`
	Messages         []AnthropicMessage   `json:"messages"`
	MaxTokens        int                  `json:"max_tokens"`
	Temperature      *float64             `json:"temperature,omitempty"`
	TopP             *float64             `json:"top_p,omitempty"`
	Tools            []AnthropicTool      `json:"tools,omitempty"`
	ToolChoice       *AnthropicToolChoice `json:"tool_choice,omitempty"`
	StopSequences    []string             `json:"stop_sequences,omitempty"`
	Thinking         any                  `json:"thinking,omitempty"`

	// NativeContent marks a request that arrived on /v1/messages with
	// already-Anthropic-shaped content. The anthropic-direct path must
	// NOT run the OpenAI-part transforms over these messages (native
	// blocks like tool_result / image / cache_control would be mangled
	// by chatPartFromAny) — it marshals Messages verbatim instead.
	NativeContent bool `json:"-"`
	// SystemRaw carries the native `system` field exactly as the client
	// sent it (string OR content-block array, possibly with
	// cache_control blocks). When non-nil the anthropic-direct path
	// sends it verbatim; System above holds the flattened string for
	// every other consumer (token estimation, OpenAI-compatible paths).
	SystemRaw any `json:"-"`

	// MaxTokensExplicit records whether the CLIENT set max_tokens, or
	// whether MaxTokens above is adapter.DefaultMaxTokens filled in
	// because the Anthropic/Bedrock wire format requires the field.
	// OpenAI-compatible upstreams treat max_tokens as optional, and
	// silently capping reasoning models at the 4096 default truncated
	// them mid-think (finish_reason=length) when direct calls with no
	// max_tokens ran to the model maximum — so the OpenAI-compatible
	// path OMITS max_tokens entirely unless the client asked for one.
	// json:"-" keeps the Anthropic/Bedrock wire bodies byte-identical.
	MaxTokensExplicit bool `json:"-"`
}

type AnthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

type AnthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}
