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
}

// OpenAIChatMessage is one message in an inbound /v1/chat/completions request.
type OpenAIChatMessage struct {
	Role    string `json:"role"` // "system" | "user" | "assistant"
	Content string `json:"content"`
}

// OpenAIChatRequest is the inbound shape we accept.
type OpenAIChatRequest struct {
	Model       string              `json:"model"`
	Models      []string            `json:"models,omitempty"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Stream      bool                `json:"stream,omitempty"`
	Temperature *float64            `json:"temperature,omitempty"`
	TopP        *float64            `json:"top_p,omitempty"`
	MaxTokens   *int                `json:"max_tokens,omitempty"`
	Provider    *ProviderRouting    `json:"provider,omitempty"`
	Metadata    map[string]any      `json:"metadata,omitempty"`
	Trace       map[string]any      `json:"trace,omitempty"`
	User        string              `json:"user,omitempty"`
	SessionID   string              `json:"session_id,omitempty"`
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

// OpenAIResponsesRequest is the text-only /v1/responses shape accepted by the
// attested gateway. Advanced fields are rejected before this struct is used.
type OpenAIResponsesRequest struct {
	Model           string           `json:"model"`
	Models          []string         `json:"models,omitempty"`
	Input           any              `json:"input"`
	Instructions    string           `json:"instructions,omitempty"`
	Stream          bool             `json:"stream,omitempty"`
	Temperature     *float64         `json:"temperature,omitempty"`
	TopP            *float64         `json:"top_p,omitempty"`
	MaxOutputTokens *int             `json:"max_output_tokens,omitempty"`
	MaxTokens       *int             `json:"max_tokens,omitempty"`
	Provider        *ProviderRouting `json:"provider,omitempty"`
	Metadata        map[string]any   `json:"metadata,omitempty"`
	Trace           map[string]any   `json:"trace,omitempty"`
	User            string           `json:"user,omitempty"`
	SessionID       string           `json:"session_id,omitempty"`
	Store           *bool            `json:"store,omitempty"`
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
	Content string `json:"content"`
}

// AnthropicMessagesRequest is the body we POST to Bedrock's
// InvokeModelWithResponseStream endpoint. Bedrock's body is identical to
// native Anthropic; we just include the bedrock-specific anthropic_version.
type AnthropicMessagesRequest struct {
	AnthropicVersion string             `json:"anthropic_version"`
	System           string             `json:"system,omitempty"`
	Messages         []AnthropicMessage `json:"messages"`
	MaxTokens        int                `json:"max_tokens"`
	Temperature      *float64           `json:"temperature,omitempty"`
	TopP             *float64           `json:"top_p,omitempty"`
}
