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
	Devices            []DeviceConfig `json:"devices"`
	BedrockAccessKey   string         `json:"bedrock_access_key"`
	BedrockSecretKey   string         `json:"bedrock_secret_key"`
	BedrockSessionTok  string         `json:"bedrock_session_token,omitempty"` // present if creds are short-lived
	Region             string         `json:"region"`
	BedrockVsockProxy  string         `json:"bedrock_vsock_proxy"` // e.g. "3:8003"
}

// OpenAIChatMessage is one message in an inbound /v1/chat/completions request.
type OpenAIChatMessage struct {
	Role    string `json:"role"`    // "system" | "user" | "assistant"
	Content string `json:"content"`
}

// OpenAIChatRequest is the inbound shape we accept.
type OpenAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Stream      bool                `json:"stream,omitempty"`
	Temperature *float64            `json:"temperature,omitempty"`
	TopP        *float64            `json:"top_p,omitempty"`
	MaxTokens   *int                `json:"max_tokens,omitempty"`
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
