package bedrock

import qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"

type anthropicBedrockWireRequest struct {
	AnthropicVersion string                      `json:"anthropic_version"`
	System           any                         `json:"system,omitempty"`
	Messages         []qtypes.AnthropicMessage   `json:"messages"`
	MaxTokens        int                         `json:"max_tokens"`
	Temperature      *float64                    `json:"temperature,omitempty"`
	TopP             *float64                    `json:"top_p,omitempty"`
	Tools            []qtypes.AnthropicTool      `json:"tools,omitempty"`
	ToolChoice       *qtypes.AnthropicToolChoice `json:"tool_choice,omitempty"`
	StopSequences    []string                    `json:"stop_sequences,omitempty"`
	Thinking         any                         `json:"thinking,omitempty"`
	Metadata         map[string]any              `json:"metadata,omitempty"`
	TopK             *int                        `json:"top_k,omitempty"`
	OutputConfig     any                         `json:"output_config,omitempty"`
}

// BuildRequestShape exposes the native projection for authorization-versus-wire checks.
func BuildRequestShape(body *qtypes.AnthropicMessagesRequest) any {
	return buildAnthropicBedrockWireRequest(body)
}

func buildAnthropicBedrockWireRequest(body *qtypes.AnthropicMessagesRequest) anthropicBedrockWireRequest {
	system := any(body.System)
	if body.SystemRaw != nil {
		system = body.SystemRaw
	}
	return anthropicBedrockWireRequest{
		AnthropicVersion: body.AnthropicVersion,
		System:           system, Messages: body.Messages,
		MaxTokens:   body.AnthropicDispatchMaxTokens(),
		Temperature: body.Temperature, TopP: body.TopP,
		Tools: body.Tools, ToolChoice: body.ToolChoice,
		StopSequences: body.StopSequences, Thinking: body.Thinking,
		Metadata: body.Metadata, TopK: body.TopK, OutputConfig: body.OutputConfig,
	}
}
