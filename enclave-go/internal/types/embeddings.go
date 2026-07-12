package types

import "encoding/json"

// EmbeddingRequest is the inbound shape we accept on POST /v1/embeddings.
// Mirrors OpenAI's embeddings request. `Input` is a string OR a []string.
// `InputType` is Cohere-only (search_document / search_query / …); OpenAI
// and Together ignore it.
type EmbeddingRequest struct {
	Model          string         `json:"model"`
	Input          any            `json:"input"`
	EncodingFormat string         `json:"encoding_format,omitempty"`
	Dimensions     *int           `json:"dimensions,omitempty"`
	InputType      string         `json:"input_type,omitempty"`
	User           string         `json:"user,omitempty"`
	SessionID      string         `json:"session_id,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Trace          map[string]any `json:"trace,omitempty"`
	Tags           *RequestTags   `json:"tags,omitempty"`
	IdempotencyKey string         `json:"-"`
	App            string         `json:"-"`
	HTTPReferer    string         `json:"-"`
	AppCategories  []string       `json:"-"`
}

// EmbeddingData is one embedding in the response. The vector is carried as
// raw JSON so the upstream's encoding (float array or base64 string) passes
// through verbatim without a lossy float round-trip.
type EmbeddingData struct {
	Object    string          `json:"object"`
	Embedding json.RawMessage `json:"embedding"`
	Index     int             `json:"index"`
}

// EmbeddingUsage — embeddings bill INPUT tokens only, so TotalTokens always
// equals PromptTokens (no completion component).
type EmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// EmbeddingResponse is the OpenAI-shaped envelope we return to the caller.
type EmbeddingResponse struct {
	Object string          `json:"object"`
	Data   []EmbeddingData `json:"data"`
	Model  string          `json:"model"`
	Usage  EmbeddingUsage  `json:"usage"`
}

// Inputs normalizes the polymorphic `input` field to a slice of strings.
// Accepts a bare string or a JSON array of strings; anything else yields an
// empty slice (the caller rejects empty input with a 400).
func (r *EmbeddingRequest) Inputs() []string {
	switch value := r.Input.(type) {
	case string:
		if value == "" {
			return nil
		}
		return []string{value}
	case []string:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// EstimateEmbeddingInputTokens is the metadata-only token estimate sent to
// the control plane for authorization + used as a settle fallback when the
// upstream omits usage. ~4 chars/token, floor 1 per input and 1 overall.
func EstimateEmbeddingInputTokens(inputs []string) int {
	total := 0
	for _, text := range inputs {
		tokens := len(text) / 4
		if tokens < 1 {
			tokens = 1
		}
		total += tokens
	}
	if total < 1 {
		return 1
	}
	return total
}
