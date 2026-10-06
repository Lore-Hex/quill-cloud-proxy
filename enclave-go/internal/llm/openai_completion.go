package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Adapt a bounded text-task JSON completion to the existing stream translator
// so usage and provider response fields have one normalization path.
func translateOpenAICompletionToAnthropic(r io.Reader, w io.Writer, provider string) error {
	const maxCompletionBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r, maxCompletionBytes+1))
	if err != nil {
		return fmt.Errorf("llm/openai-completion: read: %w", err)
	}
	invalid := func() error {
		return &upstreamHTTPError{status: http.StatusBadGateway, body: "Invalid upstream chat completion"}
	}
	if len(body) > maxCompletionBytes {
		return invalid()
	}
	var completion map[string]json.RawMessage
	if json.Unmarshal(body, &completion) != nil || completion == nil {
		return invalid()
	}
	if raw := completion["error"]; len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return invalid()
	}
	var choices []struct {
		Message      map[string]json.RawMessage `json:"message"`
		FinishReason string                     `json:"finish_reason"`
	}
	if json.Unmarshal(completion["choices"], &choices) != nil || len(choices) != 1 || choices[0].Message == nil || choices[0].FinishReason == "" {
		return invalid()
	}
	var content string
	var usage openAIStreamUsage
	if json.Unmarshal(choices[0].Message["content"], &content) != nil || content == "" ||
		json.Unmarshal(completion["usage"], &usage) != nil || usage.PromptTokens <= 0 || usage.CompletionTokens < 0 {
		return invalid()
	}
	// Do not forward arbitrary provider fields or accept upstream routing/billing
	// metadata. Only response extensions explicitly handled by the translator.
	chunk := map[string]any{
		"choices": []map[string]any{{"delta": choices[0].Message, "finish_reason": choices[0].FinishReason}},
	}
	for _, key := range []string{"usage", "service_tier", "citations", "search_results", "decision"} {
		if value, ok := completion[key]; ok {
			chunk[key] = value
		}
	}
	encoded, err := json.Marshal(chunk)
	if err != nil {
		return invalid()
	}
	var stream bytes.Buffer
	fmt.Fprintf(&stream, "data: %s\n\ndata: [DONE]\n\n", encoded)
	return translateOpenAIStreamToAnthropicForProvider(&stream, w, provider)
}
