package llm

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type upstreamHTTPError struct {
	status int
	body   string
}

func (e *upstreamHTTPError) Error() string {
	return fmt.Sprintf("llm/upstream: http %d: %s", e.status, e.body)
}

// HTTPStatusFromError returns the upstream HTTP status code carried by err when
// it originated as a non-2xx upstream response, and ok=false otherwise (e.g.
// transport, timeout, or cancellation errors that never reached an HTTP
// status). Used by the gateway's provider-failover logic to decide which
// failures are worth retrying on the next authorized provider.
func HTTPStatusFromError(err error) (status int, ok bool) {
	var httpErr *upstreamHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.status, true
	}
	return 0, false
}

// translateOpenAIStreamToAnthropic reads OpenAI Chat Completions SSE chunks
// and writes native Anthropic SSE events for the existing adapter pipeline.
func translateOpenAIStreamToAnthropic(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	stopReason := "end_turn"
	toolCalls := map[int]*openAIToolCallAccumulator{}
	var toolOrder []int
	var usage *openAIStreamUsage
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := line[len("data: "):]
		if payload == "[DONE]" {
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
					// Several Chinese OpenAI-compatible providers (Z.AI/Zhipu,
					// Moonshot in some configs) emit chain-of-thought tokens
					// in `reasoning_content` and only fill `content` for the
					// final answer. If we ignore reasoning_content, requests
					// that hit the max_tokens limit BEFORE the model finishes
					// thinking come back with empty `content` — the user sees
					// nothing. Forward reasoning_content as text so the
					// stream is never silently empty. (Tradeoff: clients see
					// the chain-of-thought inline; that's strictly more
					// information than the empty-string alternative.)
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			// usage arrives on the final stream_options.include_usage chunk
			// (choices: []) — byok.go requests it from every OpenAI-
			// compatible upstream. Some providers instead attach usage to
			// the last content chunk; both shapes land here.
			Usage *openAIStreamUsage `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.Usage != nil && (chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0) {
			usage = chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]

		if choice.Delta.Content != "" {
			if err := writeAnthropicTextDelta(w, choice.Delta.Content); err != nil {
				return err
			}
		} else if choice.Delta.ReasoningContent != "" {
			if err := writeAnthropicTextDelta(w, choice.Delta.ReasoningContent); err != nil {
				return err
			}
		}
		for _, delta := range choice.Delta.ToolCalls {
			call := toolCalls[delta.Index]
			if call == nil {
				id := delta.ID
				if id == "" {
					id = fmt.Sprintf("call_%d", delta.Index)
				}
				call = &openAIToolCallAccumulator{ID: id, Name: delta.Function.Name}
				toolCalls[delta.Index] = call
				toolOrder = append(toolOrder, delta.Index)
				if err := writeAnthropicToolStart(w, delta.Index, call.ID, call.Name); err != nil {
					return err
				}
			}
			if call.Name == "" && delta.Function.Name != "" {
				call.Name = delta.Function.Name
			}
			if delta.Function.Arguments != "" {
				call.Arguments += delta.Function.Arguments
				if err := writeAnthropicToolDelta(w, delta.Index, delta.Function.Arguments); err != nil {
					return err
				}
			}
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			stopReason = mapOpenAIFinishReason(*choice.FinishReason)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("llm/openai-stream: scan: %w", err)
	}

	for _, index := range toolOrder {
		if err := writeAnthropicToolStop(w, index); err != nil {
			return err
		}
	}
	return writeAnthropicStop(w, stopReason, usage)
}

type openAIToolCallAccumulator struct {
	ID        string
	Name      string
	Arguments string
}

// openAIStreamUsage is the OpenAI chat-completions stream usage object.
// Also constructed by the Gemini path from usageMetadata.
type openAIStreamUsage struct {
	PromptTokens            int                       `json:"prompt_tokens"`
	CompletionTokens        int                       `json:"completion_tokens"`
	TotalTokens             int                       `json:"total_tokens"`
	CompletionTokensDetails *openAIStreamUsageDetails `json:"completion_tokens_details"`
}

type openAIStreamUsageDetails struct {
	ReasoningTokens int `json:"reasoning_tokens"`
}

func writeAnthropicTextDelta(w io.Writer, text string) error {
	payload := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", body)
	return err
}

func writeAnthropicToolStart(w io.Writer, index int, id string, name string) error {
	payload := map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    id,
			"name":  name,
			"input": map[string]any{},
		},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", body)
	return err
}

func writeAnthropicToolDelta(w io.Writer, index int, partialJSON string) error {
	payload := map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type":         "input_json_delta",
			"partial_json": partialJSON,
		},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", body)
	return err
}

func writeAnthropicToolStop(w io.Writer, index int) error {
	payload := map[string]any{
		"type":  "content_block_stop",
		"index": index,
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", body)
	return err
}

func writeAnthropicStop(w io.Writer, stopReason string, usage *openAIStreamUsage) error {
	mDelta := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason},
	}
	if usage != nil {
		// Relay the upstream-reported usage on the synthetic message_delta.
		// Native Anthropic splits input (message_start) from output
		// (message_delta) but this event is OUR internal contract with
		// adapter.TransformStreamCapture/CollectAnthropicText, which read
		// whichever keys are present.
		usageBody := map[string]any{
			"input_tokens":  usage.PromptTokens,
			"output_tokens": usage.CompletionTokens,
		}
		if usage.CompletionTokensDetails != nil && usage.CompletionTokensDetails.ReasoningTokens > 0 {
			usageBody["reasoning_tokens"] = usage.CompletionTokensDetails.ReasoningTokens
		}
		mDelta["usage"] = usageBody
	}
	body, _ := json.Marshal(mDelta)
	if _, err := fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", body); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return err
}

func mapOpenAIFinishReason(reason string) string {
	switch reason {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return "end_turn"
	default:
		return "end_turn"
	}
}
