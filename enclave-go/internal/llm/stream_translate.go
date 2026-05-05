package llm

import (
	"bufio"
	"encoding/json"
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

// translateOpenAIStreamToAnthropic reads OpenAI Chat Completions SSE chunks
// and writes native Anthropic SSE events for the existing adapter pipeline.
func translateOpenAIStreamToAnthropic(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	stopReason := "end_turn"
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
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
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
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			stopReason = mapOpenAIFinishReason(*choice.FinishReason)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("llm/openai-stream: scan: %w", err)
	}

	return writeAnthropicStop(w, stopReason)
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

func writeAnthropicStop(w io.Writer, stopReason string) error {
	mDelta := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason},
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
