// Package adapter translates OpenAI Chat Completions ↔ Anthropic Messages.
//
// Bedrock's InvokeModelWithResponseStream returns AWS event-stream chunks
// whose payload is identical to native Anthropic SSE event JSON; we unwrap
// once in the bedrock package and feed those events here verbatim.
package adapter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// DefaultMaxTokens applied when the client doesn't specify one. Bedrock requires
// max_tokens, so we always provide a value.
const DefaultMaxTokens = 4096

const maxSSEBlockBytes = 64 << 20

// AdapterError signals a 4xx-class translation failure.
type AdapterError struct {
	Status  int
	Message string
	Context string
}

func (e *AdapterError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("adapter: %s [%s] (status %d)", e.Message, e.Context, e.Status)
	}
	return fmt.Sprintf("adapter: %s (status %d)", e.Message, e.Status)
}

// ToAnthropic translates an OpenAI request into an Anthropic Messages body.
func ToAnthropic(req *types.OpenAIChatRequest, defaultModel string) (*types.AnthropicMessagesRequest, error) {
	if len(req.Messages) == 0 {
		return nil, &AdapterError{Status: 400, Message: "messages must contain at least one entry"}
	}
	var systemParts []string
	var msgs []types.AnthropicMessage
	for i, m := range req.Messages {
		if types.ContentEmpty(m.Content) {
			continue
		}
		switch m.Role {
		case "system":
			if types.ContentImageCount(m.Content) > 0 {
				return nil, &AdapterError{
					Status:  400,
					Message: "system messages cannot contain images",
					Context: fmt.Sprintf("message[%d].content", i),
				}
			}
			systemParts = append(systemParts, types.ContentText(m.Content))
		case "user", "assistant":
			msgs = append(msgs, types.AnthropicMessage{Role: m.Role, Content: m.Content})
		default:
			return nil, &AdapterError{
				Status:  400,
				Message: "unsupported role",
				Context: fmt.Sprintf("message[%d].role=%q", i, m.Role),
			}
		}
	}
	if len(msgs) == 0 {
		return nil, &AdapterError{Status: 400, Message: "messages must contain a user/assistant turn"}
	}
	maxTokens := DefaultMaxTokens
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}
	out := &types.AnthropicMessagesRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		Messages:         msgs,
		MaxTokens:        maxTokens,
		Temperature:      req.Temperature,
		TopP:             req.TopP,
	}
	if len(systemParts) > 0 {
		out.System = strings.Join(systemParts, "\n\n")
	}
	_ = defaultModel // model is only used for response chunks, not the body
	return out, nil
}

// TransformStream reads native-Anthropic SSE events from `r` and writes
// OpenAI ChatCompletion chunks to `w`, finishing with `data: [DONE]\n\n`.
//
// Input is the unwrapped stream of `event: ...\ndata: {...}\n\n` framings.
func TransformStream(r io.Reader, w io.Writer, requestID, model string) error {
	_, err := TransformStreamCapture(r, w, requestID, model)
	return err
}

type StreamResult struct {
	Text         string
	FinishReason string
}

func WriteChatCompletionResponse(
	w io.Writer,
	requestID string,
	model string,
	text string,
	inputTokens int,
	outputTokens int,
	created int64,
	finishReason string,
) error {
	if finishReason == "" {
		finishReason = "stop"
	}
	payload := map[string]any{
		"id":      requestID,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": text,
				},
				"finish_reason": finishReason,
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     inputTokens,
			"completion_tokens": outputTokens,
			"total_tokens":      inputTokens + outputTokens,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func TransformStreamCapture(r io.Reader, w io.Writer, requestID, model string) (StreamResult, error) {
	created := time.Now().Unix()
	finishReason := "stop"
	roleSent := false
	var captured strings.Builder

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEBlockBytes)
	scanner.Split(splitDoubleNewline)

	for scanner.Scan() {
		block := scanner.Bytes()
		eventName, dataJSON := parseSSEBlock(block)
		if dataJSON == nil {
			continue
		}
		switch eventName {
		case "content_block_delta":
			delta := getMap(dataJSON, "delta")
			if delta == nil || getString(delta, "type") != "text_delta" {
				continue
			}
			deltaText := getString(delta, "text")
			if deltaText == "" {
				continue
			}
			_, _ = captured.WriteString(deltaText)
			if !roleSent {
				if err := writeChunk(w, requestID, model, created, map[string]string{"role": "assistant", "content": ""}, ""); err != nil {
					return StreamResult{}, err
				}
				roleSent = true
			}
			if err := writeChunk(w, requestID, model, created, map[string]string{"content": deltaText}, ""); err != nil {
				return StreamResult{}, err
			}
		case "message_delta":
			delta := getMap(dataJSON, "delta")
			if delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
		case "message_stop":
			if err := writeChunk(w, requestID, model, created, map[string]string{}, finishReason); err != nil {
				return StreamResult{}, err
			}
			_, err := w.Write([]byte("data: [DONE]\n\n"))
			return StreamResult{Text: captured.String(), FinishReason: finishReason}, err
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	if err := writeChunk(w, requestID, model, created, map[string]string{}, finishReason); err != nil {
		return StreamResult{}, err
	}
	_, err := w.Write([]byte("data: [DONE]\n\n"))
	return StreamResult{Text: captured.String(), FinishReason: finishReason}, err
}

// splitDoubleNewline is a bufio.Scanner SplitFunc that emits each "\n\n"-terminated block.
func splitDoubleNewline(data []byte, atEOF bool) (int, []byte, error) {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return i + 2, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parseSSEBlock(block []byte) (eventName string, dataJSON map[string]any) {
	for _, raw := range strings.Split(string(block), "\n") {
		line := strings.TrimRight(raw, "\r")
		switch {
		case strings.HasPrefix(line, "event: "):
			eventName = line[len("event: "):]
		case strings.HasPrefix(line, "data: "):
			var parsed map[string]any
			if err := json.Unmarshal([]byte(line[len("data: "):]), &parsed); err == nil {
				dataJSON = parsed
			}
		}
	}
	return
}

func getMap(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	out, _ := v.(map[string]any)
	return out
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func mapStopReason(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		return "stop"
	}
}

func writeChunk(
	w io.Writer,
	id, model string,
	created int64,
	delta map[string]string,
	finishReason string,
) error {
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{
			{"index": 0, "delta": delta, "finish_reason": orNil(finishReason)},
		},
	}
	body, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n\n"))
	return err
}

func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
