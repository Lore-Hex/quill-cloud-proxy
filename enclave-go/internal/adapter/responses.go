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

func RejectUnsupportedResponsesFields(raw map[string]json.RawMessage) error {
	unsupported := []string{
		"tools",
		"tool_choice",
		"previous_response_id",
		"attachments",
		"files",
		"file",
		"background",
		"plugins",
		"parallel_tool_calls",
		"reasoning",
		"reasoning_effort",
		"web_search_options",
	}
	for _, key := range unsupported {
		if presentNonNull(raw[key]) {
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: key}
		}
	}
	if value, ok := raw["store"]; ok {
		var store bool
		if err := json.Unmarshal(value, &store); err == nil && store {
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "store=true"}
		}
	}
	if value, ok := raw["modalities"]; ok {
		var modalities []string
		if err := json.Unmarshal(value, &modalities); err == nil {
			for _, modality := range modalities {
				if modality != "text" {
					return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "modalities"}
				}
			}
		}
	}
	if value, ok := raw["input"]; ok && containsUnsupportedInput(value) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "input"}
	}
	return nil
}

func ResponsesToChat(req *types.OpenAIResponsesRequest) (*types.OpenAIChatRequest, error) {
	if strings.TrimSpace(req.Model) == "" {
		return nil, &AdapterError{Status: 400, Message: "model is required"}
	}
	messages := make([]types.OpenAIChatMessage, 0, 4)
	if strings.TrimSpace(req.Instructions) != "" {
		messages = append(messages, types.OpenAIChatMessage{
			Role:    "system",
			Content: req.Instructions,
		})
	}
	inputMessages, err := responseInputMessages(req.Input)
	if err != nil {
		return nil, err
	}
	messages = append(messages, inputMessages...)
	if len(messages) == 0 {
		return nil, &AdapterError{Status: 400, Message: "input must contain text"}
	}
	maxTokens := req.MaxOutputTokens
	if maxTokens == nil {
		maxTokens = req.MaxTokens
	}
	return &types.OpenAIChatRequest{
		Model:       req.Model,
		Models:      req.Models,
		Messages:    messages,
		Stream:      req.Stream,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		MaxTokens:   maxTokens,
		Provider:    req.Provider,
		Metadata:    req.Metadata,
		Trace:       req.Trace,
		User:        req.User,
		SessionID:   req.SessionID,
	}, nil
}

func responseInputMessages(input any) ([]types.OpenAIChatMessage, error) {
	switch value := input.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil, &AdapterError{Status: 400, Message: "input must contain text"}
		}
		return []types.OpenAIChatMessage{{Role: "user", Content: value}}, nil
	case []any:
		out := make([]types.OpenAIChatMessage, 0, len(value))
		for index, item := range value {
			message, err := responseInputMessage(item, index)
			if err != nil {
				return nil, err
			}
			out = append(out, message)
		}
		return out, nil
	case map[string]any:
		message, err := responseInputMessage(value, 0)
		if err != nil {
			return nil, err
		}
		return []types.OpenAIChatMessage{message}, nil
	default:
		return nil, &AdapterError{Status: 400, Message: "input must be text or text messages"}
	}
}

func responseInputMessage(item any, index int) (types.OpenAIChatMessage, error) {
	if text, ok := item.(string); ok {
		return types.OpenAIChatMessage{Role: "user", Content: text}, nil
	}
	m, ok := item.(map[string]any)
	if !ok {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status:  400,
			Message: "input item must be text or object",
			Context: fmt.Sprintf("input[%d]", index),
		}
	}
	role := stringValue(m["role"])
	if role == "" {
		role = "user"
	}
	if role == "developer" {
		role = "system"
	}
	if role != "system" && role != "user" && role != "assistant" {
		return types.OpenAIChatMessage{}, &AdapterError{Status: 400, Message: "unsupported input role"}
	}
	content, err := textContent(m)
	if err != nil {
		return types.OpenAIChatMessage{}, err
	}
	if strings.TrimSpace(content) == "" {
		return types.OpenAIChatMessage{}, &AdapterError{Status: 400, Message: "input item must contain text"}
	}
	return types.OpenAIChatMessage{Role: role, Content: content}, nil
}

func textContent(m map[string]any) (string, error) {
	if text := stringValue(m["text"]); text != "" {
		return text, nil
	}
	switch content := m["content"].(type) {
	case string:
		return content, nil
	case []any:
		parts := make([]string, 0, len(content))
		for _, item := range content {
			part, ok := item.(map[string]any)
			if !ok {
				return "", &AdapterError{Status: 400, Message: "content part must be text object"}
			}
			partType := stringValue(part["type"])
			if partType != "" && partType != "text" && partType != "input_text" {
				return "", &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "content"}
			}
			if text := stringValue(part["text"]); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", &AdapterError{Status: 400, Message: "input item must contain text"}
	}
}

func CollectAnthropicText(r io.Reader) (StreamResult, error) {
	finishReason := "stop"
	var captured strings.Builder
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	scanner.Split(splitDoubleNewline)
	for scanner.Scan() {
		eventName, dataJSON := parseSSEBlock(scanner.Bytes())
		if dataJSON == nil {
			continue
		}
		switch eventName {
		case "content_block_delta":
			delta := getMap(dataJSON, "delta")
			if delta != nil && getString(delta, "type") == "text_delta" {
				captured.WriteString(getString(delta, "text"))
			}
		case "message_delta":
			if delta := getMap(dataJSON, "delta"); delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
		case "message_stop":
			return StreamResult{Text: captured.String(), FinishReason: finishReason}, nil
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	return StreamResult{Text: captured.String(), FinishReason: finishReason}, nil
}

func WriteResponsesResponse(
	w io.Writer,
	responseID string,
	model string,
	text string,
	inputTokens int,
	outputTokens int,
	created int64,
) error {
	payload := responsesObject(responseID, model, text, inputTokens, outputTokens, created)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func TransformResponsesStream(
	r io.Reader,
	w io.Writer,
	responseID string,
	model string,
	inputTokens int,
) (StreamResult, error) {
	created := time.Now().Unix()
	messageID := "msg_" + strings.TrimPrefix(responseID, "resp_")
	finishReason := "stop"
	var captured strings.Builder
	if err := writeResponseEvent(w, "response.created", map[string]any{
		"type":     "response.created",
		"response": responsesObject(responseID, model, "", inputTokens, 0, created),
	}); err != nil {
		return StreamResult{}, err
	}
	if err := writeResponseEvent(w, "response.output_item.added", map[string]any{
		"type":         "response.output_item.added",
		"output_index": 0,
		"item": map[string]any{
			"id":      messageID,
			"type":    "message",
			"status":  "in_progress",
			"role":    "assistant",
			"content": []any{},
		},
	}); err != nil {
		return StreamResult{}, err
	}
	if err := writeResponseEvent(w, "response.content_part.added", map[string]any{
		"type":          "response.content_part.added",
		"item_id":       messageID,
		"output_index":  0,
		"content_index": 0,
		"part":          map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
	}); err != nil {
		return StreamResult{}, err
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	scanner.Split(splitDoubleNewline)
	for scanner.Scan() {
		eventName, dataJSON := parseSSEBlock(scanner.Bytes())
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
			captured.WriteString(deltaText)
			if err := writeResponseEvent(w, "response.output_text.delta", map[string]any{
				"type":          "response.output_text.delta",
				"item_id":       messageID,
				"output_index":  0,
				"content_index": 0,
				"delta":         deltaText,
			}); err != nil {
				return StreamResult{}, err
			}
		case "message_delta":
			if delta := getMap(dataJSON, "delta"); delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
		case "message_stop":
			return finishResponsesStream(w, responseID, messageID, model, captured.String(), inputTokens, created, finishReason)
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	return finishResponsesStream(w, responseID, messageID, model, captured.String(), inputTokens, created, finishReason)
}

func finishResponsesStream(
	w io.Writer,
	responseID string,
	messageID string,
	model string,
	text string,
	inputTokens int,
	created int64,
	finishReason string,
) (StreamResult, error) {
	outputTokens := estimateTextTokens(text)
	events := []struct {
		name string
		body map[string]any
	}{
		{"response.output_text.done", map[string]any{
			"type":          "response.output_text.done",
			"item_id":       messageID,
			"output_index":  0,
			"content_index": 0,
			"text":          text,
		}},
		{"response.output_item.done", map[string]any{
			"type":         "response.output_item.done",
			"output_index": 0,
			"item": map[string]any{
				"id":      messageID,
				"type":    "message",
				"status":  "completed",
				"role":    "assistant",
				"content": []map[string]any{{"type": "output_text", "text": text, "annotations": []any{}}},
			},
		}},
		{"response.completed", map[string]any{
			"type":     "response.completed",
			"response": responsesObject(responseID, model, text, inputTokens, outputTokens, created),
		}},
	}
	for _, event := range events {
		if err := writeResponseEvent(w, event.name, event.body); err != nil {
			return StreamResult{}, err
		}
	}
	_, err := w.Write([]byte("data: [DONE]\n\n"))
	return StreamResult{Text: text, FinishReason: finishReason}, err
}

func responsesObject(responseID, model, text string, inputTokens, outputTokens int, created int64) map[string]any {
	messageID := "msg_" + strings.TrimPrefix(responseID, "resp_")
	return map[string]any{
		"id":         responseID,
		"object":     "response",
		"created_at": created,
		"status":     "completed",
		"error":      nil,
		"model":      model,
		"output": []map[string]any{{
			"id":     messageID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []map[string]any{{
				"type":        "output_text",
				"text":        text,
				"annotations": []any{},
			}},
		}},
		"usage": map[string]any{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
			"total_tokens":  inputTokens + outputTokens,
		},
	}
}

func writeResponseEvent(w io.Writer, eventName string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", eventName); err != nil {
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

func estimateTextTokens(text string) int {
	if text == "" {
		return 1
	}
	tokens := len(text) / 4
	if tokens < 1 {
		return 1
	}
	return tokens
}

func stringValue(value any) string {
	out, _ := value.(string)
	return out
}

func presentNonNull(value json.RawMessage) bool {
	if len(value) == 0 {
		return false
	}
	trimmed := strings.TrimSpace(string(value))
	return trimmed != "" && trimmed != "null" && trimmed != "[]" && trimmed != "{}"
}

func containsUnsupportedInput(raw json.RawMessage) bool {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return containsUnsupportedInputValue(parsed)
}

func containsUnsupportedInputValue(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		if t := stringValue(v["type"]); strings.Contains(t, "image") || strings.Contains(t, "file") {
			return true
		}
		for _, child := range v {
			if containsUnsupportedInputValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if containsUnsupportedInputValue(child) {
				return true
			}
		}
	}
	return false
}
