package llm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// These first-party models require Responses for reasoning with tools. Do not
// apply this contract to other providers merely hosting an OpenAI model ID.
func useOpenAIResponses(provider string, req openAICompatibleRequest) bool {
	if normalizeDirectProvider(provider) != "openai" {
		return false
	}
	model := strings.TrimPrefix(strings.ToLower(req.Model), "openai/")
	switch model {
	case "gpt-6-sol", "gpt-6-luna", "gpt-6-astra":
	default:
		return false
	}
	if len(req.Tools) > 0 {
		return true
	}
	for _, message := range req.Messages {
		if message.Role == "tool" || len(message.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

func responsesInputError(field string) error {
	return &upstreamHTTPError{status: http.StatusBadRequest, body: "OpenAI Responses tool route: unsupported or invalid " + field}
}

// Reuse the normalized chat projection (including fetched/validated images),
// not the raw caller body. Routing, secrets, and metadata never go upstream.
func buildOpenAIResponsesRequest(req openAICompatibleRequest) (map[string]any, error) {
	encoded, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	for _, field := range []string{"stop", "seed", "prediction", "frequency_penalty", "presence_penalty", "logit_bias", "logprobs", "top_logprobs", "top_k", "top_a", "min_p", "repetition_penalty", "prompt_cache_options"} {
		if _, present := out[field]; present {
			return nil, responsesInputError(field)
		}
	}
	for _, field := range []string{"messages", "max_tokens", "max_completion_tokens", "stream_options", "thinking", "reasoning_effort", "reasoning", "response_format"} {
		delete(out, field)
	}
	out["store"] = false
	if req.MaxCompletionTokens > 0 {
		out["max_output_tokens"] = req.MaxCompletionTokens
	}
	if req.ReasoningEffort != "" {
		out["reasoning"] = map[string]any{"effort": req.ReasoningEffort}
	}
	input := make([]any, 0, len(req.Messages))
	for _, message := range req.Messages {
		if message.Role == "tool" {
			input = append(input, map[string]any{"type": "function_call_output", "call_id": message.ToolCallID, "output": message.Content})
			continue
		}
		content, err := responsesMessageContent(message.Role, message.Content)
		if err != nil {
			return nil, err
		}
		if content != nil && content != "" {
			input = append(input, map[string]any{"role": message.Role, "content": content})
		}
		for _, call := range message.ToolCalls {
			function, _ := call["function"].(map[string]any)
			input = append(input, map[string]any{"type": "function_call", "call_id": call["id"], "name": function["name"], "arguments": function["arguments"]})
		}
	}
	out["input"] = input
	tools, _ := out["tools"].([]any)
	for i, raw := range tools {
		tool, _ := raw.(map[string]any)
		function, ok := tool["function"].(map[string]any)
		if tool["type"] != "function" || !ok {
			return nil, responsesInputError("tools")
		}
		function["type"] = "function"
		// Responses defaults schemas to strict; Chat Completions does not.
		if _, explicit := function["strict"]; !explicit {
			function["strict"] = false
		}
		tools[i] = function
	}
	if choice, ok := out["tool_choice"].(map[string]any); ok {
		function, ok := choice["function"].(map[string]any)
		if choice["type"] != "function" || !ok {
			return nil, responsesInputError("tool_choice")
		}
		out["tool_choice"] = map[string]any{"type": "function", "name": function["name"]}
	}
	if req.ResponseFormat != nil {
		format, ok := req.ResponseFormat.(map[string]any)
		if !ok {
			return nil, responsesInputError("response_format")
		}
		if format["type"] == "json_schema" {
			schema, ok := format["json_schema"].(map[string]any)
			if !ok {
				return nil, responsesInputError("response_format.json_schema")
			}
			copy := make(map[string]any, len(schema)+1)
			for k, v := range schema {
				copy[k] = v
			}
			copy["type"] = "json_schema"
			format = copy
		}
		out["text"] = map[string]any{"format": format}
	}
	return out, nil
}

func responsesMessageContent(role string, content any) (any, error) {
	if content == nil {
		return nil, nil
	}
	if text, ok := content.(string); ok {
		return text, nil
	}
	blocks, ok := anthropicContentBlocks(content)
	if !ok {
		return nil, responsesInputError("message content")
	}
	parts := make([]any, 0, len(blocks))
	for _, block := range blocks {
		switch block["type"] {
		case "text":
			kind := "input_text"
			if role == "assistant" {
				kind = "output_text"
			}
			parts = append(parts, map[string]any{"type": kind, "text": block["text"]})
		case "image_url":
			image, ok := block["image_url"].(map[string]any)
			if !ok || role != "user" {
				return nil, responsesInputError("image content")
			}
			part := map[string]any{"type": "input_image", "image_url": image["url"]}
			if detail, ok := image["detail"]; ok {
				part["detail"] = detail
			}
			parts = append(parts, part)
		default:
			return nil, responsesInputError("content type")
		}
	}
	return parts, nil
}

type responsesStreamEvent struct {
	Type        string `json:"type"`
	OutputIndex int    `json:"output_index"`
	Delta       string `json:"delta"`
	Item        struct {
		Type   string `json:"type"`
		CallID string `json:"call_id"`
		Name   string `json:"name"`
	} `json:"item"`
	Response struct {
		ServiceTier string `json:"service_tier"`
		Usage       *struct {
			InputTokens   int                       `json:"input_tokens"`
			OutputTokens  int                       `json:"output_tokens"`
			TotalTokens   int                       `json:"total_tokens"`
			InputDetails  *openAIPromptTokenDetails `json:"input_tokens_details"`
			OutputDetails *openAIStreamUsageDetails `json:"output_tokens_details"`
		} `json:"usage"`
		IncompleteDetails struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
	} `json:"response"`
}

// Emit the same internal events as every other provider. Settlement, refunds,
// public Chat/Responses/Messages output, and cache accounting remain shared.
func translateOpenAIResponsesStream(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	tools := make(map[int]bool)
	thinkingStarted := false
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			data.WriteByte('\n')
			if data.Len() > 1<<20 {
				return fmt.Errorf("llm/openai-responses: oversized event")
			}
			continue
		}
		if line != "" || data.Len() == 0 {
			continue
		}
		var event responsesStreamEvent
		if err := json.Unmarshal([]byte(data.String()), &event); err != nil {
			return fmt.Errorf("llm/openai-responses: malformed event")
		}
		data.Reset()
		var err error
		switch event.Type {
		case "response.output_text.delta", "response.refusal.delta":
			err = writeAnthropicTextDelta(w, event.Delta)
		case "response.reasoning_summary_text.delta":
			if !thinkingStarted {
				thinkingStarted = true
				if err = writeAnthropicThinkingStart(w, 0); err != nil {
					return err
				}
			}
			err = writeAnthropicThinkingDelta(w, 0, event.Delta)
		case "response.output_item.added":
			if event.Item.Type == "function_call" {
				if _, duplicate := tools[event.OutputIndex]; duplicate || event.Item.CallID == "" || event.Item.Name == "" {
					return fmt.Errorf("llm/openai-responses: invalid function call")
				}
				tools[event.OutputIndex] = false
				err = writeAnthropicToolStart(w, event.OutputIndex+1, event.Item.CallID, event.Item.Name)
			}
		case "response.function_call_arguments.delta":
			if done, exists := tools[event.OutputIndex]; !exists || done {
				return fmt.Errorf("llm/openai-responses: arguments without open function call")
			}
			err = writeAnthropicToolDelta(w, event.OutputIndex+1, event.Delta)
		case "response.output_item.done":
			if event.Item.Type == "function_call" {
				if done, exists := tools[event.OutputIndex]; !exists || done {
					return fmt.Errorf("llm/openai-responses: invalid function completion")
				}
				tools[event.OutputIndex] = true
				err = writeAnthropicToolStop(w, event.OutputIndex+1)
			}
		case "error", "response.failed":
			// Provider messages can echo prompts; never include event payloads.
			return &upstreamHTTPError{status: http.StatusBadGateway, body: "OpenAI Responses stream failed"}
		case "response.completed", "response.incomplete":
			usage := event.Response.Usage
			if usage == nil || usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens != usage.InputTokens+usage.OutputTokens {
				return fmt.Errorf("llm/openai-responses: missing or invalid usage")
			}
			if details := usage.InputDetails; details != nil && (details.CachedTokens < 0 || details.CachedTokens > usage.InputTokens) {
				return fmt.Errorf("llm/openai-responses: invalid cached usage")
			}
			if details := usage.OutputDetails; details != nil && (details.ReasoningTokens < 0 || details.ReasoningTokens > usage.OutputTokens) {
				return fmt.Errorf("llm/openai-responses: invalid reasoning usage")
			}
			stop := "end_turn"
			if len(tools) > 0 {
				stop = "tool_use"
			}
			if event.Type == "response.incomplete" {
				switch event.Response.IncompleteDetails.Reason {
				case "max_output_tokens":
					stop = "max_tokens"
				case "content_filter":
					stop = mapOpenAIFinishReason("content_filter")
				default:
					return fmt.Errorf("llm/openai-responses: unknown incomplete reason")
				}
			}
			indices := make([]int, 0, len(tools))
			for index := range tools {
				indices = append(indices, index)
			}
			sort.Ints(indices)
			for _, index := range indices {
				if !tools[index] {
					if event.Type == "response.completed" {
						return fmt.Errorf("llm/openai-responses: unfinished function call")
					}
					if err := writeAnthropicToolStop(w, index+1); err != nil {
						return err
					}
				}
			}
			return writeAnthropicStop(w, stop, &openAIStreamUsage{
				PromptTokens: usage.InputTokens, CompletionTokens: usage.OutputTokens, TotalTokens: usage.TotalTokens,
				PromptTokensDetails: usage.InputDetails, CompletionTokensDetails: usage.OutputDetails,
				ServiceTier: event.Response.ServiceTier,
			}, nil, nil)
		}
		if err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("llm/openai-responses: read: %w", err)
	}
	return fmt.Errorf("llm/openai-responses: stream ended without terminal usage")
}
