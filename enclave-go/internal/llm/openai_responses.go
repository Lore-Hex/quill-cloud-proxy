package llm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// Match family boundaries so future variants/snapshots work without admitting
// unrelated versions such as gpt-5.60 or gpt-60.
var openAIResponsesModelFamily = regexp.MustCompile(`^gpt-(5\.[56]|6(\.[0-9]+)?)(-|$)`)

// These models, and their dated snapshots, document reasoning.effort none in
// OpenAI's model pages and reasoning guide. GPT-6 Astra and GPT-6.1 Sol
// document that they reject it, and no pro page documents it. For every other
// member of the family an Off is refused by this route at preparation, as any
// switch was before, so the request fails over to the next candidate.
var openAIResponsesEffortNone = regexp.MustCompile(`^gpt-(5\.5|5\.6-(luna|sol|terra)|6-(luna|sol)|6\.1-terra)(-[0-9]{4}-[0-9]{2}-[0-9]{2})?$`)

// openAIResponsesModel reports a model that uses Responses for reasoning with
// tools on the first-party route, and its ID as that route names it. A catalog
// ID may carry the author prefix.
func openAIResponsesModel(model string) (string, bool) {
	model = strings.TrimPrefix(strings.ToLower(model), "openai/")
	if !openAIResponsesModelFamily.MatchString(model) {
		return model, false
	}
	// GPT-5.5 Pro does not support streaming; ordinary dispatch and the
	// Responses translator require an upstream SSE stream, even for JSON callers.
	if model == "gpt-5.5-pro" || strings.HasPrefix(model, "gpt-5.5-pro-") {
		return model, false
	}
	return model, true
}

// These first-party models require Responses for reasoning with tools. Do not
// apply this contract to other providers merely hosting an OpenAI model ID.
func useOpenAIResponses(provider string, req openAICompatibleRequest) bool {
	if normalizeDirectProvider(provider) != "openai" {
		return false
	}
	if _, ok := openAIResponsesModel(req.Model); !ok {
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

// responsesUnhonoredReasoning names a reasoning control that the model cannot
// honor on this route: Off where the model documents no way to stop
// reasoning, and a thinking token budget, which these models do not take. It
// is empty for a control the route can honor.
func responsesUnhonoredReasoning(model string, reasoning any) string {
	values, _ := reasoning.(map[string]any)
	if enabled, explicit := values["enabled"].(bool); explicit && !enabled {
		if !openAIResponsesEffortNone.MatchString(model) {
			return "this model cannot turn reasoning off"
		}
	}
	for _, key := range []string{"max_tokens", "thinking_budget", "budget_tokens"} {
		if values[key] != nil {
			return "this model takes a reasoning effort, not a thinking token budget"
		}
	}
	return ""
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
	var normalized map[string]any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return nil, err
	}
	out := map[string]any{"store": false}
	// New chat/provider-specific fields cannot silently enter the Responses
	// wire. Converted fields are handled below; everything else fails closed.
	for field, value := range normalized {
		switch field {
		case "model", "stream", "temperature", "top_p", "tools", "tool_choice", "parallel_tool_calls", "prompt_cache_key", "service_tier", "safety_identifier":
			out[field] = value
		case "messages", "max_tokens", "max_completion_tokens", "stream_options", "reasoning_effort", "reasoning", "response_format":
		default:
			return nil, responsesInputError(field)
		}
	}
	limit := req.MaxCompletionTokens
	if limit == 0 {
		limit = req.MaxTokens
	}
	if limit > 0 {
		out["max_output_tokens"] = limit
	}
	reasoning, err := responsesReasoning(req)
	if err != nil {
		return nil, err
	}
	out["reasoning"] = reasoning
	input := make([]any, 0, len(req.Messages))
	var seenCalls, seenOutputs map[string]bool
	if req.NativeCustom != nil {
		seenCalls, seenOutputs = map[string]bool{}, map[string]bool{}
	}
	for _, message := range req.Messages {
		if message.Role == "tool" {
			output, ok := message.Content.(string)
			if !ok || strings.TrimSpace(message.ToolCallID) == "" {
				return nil, responsesInputError("tool result")
			}
			kind := "function_call_output"
			if req.NativeCustom != nil && req.NativeCustom.OutputIDs[message.ToolCallID] {
				if seenOutputs[message.ToolCallID] {
					return nil, responsesInputError("duplicate custom tool result")
				}
				seenOutputs[message.ToolCallID] = true
				kind = "custom_tool_call_output"
			}
			input = append(input, map[string]any{"type": kind, "call_id": message.ToolCallID, "output": output})
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
			id, _ := call["id"].(string)
			name, _ := function["name"].(string)
			arguments, ok := function["arguments"].(string)
			if strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" || !ok || !json.Valid([]byte(arguments)) {
				return nil, responsesInputError("tool call history")
			}
			if req.NativeCustom != nil && req.NativeCustom.CallIDs[id] {
				if seenCalls[id] {
					return nil, responsesInputError("duplicate custom tool call")
				}
				seenCalls[id] = true
				var arg struct {
					Input *string `json:"input"`
				}
				if json.Unmarshal([]byte(arguments), &arg) != nil || arg.Input == nil {
					return nil, responsesInputError("custom tool call input")
				}
				input = append(input, map[string]any{"type": "custom_tool_call", "call_id": id, "name": name, "input": *arg.Input})
			} else {
				input = append(input, map[string]any{"type": "function_call", "call_id": id, "name": name, "arguments": arguments})
			}
		}
	}
	if req.NativeCustom != nil && (len(seenCalls) != len(req.NativeCustom.CallIDs) || len(seenOutputs) != len(req.NativeCustom.OutputIDs)) {
		return nil, responsesInputError("normalized custom tool history IDs do not match")
	}
	out["input"] = input
	tools, _ := out["tools"].([]any)
	for i, raw := range tools {
		tool, _ := raw.(map[string]any)
		function, ok := tool["function"].(map[string]any)
		if tool["type"] != "function" || !ok {
			return nil, responsesInputError("tools")
		}
		if req.NativeCustom != nil {
			if definition := req.NativeCustom.Definitions[stringValue(function["name"])]; definition != nil {
				tools[i] = definition
				continue
			}
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
		kind := "function"
		if req.NativeCustom != nil && req.NativeCustom.Choice != "" {
			if req.NativeCustom.Choice != function["name"] {
				return nil, responsesInputError("custom tool_choice")
			}
			kind = "custom"
		}
		out["tool_choice"] = map[string]any{"type": kind, "name": function["name"]}
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

// responsesReasoning projects the reasoning control onto Responses, which has
// an effort and no switch. These models reason by default, so On is the
// request without the switch: the effort when one was sent, else the model's
// own default. Off is the documented effort none, and governs an effort sent
// beside it. What the route cannot honor is the same 400 at preparation that
// every switch was: a later candidate for the model is still tried.
func responsesReasoning(req openAICompatibleRequest) (map[string]any, error) {
	model, _ := openAIResponsesModel(req.Model)
	if message := responsesUnhonoredReasoning(model, req.Reasoning); message != "" {
		return nil, &upstreamHTTPError{status: http.StatusBadRequest, body: "OpenAI Responses tool route: " + message}
	}
	out := map[string]any{"summary": "auto"}
	off := false
	if req.Reasoning != nil {
		values, ok := req.Reasoning.(map[string]any)
		if !ok {
			return nil, responsesInputError("reasoning")
		}
		for key, value := range values {
			switch key {
			case "effort", "summary":
				out[key] = value
			case "enabled":
				enabled, ok := value.(bool)
				if !ok {
					return nil, responsesInputError("reasoning option")
				}
				off = !enabled
			default:
				return nil, responsesInputError("reasoning option")
			}
		}
	}
	if req.ReasoningEffort != "" {
		out["effort"] = req.ReasoningEffort
	}
	if off {
		out["effort"] = "none"
	}
	if out["effort"] == "none" {
		// None has no reasoning to summarize. Preserve explicit summary values
		// for the provider to validate rather than silently override them.
		values, _ := req.Reasoning.(map[string]any)
		if _, explicit := values["summary"]; !explicit {
			delete(out, "summary")
		}
	}
	return out, nil
}

func responsesMessageContent(role string, content any) (any, error) {
	var emptied bool
	content, emptied = withoutProviderHistory(content)
	if emptied {
		return nil, nil
	}
	if content == nil {
		return nil, nil
	}
	if text, ok := content.(string); ok {
		return text, nil
	}
	switch parts := content.(type) {
	case []any:
		if len(parts) == 0 {
			return nil, nil
		}
	case []map[string]any:
		if len(parts) == 0 {
			return nil, nil
		}
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
			return nil, &contentInputError{kind: stringValue(block["type"])}
		}
	}
	return parts, nil
}

type responsesStreamEvent struct {
	Type        string  `json:"type"`
	Input       *string `json:"input"`
	ItemID      string  `json:"item_id"`
	OutputIndex int     `json:"output_index"`
	Delta       string  `json:"delta"`
	Item        struct {
		Type   string  `json:"type"`
		ID     string  `json:"id"`
		CallID string  `json:"call_id"`
		Status string  `json:"status"`
		Name   string  `json:"name"`
		Input  *string `json:"input"`
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
	return translateNativeResponsesStream(r, w, nil)
}

func translateNativeResponsesStream(r io.Reader, w io.Writer, custom *qtypes.NativeCustomTools) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	tools := make(map[int]bool)
	customCalls := make(map[int]*nativeCustomStreamCall)
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
		if err := upstreamerror.CheckEvent("", data.String()); err != nil {
			return err
		}
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
			if event.Item.Type == "custom_tool_call" {
				if custom == nil || custom.Definitions[event.Item.Name] == nil || event.Item.CallID == "" || event.Item.ID == "" {
					return fmt.Errorf("llm/openai-responses: undeclared custom call")
				}
				if _, duplicate := tools[event.OutputIndex]; duplicate {
					return fmt.Errorf("llm/openai-responses: duplicate custom call")
				}
				c := newNativeCustomStreamCall(event.Item.CallID, event.Item.Name, event.Item.ID)
				customCalls[event.OutputIndex], tools[event.OutputIndex] = c, false
				err = writeAnthropicToolStart(w, event.OutputIndex+1, c.id, c.name)
				if err == nil && event.Item.Input != nil && *event.Item.Input != "" {
					err = c.writeDelta(w, event.OutputIndex, *event.Item.Input)
				}
			}
			if event.Item.Type == "function_call" {
				if custom != nil && custom.Definitions[event.Item.Name] != nil {
					return fmt.Errorf("llm/openai-responses: custom tool returned as function")
				}
				if _, duplicate := tools[event.OutputIndex]; duplicate || event.Item.CallID == "" || event.Item.Name == "" {
					return fmt.Errorf("llm/openai-responses: invalid function call")
				}
				tools[event.OutputIndex] = false
				err = writeAnthropicToolStart(w, event.OutputIndex+1, event.Item.CallID, event.Item.Name)
			}
		case "response.function_call_arguments.delta":
			if done, exists := tools[event.OutputIndex]; !exists || done || customCalls[event.OutputIndex] != nil {
				return fmt.Errorf("llm/openai-responses: arguments without open function call")
			}
			err = writeAnthropicToolDelta(w, event.OutputIndex+1, event.Delta)
		case "response.custom_tool_call_input.delta", "response.custom_tool_call_input.done":
			c := customCalls[event.OutputIndex]
			if c == nil || c.inputDone || c.truncated || tools[event.OutputIndex] || event.ItemID != c.itemID {
				return fmt.Errorf("llm/openai-responses: custom input without open call")
			}
			if event.Type == "response.custom_tool_call_input.delta" {
				err = c.writeDelta(w, event.OutputIndex, event.Delta)
			} else if !c.matches(event.Input) {
				return fmt.Errorf("llm/openai-responses: inconsistent custom input")
			} else {
				c.inputDone = true
			}
		case "response.output_item.done":
			if event.Item.Type == "custom_tool_call" {
				c := customCalls[event.OutputIndex]
				if c == nil || c.truncated || tools[event.OutputIndex] || event.Item.CallID != c.id || event.Item.Name != c.name || event.Item.ID != c.itemID {
					return fmt.Errorf("llm/openai-responses: invalid custom call completion")
				}
				if event.Item.Status == "incomplete" {
					if event.Item.Input != nil && !c.matches(event.Item.Input) {
						return fmt.Errorf("llm/openai-responses: inconsistent partial custom input")
					}
					// Wait for the terminal response with actual usage before closing this partial item.
					c.truncated = true
					continue
				}
				if (event.Item.Status != "" && event.Item.Status != "completed") || !c.inputDone || !c.matches(event.Item.Input) {
					return fmt.Errorf("llm/openai-responses: invalid completed custom input")
				}
				tools[event.OutputIndex] = true
				err = writeAnthropicToolStop(w, event.OutputIndex+1)
			}
			if event.Item.Type == "function_call" {
				if done, exists := tools[event.OutputIndex]; !exists || done || customCalls[event.OutputIndex] != nil {
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
					if customCalls[index] != nil {
						// Distinguish truncation from a successful tool call in both public renderers.
						if _, err := fmt.Fprintf(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d,\"tr_custom_incomplete\":true}\n\n", index+1); err != nil {
							return err
						}
						continue
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
			}, nil, nil, nil)
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
