package adapter

import (
	"fmt"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func customError(field, message string) error {
	return &AdapterError{Status: 400, Context: field, Message: message}
}

func responseToolWire(name string, meta *types.ResponseRequestMeta) (kind, field, events string) {
	if meta.CustomTool(name) {
		return "custom_tool_call", "input", "response.custom_tool_call_input."
	}
	return "function_call", "arguments", "response.function_call_arguments."
}

func validateCustomTool(m map[string]any) error {
	for k := range m {
		switch k {
		case "type", "name", "description", "format":
		default:
			return customError("tools", "unknown custom tool field")
		}
	}
	if !providerFunctionName.MatchString(stringValue(m["name"])) {
		return customError("tools.name", "invalid custom tool name")
	}
	if desc, exists := m["description"]; exists {
		if _, ok := desc.(string); !ok {
			return customError("tools.description", "custom tool description must be a string")
		}
	}
	raw, exists := m["format"]
	if !exists {
		return nil
	}
	f, _ := raw.(map[string]any)
	switch stringValue(f["type"]) {
	case "text":
		if len(f) == 1 {
			return nil
		}
	case "grammar":
		syntax := stringValue(f["syntax"])
		if len(f) == 3 && (syntax == "lark" || syntax == "regex") && strings.TrimSpace(stringValue(f["definition"])) != "" {
			return nil
		}
	}
	return customError("tools.format", "expected text or a grammar with syntax and definition")
}

func nativeCustomRequest(req *types.OpenAIResponsesRequest) (*types.NativeCustomTools, error) {
	if len(req.Tools) == 0 && req.ToolChoice == nil {
		if _, text := req.Input.(string); text || !types.NativeCustomModel(req.Model) {
			return nil, nil
		}
	}
	n := &types.NativeCustomTools{Definitions: map[string]map[string]any{}, CallIDs: map[string]bool{}, OutputIDs: map[string]bool{}}
	names := map[string]int{}
	other := false
	for _, raw := range req.Tools {
		tool, _ := raw.(map[string]any)
		name := stringValue(tool["name"])
		switch stringValue(tool["type"]) {
		case "custom":
			if err := validateCustomTool(tool); err != nil {
				return nil, err
			}
			n.Definitions[name] = tool
		case "function":
			if fn, ok := tool["function"].(map[string]any); ok {
				name = stringValue(fn["name"])
			}
		default:
			other = true
		}
		names[strings.TrimSpace(name)]++
	}
	choice, _ := req.ToolChoice.(map[string]any)
	if choice["type"] == "custom" {
		n.Choice = stringValue(choice["name"])
		if len(choice) != 2 || n.Definitions[n.Choice] == nil {
			return nil, customError("tool_choice", "custom tool_choice must name a declared custom tool")
		}
	}
	// Preserve legacy replay on other models when no native capability was requested.
	if len(n.Definitions) == 0 && !types.NativeCustomModel(req.Model) {
		return nil, nil
	}
	items, _ := req.Input.([]any)
	if item, ok := req.Input.(map[string]any); ok {
		items = []any{item}
	}
	functionIDs := map[string]bool{}
	for index, raw := range items {
		item, _ := raw.(map[string]any)
		rawID := stringValue(item["call_id"])
		id := strings.TrimSpace(rawID)
		if kind := stringValue(item["type"]); (kind == "custom_tool_call" || kind == "custom_tool_call_output") && (id == "" || id != rawID) {
			return nil, customError(fmt.Sprintf("input[%d].call_id", index), "custom tool call_id must be nonempty and have no surrounding whitespace")
		}
		switch stringValue(item["type"]) {
		case "custom_tool_call":
			if _, ok := item["input"].(string); !ok || n.CallIDs[id] {
				return nil, customError(fmt.Sprintf("input[%d]", index), "expected custom call with unique call_id and string input")
			}
			n.CallIDs[id] = true
		case "custom_tool_call_output":
			if n.OutputIDs[id] {
				return nil, customError(fmt.Sprintf("input[%d].call_id", index), "duplicate custom tool output")
			}
			n.OutputIDs[id] = true
		case "function_call", "function_call_output":
			functionIDs[id] = true
		}
	}
	if len(n.Definitions)+len(n.CallIDs)+len(n.OutputIDs) == 0 {
		return nil, nil
	}
	for name := range n.Definitions {
		if names[name] != 1 {
			return nil, customError("tools.name", "custom tool name is ambiguous")
		}
	}
	if choice["type"] == "function" {
		name := stringValue(choice["name"])
		if fn, ok := choice["function"].(map[string]any); name == "" && ok {
			name = stringValue(fn["name"])
		}
		if n.Definitions[name] != nil {
			return nil, customError("tool_choice", "tool_choice type does not match the declared custom tool")
		}
	}
	for id := range functionIDs {
		if n.CallIDs[id] || n.OutputIDs[id] {
			return nil, customError("input", "call_id used for both function and custom tools")
		}
	}
	if bool(req.Deidentify) {
		return nil, customError("deidentify", "deidentification is not supported for native custom tools")
	}
	if !types.NativeCustomModel(req.Model) || len(req.Models) > 0 || other || req.Polyphemus != nil || len(req.Plugins) > 0 {
		return nil, customError("tools", "native custom tools require a supported first-party OpenAI Responses route without hosted tools, plugins, or model switching")
	}
	return n, nil
}
