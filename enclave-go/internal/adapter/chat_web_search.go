package adapter

import (
	"fmt"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const maxChatWebSearchCalls = 30

// ConfigureChatWebSearch turns OpenRouter's hosted web-search surface into the
// enclave's private function-tool contract. Providers see only the generated
// function call and its result; the Exa credential never leaves the enclave.
func ConfigureChatWebSearch(req *types.OpenAIChatRequest) error {
	if req == nil {
		return nil
	}
	var config *types.ResponseWebSearchConfig
	normalizedTools := make([]any, 0, len(req.Tools)+1)
	for index, rawTool := range req.Tools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			return &AdapterError{Status: 400, Message: "tool must be an object", Context: fmt.Sprintf("tools[%d]", index)}
		}
		toolType := strings.TrimSpace(stringValue(tool["type"]))
		if strings.HasPrefix(toolType, "trustedrouter:") {
			// TrustedRouter orchestration tools are validated and consumed by the
			// orchestration router after this hosted-tool normalization pass.
			normalizedTools = append(normalizedTools, tool)
			continue
		}
		switch toolType {
		case "function":
			normalized, err := normalizeChatFunctionToolFromChat(tool)
			if err != nil {
				return err
			}
			normalizedTools = append(normalizedTools, normalized)
		case "openrouter:web_search":
			if config != nil {
				return &AdapterError{Status: 400, Message: "only one hosted web search tool is allowed", Context: "tools"}
			}
			parsed, err := parseOpenRouterWebSearchTool(tool)
			if err != nil {
				return err
			}
			config = parsed
			normalizedTools = append(normalizedTools, trustedRouterWebSearchFunctionTool(map[string]any{
				"user_location": webSearchUserLocation(parsed),
			}))
		default:
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: fmt.Sprintf("tools[%d].type", index)}
		}
	}

	pluginConfig, err := chatWebPluginConfig(req.Plugins, req.WebSearchOptions)
	if err != nil {
		return err
	}
	if pluginConfig != nil {
		if config != nil {
			return &AdapterError{Status: 400, Message: "web plugin and server tool cannot be combined", Context: "plugins.web"}
		}
		config = pluginConfig
		normalizedTools = append(normalizedTools, trustedRouterWebSearchFunctionTool(nil))
	}
	if config == nil {
		if len(req.WebSearchOptions) > 0 {
			return &AdapterError{Status: 400, Message: "web_search_options requires the web plugin", Context: "web_search_options"}
		}
		return nil
	}
	if req.MaxToolCalls != nil {
		if *req.MaxToolCalls < 1 || *req.MaxToolCalls > maxChatWebSearchCalls {
			return &AdapterError{Status: 400, Message: "max_tool_calls must be between 1 and 30", Context: "max_tool_calls"}
		}
		config.MaxCalls = min(config.MaxCalls, *req.MaxToolCalls)
	}
	if config.MaxTotalResults > 0 {
		config.MaxCalls = min(config.MaxCalls, config.MaxTotalResults)
	}
	if config.MaxCalls < 1 {
		config.MaxCalls = 1
	}
	if config.ForceSearch {
		req.ToolChoice = map[string]any{
			"type": "function", "function": map[string]any{"name": TrustedRouterWebSearchFunction},
		}
	} else if choice, ok := req.ToolChoice.(map[string]any); ok &&
		strings.TrimSpace(stringValue(choice["type"])) == "openrouter:web_search" {
		req.ToolChoice = map[string]any{
			"type": "function", "function": map[string]any{"name": TrustedRouterWebSearchFunction},
		}
	}
	req.Tools = normalizedTools
	req.WebSearchOptions = nil
	if req.Response == nil {
		req.Response = &types.ResponseRequestMeta{}
	}
	req.Response.WebSearch = config
	return nil
}

func normalizeChatFunctionToolFromChat(tool map[string]any) (map[string]any, error) {
	fn, ok := tool["function"].(map[string]any)
	if !ok {
		return nil, &AdapterError{Status: 400, Message: "function tool body is required", Context: "tools.function"}
	}
	return normalizeChatFunctionTool(fn)
}

func parseOpenRouterWebSearchTool(tool map[string]any) (*types.ResponseWebSearchConfig, error) {
	for key, value := range tool {
		if value == nil {
			continue
		}
		if key != "type" && key != "parameters" {
			return nil, unknownRequestParameter("tools." + key)
		}
	}
	parameters := map[string]any{}
	if raw, present := tool["parameters"]; present && raw != nil {
		var ok bool
		parameters, ok = raw.(map[string]any)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "web search parameters must be an object", Context: "tools.parameters"}
		}
	}
	config, err := parseExaWebSearchParameters(parameters, "tools.parameters")
	if err != nil {
		return nil, err
	}
	config.ToolType = "openrouter:web_search"
	config.RouteType = "chat.completions.web_search"
	return config, nil
}

func chatWebPluginConfig(plugins []any, webOptions map[string]any) (*types.ResponseWebSearchConfig, error) {
	var config *types.ResponseWebSearchConfig
	for index, rawPlugin := range plugins {
		plugin, ok := rawPlugin.(map[string]any)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "plugin must be an object", Context: fmt.Sprintf("plugins[%d]", index)}
		}
		id := strings.ToLower(strings.TrimSpace(stringValue(plugin["id"])))
		if id != "web" || pluginEnabledFalse(plugin) {
			continue
		}
		if config != nil {
			return nil, &AdapterError{Status: 400, Message: "only one web plugin is allowed", Context: "plugins.web"}
		}
		parameters := map[string]any{}
		for key, value := range plugin {
			switch key {
			case "id", "enabled":
			case "engine", "max_results", "search_prompt", "include_domains", "exclude_domains":
				parameters[key] = value
			default:
				if value != nil {
					return nil, unknownRequestParameter("plugins.web." + key)
				}
			}
		}
		parameters["allowed_domains"] = parameters["include_domains"]
		parameters["excluded_domains"] = parameters["exclude_domains"]
		delete(parameters, "include_domains")
		delete(parameters, "exclude_domains")
		parsed, err := parseExaWebSearchParameters(parameters, "plugins.web")
		if err != nil {
			return nil, err
		}
		parsed.ToolType = "web_plugin"
		parsed.RouteType = "chat.completions.web_search"
		parsed.MaxCalls = 1
		parsed.ForceSearch = true
		config = parsed
	}
	if config == nil {
		return nil, nil
	}
	for key, value := range webOptions {
		if key != "search_context_size" {
			return nil, unknownRequestParameter("web_search_options." + key)
		}
		size, ok := value.(string)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "search_context_size must be a string", Context: "web_search_options.search_context_size"}
		}
		if err := applySearchContextSize(config, size, "web_search_options.search_context_size"); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func parseExaWebSearchParameters(parameters map[string]any, context string) (*types.ResponseWebSearchConfig, error) {
	config := &types.ResponseWebSearchConfig{
		Engine: "exa", Mode: "auto", MaxResults: 5, MaxCalls: maxChatWebSearchCalls,
	}
	for key, value := range parameters {
		if value == nil {
			continue
		}
		switch key {
		case "engine":
			engine, ok := value.(string)
			if !ok {
				return nil, &AdapterError{Status: 400, Message: "web search engine must be a string", Context: context + ".engine"}
			}
			switch strings.ToLower(strings.TrimSpace(engine)) {
			case "", "auto", "exa":
				config.Engine = "exa"
			default:
				return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: context + ".engine"}
			}
		case "mode":
			mode, ok := value.(string)
			if !ok {
				return nil, &AdapterError{Status: 400, Message: "web search mode must be a string", Context: context + ".mode"}
			}
			mode = strings.ToLower(strings.TrimSpace(mode))
			switch mode {
			case "instant", "fast", "auto", "deep-lite", "deep", "deep-reasoning":
				config.Mode = mode
			default:
				return nil, &AdapterError{Status: 400, Message: "invalid Exa search mode", Context: context + ".mode"}
			}
		case "max_results":
			value, ok := integerParameter(value)
			if !ok || value < 1 || value > 25 {
				return nil, &AdapterError{Status: 400, Message: "max_results must be between 1 and 25", Context: context + ".max_results"}
			}
			config.MaxResults = value
		case "max_uses":
			value, ok := integerParameter(value)
			if !ok || value < 1 || value > maxChatWebSearchCalls {
				return nil, &AdapterError{Status: 400, Message: "max_uses must be between 1 and 30", Context: context + ".max_uses"}
			}
			config.MaxCalls = value
		case "max_total_results":
			value, ok := integerParameter(value)
			if !ok || value < 1 || value > 750 {
				return nil, &AdapterError{Status: 400, Message: "max_total_results must be between 1 and 750", Context: context + ".max_total_results"}
			}
			config.MaxTotalResults = value
		case "search_context_size":
			size, ok := value.(string)
			if !ok {
				return nil, &AdapterError{Status: 400, Message: "search_context_size must be a string", Context: context + ".search_context_size"}
			}
			if err := applySearchContextSize(config, size, context+".search_context_size"); err != nil {
				return nil, err
			}
		case "max_characters":
			value, ok := integerParameter(value)
			if !ok || value < 1 || value > 100_000 {
				return nil, &AdapterError{Status: 400, Message: "max_characters must be between 1 and 100000", Context: context + ".max_characters"}
			}
			config.MaxCharacters = value
		case "allowed_domains":
			domains, err := validatedDomains(value)
			if err != nil {
				return nil, err
			}
			config.AllowedDomains = domains
		case "excluded_domains":
			domains, err := validatedDomains(value)
			if err != nil {
				return nil, err
			}
			config.BlockedDomains = domains
		case "search_prompt":
			prompt, ok := value.(string)
			if !ok || len(prompt) > 4096 {
				return nil, &AdapterError{Status: 400, Message: "search_prompt must be a string of at most 4096 bytes", Context: context + ".search_prompt"}
			}
			config.SearchPrompt = strings.TrimSpace(prompt)
		case "user_location":
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: context + ".user_location"}
		default:
			return nil, unknownRequestParameter(context + "." + key)
		}
	}
	return config, nil
}

func applySearchContextSize(config *types.ResponseWebSearchConfig, size, context string) error {
	size = strings.ToLower(strings.TrimSpace(size))
	switch size {
	case "low", "medium", "high":
		config.SearchContextSize = size
		return nil
	default:
		return &AdapterError{Status: 400, Message: "invalid web search context size", Context: context}
	}
}

func integerParameter(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		return value, true
	case float64:
		if value != float64(int(value)) {
			return 0, false
		}
		return int(value), true
	default:
		return 0, false
	}
}

func pluginEnabledFalse(plugin map[string]any) bool {
	value, present := plugin["enabled"]
	if !present {
		return false
	}
	enabled, ok := value.(bool)
	return ok && !enabled
}

func webSearchUserLocation(config *types.ResponseWebSearchConfig) map[string]any {
	if config == nil || (config.UserCountry == "" && config.UserCity == "" && config.UserRegion == "" && config.UserTimezone == "") {
		return nil
	}
	return map[string]any{
		"type": "approximate", "country": config.UserCountry, "city": config.UserCity,
		"region": config.UserRegion, "timezone": config.UserTimezone,
	}
}
