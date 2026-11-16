package llm

import (
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// claudeReasoningClass is how a Claude model takes a reasoning request.
type claudeReasoningClass string

const (
	// claudeFull thinks adaptively at low, medium, high, xhigh or max.
	claudeFull claudeReasoningClass = "full"
	// claudeV46 thinks adaptively at low, medium, high or max.
	claudeV46 claudeReasoningClass = "v46"
	// claudeOpus45 takes a thinking token budget beside an effort of low,
	// medium or high.
	claudeOpus45 claudeReasoningClass = "opus45"
	// claudeBudget takes a thinking token budget and has no effort field.
	// Every Claude ID that claudeReasoningModels does not name is here.
	claudeBudget claudeReasoningClass = "budget"
)

// claudeReasoningModels names the Claude models that are not budget-only. An
// ID is matched lowercased, with "." read as "-", by substring, so a catalog
// ID, a dated snapshot, a Bedrock profile and a Vertex ID all match. A new
// Claude model must be added here or it takes the budget path, which the
// newer models refuse: TestEveryKnownClaudeModelHasAReasoningClass fails for
// an ID in a route table that the test's own table does not list.
var claudeReasoningModels = []struct {
	id    string
	class claudeReasoningClass
}{
	{"claude-opus-4-5", claudeOpus45},
	{"claude-opus-4-6", claudeV46},
	{"claude-sonnet-4-6", claudeV46},
	{"claude-opus-4-7", claudeFull},
	{"claude-opus-4-8", claudeFull},
	{"claude-opus-5", claudeFull},
	{"claude-sonnet-5", claudeFull},
	{"claude-haiku-5", claudeFull},
	{"claude-fable-5", claudeFull},
	{"claude-mythos-5", claudeFull},
}

// claudeReasoningClassOf is the class of a model ID, and false for an ID that
// is not a Claude model: its body is sent as built.
func claudeReasoningClassOf(model string) (claudeReasoningClass, bool) {
	model = claudeModelKey(model)
	if !strings.Contains(model, "claude") {
		return "", false
	}
	for _, known := range claudeReasoningModels {
		if strings.Contains(model, known.id) {
			return known.class, true
		}
	}
	return claudeBudget, true
}

// claudeModelKey is a model ID in the form the class table matches.
func claudeModelKey(model string) string {
	return strings.ReplaceAll(strings.ToLower(model), ".", "-")
}

// claudeEffortStep is what one effort word becomes on one class: the
// output_config.effort sent, and the thinking token budget where the class
// takes one. A zero budget is no thinking.
type claudeEffortStep struct {
	effort string
	budget int
}

// claudeEffortLadders states each class's ladder. An effort is a request for
// depth, so it never fails a request and is never ignored: an effort the
// model does not have becomes the nearest one it has, rounding down. Minimal
// sits below every ladder. It becomes the lowest effort where the model has
// an effort field, and no thinking where the only control is a budget, whose
// floor of 1,024 tokens is already low. A word that is not listed is sent as
// written where there is an effort field and sets no budget.
var claudeEffortLadders = map[claudeReasoningClass]map[string]claudeEffortStep{
	claudeFull: {
		"minimal": {effort: "low"}, "low": {effort: "low"}, "medium": {effort: "medium"},
		"high": {effort: "high"}, "xhigh": {effort: "xhigh"}, "max": {effort: "max"},
	},
	claudeV46: {
		"minimal": {effort: "low"}, "low": {effort: "low"}, "medium": {effort: "medium"},
		"high": {effort: "high"}, "xhigh": {effort: "high"}, "max": {effort: "max"},
	},
	claudeOpus45: {
		"minimal": {effort: "low"}, "low": {effort: "low", budget: 1024}, "medium": {effort: "medium", budget: 4096},
		"high": {effort: "high", budget: 8192}, "xhigh": {effort: "high", budget: 8192}, "max": {effort: "high", budget: 8192},
	},
	claudeBudget: {
		"minimal": {}, "low": {budget: 1024}, "medium": {budget: 4096},
		"high": {budget: 8192}, "xhigh": {budget: 8192}, "max": {budget: 8192},
	},
}

func (class claudeReasoningClass) step(effort string) claudeEffortStep {
	if step, listed := claudeEffortLadders[class][effort]; listed {
		return step
	}
	if class == claudeBudget {
		return claudeEffortStep{}
	}
	return claudeEffortStep{effort: effort}
}

// claudeReasoningAsk is what a chat request asks of a Claude model.
type claudeReasoningAsk struct {
	// effort is the effort word, lowercased. It is "none" when the request
	// turns thinking off, which governs over any effort beside it.
	effort string
	// on is true when the caller turned thinking on, not only named a depth.
	on bool
	// budget is true when the caller named a thinking token budget.
	budget bool
}

func claudeReasoningAskOf(req *qtypes.OpenAIChatRequest) claudeReasoningAsk {
	ask := claudeReasoningAsk{effort: chatReasoningEffort(req), budget: adapter.ExplicitThinkingBudget(req.Reasoning) > 0}
	switch reasoning := req.Reasoning.(type) {
	case bool:
		ask.on = reasoning
	case map[string]any:
		if mode, _ := reasoning["type"].(string); strings.EqualFold(mode, "enabled") || strings.EqualFold(mode, "adaptive") {
			ask.on = true
		}
		if enabled, present := reasoning["enabled"].(bool); present {
			ask.on = enabled
			if !enabled {
				ask.effort = "none"
			}
		}
	}
	return ask
}

// Resolve effort at dispatch, after fallback has selected the actual model.
// Never mutate the shared request body or reinterpret native Messages input.
func anthropicChatReasoningBody(model string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) *qtypes.AnthropicMessagesRequest {
	if req == nil || body == nil || body.NativeContent {
		return body
	}
	class, claude := claudeReasoningClassOf(model)
	if !claude {
		return body
	}
	ask := claudeReasoningAskOf(req)
	if class == claudeFull || class == claudeV46 {
		return claudeAdaptiveReasoningBody(model, class, ask, req, body)
	}
	return claudeBudgetReasoningBody(class, ask, req, body)
}

func claudeAdaptiveReasoningBody(model string, class claudeReasoningClass, ask claudeReasoningAsk, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) *qtypes.AnthropicMessagesRequest {
	if ask.effort == "" {
		// A body whose thinking is already configured keeps its own limit.
		if body.Thinking == nil && anthropicThinkingDefaultCapApplies(req, body) {
			result := *body
			result.AnthropicMaxTokens = AnthropicThinkingDefaultMaxTokens
			return &result
		}
		return body
	}
	result := *body
	if ask.effort == "none" {
		result.Thinking = map[string]any{"type": "disabled"}
		// Sonnet 5.5 refuses disabled and names this as its Off: it does not
		// think before responding. Opus 5.5 and Fable 5 have no Off at all.
		if strings.Contains(claudeModelKey(model), "claude-sonnet-5-5") {
			result.Thinking = map[string]any{"type": "between_tools"}
		}
		result.AnthropicMaxTokens = 0
		return &result
	}
	result.OutputConfig = claudeOutputConfigWithEffort(body, class.step(ask.effort).effort)
	// An explicit caller budget still takes precedence over an effort-derived
	// thinking mode. The provider validates whether its model accepts budgets.
	if values, ok := req.Reasoning.(map[string]any); ok && values["max_tokens"] != nil {
		return &result
	}
	result.Thinking = map[string]any{"type": "adaptive"}
	result.AnthropicMaxTokens = 0
	if anthropicThinkingDefaultCapApplies(req, body) {
		result.AnthropicMaxTokens = AnthropicThinkingDefaultMaxTokens
	}
	result.Temperature = nil
	result.TopP = nil
	return &result
}

// claudeBudgetReasoningBody serves Opus 4.5 and the budget-only models, whose
// thinking is a token budget. The shared projection has already written a
// budget for On alone and for a budget the caller named, and those stand.
// What the selected model's ladder decides is settled here.
func claudeBudgetReasoningBody(class claudeReasoningClass, ask claudeReasoningAsk, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) *qtypes.AnthropicMessagesRequest {
	result := *body
	switch {
	case ask.effort == "none":
		// Off governs, even beside an effort or a budget. Nothing is left of
		// the room the shared projection made for a budget that is not sent.
		result.Thinking = nil
		if class == claudeOpus45 {
			result.Thinking = map[string]any{"type": "disabled"}
		}
		result.AnthropicMaxTokens = 0
		return &result
	case ask.effort != "":
		step := class.step(ask.effort)
		if step.effort != "" {
			result.OutputConfig = claudeOutputConfigWithEffort(body, step.effort)
		}
		if ask.budget {
			break
		}
		// On beside an effort is that effort, so the ladder's budget replaces
		// whatever the shared projection chose. Thinking that only an effort
		// asked for gives way where Anthropic refuses thinking outright.
		// Thinking the caller turned on is left for the provider to judge.
		budget := step.budget
		if !ask.on && claudeRefusesThinking(body) {
			budget = 0
		}
		result.Thinking, result.AnthropicMaxTokens = adapter.AnthropicBudgetThinking(req, budget, body.MaxTokens)
	}
	if thinking, ok := result.Thinking.(map[string]any); !ok || thinking["budget_tokens"] == nil {
		if ask.effort == "" {
			return body
		}
		return &result
	}
	// Anthropic refuses these beside budget thinking: a temperature other
	// than 1, top_k, and a top_p below 0.95. Thinking is what was asked for.
	if result.Temperature != nil && *result.Temperature != 1 {
		result.Temperature = nil
	}
	if result.TopP != nil && *result.TopP < 0.95 {
		result.TopP = nil
	}
	result.TopK = nil
	return &result
}

// claudeRefusesThinking reports a request Anthropic refuses with budget
// thinking on: a forced tool choice, or a final assistant message to continue.
func claudeRefusesThinking(body *qtypes.AnthropicMessagesRequest) bool {
	if choice := body.ToolChoice; choice != nil && (choice.Type == "any" || choice.Type == "tool") {
		return true
	}
	return len(body.Messages) > 0 && body.Messages[len(body.Messages)-1].Role == "assistant"
}

// Keep format and other native output controls while adding effort.
func claudeOutputConfigWithEffort(body *qtypes.AnthropicMessagesRequest, effort string) map[string]any {
	config := map[string]any{}
	if original, ok := body.OutputConfig.(map[string]any); ok {
		for key, value := range original {
			config[key] = value
		}
	}
	config["effort"] = effort
	return config
}

// AnthropicThinkingDefaultMaxTokens is the output ceiling sent to a model that
// thinks adaptively when the caller set none. adapter.DefaultMaxTokens (4096)
// is a wire requirement, not a choice, and it counts thinking: a high-effort
// Opus 5.5 turn spent all 4096 thinking and was cut off (AnyEval Terminal-Bench
// 4.0, 2026-10-02). OpenAI-compatible upstreams already omit the cap entirely.
// 32000 is within every listed model's output maximum; upstream calls stream.
// Authorization is unchanged: an uncapped request is still estimated at 512.
const AnthropicThinkingDefaultMaxTokens = 32000

// anthropicThinkingDefaultCapApplies is true only for a caller that set no cap
// and no funded orchestration allowance, on a body still at the wire default.
// An adapter-derived AnthropicMaxTokens (budget + default) is not a caller cap:
// adaptive dispatch discards it, and an explicit caller budget returns earlier.
func anthropicThinkingDefaultCapApplies(req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) bool {
	return !body.MaxTokensExplicit && req.InternalOutputTokenLimit <= 0 &&
		body.MaxTokens == adapter.DefaultMaxTokens
}
