package llm

import (
	"regexp"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// claudeReasoningClass is how a Claude model takes a reasoning request.
type claudeReasoningClass string

const (
	// claudeFull thinks adaptively at low, medium, high, xhigh or max, and
	// refuses a thinking budget. Every Claude ID that claudeReasoningModels
	// does not name is here.
	claudeFull claudeReasoningClass = "full"
	// claudeV46 thinks adaptively at low, medium, high or max, and still
	// takes a thinking budget.
	claudeV46 claudeReasoningClass = "v46"
	// claudeOpus45 takes a thinking token budget beside an effort of low,
	// medium or high.
	claudeOpus45 claudeReasoningClass = "opus45"
	// claudeBudget takes a thinking token budget and has no effort field. It
	// is a closed list of older models.
	claudeBudget claudeReasoningClass = "budget"
)

// claudeVersionEnd follows a version number in a model ID: the ID ends there,
// or what follows is not another digit. So 4-5 never matches 4-50.
const claudeVersionEnd = `($|[^0-9])`

// claudeReasoningModels names every Claude model that is not in the full
// class. An ID is matched lowercased, with "." read as "-", anywhere in the
// ID, so a catalog ID, a dated snapshot, a Bedrock profile and a Vertex ID
// all match. Each model is listed family first, as Anthropic names it now
// (claude-sonnet-4-5), and version first, as older IDs and some deployment
// names have it (claude-4-5-sonnet, claude-3-7-sonnet).
//
// The default is the full class on purpose. A new Claude model reaches the
// gateway through the catalog, with no change here, and every model since
// Opus 4.7 refuses a thinking budget. So the budget classes are closed lists
// of models that exist, and an ID nobody listed is sent adaptive thinking.
// TestEveryKnownClaudeModelHasAReasoningClass pins the class of every Claude
// ID written in the source.
var claudeReasoningModels = []struct {
	match *regexp.Regexp
	class claudeReasoningClass
}{
	{regexp.MustCompile(`claude-opus-4-5` + claudeVersionEnd + `|claude-4-5-opus`), claudeOpus45},
	{regexp.MustCompile(`claude-(opus|sonnet)-4-6` + claudeVersionEnd + `|claude-4-6-`), claudeV46},
	// Haiku 4.5, Sonnet 4.5 and Opus 4.1.
	{regexp.MustCompile(`claude-(sonnet|haiku)-4-5` + claudeVersionEnd + `|claude-4-5-(sonnet|haiku)`), claudeBudget},
	{regexp.MustCompile(`claude-opus-4-1` + claudeVersionEnd + `|claude-4-1-opus`), claudeBudget},
	// Opus 4 and Sonnet 4. Family first, the ID ends at the 4, or what follows
	// is a date, a Vertex "@", a ":" or the "-0" of the 4-0 alias. A minor
	// version does not match, so Sonnet 4.6, Opus 4.7 and any later 4.x fall
	// through to their own class. Version first, only the bare 4 is here: any
	// other version-first 4.x that no row names is in the full class.
	{regexp.MustCompile(`claude-(opus|sonnet)-4($|[@:]|-0` + claudeVersionEnd + `|-[0-9]{8})|claude-4-(opus|sonnet)`), claudeBudget},
	// The 3.x families and everything older.
	{regexp.MustCompile(`claude-(3|v?2|instant)` + claudeVersionEnd + `|claude-(opus|sonnet|haiku)-3` + claudeVersionEnd), claudeBudget},
}

// claudeSonnet55 matches the one model whose Off is between_tools.
var claudeSonnet55 = regexp.MustCompile(`claude-sonnet-5-5` + claudeVersionEnd)

// claudeReasoningClassOf is the class of a model ID, and false for an ID that
// is not a Claude model: its body is sent as built.
func claudeReasoningClassOf(model string) (claudeReasoningClass, bool) {
	model = claudeModelKey(model)
	if !strings.Contains(model, "claude") {
		return "", false
	}
	for _, known := range claudeReasoningModels {
		if known.match.MatchString(model) {
			return known.class, true
		}
	}
	return claudeFull, true
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
// written where there is an effort field and sets no budget. On beside either
// still thinks on a budget class: see claudeBudgetReasoningBody.
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

// step is what an effort word becomes on a class, and whether the class's
// ladder lists the word.
func (class claudeReasoningClass) step(effort string) (claudeEffortStep, bool) {
	if step, listed := claudeEffortLadders[class][effort]; listed {
		return step, true
	}
	if class == claudeBudget {
		return claudeEffortStep{}, false
	}
	return claudeEffortStep{effort: effort}, false
}

// claudeKnownEffortWord reports a word the gateway knows as an effort: a step
// every ladder lists, or a word that means Off.
func claudeKnownEffortWord(word string) bool {
	_, step := claudeEffortLadders[claudeFull][word]
	return step || adapter.ReasoningEffortOff(word)
}

const (
	// claudeMinimumBudget is the smallest thinking budget Anthropic takes.
	claudeMinimumBudget = 1024
	// claudeOnBudget is the thinking budget On alone is, as the shared
	// projection writes it.
	claudeOnBudget = 4096
)

// claudeReasoningAsk is what a chat request asks of a Claude model.
type claudeReasoningAsk struct {
	// off is true when the request turns thinking off. Off governs over an
	// On, an effort and a budget beside it.
	off bool
	// effort is the effort word, lowercased. With two efforts in a request
	// it is the top-level one.
	effort string
	// on is true when the caller turned thinking on, not only named a depth.
	on bool
	// budget is true when the caller named a thinking token budget.
	budget bool
}

// claudeReasoningAskOf reads the request. Off has two kinds of spelling. The
// switch forms always govern: reasoning.enabled false, a bare reasoning
// false, and reasoning.type disabled. The word forms are efforts: none, off,
// disable and disabled. A word is Off only when it is the request's effort,
// and with two efforts in a request that is the top-level one. So an Off word
// in the reasoning object beside a top-level effort is not Off. The contract
// layer has already refused a switch beside an Off word, so On beside one
// arrives here only from the reasoning object.
//
// A bare string, reasoning "high", is an effort written in the reasoning
// field, when it is a word the gateway knows. Then it is read like
// reasoning.effort: it is the request's effort when there is no top-level
// one. Any other string is not an effort and asks nothing, as it always has:
// reading it as one would send an unknown word to models that refuse it.
func claudeReasoningAskOf(req *qtypes.OpenAIChatRequest) claudeReasoningAsk {
	ask := claudeReasoningAsk{effort: chatReasoningEffort(req), budget: adapter.ExplicitThinkingBudget(req.Reasoning) > 0}
	if bare, isString := req.Reasoning.(string); isString && ask.effort == "" {
		if word := strings.ToLower(strings.TrimSpace(bare)); claudeKnownEffortWord(word) {
			ask.effort = word
		}
	}
	ask.off = adapter.ReasoningEffortOff(ask.effort)
	switch reasoning := req.Reasoning.(type) {
	case bool:
		ask.on, ask.off = reasoning, ask.off || !reasoning
	case map[string]any:
		mode, _ := reasoning["type"].(string)
		enabled, switched := reasoning["enabled"].(bool)
		ask.on = (switched && enabled) || strings.EqualFold(mode, "enabled") || strings.EqualFold(mode, "adaptive")
		ask.off = ask.off || (switched && !enabled) || strings.EqualFold(mode, "disabled")
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
	result := *body
	switch {
	case ask.off:
		result.Thinking = map[string]any{"type": "disabled"}
		// Sonnet 5.5 refuses disabled and names this as its Off: it does not
		// think before responding. Opus 5.5 and Fable 5 have no Off at all.
		if claudeSonnet55.MatchString(claudeModelKey(model)) {
			result.Thinking = map[string]any{"type": "between_tools"}
		}
		// No room is kept for a budget that is not sent. A caller who set no
		// limit keeps the default of the class, the same one a request with
		// no reasoning ask gets: Off must not shorten the answer.
		result.AnthropicMaxTokens = 0
		if anthropicThinkingDefaultCapApplies(req, body) {
			result.AnthropicMaxTokens = AnthropicThinkingDefaultMaxTokens
		}
		return &result
	case ask.effort != "":
		step, _ := class.step(ask.effort)
		result.OutputConfig = claudeOutputConfigWithEffort(body, step.effort)
		// An explicit caller budget still takes precedence over an effort-derived
		// thinking mode. The provider validates whether its model accepts budgets.
		if values, ok := req.Reasoning.(map[string]any); ok && values["max_tokens"] != nil {
			return &result
		}
	case class == claudeFull && ask.on && !ask.budget && !claudeAllowanceTooSmallToThink(req):
		// On alone. The full class refuses a thinking budget, so the 4,096
		// tokens the shared projection wrote for On cannot be sent. On is
		// adaptive thinking with no effort named: the model's own depth. The
		// 4.6 models still take the budget, and a budget the caller named is
		// left for the provider to judge.
	default:
		// A body whose thinking is already configured keeps its own limit.
		if body.Thinking == nil && anthropicThinkingDefaultCapApplies(req, body) {
			result.AnthropicMaxTokens = AnthropicThinkingDefaultMaxTokens
			return &result
		}
		return body
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

// claudeAllowanceTooSmallToThink is true for a funded allowance that cannot
// hold thinking and an answer. The shared projection writes no budget for
// one, and On alone asks for no adaptive thinking inside one either.
func claudeAllowanceTooSmallToThink(req *qtypes.OpenAIChatRequest) bool {
	return req.InternalOutputTokenLimit > 0 && req.InternalOutputTokenLimit <= claudeMinimumBudget
}

// claudeBudgetReasoningBody serves Opus 4.5 and the budget-only models, whose
// thinking is a token budget. The shared projection has already written a
// budget for On alone and for a budget the caller named, and those stand.
// What the selected model's ladder decides is settled here.
func claudeBudgetReasoningBody(class claudeReasoningClass, ask claudeReasoningAsk, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) *qtypes.AnthropicMessagesRequest {
	if ask == (claudeReasoningAsk{}) && body.Thinking == nil {
		return body
	}
	result := *body
	switch {
	case ask.off:
		// Off governs, even beside an effort or a budget. Nothing is left of
		// the room the shared projection made for a budget that is not sent.
		result.Thinking = nil
		if class == claudeOpus45 {
			result.Thinking = map[string]any{"type": "disabled"}
		}
		result.AnthropicMaxTokens = 0
		return &result
	case ask.effort != "":
		step, listed := class.step(ask.effort)
		if step.effort != "" {
			result.OutputConfig = claudeOutputConfigWithEffort(body, step.effort)
		}
		if ask.budget {
			break
		}
		// On beside an effort is that effort, so the ladder's budget replaces
		// whatever the shared projection chose.
		budget := step.budget
		if ask.on && budget == 0 {
			// On is an explicit ask, so it always turns thinking on. Beside an
			// effort below the ladder it is the smallest budget. Beside a word
			// the ladder does not know it is what On alone asks for.
			budget = claudeOnBudget
			if listed {
				budget = claudeMinimumBudget
			}
		}
		result.Thinking, result.AnthropicMaxTokens = adapter.AnthropicBudgetThinking(req, budget, body.MaxTokens)
	}
	thinking, _ := result.Thinking.(map[string]any)
	if thinking["budget_tokens"] == nil {
		return &result
	}
	// A forced tool choice or a prefill beats any budget the gateway chose,
	// from an effort or from On. Anthropic refuses budget thinking beside
	// them every time, so sending it has one outcome. Only a budget the
	// caller named in tokens is left for the provider to judge.
	if !ask.budget && claudeRefusesThinking(body) {
		result.Thinking, result.AnthropicMaxTokens = nil, 0
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
