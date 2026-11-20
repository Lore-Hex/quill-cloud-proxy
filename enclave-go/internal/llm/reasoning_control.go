package llm

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Moonshot accepts unknown efforts but silently uses a default. Enforce its
// reviewed K3 contract locally rather than treating HTTP 200 as validation.
func validateKimiReasoningEffort(provider string, req *qtypes.OpenAIChatRequest, model string) error {
	if normalizeDirectProvider(provider) != "kimi" || model != "kimi-k3" {
		return nil
	}
	effort := chatReasoningEffort(req)
	switch effort {
	case "", "low", "high", "max":
		return nil
	default:
		return &upstreamHTTPError{status: http.StatusBadRequest, body: fmt.Sprintf("Kimi K3 reasoning_effort must be low, high, or max; got %q", effort)}
	}
}

func chatReasoningEffort(req *qtypes.OpenAIChatRequest) string {
	if req == nil {
		return ""
	}
	if value := strings.TrimSpace(req.ReasoningEffort); value != "" {
		return strings.ToLower(value)
	}
	values, _ := req.Reasoning.(map[string]any)
	value, _ := values["effort"].(string)
	return strings.ToLower(strings.TrimSpace(value))
}

func applyChatReasoningEffort(provider string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, wire *openAICompatibleRequest) {
	effort := chatReasoningEffort(req)
	if effort == "" {
		return
	}
	dropSynthesizedThinkingBudget(body, wire)
	switch normalizeDirectProvider(provider) {
	case "meta", "openai", "gemini", "google-ai-studio", "deepseek", "zai", "kimi", "mistral", "alibaba", "tencent", "tinfoil", "grok", "baseten", "crusoe", "cerebras", "fireworks":
		// These chat endpoints consume top-level reasoning_effort. Responses
		// arrives here with nested reasoning.effort; passing that object through
		// silently used upstream defaults (including when effort was "none").
		wire.ReasoningEffort = effort
		wire.Reasoning = nil
	case "deepinfra", "io-net", "nebius", "novita", "parasail", "together":
		// Hosts outside the effort list, each observed on 2026-11-16
		// (docs/reasoning-output.md) to accept a top-level reasoning_effort,
		// alone and together with the reasoning object, and to accept it alone
		// on a model that does not reason. Five of them showed a clear
		// difference between low and high at the top level. Novita's was small
		// there and clear with both fields. Together and Nebius, and probably
		// Parasail, ignore an effort that is only inside the object. So here an
		// effort of low, medium or high written only inside the object also
		// goes top-level, and the object stays as the request holds it. Beside
		// reasoning.enabled=false nothing is added. A request that itself
		// holds both that Off and a top-level effort is sent with both, as
		// before. A native Messages request is passed through: its thinking
		// object is forwarded as written and nothing is derived from it.
		//
		// Served requests change here, so the list holds only what was
		// observed. Add a host after it has been observed, not before. Every
		// other host is sent the reasoning fields as the request holds them.
		native := body != nil && body.NativeContent
		if !native && strings.TrimSpace(req.ReasoningEffort) == "" && !chatReasoningExplicitlyOff(req) && topLevelCopiedEffort(effort) {
			wire.ReasoningEffort = effort
		}
	}
}

// topLevelCopiedEffort reports the efforts copied top-level for the observed
// hosts. The probe sent low and high. Medium was not probed: it is copied
// because it sits between those two. Any other word (none, off, minimal,
// xhigh, max, auto, an unknown one) stays inside the object alone, because a
// host that validates the top-level field could refuse it.
func topLevelCopiedEffort(effort string) bool {
	switch effort {
	case "low", "medium", "high":
		return true
	}
	return false
}

// chatReasoningExplicitlyOff reports a reasoning object that says
// enabled=false. A missing or non-boolean enabled is not Off.
func chatReasoningExplicitlyOff(req *qtypes.OpenAIChatRequest) bool {
	if req == nil {
		return false
	}
	values, _ := req.Reasoning.(map[string]any)
	enabled, explicit := values["enabled"].(bool)
	return explicit && !enabled
}

// The shared Anthropic projection synthesizes a budget for old Claude models.
// It is not a native thinking configuration for other providers.
func dropSynthesizedThinkingBudget(body *qtypes.AnthropicMessagesRequest, wire *openAICompatibleRequest) {
	if body != nil && !body.NativeContent {
		if thinking, ok := wire.Thinking.(map[string]any); ok && thinking["budget_tokens"] != nil {
			wire.Thinking = nil
		}
	}
}

// Native hybrid-model switches are not OpenAI reasoning objects or Anthropic
// token budgets. In particular, forwarding enabled:false unchanged can be
// silently ignored by a direct provider and leave thinking on.
func applyHybridReasoningControl(provider string, req *qtypes.OpenAIChatRequest, wire *openAICompatibleRequest) {
	if req == nil {
		return
	}
	switch normalizeDirectProvider(provider) {
	case "zai", "deepseek", "kimi", "tencent":
	default:
		return
	}
	values, ok := req.Reasoning.(map[string]any)
	if !ok {
		return
	}
	enabled, explicit := values["enabled"].(bool)
	if !explicit {
		return
	}
	mode := "disabled"
	if enabled {
		mode = "enabled"
		// TokenHub's MiniMax M3 supports adaptive, not enabled.
		if normalizeDirectProvider(provider) == "tencent" && wire.Model == "minimax-m3" {
			mode = "adaptive"
		}
	}
	wire.Thinking = map[string]string{"type": mode}
	wire.Reasoning = nil
	if normalizeDirectProvider(provider) == "tencent" && enabled && (wire.Model == "kimi-k3" || wire.Model == "kimi-k2.8-preview") {
		// These always-thinking Kimi models use effort, not thinking.type.
		wire.Thinking = nil
		if wire.ReasoningEffort == "" {
			wire.ReasoningEffort = "high"
			if wire.Model == "kimi-k2.8-preview" {
				wire.ReasoningEffort = "max"
			}
		}
	}
	// An explicit Off cannot coexist with an effort that turns thinking back
	// on. On keeps a separately supplied effort for providers that accept it.
	if !enabled {
		wire.ReasoningEffort = ""
	}
}

func validateTencentThinking(wire openAICompatibleRequest) error {
	mode := ""
	switch thinking := wire.Thinking.(type) {
	case map[string]string:
		mode = thinking["type"]
	case map[string]any:
		mode, _ = thinking["type"].(string)
	}
	// Reject unsupported explicit controls rather than silently turning thinking
	// back on. Native IDs remain opaque; these are documented exact model IDs.
	switch wire.Model {
	case "glm-5.3", "glm-5.3-flash", "glm-5.3-flashx", "kimi-k2.7-code", "kimi-k2.7-code-highspeed":
		if mode == "disabled" {
			return &upstreamHTTPError{status: http.StatusBadRequest, body: "Tencent TokenHub model does not support disabling thinking"}
		}
	case "kimi-k3", "kimi-k2.8-preview":
		if wire.Thinking != nil {
			return &upstreamHTTPError{status: http.StatusBadRequest, body: "Tencent TokenHub model is always thinking; use reasoning_effort instead of thinking"}
		}
	case "minimax-m3":
		if mode == "enabled" {
			return &upstreamHTTPError{status: http.StatusBadRequest, body: "Tencent TokenHub MiniMax M3 requires adaptive or disabled thinking"}
		}
	}
	return nil
}

func explicitHybridThinkingConflict(provider string, req *qtypes.OpenAIChatRequest, wire openAICompatibleRequest) bool {
	if normalizeDirectProvider(provider) != "kimi" || req == nil {
		return false
	}
	values, _ := req.Reasoning.(map[string]any)
	enabled, _ := values["enabled"].(bool)
	thinking, _ := wire.Thinking.(map[string]string)
	return enabled && thinking["type"] == "disabled"
}

// openAIChatEffortNone names the first-party OpenAI models whose reviewed
// reasoning_effort list holds none (quill-router
// data/request_capabilities.json), each alone or with a -YYYY-MM-DD snapshot.
// gpt-5, gpt-5-mini, gpt-5-nano and the o-series document no way to stop
// reasoning, and neither does any model not listed here.
var openAIChatEffortNone = regexp.MustCompile(`^gpt-(5\.(1|2|4)(-mini|-nano)?|5\.5|5\.6-(luna|sol|terra)|6-(luna|sol)|6\.1-terra)(-[0-9]{4}-[0-9]{2}-[0-9]{2})?$`)

// openAIChatNoReasoning names the first-party OpenAI chat models that do not
// reason (quill-router data/request_capabilities.json lists no effort for
// them). Off asks nothing of them, so it is the request without a control.
var openAIChatNoReasoning = regexp.MustCompile(`^(gpt-4|gpt-3\.5|chat-latest)`)

// openAIChatOnEffort is the effort On alone sends to first-party OpenAI chat
// completions. Every reviewed OpenAI reasoning model lists it, it is OpenAI's
// documented default for the models that reason by default, and it is the
// depth the shared projection already gives On alone elsewhere (the medium
// budget). Sending nothing would leave On ignored on gpt-5.1 and later chat
// models, whose default effort is none.
const openAIChatOnEffort = "medium"

// applyOpenAIChatReasoning projects the reasoning controls onto first-party
// OpenAI chat completions, whose only reasoning control is top-level
// reasoning_effort. OpenAI answers 400 "Unknown parameter" to a thinking
// field or a reasoning object, so neither is ever sent. The switch becomes an
// effort: On alone is medium, On with an effort is that effort, Off is none
// and governs an effort beside it; on a model that does not reason Off is
// the request without a control. Off on a reasoning model that cannot turn
// reasoning off, and a thinking token budget, which OpenAI does not take, are refused
// here, the same retryable 400 the Responses tool route gives them, so the
// next candidate for the model is tried. The Responses tool route has its own
// projection (responsesReasoning) and does not come here.
func applyOpenAIChatReasoning(model string, req *qtypes.OpenAIChatRequest, wire *openAICompatibleRequest) error {
	wire.Thinking = nil
	wire.Reasoning = nil
	if req == nil {
		return nil
	}
	model = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(model)), "openai/")
	refuse := func(message string) error {
		return &upstreamHTTPError{status: http.StatusBadRequest, body: "OpenAI chat route: " + message}
	}
	ask := claudeReasoningAskOf(req)
	switch {
	case ask.off && openAIChatNoReasoning.MatchString(model):
		wire.ReasoningEffort = ""
	case ask.off:
		if !openAIChatEffortNone.MatchString(model) {
			return refuse("this model cannot turn reasoning off")
		}
		wire.ReasoningEffort = "none"
	case ask.budget:
		return refuse("this model takes a reasoning effort, not a thinking token budget")
	case ask.effort != "":
		wire.ReasoningEffort = ask.effort
	case ask.on:
		wire.ReasoningEffort = openAIChatOnEffort
	}
	return nil
}
