package adapter

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func projectedThinking(t *testing.T, req *types.OpenAIChatRequest) *types.AnthropicMessagesRequest {
	t.Helper()
	req.Messages = []types.OpenAIChatMessage{{Role: "user", Content: "think"}}
	body, err := ToAnthropic(req, "model-ignored")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Every provider reads the shared projection, so the Claude effort ladder
// lives in the Claude dispatch and the projection keeps what it has always
// written. A change here would reach providers that are not Claude.
func TestSharedProjectionIsNotChangedByTheClaudeLadder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		req    types.OpenAIChatRequest
		budget any
	}{
		{"low", types.OpenAIChatRequest{ReasoningEffort: "low"}, 1024},
		{"medium", types.OpenAIChatRequest{ReasoningEffort: "medium"}, 4096},
		{"high", types.OpenAIChatRequest{ReasoningEffort: "high"}, 8192},
		{"xhigh", types.OpenAIChatRequest{ReasoningEffort: "xhigh"}, 8192},
		{"max", types.OpenAIChatRequest{ReasoningEffort: "max"}, nil},
		{"minimal", types.OpenAIChatRequest{ReasoningEffort: "minimal"}, nil},
		{"unknown", types.OpenAIChatRequest{ReasoningEffort: "ultra"}, nil},
		{"On alone", types.OpenAIChatRequest{Reasoning: map[string]any{"enabled": true}}, 4096},
		{"On beside a top-level effort", types.OpenAIChatRequest{Reasoning: map[string]any{"enabled": true}, ReasoningEffort: "low"}, 4096},
		{"Off beside a top-level effort", types.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}, ReasoningEffort: "high"}, 8192},
		{"Off alone", types.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}}, nil},
	} {
		body := projectedThinking(t, &tc.req)
		thinking, _ := body.Thinking.(map[string]any)
		if !reflect.DeepEqual(thinking["budget_tokens"], tc.budget) {
			t.Errorf("%s: budget_tokens=%v, want %v", tc.name, thinking["budget_tokens"], tc.budget)
		}
	}
}

// The Claude dispatch builds a ladder budget with AnthropicBudgetThinking. It
// must give exactly what ToAnthropic gives for the same budget, including a
// caller cap below the budget and a funded allowance that includes thinking.
func TestAnthropicBudgetThinkingMatchesTheProjection(t *testing.T) {
	limit := func(n int) *int { return &n }
	for _, maxTokens := range []*int{nil, limit(1), limit(100), limit(512), limit(1024), limit(4096), limit(8192), limit(8193), limit(60000)} {
		for _, funded := range []int{0, 1, 1024, 1025, 2000, 8192, 60000} {
			for effort, budget := range map[string]int{"low": 1024, "medium": 4096, "high": 8192} {
				req := &types.OpenAIChatRequest{ReasoningEffort: effort, MaxTokens: maxTokens, InternalOutputTokenLimit: funded}
				body := projectedThinking(t, req)
				thinking, wireMax := AnthropicBudgetThinking(req, budget, body.MaxTokens)
				if !reflect.DeepEqual(thinking, body.Thinking) || wireMax != body.AnthropicMaxTokens {
					got, _ := json.Marshal(thinking)
					want, _ := json.Marshal(body.Thinking)
					t.Errorf("max_tokens=%v funded=%d %s: got %s and %d, the projection writes %s and %d", body.MaxTokens, funded, effort, got, wireMax, want, body.AnthropicMaxTokens)
				}
			}
		}
	}
	if thinking, wireMax := AnthropicBudgetThinking(&types.OpenAIChatRequest{}, 0, 4096); thinking != nil || wireMax != 0 {
		t.Errorf("no budget: thinking=%v max_tokens=%d", thinking, wireMax)
	}
	if thinking, wireMax := AnthropicBudgetThinking(nil, 8192, 4096); thinking != nil || wireMax != 0 {
		t.Errorf("no request: thinking=%v max_tokens=%d", thinking, wireMax)
	}
}

func TestExplicitThinkingBudget(t *testing.T) {
	for _, tc := range []struct {
		reasoning any
		want      int
	}{
		{nil, 0}, {true, 0}, {"high", 0},
		{map[string]any{"effort": "high"}, 0},
		{map[string]any{"enabled": true}, 0},
		{map[string]any{"max_tokens": 0}, 0},
		{map[string]any{"thinking_budget": -1}, 0},
		{map[string]any{"max_tokens": float64(2048)}, 2048},
		{map[string]any{"thinking_budget": 4000}, 4000},
		{map[string]any{"budget_tokens": json.Number("6000")}, 6000},
		{map[string]any{"max_tokens": 2048, "budget_tokens": 6000}, 2048},
	} {
		if got := ExplicitThinkingBudget(tc.reasoning); got != tc.want {
			t.Errorf("%v: got %d, want %d", tc.reasoning, got, tc.want)
		}
		// It is the budget the projection itself reads from the object.
		if budget, ok := anthropicThinkingBudgetFromReasoning(tc.reasoning); tc.want > 0 && (!ok || budget != tc.want) {
			t.Errorf("%v: the projection reads %d", tc.reasoning, budget)
		}
	}
}
