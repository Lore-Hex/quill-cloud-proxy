package llm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/testutil/fundedrequest"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// The four classes, each in every ID spelling the dispatch is handed: the
// Anthropic ID, a dated snapshot, the catalog ID, a Bedrock profile and a
// Vertex ID.
var (
	claudeFullIDs = []string{
		"claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-opus-5-5", "claude-sonnet-5", "claude-sonnet-5-5",
		"claude-fable-5-1", "claude-haiku-5-5", "claude-mythos-5", "claude-mythos-5-2",
		"anthropic/claude-haiku-5.5", "anthropic/claude-fable-5.1", "us.anthropic.claude-haiku-5-5", "us.anthropic.claude-opus-5-5",
		"claude-haiku-5-5@20261001", "claude-mythos-5@20261101", "claude-sonnet-5-20260203", "Claude-Opus-4.8",
	}
	claudeV46IDs    = []string{"claude-sonnet-4-6", "claude-opus-4-6", "anthropic/claude-sonnet-4.6", "us.anthropic.claude-sonnet-4-6", "claude-opus-4-6@20260205"}
	claudeOpus45IDs = []string{"claude-opus-4-5", "claude-opus-4-5-20251101", "anthropic/claude-opus-4.5", "us.anthropic.claude-opus-4-5-20251101-v1:0", "claude-opus-4-5@20251101"}
	claudeBudgetIDs = []string{
		"claude-haiku-4-5", "claude-haiku-4-5-20251001", "anthropic/claude-haiku-4.5", "us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5@20251001",
		"claude-sonnet-4-5-20250929", "claude-sonnet-4-5@20250929", "claude-opus-4-1-20250805", "claude-opus-4-20250514", "claude-sonnet-4-20250514",
		"claude-3-5-sonnet-20241022", "claude-3-7-sonnet-20250219", "claude-3-5-haiku-20241022",
	}
)

const claudeTestTools = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}]`

// claudeChat builds the chat request and the shared projection the gateway
// builds for it. fields is the request JSON after the messages.
func claudeChat(t *testing.T, fields string) (*qtypes.OpenAIChatRequest, *qtypes.AnthropicMessagesRequest) {
	t.Helper()
	payload := `{"messages":[{"role":"user","content":"test"}]`
	if strings.Contains(fields, `"messages"`) {
		payload = `{"model":"m"`
	}
	if fields != "" {
		payload += "," + fields
	}
	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(payload+"}"), &req); err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	body, err := adapter.ToAnthropic(&req, "m")
	if err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	return &req, body
}

// claudeControls renders the named fields of a provider wire body as compact
// JSON with sorted keys. A field that is not sent is left out.
func claudeControls(t *testing.T, wire any, keys ...string) string {
	t.Helper()
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	controls := map[string]any{}
	for _, key := range keys {
		if sent[key] != nil {
			controls[key] = sent[key]
		}
	}
	out, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// claudeWire is what a chat request puts on the direct Anthropic wire for a
// model: the reasoning controls and max_tokens, plus any other field named.
// It fails if the dispatch changed the shared projection.
func claudeWire(t *testing.T, model, fields string, more ...string) string {
	t.Helper()
	req, body := claudeChat(t, fields)
	before, err := json.Marshal(*body)
	if err != nil {
		t.Fatal(err)
	}
	reasoningBefore, _ := json.Marshal(req.Reasoning)
	native := anthropicChatReasoningBody(model, req, body)
	after, _ := json.Marshal(*body)
	reasoningAfter, _ := json.Marshal(req.Reasoning)
	if string(before) != string(after) || string(reasoningBefore) != string(reasoningAfter) {
		t.Fatalf("%s %s: dispatch changed the shared request", model, fields)
	}
	return claudeControls(t, buildAnthropicWireRequest(model, native.Messages, native), append([]string{"thinking", "output_config", "max_tokens"}, more...)...)
}

func TestClaudeReasoningClassOfEveryIDSpelling(t *testing.T) {
	for class, ids := range map[claudeReasoningClass][]string{claudeFull: claudeFullIDs, claudeV46: claudeV46IDs, claudeOpus45: claudeOpus45IDs, claudeBudget: claudeBudgetIDs} {
		for _, id := range ids {
			if got, claude := claudeReasoningClassOf(id); !claude || got != class {
				t.Errorf("%s: class %q (claude=%t), want %q", id, got, claude, class)
			}
		}
	}
	for _, id := range []string{"", "gpt-5.5", "minimax-m3", "anthropic/other", "glm-5.3", "kimi-k3"} {
		if got, claude := claudeReasoningClassOf(id); claude {
			t.Errorf("%s: read as Claude class %q", id, got)
		}
	}
}

// A model that is not Claude can share the Anthropic wire. Its body is sent
// exactly as the shared projection built it, whatever the request asks.
func TestNonClaudeModelOnTheAnthropicWireIsSentAsBuilt(t *testing.T) {
	for _, fields := range []string{
		`"reasoning_effort":"max"`, `"reasoning_effort":"high","temperature":0.2,"top_k":40`,
		`"reasoning":{"enabled":false},"reasoning_effort":"high"`, `"reasoning":{"enabled":true},"reasoning_effort":"low"`,
		`"reasoning":{"enabled":true}`, `"reasoning_effort":"high","tool_choice":"required",` + claudeTestTools,
	} {
		req, body := claudeChat(t, fields)
		for _, model := range []string{"minimax-m3", "glm-5.3", "some-model"} {
			if anthropicChatReasoningBody(model, req, body) != body {
				t.Errorf("%s %s: body was rewritten", model, fields)
			}
		}
	}
}

// Decision 2: an effort the model does not have becomes the nearest one it
// has. The effort is spelled top-level and inside the reasoning object.
func TestClaudeEffortLadderPerClass(t *testing.T) {
	const (
		adaptive = `"thinking":{"type":"adaptive"}`
		budget1k = `{"max_tokens":4096,"thinking":{"budget_tokens":1024,"type":"enabled"}}`
		budget4k = `{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"}}`
		budget8k = `{"max_tokens":12288,"thinking":{"budget_tokens":8192,"type":"enabled"}}`
		none     = `{"max_tokens":4096}`
	)
	effortAt := func(effort string) string {
		return `{"max_tokens":32000,"output_config":{"effort":"` + effort + `"},` + adaptive + `}`
	}
	opus45 := func(effort, thinking string) string {
		if thinking == "" {
			return `{"max_tokens":4096,"output_config":{"effort":"` + effort + `"}}`
		}
		return strings.Replace(thinking, `,"thinking"`, `,"output_config":{"effort":"`+effort+`"},"thinking"`, 1)
	}
	for _, tc := range []struct {
		ids  []string
		want map[string]string
	}{
		{claudeFullIDs, map[string]string{
			"minimal": effortAt("low"), "low": effortAt("low"), "medium": effortAt("medium"), "high": effortAt("high"),
			"xhigh": effortAt("xhigh"), "max": effortAt("max"), "ultra": effortAt("ultra"),
		}},
		{claudeV46IDs, map[string]string{
			"minimal": effortAt("low"), "low": effortAt("low"), "medium": effortAt("medium"), "high": effortAt("high"),
			"xhigh": effortAt("high"), "max": effortAt("max"), "ultra": effortAt("ultra"),
		}},
		{claudeOpus45IDs, map[string]string{
			"minimal": opus45("low", ""), "low": opus45("low", budget1k), "medium": opus45("medium", budget4k), "high": opus45("high", budget8k),
			"xhigh": opus45("high", budget8k), "max": opus45("high", budget8k), "ultra": opus45("ultra", ""),
		}},
		{claudeBudgetIDs, map[string]string{
			"minimal": none, "low": budget1k, "medium": budget4k, "high": budget8k,
			"xhigh": budget8k, "max": budget8k, "ultra": none,
		}},
	} {
		for _, id := range tc.ids {
			for effort, want := range tc.want {
				for _, fields := range []string{`"reasoning_effort":"` + effort + `"`, `"reasoning":{"effort":"` + effort + `"}`, `"reasoning_effort":"` + strings.ToUpper(effort) + `"`} {
					if got := claudeWire(t, id, fields); got != want {
						t.Errorf("%s %s:\n got %s\nwant %s", id, fields, got, want)
					}
				}
			}
		}
	}
}

// The budgets the ladder names are the ones the shared projection has always
// used, so the two cannot drift apart for the efforts both know.
func TestClaudeLadderBudgetsMatchTheSharedProjection(t *testing.T) {
	for _, effort := range []string{"low", "medium", "high", "xhigh"} {
		_, body := claudeChat(t, `"reasoning_effort":"`+effort+`"`)
		shared, _ := body.Thinking.(map[string]any)
		for _, class := range []claudeReasoningClass{claudeBudget, claudeOpus45} {
			if step := class.step(effort); shared["budget_tokens"] != step.budget {
				t.Errorf("%s %s: ladder budget %d, shared projection %v", class, effort, step.budget, shared["budget_tokens"])
			}
		}
	}
}

// Decision 1: Off governs on every class, even beside an effort or a budget,
// and max_tokens keeps no room for a budget that is not sent.
func TestClaudeOffGovernsOnEveryClass(t *testing.T) {
	offs := []string{
		`"reasoning":{"enabled":false},"reasoning_effort":"high"`,
		`"reasoning":{"enabled":false,"effort":"high"}`,
		`"reasoning":{"enabled":false},"reasoning_effort":"max"`,
		`"reasoning":{"enabled":false,"max_tokens":8192}`,
		`"reasoning":{"enabled":false}`,
		`"reasoning":{"enabled":true},"reasoning_effort":"none"`,
		`"reasoning_effort":"none"`,
	}
	for _, tc := range []struct {
		ids  []string
		want string
	}{
		{claudeBudgetIDs, `{"max_tokens":4096}`},
		{claudeOpus45IDs, `{"max_tokens":4096,"thinking":{"type":"disabled"}}`},
		{claudeV46IDs, `{"max_tokens":4096,"thinking":{"type":"disabled"}}`},
	} {
		for _, id := range tc.ids {
			for _, off := range offs {
				if got := claudeWire(t, id, off); got != tc.want {
					t.Errorf("%s %s:\n got %s\nwant %s", id, off, got, tc.want)
				}
			}
			// A caller cap is sent as the caller set it.
			want := strings.Replace(tc.want, "4096", "512", 1)
			if got := claudeWire(t, id, offs[0]+`,"max_tokens":512`); got != want {
				t.Errorf("%s Off with a cap:\n got %s\nwant %s", id, got, want)
			}
		}
	}
}

// Decision 6: Sonnet 5.5 names between_tools as its Off. No other model does.
func TestClaudeSonnet55OffIsBetweenTools(t *testing.T) {
	offs := []string{`"reasoning":{"enabled":false}`, `"reasoning":{"enabled":false},"reasoning_effort":"high"`, `"reasoning":{"enabled":false,"effort":"max"}`, `"reasoning_effort":"none"`}
	for _, id := range []string{"claude-sonnet-5-5", "anthropic/claude-sonnet-5.5", "us.anthropic.claude-sonnet-5-5", "claude-sonnet-5-5@20261001", "claude-sonnet-5-5-20261001"} {
		if class, _ := claudeReasoningClassOf(id); class != claudeFull {
			t.Errorf("%s: class %q", id, class)
		}
		for _, off := range offs {
			if got := claudeWire(t, id, off); got != `{"max_tokens":4096,"thinking":{"type":"between_tools"}}` {
				t.Errorf("%s %s: got %s", id, off, got)
			}
		}
		// On and an effort are not Off.
		if got := claudeWire(t, id, `"reasoning_effort":"high"`); got != `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}` {
			t.Errorf("%s effort: got %s", id, got)
		}
	}
	for _, id := range claudeFullIDs {
		if strings.Contains(claudeModelKey(id), "claude-sonnet-5-5") {
			continue
		}
		for _, off := range offs {
			if got := claudeWire(t, id, off); got != `{"max_tokens":4096,"thinking":{"type":"disabled"}}` {
				t.Errorf("%s %s: got %s", id, off, got)
			}
		}
	}
}

// Decision 3: On beside an effort is that effort, wherever the effort is
// written. On alone stays 4,096 tokens on the budget classes.
func TestClaudeOnBesideAnEffortIsThatEffort(t *testing.T) {
	for _, ids := range [][]string{claudeFullIDs, claudeV46IDs, claudeOpus45IDs, claudeBudgetIDs} {
		for _, id := range ids {
			for _, effort := range []string{"minimal", "low", "medium", "high", "xhigh", "max", "ultra", "none"} {
				alone := claudeWire(t, id, `"reasoning_effort":"`+effort+`"`)
				for _, on := range []string{
					`"reasoning":{"enabled":true},"reasoning_effort":"` + effort + `"`,
					`"reasoning":{"enabled":true,"effort":"` + effort + `"}`,
					`"reasoning":true,"reasoning_effort":"` + effort + `"`,
					`"reasoning":{"type":"enabled"},"reasoning_effort":"` + effort + `"`,
				} {
					if got := claudeWire(t, id, on); got != alone {
						t.Errorf("%s %s:\n got %s\nthe effort alone sends %s", id, on, got, alone)
					}
				}
			}
		}
	}
	for _, id := range append(append([]string{}, claudeBudgetIDs...), claudeOpus45IDs...) {
		if got := claudeWire(t, id, `"reasoning":{"enabled":true}`); got != `{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"}}` {
			t.Errorf("%s On alone: got %s", id, got)
		}
	}
	// Different efforts beside On are different requests on a budget model.
	low := claudeWire(t, "claude-haiku-4-5", `"reasoning":{"enabled":true},"reasoning_effort":"low"`)
	high := claudeWire(t, "claude-haiku-4-5", `"reasoning":{"enabled":true},"reasoning_effort":"high"`)
	if low != `{"max_tokens":4096,"thinking":{"budget_tokens":1024,"type":"enabled"}}` || high != `{"max_tokens":12288,"thinking":{"budget_tokens":8192,"type":"enabled"}}` {
		t.Errorf("On beside low sends %s, beside high %s", low, high)
	}
}

// Decision 4: budget thinking is never sent with sampling Anthropic refuses
// beside it. Without thinking the caller's sampling is sent untouched.
func TestClaudeBudgetThinkingDropsRefusedSampling(t *testing.T) {
	const thinks = `"thinking":{"budget_tokens":8192,"type":"enabled"}`
	for _, id := range append(append([]string{}, claudeBudgetIDs...), claudeOpus45IDs...) {
		opus45 := strings.Contains(claudeModelKey(id), "claude-opus-4-5")
		for _, tc := range []struct{ name, fields, want string }{
			{"effort + temperature 0.2", `"reasoning_effort":"high","temperature":0.2`, `{` + thinks + `}`},
			{"effort + temperature 1", `"reasoning_effort":"high","temperature":1`, `{"temperature":1,` + thinks + `}`},
			{"effort + top_k", `"reasoning_effort":"high","top_k":40`, `{` + thinks + `}`},
			{"effort + top_p 0.5", `"reasoning_effort":"high","top_p":0.5`, `{` + thinks + `}`},
			{"effort + top_p 0.97", `"reasoning_effort":"high","top_p":0.97`, `{` + thinks + `,"top_p":0.97}`},
			{"effort + top_p 0.95", `"reasoning_effort":"high","top_p":0.95`, `{` + thinks + `,"top_p":0.95}`},
			{"effort + all three", `"reasoning_effort":"max","temperature":0.2,"top_k":40,"top_p":0.5`, `{` + thinks + `}`},
			{"On + temperature", `"reasoning":{"enabled":true},"temperature":0.2,"top_k":40,"top_p":0.5`, `{"thinking":{"budget_tokens":4096,"type":"enabled"}}`},
			{"explicit budget + sampling", `"reasoning":{"max_tokens":2048},"temperature":0.2,"top_k":40,"top_p":0.5`, `{"thinking":{"budget_tokens":2048,"type":"enabled"}}`},
			{"no thinking keeps sampling", `"temperature":0.2,"top_k":40,"top_p":0.5`, `{"temperature":0.2,"top_k":40,"top_p":0.5}`},
			{"Off keeps sampling", `"reasoning":{"enabled":false},"reasoning_effort":"high","temperature":0.2,"top_k":40,"top_p":0.5`, `{"temperature":0.2,"top_k":40,"top_p":0.5}`},
		} {
			want := tc.want
			if opus45 && strings.Contains(tc.name, "Off") {
				want = `{"temperature":0.2,"thinking":{"type":"disabled"},"top_k":40,"top_p":0.5}`
			}
			req, body := claudeChat(t, tc.fields)
			native := anthropicChatReasoningBody(id, req, body)
			for transport, wire := range map[string]any{
				"anthropic": buildAnthropicWireRequest(id, native.Messages, native),
				"bedrock":   bedrock.BuildRequestShape(native),
			} {
				if got := claudeControls(t, wire, "thinking", "temperature", "top_p", "top_k"); got != want {
					t.Errorf("%s %s on %s:\n got %s\nwant %s", id, tc.name, transport, got, want)
				}
			}
			if body.Temperature != req.Temperature || body.TopP != req.TopP || body.TopK != req.TopK {
				t.Errorf("%s %s: sampling was removed from the shared projection", id, tc.name)
			}
		}
	}
}

// The adaptive classes are not changed by decision 4. This records what they
// do today with an effort: temperature and top_p are not sent, top_k is.
func TestClaudeAdaptiveSamplingIsUnchanged(t *testing.T) {
	for _, id := range []string{"claude-sonnet-4-6", "claude-opus-4-6"} {
		if got := claudeWire(t, id, `"reasoning_effort":"high","temperature":0.2,"top_k":40,"top_p":0.5`, "temperature", "top_p", "top_k"); got != `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"},"top_k":40}` {
			t.Errorf("%s: got %s", id, got)
		}
	}
}

// Decision 5: a forced tool choice or an assistant prefill beats an effort.
// Thinking the caller asked for explicitly is still sent.
func TestClaudeForcedToolOrPrefillBeatsAnEffort(t *testing.T) {
	const (
		prefill = `"messages":[{"role":"user","content":"test"},{"role":"assistant","content":"{"}]`
		named   = `"tool_choice":{"type":"function","function":{"name":"lookup"}},` + claudeTestTools
		anyTool = `"tool_choice":"required",` + claudeTestTools
		auto    = `"tool_choice":"auto",` + claudeTestTools
		budget  = `"thinking":{"budget_tokens":8192,"type":"enabled"}`
	)
	for _, id := range append(append([]string{}, claudeBudgetIDs...), claudeOpus45IDs...) {
		opus45 := strings.Contains(claudeModelKey(id), "claude-opus-4-5")
		effort := func(word string) string {
			if opus45 {
				return `"output_config":{"effort":"` + word + `"},`
			}
			return ""
		}
		for _, tc := range []struct{ name, fields, want string }{
			{"effort + required tool", `"reasoning_effort":"high",` + anyTool, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"type":"any"}}`},
			{"effort + named tool", `"reasoning_effort":"high",` + named, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"name":"lookup","type":"tool"}}`},
			{"max + required tool", `"reasoning":{"effort":"max"},` + anyTool, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"type":"any"}}`},
			{"effort + required tool keeps sampling", `"reasoning_effort":"high","temperature":0.2,` + anyTool, `{"max_tokens":4096,` + effort("high") + `"temperature":0.2,"tool_choice":{"type":"any"}}`},
			{"effort + prefill", `"reasoning_effort":"high",` + prefill, `{"max_tokens":4096` + strings.TrimSuffix(","+effort("high"), ",") + `}`},
			{"effort + cap + prefill", `"reasoning_effort":"high","max_tokens":512,` + prefill, `{"max_tokens":512` + strings.TrimSuffix(","+effort("high"), ",") + `}`},
			{"effort + auto tool thinks", `"reasoning_effort":"high",` + auto, `{"max_tokens":12288,` + effort("high") + budget + `,"tool_choice":{"type":"auto"}}`},
			{"effort + tools, no choice, thinks", `"reasoning_effort":"high",` + claudeTestTools, `{"max_tokens":12288,` + effort("high") + budget + `}`},
			{"explicit budget + required tool", `"reasoning":{"max_tokens":8192},` + anyTool, `{"max_tokens":12288,` + budget + `,"tool_choice":{"type":"any"}}`},
			{"explicit budget + prefill", `"reasoning":{"max_tokens":8192},` + prefill, `{"max_tokens":12288,` + budget + `}`},
			{"On + required tool", `"reasoning":{"enabled":true},` + anyTool, `{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"},"tool_choice":{"type":"any"}}`},
			{"On + effort + required tool", `"reasoning":{"enabled":true,"effort":"high"},` + anyTool, `{"max_tokens":12288,` + effort("high") + budget + `,"tool_choice":{"type":"any"}}`},
			{"On + top-level effort + prefill", `"reasoning":{"enabled":true},"reasoning_effort":"high",` + prefill, `{"max_tokens":12288,` + effort("high") + budget + `}`},
		} {
			if got := claudeWire(t, id, tc.fields, "tool_choice", "temperature"); got != tc.want {
				t.Errorf("%s %s:\n got %s\nwant %s", id, tc.name, got, tc.want)
			}
		}
	}
}

// Decision 7: Haiku 5.5 and Mythos 5 refuse budget thinking, so no effort may
// ever reach them as thinking.type enabled.
func TestClaudeHaiku55AndMythos5NeverGetBudgetThinkingFromAnEffort(t *testing.T) {
	for _, id := range []string{"claude-haiku-5-5", "anthropic/claude-haiku-5.5", "us.anthropic.claude-haiku-5-5", "claude-haiku-5-5@20261001", "claude-mythos-5", "claude-mythos-5-1"} {
		for _, effort := range []string{"minimal", "low", "medium", "high", "xhigh", "max"} {
			for _, fields := range []string{`"reasoning_effort":"` + effort + `"`, `"reasoning":{"effort":"` + effort + `"}`, `"reasoning":{"enabled":true,"effort":"` + effort + `"}`, `"reasoning":{"enabled":true},"reasoning_effort":"` + effort + `"`} {
				req, body := claudeChat(t, fields)
				native := anthropicChatReasoningBody(id, req, body)
				thinking, _ := native.Thinking.(map[string]any)
				config, _ := native.OutputConfig.(map[string]any)
				if len(thinking) != 1 || thinking["type"] != "adaptive" || config["effort"] == nil {
					t.Errorf("%s %s: thinking=%v output_config=%v", id, fields, native.Thinking, native.OutputConfig)
				}
			}
		}
	}
}

// A budget the ladder derives at dispatch fits a funded allowance exactly as
// one the shared projection derives: max_tokens is the authorization and the
// budget is below it.
func TestClaudeLadderBudgetFitsAFundedAllowance(t *testing.T) {
	for _, total := range []int{1, 1024, 1025, 2000, 8192, 8193, 60000} {
		for _, effort := range []string{"max", "xhigh", "high"} {
			req, body, authorized := fundedrequest.New(t, total, nil, effort)
			for _, model := range []string{"claude-haiku-4-5", "claude-opus-4-5"} {
				native := anthropicChatReasoningBody(model, req, body)
				fundedrequest.Check(t, buildAnthropicWireRequest(model, native.Messages, native), authorized, false)
				thinking, _ := native.Thinking.(map[string]any)
				want := min(8192, total-1)
				if total <= 1024 {
					if native.Thinking != nil {
						t.Errorf("%s total=%d %s: thinking=%v below the provider minimum", model, total, effort, native.Thinking)
					}
				} else if thinking["budget_tokens"] != want {
					t.Errorf("%s total=%d %s: budget=%v, want %d", model, total, effort, thinking["budget_tokens"], want)
				}
			}
		}
	}
}

// The ladder is total: every class answers every effort word, and a class
// with an effort field never sends an effort outside its own list for a word
// the gateway knows.
func TestClaudeEffortLaddersAreComplete(t *testing.T) {
	allowed := map[claudeReasoningClass][]string{
		claudeFull:   {"low", "medium", "high", "xhigh", "max"},
		claudeV46:    {"low", "medium", "high", "max"},
		claudeOpus45: {"low", "medium", "high"},
		claudeBudget: {""},
	}
	if len(claudeEffortLadders) != len(allowed) {
		t.Fatalf("ladders for %d classes, want %d", len(claudeEffortLadders), len(allowed))
	}
	for class, efforts := range allowed {
		for _, word := range []string{"minimal", "low", "medium", "high", "xhigh", "max"} {
			step, listed := claudeEffortLadders[class][word]
			if !listed {
				t.Errorf("%s has no step for %s", class, word)
				continue
			}
			ok := false
			for _, effort := range efforts {
				ok = ok || step.effort == effort
			}
			if !ok {
				t.Errorf("%s sends effort %q for %s, outside %v", class, step.effort, word, efforts)
			}
			if (class == claudeFull || class == claudeV46) && step.budget != 0 {
				t.Errorf("%s names a budget for %s on an adaptive class", class, word)
			}
			if step.budget != 0 && step.budget < 1024 {
				t.Errorf("%s budget %d for %s is below the provider minimum", class, step.budget, word)
			}
		}
	}
}
