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

// A Claude ID that no table entry names is in the full class. A new model
// reaches the gateway through the catalog with no change to this code, and
// every model since Opus 4.7 refuses a thinking budget, so the default must
// be adaptive thinking.
func TestUnlistedClaudeModelIsInTheFullClass(t *testing.T) {
	for _, id := range []string{
		"claude-opus-6", "claude-sonnet-4-7", "claude-haiku-6", "claude-fable-6-1", "claude-opus-4-9", "claude-haiku-4-6", "claude-sonnet-4-8",
		"anthropic/claude-opus-6.1", "us.anthropic.claude-haiku-6", "claude-opus-7@20280101", "claude-sonnet-6-5-20270101", "claude-atlas-1",
		// A longer version number is a different model from the one it starts with.
		"claude-opus-4-10", "claude-opus-4-50", "claude-sonnet-4-50", "claude-sonnet-4-60", "claude-haiku-4-50",
		"claude-4-10-opus", "claude-4-50-sonnet", "claude-sonnet-30", "claude-opus-30-1",
		// Version first, a 4.x that no row names is a newer model too.
		"claude-4-7-opus", "claude-4-8-sonnet", "claude-4-7-sonnet-20270101", "claude-5-sonnet", "claude-5-5-opus",
		// A 4.0 model is matched by a date, an "@", a ":" or "-0" after the 4,
		// and by nothing looser: a free-form suffix is some other model.
		"claude-opus-4-v2-preview", "claude-sonnet-4-v3", "claude-opus-4-latest", "claude-sonnet-4-preview",
	} {
		if got, claude := claudeReasoningClassOf(id); !claude || got != claudeFull {
			t.Errorf("%s: class %q (claude=%t), want %q", id, got, claude, claudeFull)
		}
		if got := claudeWire(t, id, `"reasoning_effort":"high"`); got != `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}` {
			t.Errorf("%s effort: got %s", id, got)
		}
		if got := claudeWire(t, id, `"reasoning":{"enabled":true}`); got != `{"max_tokens":32000,"thinking":{"type":"adaptive"}}` {
			t.Errorf("%s On alone: got %s", id, got)
		}
	}
}

// The budget class is a closed list: the 3.x families and older, Opus 4 and
// Sonnet 4 in every spelling, Opus 4.1, Sonnet 4.5 and Haiku 4.5. The 4.0
// entries match by what follows the 4, so they never take in a later 4.x.
func TestClaudeBudgetClassIsAClosedList(t *testing.T) {
	for _, id := range []string{
		"claude-sonnet-4", "claude-opus-4", "anthropic/claude-sonnet-4", "anthropic/claude-opus-4",
		"claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-sonnet-4@20250514", "claude-opus-4@20250514",
		"us.anthropic.claude-sonnet-4-20250514-v1:0", "anthropic.claude-opus-4-20250514-v1:0", "claude-sonnet-4-0", "claude-opus-4-0", "anthropic/claude-opus-4.0",
		"claude-opus-4-1", "anthropic/claude-opus-4.1", "claude-opus-4-1-20250805", "claude-opus-4-1@20250805", "us.anthropic.claude-opus-4-1-20250805-v1:0",
		"claude-sonnet-4-5", "anthropic/claude-sonnet-4.5", "claude-sonnet-4-5-20250929", "claude-sonnet-4-5@20250929", "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"claude-haiku-4-5", "anthropic/claude-haiku-4.5", "claude-haiku-4-5-20251001", "claude-haiku-4-5@20251001", "us.anthropic.claude-haiku-4-5-20251001-v1:0",
		"claude-3-opus-20240229", "claude-3-haiku-20240307", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-7-sonnet-20250219",
		"anthropic/claude-3.7-sonnet", "anthropic/claude-3-5-sonnet", "anthropic.claude-3-5-sonnet-20241022-v2:0", "claude-3-7-sonnet@20250219",
		"claude-2", "claude-2.1", "anthropic.claude-v2:1", "claude-instant-1.2", "anthropic.claude-instant-v1",
		// The same models named version first, as older IDs and some
		// deployment names have them.
		"claude-4-sonnet", "claude-4-opus", "claude-4-sonnet-20250514", "anthropic/claude-4-opus", "claude-4-sonnet@20250514",
		"claude-4-1-opus", "claude-4.1-opus", "claude-4-1-opus-20250805",
		"claude-4-5-sonnet", "claude-4.5-sonnet", "claude-4-5-haiku", "claude-4-5-haiku-20251001",
		// And the 3.x models named family first.
		"claude-sonnet-3", "claude-haiku-3", "claude-opus-3", "claude-sonnet-3-5", "claude-sonnet-3-7", "claude-haiku-3-5",
		"anthropic/claude-sonnet-3.7", "claude-opus-3-20240229", "claude-sonnet-3-7@20250219",
	} {
		if got, claude := claudeReasoningClassOf(id); !claude || got != claudeBudget {
			t.Errorf("%s: class %q (claude=%t), want %q", id, got, claude, claudeBudget)
		}
	}
	// The neighbours of the 4.0 models keep their own classes.
	for id, want := range map[string]claudeReasoningClass{
		"claude-opus-4-5": claudeOpus45, "claude-opus-4-5-20251101": claudeOpus45,
		"claude-sonnet-4-6": claudeV46, "claude-opus-4-6": claudeV46, "claude-sonnet-4-6@20260217": claudeV46,
		"claude-opus-4-7": claudeFull, "claude-opus-4-8": claudeFull, "claude-sonnet-4-7": claudeFull, "claude-sonnet-4-7-20270101": claudeFull,
		// Version first: Opus 4.5 and the 4.6 models keep their classes, and
		// a later 4.x is in the full class.
		"claude-4-5-opus": claudeOpus45, "claude-4.5-opus-20251101": claudeOpus45,
		"claude-4-6-sonnet": claudeV46, "claude-4-6-opus": claudeV46, "claude-4.6-sonnet-20260217": claudeV46,
		"claude-4-7-opus": claudeFull, "claude-4-8-opus": claudeFull,
		// A real Bedrock 4.0 ID is matched by its date, not by its version suffix.
		"us.anthropic.claude-opus-4-20250514-v1:0": claudeBudget, "anthropic.claude-sonnet-4-20250514-v1:0": claudeBudget,
	} {
		if got, _ := claudeReasoningClassOf(id); got != want {
			t.Errorf("%s: class %q, want %q", id, got, want)
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
			if step, listed := class.step(effort); !listed || shared["budget_tokens"] != step.budget {
				t.Errorf("%s %s: ladder budget %d, shared projection %v", class, effort, step.budget, shared["budget_tokens"])
			}
		}
	}
	// The budget On adds beside an unknown effort is the one On alone is.
	_, body := claudeChat(t, `"reasoning":{"enabled":true}`)
	if shared, _ := body.Thinking.(map[string]any); shared["budget_tokens"] != claudeOnBudget {
		t.Errorf("On alone: dispatch budget %d, shared projection %v", claudeOnBudget, shared["budget_tokens"])
	}
	// The floor On uses beside minimal is the lowest step of the ladder.
	if step, _ := claudeBudget.step("low"); step.budget != claudeMinimumBudget {
		t.Errorf("low is %d tokens, the floor is %d", step.budget, claudeMinimumBudget)
	}
}

// claudeOffSpellings is every way a chat request that reaches the dispatch
// turns thinking off: reasoning.enabled false, a bare reasoning false,
// reasoning.type disabled, and an effort of none, off, disable or disabled,
// top-level or in the reasoning object. Each is also written beside an On, an
// effort or a budget, which it governs. The first entry is the plain one.
var claudeOffSpellings = []string{
	`"reasoning":{"enabled":false},"reasoning_effort":"high"`,
	`"reasoning":{"enabled":false,"effort":"high"}`,
	`"reasoning":{"enabled":false},"reasoning_effort":"max"`,
	`"reasoning":{"enabled":false,"max_tokens":8192}`,
	`"reasoning":{"enabled":false}`,
	`"reasoning":{"enabled":false,"type":"enabled"}`,
	`"reasoning":false`,
	`"reasoning":false,"reasoning_effort":"high"`,
	`"reasoning":{"type":"disabled"}`,
	`"reasoning":{"type":"disabled"},"reasoning_effort":"high"`,
	`"reasoning":{"type":"disabled","effort":"max"}`,
	`"reasoning":{"type":"disabled","max_tokens":8192}`,
	`"reasoning_effort":"none"`,
	`"reasoning_effort":"off"`,
	`"reasoning_effort":"disable"`,
	`"reasoning_effort":"disabled"`,
	`"reasoning_effort":"NONE"`,
	`"reasoning":{"effort":"none"}`,
	`"reasoning":{"effort":"off"}`,
	`"reasoning":{"effort":"disable"}`,
	`"reasoning":{"effort":"disabled"}`,
	// On beside an Off word. A switch beside one is refused before dispatch,
	// so this arrives only from the reasoning object.
	`"reasoning":{"enabled":true},"reasoning_effort":"none"`,
	`"reasoning":{"enabled":true},"reasoning_effort":"off"`,
	`"reasoning":{"enabled":true,"effort":"disabled"}`,
	`"reasoning":true,"reasoning_effort":"off"`,
	`"reasoning":{"type":"enabled"},"reasoning_effort":"none"`,
	// A top-level Off word is the request's effort, whatever the object says.
	`"reasoning":{"effort":"high"},"reasoning_effort":"none"`,
	`"reasoning":{"effort":"max"},"reasoning_effort":"off"`,
	`"reasoning":{"enabled":true,"effort":"high"},"reasoning_effort":"disabled"`,
	// An Off word beside a named budget.
	`"reasoning":{"max_tokens":8192},"reasoning_effort":"off"`,
	`"reasoning":{"max_tokens":8192,"effort":"none"}`,
}

// A bare string in the reasoning field, reasoning "high", is an effort when
// it is a word the gateway knows: a ladder word or an Off word. Then it is
// read like reasoning.effort: with no top-level effort it is the request's
// effort, with the same ladder and the same Off words, and a top-level effort
// beside it wins. Any other string is not an effort. The contract layer lets
// a bare string through unchecked, alone or beside reasoning_effort, and
// refuses it beside a switch.
func TestClaudeBareStringReasoningIsAnEffort(t *testing.T) {
	// What a request that asks nothing is sent. For a string the gateway does
	// not know this is the wire before the effort ladder existed, on every
	// model whose class is the one it had then.
	nothingAsked := map[claudeReasoningClass]string{
		claudeBudget: `{"max_tokens":4096}`, claudeOpus45: `{"max_tokens":4096}`, claudeV46: `{"max_tokens":32000}`, claudeFull: `{"max_tokens":32000}`,
	}
	for class, ids := range map[claudeReasoningClass][]string{claudeFull: claudeFullIDs, claudeV46: claudeV46IDs, claudeOpus45: claudeOpus45IDs, claudeBudget: claudeBudgetIDs} {
		for _, id := range ids {
			for _, word := range []string{"minimal", "low", "medium", "high", "xhigh", "max", "none", "off", "disable", "disabled"} {
				want := claudeWire(t, id, `"reasoning_effort":"`+word+`"`)
				for _, fields := range []string{`"reasoning":"` + word + `"`, `"reasoning":" ` + strings.ToUpper(word) + ` "`, `"reasoning":"` + word + `","reasoning_effort":""`} {
					if got := claudeWire(t, id, fields); got != want {
						t.Errorf("%s %s:\n got %s\nwant what reasoning_effort %s sends, %s", id, fields, got, word, want)
					}
				}
			}
			// A string that is not a known word asks nothing. It is never sent
			// as an effort, which the models with an effort field would refuse.
			for _, word := range []string{"ultra", "anything", "true", "enabled", "auto", "highest", ""} {
				if got := claudeWire(t, id, `"reasoning":"`+word+`"`); got != nothingAsked[class] || got != claudeWire(t, id, ``) {
					t.Errorf("%s string %q:\n got %s\nwant what nothing asked sends, %s", id, word, got, nothingAsked[class])
				}
				for _, extra := range []string{`,"max_tokens":512`, `,"temperature":0.2,"top_k":40,"top_p":0.5`, `,"tool_choice":"required",` + claudeTestTools} {
					want := claudeWire(t, id, strings.TrimPrefix(extra, ","), "temperature", "top_p", "top_k", "tool_choice")
					if got := claudeWire(t, id, `"reasoning":"`+word+`"`+extra, "temperature", "top_p", "top_k", "tool_choice"); got != want {
						t.Errorf("%s string %q%s:\n got %s\nwant %s", id, word, extra, got, want)
					}
				}
				// A top-level effort beside it is still the request's effort.
				if got, want := claudeWire(t, id, `"reasoning":"`+word+`","reasoning_effort":"high"`), claudeWire(t, id, `"reasoning_effort":"high"`); got != want {
					t.Errorf("%s string %q beside top-level high:\n got %s\nwant %s", id, word, got, want)
				}
			}
			// The unknown word written as an effort is still sent as written
			// where there is an effort field: only the bare string is not read.
			if class != claudeBudget {
				if got := claudeWire(t, id, `"reasoning_effort":"ultra"`); !strings.Contains(got, `"output_config":{"effort":"ultra"}`) {
					t.Errorf("%s reasoning_effort ultra: got %s, want the word as written", id, got)
				}
			}
			high, low, off := claudeWire(t, id, `"reasoning_effort":"high"`), claudeWire(t, id, `"reasoning_effort":"low"`), claudeWire(t, id, `"reasoning_effort":"none"`)
			if high == low || high == off || low == off {
				t.Fatalf("%s: high %s, low %s, Off %s: the rows below would prove nothing", id, high, low, off)
			}
			for fields, want := range map[string]string{
				// A top-level effort wins over the string, in every order.
				`"reasoning":"high","reasoning_effort":"low"`:  low,
				`"reasoning":"low","reasoning_effort":"high"`:  high,
				`"reasoning":"none","reasoning_effort":"high"`: high,
				`"reasoning":"off","reasoning_effort":"low"`:   low,
				`"reasoning":"high","reasoning_effort":"none"`: off,
				`"reasoning":"max","reasoning_effort":"off"`:   off,
				// The other fields of the request are treated as an effort treats them.
				`"reasoning":"high","max_tokens":512`: claudeWire(t, id, `"reasoning_effort":"high","max_tokens":512`),
			} {
				if got := claudeWire(t, id, fields); got != want {
					t.Errorf("%s %s:\n got %s\nwant %s", id, fields, got, want)
				}
			}
			for _, extra := range []string{`,"temperature":0.2,"top_k":40,"top_p":0.5`, `,"tool_choice":"required",` + claudeTestTools, `,"messages":[{"role":"user","content":"test"},{"role":"assistant","content":"{"}]`} {
				want := claudeWire(t, id, `"reasoning_effort":"high"`+extra, "temperature", "top_p", "top_k", "tool_choice")
				if got := claudeWire(t, id, `"reasoning":"high"`+extra, "temperature", "top_p", "top_k", "tool_choice"); got != want {
					t.Errorf("%s string high%s:\n got %s\nwant %s", id, extra, got, want)
				}
			}
		}
	}
	// No full class model is sent a budget for a string effort any more.
	for _, id := range claudeFullIDs {
		req, body := claudeChat(t, `"reasoning":"high"`)
		if shared, _ := body.Thinking.(map[string]any); shared["budget_tokens"] == nil {
			t.Fatal("the shared projection wrote no budget for a string effort: this check proves nothing")
		}
		native := anthropicChatReasoningBody(id, req, body)
		if thinking, _ := native.Thinking.(map[string]any); len(thinking) != 1 || thinking["type"] != "adaptive" {
			t.Errorf("%s string high: thinking=%v", id, native.Thinking)
		}
	}
}

// When a request carries two efforts the top-level one wins, on every class.
// An Off word is an effort, so the same rule decides it: in the reasoning
// object beside a top-level effort it is not Off, and at the top level it is
// Off whatever the object says. The switch forms of Off are not efforts and
// always govern, which TestClaudeOffGovernsOnEveryClass covers.
func TestClaudeTwoEffortsTheTopLevelOneWins(t *testing.T) {
	offWords := []string{"none", "off", "disable", "disabled"}
	for class, ids := range map[claudeReasoningClass][]string{
		claudeBudget: claudeBudgetIDs, claudeOpus45: claudeOpus45IDs, claudeV46: claudeV46IDs, claudeFull: claudeFullIDs,
	} {
		for _, id := range ids {
			off := `{"max_tokens":32000,"thinking":{"type":"disabled"}}`
			switch {
			case class == claudeBudget:
				off = `{"max_tokens":4096}`
			case class == claudeOpus45:
				off = `{"max_tokens":4096,"thinking":{"type":"disabled"}}`
			case claudeSonnet55.MatchString(claudeModelKey(id)):
				off = `{"max_tokens":32000,"thinking":{"type":"between_tools"}}`
			}
			high := claudeWire(t, id, `"reasoning_effort":"high"`)
			low := claudeWire(t, id, `"reasoning_effort":"low"`)
			if high == off || low == off || high == low {
				t.Fatalf("%s: high sends %s, low %s, Off %s: the rows below would prove nothing", id, high, low, off)
			}
			for _, word := range offWords {
				// An Off word in the object loses to the top-level effort.
				for _, fields := range []string{
					`"reasoning":{"effort":"` + word + `"},"reasoning_effort":"high"`,
					`"reasoning":{"effort":"` + strings.ToUpper(word) + `"},"reasoning_effort":"high"`,
				} {
					if got := claudeWire(t, id, fields); got != high {
						t.Errorf("%s %s:\n got %s\nwant what high alone sends, %s", id, fields, got, high)
					}
				}
				// A top-level Off word wins over the effort in the object.
				for _, fields := range []string{
					`"reasoning":{"effort":"high"},"reasoning_effort":"` + word + `"`,
					`"reasoning":{"effort":"max"},"reasoning_effort":"` + word + `"`,
					`"reasoning":{"enabled":true,"effort":"high"},"reasoning_effort":"` + word + `"`,
				} {
					if got := claudeWire(t, id, fields); got != off {
						t.Errorf("%s %s:\n got %s\nwant Off, %s", id, fields, got, off)
					}
				}
				// With no top-level effort the object's word is the effort.
				if got := claudeWire(t, id, `"reasoning":{"effort":"`+word+`"}`); got != off {
					t.Errorf("%s effort %s in the object alone:\n got %s\nwant Off, %s", id, word, got, off)
				}
			}
			// Two real efforts: the top-level one wins in both orders.
			if got := claudeWire(t, id, `"reasoning":{"effort":"high"},"reasoning_effort":"low"`); got != low {
				t.Errorf("%s object high beside top-level low:\n got %s\nwant %s", id, got, low)
			}
			if got := claudeWire(t, id, `"reasoning":{"effort":"low"},"reasoning_effort":"high"`); got != high {
				t.Errorf("%s object low beside top-level high:\n got %s\nwant %s", id, got, high)
			}
			// A switch form of Off still governs over a top-level effort.
			for _, fields := range []string{`"reasoning":{"enabled":false,"effort":"none"},"reasoning_effort":"high"`, `"reasoning":{"type":"disabled","effort":"low"},"reasoning_effort":"high"`, `"reasoning":false,"reasoning_effort":"high"`} {
				if got := claudeWire(t, id, fields); got != off {
					t.Errorf("%s %s:\n got %s\nwant Off, %s", id, fields, got, off)
				}
			}
		}
	}
}

// Decision 1: Off governs on every class, even beside an effort or a budget,
// and max_tokens keeps no room for a budget that is not sent. On the adaptive
// classes a caller who set no limit keeps the 32,000 default of the class,
// the one a request with no reasoning ask gets, so Off never shortens an
// answer. The budget classes have a 4,096 default with or without Off.
func TestClaudeOffGovernsOnEveryClass(t *testing.T) {
	offs := claudeOffSpellings
	var fullWithDisabled []string
	for _, id := range claudeFullIDs {
		if !claudeSonnet55.MatchString(claudeModelKey(id)) {
			fullWithDisabled = append(fullWithDisabled, id)
		}
	}
	for _, tc := range []struct {
		ids  []string
		want string
	}{
		{claudeBudgetIDs, `{"max_tokens":4096}`},
		{claudeOpus45IDs, `{"max_tokens":4096,"thinking":{"type":"disabled"}}`},
		{claudeV46IDs, `{"max_tokens":32000,"thinking":{"type":"disabled"}}`},
		{fullWithDisabled, `{"max_tokens":32000,"thinking":{"type":"disabled"}}`},
		{[]string{"claude-opus-6", "claude-sonnet-4-7"}, `{"max_tokens":32000,"thinking":{"type":"disabled"}}`},
	} {
		for _, id := range tc.ids {
			nothingAsked := claudeWire(t, id, ``)
			for _, off := range offs {
				if got := claudeWire(t, id, off); got != tc.want {
					t.Errorf("%s %s:\n got %s\nwant %s", id, off, got, tc.want)
				}
				// Off never leaves less room than the same request without it.
				if !strings.HasPrefix(claudeWire(t, id, off), strings.TrimSuffix(nothingAsked, "}")) {
					t.Errorf("%s %s: sends %s, but nothing asked sends %s", id, off, claudeWire(t, id, off), nothingAsked)
				}
				// A caller limit is sent as the caller set it, the 4,096 the
				// gateway would otherwise fill in included.
				for _, limit := range []string{"512", "4096", "20000"} {
					want := strings.Replace(strings.Replace(tc.want, `"max_tokens":32000`, `"max_tokens":`+limit, 1), `"max_tokens":4096`, `"max_tokens":`+limit, 1)
					if strings.Contains(off, `"max_tokens"`) {
						continue
					}
					if got := claudeWire(t, id, off+`,"max_tokens":`+limit); got != want {
						t.Errorf("%s %s with max_tokens %s:\n got %s\nwant %s", id, off, limit, got, want)
					}
				}
			}
		}
	}
	// Inside a funded allowance Off is sent the allowance, never the default.
	for _, model := range []string{"claude-opus-4-8", "claude-sonnet-4-6", "claude-sonnet-5-5", "claude-haiku-4-5", "claude-opus-4-5"} {
		for _, total := range []int{512, 4096, 6000} {
			req, body, authorized := fundedrequest.New(t, total, map[string]any{"enabled": false}, "")
			native := anthropicChatReasoningBody(model, req, body)
			fundedrequest.Check(t, buildAnthropicWireRequest(model, native.Messages, native), authorized, false)
		}
	}
}

// Decision 6: Sonnet 5.5 names between_tools as its Off. No other model does.
func TestClaudeSonnet55OffIsBetweenTools(t *testing.T) {
	offs := claudeOffSpellings
	for _, id := range []string{"claude-sonnet-5-5", "anthropic/claude-sonnet-5.5", "us.anthropic.claude-sonnet-5-5", "claude-sonnet-5-5@20261001", "claude-sonnet-5-5-20261001"} {
		if class, _ := claudeReasoningClassOf(id); class != claudeFull {
			t.Errorf("%s: class %q", id, class)
		}
		for _, off := range offs {
			if got := claudeWire(t, id, off); got != `{"max_tokens":32000,"thinking":{"type":"between_tools"}}` {
				t.Errorf("%s %s: got %s", id, off, got)
			}
		}
		if got := claudeWire(t, id, `"reasoning":{"enabled":false},"max_tokens":512`); got != `{"max_tokens":512,"thinking":{"type":"between_tools"}}` {
			t.Errorf("%s Off with a limit: got %s", id, got)
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
			if got := claudeWire(t, id, off); got != `{"max_tokens":32000,"thinking":{"type":"disabled"}}` {
				t.Errorf("%s %s: got %s", id, off, got)
			}
		}
	}
}

// Decision 3: On beside an effort is that effort, wherever the effort is
// written. On alone stays 4,096 tokens on the budget classes. On is an
// explicit ask, so it always turns thinking on: where the effort alone sets
// no budget on a budget class, On adds one. Beside minimal that is the
// smallest budget, and beside an unknown word it is what On alone is.
func TestClaudeOnBesideAnEffortIsThatEffort(t *testing.T) {
	onAdds := map[string]string{
		"minimal": `{"max_tokens":4096,"thinking":{"budget_tokens":1024,"type":"enabled"}}`,
		"ultra":   `{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"}}`,
	}
	for class, ids := range map[claudeReasoningClass][]string{claudeFull: claudeFullIDs, claudeV46: claudeV46IDs, claudeOpus45: claudeOpus45IDs, claudeBudget: claudeBudgetIDs} {
		for _, id := range ids {
			for _, effort := range []string{"minimal", "low", "medium", "high", "xhigh", "max", "ultra", "none"} {
				alone := claudeWire(t, id, `"reasoning_effort":"`+effort+`"`)
				if added, adds := onAdds[effort]; adds && (class == claudeBudget || class == claudeOpus45) {
					if strings.Contains(alone, `"thinking"`) {
						t.Errorf("%s %s alone thinks: %s", id, effort, alone)
					}
					// Opus 4.5 keeps the effort the word alone sends.
					if class == claudeOpus45 {
						word := map[string]string{"minimal": "low", "ultra": "ultra"}[effort]
						added = strings.Replace(added, `,"thinking"`, `,"output_config":{"effort":"`+word+`"},"thinking"`, 1)
					}
					alone = added
				}
				for _, on := range []string{
					`"reasoning":{"enabled":true},"reasoning_effort":"` + effort + `"`,
					`"reasoning":{"enabled":true,"effort":"` + effort + `"}`,
					`"reasoning":true,"reasoning_effort":"` + effort + `"`,
					`"reasoning":{"type":"enabled"},"reasoning_effort":"` + effort + `"`,
				} {
					if got := claudeWire(t, id, on); got != alone {
						t.Errorf("%s %s:\n got %s\nwant %s", id, on, got, alone)
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

// On always turns thinking on, on Opus 4.5 and the budget-only models. An
// effort that sets no budget by itself must not make an explicit On vanish.
func TestClaudeOnAlwaysThinksOnBudgetClasses(t *testing.T) {
	const (
		prefill = `"messages":[{"role":"user","content":"test"},{"role":"assistant","content":"{"}]`
		anyTool = `"tool_choice":"required",` + claudeTestTools
		floor   = `"thinking":{"budget_tokens":1024,"type":"enabled"}`
		onDepth = `"thinking":{"budget_tokens":4096,"type":"enabled"}`
	)
	for _, id := range append(append([]string{}, claudeBudgetIDs...), claudeOpus45IDs...) {
		opus45 := strings.Contains(claudeModelKey(id), "claude-opus-4-5")
		effort := func(word string) string {
			if opus45 {
				return `"output_config":{"effort":"` + word + `"},`
			}
			return ""
		}
		off := `{"max_tokens":4096}`
		if opus45 {
			off = `{"max_tokens":4096,"thinking":{"type":"disabled"}}`
		}
		for _, tc := range []struct{ name, fields, want string }{
			// On beside minimal: thinking on at the least depth.
			{"On object beside minimal", `"reasoning":{"enabled":true},"reasoning_effort":"minimal"`, `{"max_tokens":4096,` + effort("low") + floor + `}`},
			{"On object holding minimal", `"reasoning":{"enabled":true,"effort":"minimal"}`, `{"max_tokens":4096,` + effort("low") + floor + `}`},
			{"bare true beside minimal", `"reasoning":true,"reasoning_effort":"minimal"`, `{"max_tokens":4096,` + effort("low") + floor + `}`},
			{"reasoning.type beside minimal", `"reasoning":{"type":"enabled"},"reasoning_effort":"minimal"`, `{"max_tokens":4096,` + effort("low") + floor + `}`},
			// On beside a word the gateway does not know: what On alone is.
			{"On object beside an unknown word", `"reasoning":{"enabled":true},"reasoning_effort":"ultra"`, `{"max_tokens":8192,` + effort("ultra") + onDepth + `}`},
			{"On object holding an unknown word", `"reasoning":{"enabled":true,"effort":"ultra"}`, `{"max_tokens":8192,` + effort("ultra") + onDepth + `}`},
			{"bare true beside an unknown word", `"reasoning":true,"reasoning_effort":"ultra"`, `{"max_tokens":8192,` + effort("ultra") + onDepth + `}`},
			// A forced tool choice or a prefill beats the budget On adds too.
			{"On + minimal + required tool", `"reasoning":{"enabled":true,"effort":"minimal"},` + anyTool, `{"max_tokens":4096,` + effort("low") + `"tool_choice":{"type":"any"}}`},
			{"On + minimal + prefill", `"reasoning":{"enabled":true},"reasoning_effort":"minimal",` + prefill, `{"max_tokens":4096` + strings.TrimSuffix(","+effort("low"), ",") + `}`},
			{"On + unknown word + required tool", `"reasoning":{"enabled":true,"effort":"ultra"},` + anyTool, `{"max_tokens":4096,` + effort("ultra") + `"tool_choice":{"type":"any"}}`},
			// The budget is sent as a request Anthropic accepts.
			{"On + minimal + sampling", `"reasoning":{"enabled":true,"effort":"minimal"},"temperature":0.2,"top_k":40,"top_p":0.5`, `{"max_tokens":4096,` + effort("low") + floor + `}`},
			{"On + minimal with a cap", `"reasoning":{"enabled":true,"effort":"minimal"},"max_tokens":512`, `{"max_tokens":1536,` + effort("low") + floor + `}`},
			{"On + unknown word with a cap", `"reasoning":{"enabled":true,"effort":"ultra"},"max_tokens":512`, `{"max_tokens":4608,` + effort("ultra") + onDepth + `}`},
			// Off still governs, and without On nothing changes.
			{"On beside none", `"reasoning":{"enabled":true},"reasoning_effort":"none"`, off},
			{"On holding none", `"reasoning":{"enabled":true,"effort":"none"}`, off},
			{"Off beside minimal", `"reasoning":{"enabled":false},"reasoning_effort":"minimal"`, off},
			{"minimal alone", `"reasoning_effort":"minimal"`, `{"max_tokens":4096` + strings.TrimSuffix(","+effort("low"), ",") + `}`},
			{"minimal alone, in the object", `"reasoning":{"effort":"minimal"}`, `{"max_tokens":4096` + strings.TrimSuffix(","+effort("low"), ",") + `}`},
			{"an unknown word alone", `"reasoning_effort":"ultra"`, `{"max_tokens":4096` + strings.TrimSuffix(","+effort("ultra"), ",") + `}`},
			{"a bare false beside minimal is Off", `"reasoning":false,"reasoning_effort":"minimal"`, off},
			// A budget the caller named stands.
			{"named budget beside minimal", `"reasoning":{"enabled":true,"max_tokens":2048},"reasoning_effort":"minimal"`, `{"max_tokens":4096,` + effort("low") + `"thinking":{"budget_tokens":2048,"type":"enabled"}}`},
		} {
			if got := claudeWire(t, id, tc.fields, "tool_choice", "temperature", "top_p", "top_k"); got != tc.want {
				t.Errorf("%s %s:\n got %s\nwant %s", id, tc.name, got, tc.want)
			}
		}
	}
	// Inside a funded allowance the budget On adds still fits below it.
	for _, total := range []int{1024, 1025, 2000, 4096, 60000} {
		for effort, budget := range map[string]int{"minimal": 1024, "ultra": 4096} {
			req, body, authorized := fundedrequest.New(t, total, map[string]any{"enabled": true}, effort)
			for _, model := range []string{"claude-haiku-4-5", "claude-opus-4-5"} {
				native := anthropicChatReasoningBody(model, req, body)
				fundedrequest.Check(t, buildAnthropicWireRequest(model, native.Messages, native), authorized, false)
				thinking, _ := native.Thinking.(map[string]any)
				if total <= 1024 {
					if native.Thinking != nil {
						t.Errorf("%s total=%d %s: thinking=%v below the provider minimum", model, total, effort, native.Thinking)
					}
				} else if want := min(budget, total-1); thinking["budget_tokens"] != want {
					t.Errorf("%s total=%d %s: budget=%v, want %d", model, total, effort, thinking["budget_tokens"], want)
				}
			}
		}
	}
}

// Decision 9: On alone is adaptive thinking on the full class, whose models
// refuse a thinking budget. No effort is named, so the model thinks at its
// own depth. Every other class is still sent the 4,096 token budget.
func TestClaudeOnAlonePerClass(t *testing.T) {
	ons := []string{`"reasoning":{"enabled":true}`, `"reasoning":true`, `"reasoning":{"type":"enabled"}`}
	const budget = `{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"}}`
	for _, tc := range []struct {
		ids  []string
		want string
	}{
		{claudeFullIDs, `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`},
		{claudeV46IDs, budget},
		{claudeOpus45IDs, budget},
		{claudeBudgetIDs, budget},
	} {
		for _, id := range tc.ids {
			for _, on := range ons {
				if got := claudeWire(t, id, on); got != tc.want {
					t.Errorf("%s %s:\n got %s\nwant %s", id, on, got, tc.want)
				}
			}
		}
	}
	const explicit = `{"max_tokens":4096,"thinking":{"budget_tokens":2048,"type":"enabled"}}`
	for _, id := range claudeFullIDs {
		for _, tc := range []struct{ name, fields, want string }{
			{"a caller cap is sent as set", `"reasoning":{"enabled":true},"max_tokens":512`, `{"max_tokens":512,"thinking":{"type":"adaptive"}}`},
			{"top_p is not sent, top_k is", `"reasoning":{"enabled":true},"temperature":0.2,"top_k":40,"top_p":0.5`, `{"max_tokens":32000,"thinking":{"type":"adaptive"},"top_k":40}`},
			{"a forced tool choice is sent", `"reasoning":true,"tool_choice":"required",` + claudeTestTools, `{"max_tokens":32000,"thinking":{"type":"adaptive"},"tool_choice":{"type":"any"}}`},
			// A budget the caller named is left for the provider to refuse.
			{"explicit budget", `"reasoning":{"max_tokens":2048}`, explicit},
			{"On with an explicit budget", `"reasoning":{"enabled":true,"max_tokens":2048}`, explicit},
			{"On with budget_tokens", `"reasoning":{"enabled":true,"budget_tokens":2048}`, explicit},
			{"On with thinking_budget", `"reasoning":{"type":"enabled","thinking_budget":2048}`, explicit},
			{"On beside an effort", `"reasoning":{"enabled":true},"reasoning_effort":"high"`, `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`},
			{"nothing asked", ``, `{"max_tokens":32000}`},
		} {
			if got := claudeWire(t, id, tc.fields, "top_p", "top_k", "tool_choice"); got != tc.want {
				t.Errorf("%s %s:\n got %s\nwant %s", id, tc.name, got, tc.want)
			}
		}
		// Max tokens and sampling are treated exactly as an effort treats
		// them: the same request with an effort differs only by the effort.
		for _, extra := range []string{``, `,"max_tokens":512`, `,"max_tokens":20000`, `,"temperature":0.2,"top_k":40,"top_p":0.5`, `,"top_p":0.97`, `,"tool_choice":"required",` + claudeTestTools} {
			withEffort := claudeWire(t, id, `"reasoning":{"enabled":true,"effort":"high"}`+extra, "temperature", "top_p", "top_k", "tool_choice")
			want := strings.Replace(withEffort, `"output_config":{"effort":"high"},`, ``, 1)
			if got := claudeWire(t, id, `"reasoning":{"enabled":true}`+extra, "temperature", "top_p", "top_k", "tool_choice"); got != want || want == withEffort {
				t.Errorf("%s On alone%s:\n got %s\nwant %s", id, extra, got, want)
			}
		}
		// The wire builder drops temperature for most of these IDs by itself,
		// so check the dispatched body too.
		req, body := claudeChat(t, `"reasoning":{"enabled":true},"temperature":0.2,"top_k":40,"top_p":0.5`)
		native := anthropicChatReasoningBody(id, req, body)
		if native.Temperature != nil || native.TopP != nil || native.TopK == nil || *native.TopK != 40 || native.OutputConfig != nil {
			t.Errorf("%s On alone: temperature=%v top_p=%v top_k=%v output_config=%v", id, native.Temperature, native.TopP, native.TopK, native.OutputConfig)
		}
		if got := claudeControls(t, bedrock.BuildRequestShape(native), "thinking", "output_config", "max_tokens", "temperature", "top_p", "top_k"); got != `{"max_tokens":32000,"thinking":{"type":"adaptive"},"top_k":40}` {
			t.Errorf("%s On alone on the Bedrock wire: got %s", id, got)
		}
	}
	// On alone inside a funded allowance: max_tokens is the authorization. An
	// allowance of 1,024 tokens or less cannot hold thinking and an answer,
	// so no thinking is sent and the body goes out as built.
	for _, total := range []int{1, 512, 1024, 1025, 8192, 60000} {
		for _, hint := range []any{true, map[string]any{"enabled": true}, map[string]any{"type": "enabled"}} {
			for _, model := range []string{"claude-opus-5-5", "claude-haiku-5-5", "claude-opus-6"} {
				req, body, authorized := fundedrequest.New(t, total, hint, "")
				native := anthropicChatReasoningBody(model, req, body)
				fundedrequest.Check(t, buildAnthropicWireRequest(model, native.Messages, native), authorized, false)
				if total <= 1024 {
					if native != body || native.Thinking != nil || native.OutputConfig != nil {
						t.Errorf("%s funded total=%d %v: thinking=%v output_config=%v, want the body as built", model, total, hint, native.Thinking, native.OutputConfig)
					}
					continue
				}
				if thinking, _ := native.Thinking.(map[string]any); len(thinking) != 1 || thinking["type"] != "adaptive" {
					t.Errorf("%s funded total=%d %v: thinking=%v", model, total, hint, native.Thinking)
				}
			}
		}
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

// Decision 5: a forced tool choice or an assistant prefill beats any thinking
// budget the gateway chose, from an effort, from On alone, from On beside an
// effort, and from the budget On adds. Anthropic refuses budget thinking
// beside them every time. Only a budget the caller named in tokens is still
// sent, for the provider to judge.
func TestClaudeForcedToolOrPrefillBeatsAGatewayChosenBudget(t *testing.T) {
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
		bare := func(word string) string { return strings.TrimSuffix(","+effort(word), ",") }
		for _, tc := range []struct{ name, fields, want string }{
			{"effort + required tool", `"reasoning_effort":"high",` + anyTool, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"type":"any"}}`},
			{"effort + named tool", `"reasoning_effort":"high",` + named, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"name":"lookup","type":"tool"}}`},
			{"max + required tool", `"reasoning":{"effort":"max"},` + anyTool, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"type":"any"}}`},
			{"effort + required tool keeps sampling", `"reasoning_effort":"high","temperature":0.2,` + anyTool, `{"max_tokens":4096,` + effort("high") + `"temperature":0.2,"tool_choice":{"type":"any"}}`},
			{"effort + prefill", `"reasoning_effort":"high",` + prefill, `{"max_tokens":4096` + bare("high") + `}`},
			{"effort + cap + prefill", `"reasoning_effort":"high","max_tokens":512,` + prefill, `{"max_tokens":512` + bare("high") + `}`},
			{"effort + auto tool thinks", `"reasoning_effort":"high",` + auto, `{"max_tokens":12288,` + effort("high") + budget + `,"tool_choice":{"type":"auto"}}`},
			{"effort + tools, no choice, thinks", `"reasoning_effort":"high",` + claudeTestTools, `{"max_tokens":12288,` + effort("high") + budget + `}`},
			// On is a budget the gateway chose as well.
			{"On + required tool", `"reasoning":{"enabled":true},` + anyTool, `{"max_tokens":4096,"tool_choice":{"type":"any"}}`},
			{"On + named tool", `"reasoning":{"enabled":true},` + named, `{"max_tokens":4096,"tool_choice":{"name":"lookup","type":"tool"}}`},
			{"On + prefill", `"reasoning":{"enabled":true},` + prefill, `{"max_tokens":4096}`},
			{"bare true + required tool", `"reasoning":true,` + anyTool, `{"max_tokens":4096,"tool_choice":{"type":"any"}}`},
			{"On + cap + required tool", `"reasoning":{"enabled":true},"max_tokens":512,` + anyTool, `{"max_tokens":512,"tool_choice":{"type":"any"}}`},
			{"On + auto tool thinks", `"reasoning":{"enabled":true},` + auto, `{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"},"tool_choice":{"type":"auto"}}`},
			{"On + effort + required tool", `"reasoning":{"enabled":true,"effort":"high"},` + anyTool, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"type":"any"}}`},
			{"On + max + required tool", `"reasoning":{"enabled":true,"effort":"max"},` + anyTool, `{"max_tokens":4096,` + effort("high") + `"tool_choice":{"type":"any"}}`},
			{"On + top-level effort + prefill", `"reasoning":{"enabled":true},"reasoning_effort":"high",` + prefill, `{"max_tokens":4096` + bare("high") + `}`},
			{"On + top-level effort + required tool keeps sampling", `"reasoning":true,"reasoning_effort":"low","temperature":0.2,` + anyTool, `{"max_tokens":4096,` + effort("low") + `"temperature":0.2,"tool_choice":{"type":"any"}}`},
			// A budget the caller named in tokens is left for the provider.
			{"named budget + required tool", `"reasoning":{"max_tokens":8192},` + anyTool, `{"max_tokens":12288,` + budget + `,"tool_choice":{"type":"any"}}`},
			{"named budget + prefill", `"reasoning":{"max_tokens":8192},` + prefill, `{"max_tokens":12288,` + budget + `}`},
			{"On with a named budget + required tool", `"reasoning":{"enabled":true,"max_tokens":8192},` + anyTool, `{"max_tokens":12288,` + budget + `,"tool_choice":{"type":"any"}}`},
			{"budget_tokens + required tool", `"reasoning":{"budget_tokens":8192},` + anyTool, `{"max_tokens":12288,` + budget + `,"tool_choice":{"type":"any"}}`},
			{"thinking_budget + named tool", `"reasoning":{"thinking_budget":8192},` + named, `{"max_tokens":12288,` + budget + `,"tool_choice":{"name":"lookup","type":"tool"}}`},
			{"named budget beside an effort + required tool", `"reasoning":{"max_tokens":8192,"effort":"high"},` + anyTool, `{"max_tokens":12288,` + effort("high") + budget + `,"tool_choice":{"type":"any"}}`},
		} {
			if got := claudeWire(t, id, tc.fields, "tool_choice", "temperature"); got != tc.want {
				t.Errorf("%s %s:\n got %s\nwant %s", id, tc.name, got, tc.want)
			}
		}
	}
}

// The same rule as a property, over every way the gateway comes to choose a
// budget: none of them is ever on the wire beside a forced tool choice or a
// prefill, on any budget class ID. A budget the caller named always is.
func TestClaudeNoGatewayChosenBudgetBesideAForcedToolOrPrefill(t *testing.T) {
	var chosen []string
	for _, word := range []string{"minimal", "low", "medium", "high", "xhigh", "max", "ultra"} {
		chosen = append(chosen,
			`"reasoning_effort":"`+word+`"`, `"reasoning":{"effort":"`+word+`"}`, `"reasoning":"`+word+`"`,
			`"reasoning":{"enabled":true,"effort":"`+word+`"}`, `"reasoning":{"enabled":true},"reasoning_effort":"`+word+`"`,
			`"reasoning":true,"reasoning_effort":"`+word+`"`, `"reasoning":{"type":"enabled"},"reasoning_effort":"`+word+`"`,
			`"reasoning":{"type":"adaptive","effort":"`+word+`"}`)
	}
	chosen = append(chosen, `"reasoning":{"enabled":true}`, `"reasoning":true`, `"reasoning":{"type":"enabled"}`, `"reasoning":{"type":"adaptive"}`)
	namedBudgets := []string{
		`"reasoning":{"max_tokens":2048}`, `"reasoning":{"budget_tokens":2048}`, `"reasoning":{"thinking_budget":2048}`,
		`"reasoning":{"enabled":true,"max_tokens":2048}`, `"reasoning":{"max_tokens":2048,"effort":"high"}`, `"reasoning":{"max_tokens":2048},"reasoning_effort":"max"`,
	}
	refusers := map[string]string{
		"required tool": `,"tool_choice":"required",` + claudeTestTools,
		"named tool":    `,"tool_choice":{"type":"function","function":{"name":"lookup"}},` + claudeTestTools,
		"prefill":       `,"messages":[{"role":"user","content":"test"},{"role":"assistant","content":"{"}]`,
		"prefill + cap": `,"max_tokens":512,"messages":[{"role":"user","content":"test"},{"role":"assistant","content":"{"}]`,
	}
	budgeted := func(id, fields string) (bool, int) {
		req, body := claudeChat(t, fields)
		native := anthropicChatReasoningBody(id, req, body)
		thinking, _ := native.Thinking.(map[string]any)
		return thinking["budget_tokens"] != nil, native.AnthropicDispatchMaxTokens() - body.MaxTokens
	}
	thinks := 0
	for _, id := range append(append([]string{}, claudeBudgetIDs...), claudeOpus45IDs...) {
		for name, refuser := range refusers {
			for _, fields := range chosen {
				if has, room := budgeted(id, fields+refuser); has || room != 0 {
					t.Errorf("%s %s + %s: budget thinking sent=%t, max_tokens raised by %d", id, fields, name, has, room)
				}
				// The control: without the refuser the same request can think.
				if has, _ := budgeted(id, fields); has {
					thinks++
				}
			}
			for _, fields := range namedBudgets {
				if has, _ := budgeted(id, fields+refuser); !has {
					t.Errorf("%s %s + %s: the budget the caller named was dropped", id, fields, name)
				}
			}
		}
	}
	if thinks == 0 {
		t.Fatal("no request in this test thinks without a forced tool or prefill: the property proves nothing")
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
