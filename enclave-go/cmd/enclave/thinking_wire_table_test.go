package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

// wireRoute is one way a chat request reaches a provider.
type wireRoute struct {
	kind     string // "chat" for the OpenAI-compatible projection, "claude" for the Anthropic wire
	provider string
	model    string // the catalog model the caller names
	upstream string // the provider's own model ID
	tools    bool
}

const wireTableTools = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}],`

// reasoningWire parses a chat request as the gateway does and returns the
// reasoning controls it puts on the provider wire, as compact JSON. A request
// the provider route refuses at preparation is "route 400", the failure that
// sends it to the next candidate. One refused before authorization would be
// "refused at <parameter>": no row of these tables expects that.
func reasoningWire(t *testing.T, route wireRoute, fields string) string {
	t.Helper()
	extra := ""
	if route.tools {
		extra = wireTableTools
	}
	req, err := parseChatRequest([]byte(`{"model":"` + route.model + `","messages":[{"role":"user","content":"test"}],` + extra + fields + `}`))
	if err != nil {
		var rejected *adapter.AdapterError
		if !errors.As(err, &rejected) || rejected.Status != 400 {
			t.Fatalf("%s: %v", fields, err)
		}
		return "refused at " + rejected.Context
	}
	body, err := adapter.ToAnthropic(req, route.model)
	if err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	keys := []string{"reasoning", "reasoning_effort", "thinking", "enable_thinking", "chat_template_kwargs"}
	if route.kind == "claude" {
		keys = []string{"thinking", "output_config"}
		if encoded, err = json.Marshal(llm.BuildAnthropicRequestShape(route.upstream, req, body)); err != nil {
			t.Fatal(err)
		}
	} else {
		prepared, err := llm.PrepareChatRequest(route.provider, route.upstream, req, body, []llm.ChatMessage{{Role: "user", Content: "test"}}, llm.ChatPreparationOptions{})
		if err != nil {
			if status, ok := llm.HTTPStatusFromError(err); !ok || status != 400 {
				t.Fatalf("%s %s: %v", route.provider, fields, err)
			}
			return "route 400"
		}
		encoded = prepared.Bytes
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	controls := map[string]any{}
	for _, key := range keys {
		if wire[key] != nil {
			controls[key] = wire[key]
		}
	}
	out, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The five requests the table describes. Every switch spelling builds the same
// request, so the table uses one and the spellings are checked against it.
const (
	wireEffortOnly = `"reasoning_effort":"high"`
	wireOnOnly     = `"thinking":{"type":"enabled"}`
	wireOffOnly    = `"thinking":{"type":"disabled"}`
	wireOnEffort   = `"thinking":{"type":"enabled"},"reasoning_effort":"high"`
	wireOffEffort  = `"thinking":{"type":"disabled"},"reasoning_effort":"high"`
)

var wireSwitchSpellings = map[string][]string{
	wireOnOnly:    {`"enable_thinking":true`, `"chat_template_kwargs":{"enable_thinking":true}`, `"chat_template_kwargs":{"thinking":true}`},
	wireOffOnly:   {`"enable_thinking":false`, `"chat_template_kwargs":{"enable_thinking":false}`, `"chat_template_kwargs":{"thinking":false}`},
	wireOnEffort:  {`"enable_thinking":true,"reasoning_effort":"high"`, `"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"high"`, `"chat_template_kwargs":{"thinking":true},"reasoning_effort":"high"`, `"thinking":{"type":"adaptive"},"reasoning_effort":"high"`},
	wireOffEffort: {`"enable_thinking":false,"reasoning_effort":"high"`, `"chat_template_kwargs":{"enable_thinking":false},"reasoning_effort":"high"`, `"chat_template_kwargs":{"thinking":false},"reasoning_effort":"high"`},
}

// TestChatThinkingSwitchWireTable records, per provider family, what each of
// the five requests puts on the wire today. It records current behavior, not
// a rule: where a row looks wrong, the row is the finding. In particular a
// host with no reviewed reasoning contract is sent the effort of a switch
// plus effort request inside the reasoning object, while an effort alone goes
// top-level. See the open decisions in docs/reasoning-output.md.
func TestChatThinkingSwitchWireTable(t *testing.T) {
	const (
		effortField  = `{"reasoning_effort":"high"}`
		budget       = `"thinking":{"budget_tokens":4096,"type":"enabled"}`
		reasoningOn  = `"reasoning":{"enabled":true}`
		reasoningOff = `{"reasoning":{"enabled":false}}`
	)
	type row struct {
		routes                                   []wireRoute
		effort, on, off, onWithEffort, offEffort string
	}
	chat := func(provider, model, upstream string) wireRoute {
		return wireRoute{kind: "chat", provider: provider, model: model, upstream: upstream}
	}
	hosts := func(providers ...string) []wireRoute {
		routes := make([]wireRoute, 0, len(providers))
		for _, provider := range providers {
			routes = append(routes, wireHost(provider))
		}
		return routes
	}
	claude := func(upstreams ...string) []wireRoute {
		routes := make([]wireRoute, 0, len(upstreams))
		for _, upstream := range upstreams {
			routes = append(routes, wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/" + upstream, upstream: upstream})
		}
		return routes
	}
	for name, tc := range map[string]row{
		// Hosts with no reviewed reasoning contract take the request fields as
		// sent: a switch beside an effort is the reasoning object holding both.
		"generic hosts": {
			routes: hosts("together", "deepinfra", "novita", "groq", "parasail", "nebius", "siliconflow", "venice", "phala", "near-ai", "gmi", "friendli", "wafer", "minimax", "chutes", "cloudflare-workers-ai", "azure", "nvidia-nim", "sambanova", "huggingface"),
			effort: effortField, on: `{` + reasoningOn + `,` + budget + `}`, off: reasoningOff,
			onWithEffort: `{"reasoning":{"effort":"high","enabled":true}}`, offEffort: reasoningOff,
		},
		// Chat endpoints that read top-level reasoning_effort and no reasoning object.
		"reasoning_effort hosts": {
			routes: append(hosts("mistral", "alibaba", "grok", "cerebras", "crusoe", "baseten", "tinfoil"), chat("openai", "openai/gpt-5.5", "gpt-5.5"), chat("google-ai-studio", "google/gemini-2.5-flash", "gemini-2.5-flash")),
			effort: effortField, on: `{` + reasoningOn + `,` + budget + `}`, off: reasoningOff,
			onWithEffort: effortField, offEffort: reasoningOff,
		},
		"meta": {
			routes: hosts("meta"),
			effort: effortField, on: `{` + reasoningOn + `}`, off: reasoningOff, onWithEffort: effortField, offEffort: reasoningOff,
		},
		"google-ai-studio gemini 3": {
			routes: []wireRoute{chat("google-ai-studio", "google/gemini-3.5-flash", "gemini-3.5-flash")},
			effort: effortField, on: `{` + reasoningOn + `,"reasoning_effort":"high"}`, off: reasoningOff, onWithEffort: effortField, offEffort: reasoningOff,
		},
		// Hybrid APIs take the switch and the depth as two fields.
		"thinking.type hosts": {
			routes: []wireRoute{chat("deepseek", "deepseek/deepseek-v4.1-flash", "deepseek-v4.1-flash"), chat("zai", "z-ai/glm-5.3", "glm-5.3"), chat("kimi", "moonshotai/kimi-k2.6", "kimi-k2.6"), chat("kimi", "moonshotai/kimi-k3", "kimi-k3"), chat("tencent", "deepseek/deepseek-v4.1", "deepseek-v4.1")},
			effort: effortField, on: `{"thinking":{"type":"enabled"}}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"reasoning_effort":"high","thinking":{"type":"enabled"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
		},
		"tencent minimax-m3": {
			routes: []wireRoute{chat("tencent", "minimax/minimax-m3", "minimax-m3")},
			effort: effortField, on: `{"thinking":{"type":"adaptive"}}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"reasoning_effort":"high","thinking":{"type":"adaptive"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
		},
		"tencent always-thinking glm": {
			routes: []wireRoute{chat("tencent", "z-ai/glm-5.3", "glm-5.3")},
			effort: effortField, on: `{"thinking":{"type":"enabled"}}`, off: "route 400",
			onWithEffort: `{"reasoning_effort":"high","thinking":{"type":"enabled"}}`, offEffort: "route 400",
		},
		"tencent always-thinking kimi": {
			routes: []wireRoute{chat("tencent", "moonshotai/kimi-k3", "kimi-k3")},
			effort: effortField, on: effortField, off: "route 400", onWithEffort: effortField, offEffort: "route 400",
		},
		"fireworks": {
			routes: []wireRoute{chat("fireworks", "m", "m"), chat("fireworks", "minimax/minimax-m3", "accounts/fireworks/models/minimax-m3")},
			effort: effortField, on: `{` + budget + `}`, off: `{"reasoning_effort":"none"}`, onWithEffort: effortField, offEffort: `{"reasoning_effort":"none"}`,
		},
		// Another host of the same OpenAI model is a generic host.
		"openai model on another host": {
			routes: []wireRoute{{kind: "chat", provider: "gmi", model: "openai/gpt-5.5", upstream: "gpt-5.5", tools: true}},
			effort: effortField, on: `{` + reasoningOn + `,` + budget + `}`, off: reasoningOff,
			onWithEffort: `{"reasoning":{"effort":"high","enabled":true}}`, offEffort: reasoningOff,
		},
		"claude budget-only": {
			routes: claude("claude-haiku-4-5", "claude-sonnet-4-5", "us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-sonnet-4-5@20250929"),
			effort: `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`, on: `{` + budget + `}`, off: `{}`,
			onWithEffort: `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`, offEffort: `{}`,
		},
		"claude opus 4.5": {
			routes: claude("claude-opus-4-5", "claude-opus-4-5-20251101", "claude-opus-4-5@20251101"),
			effort: `{"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`, on: `{` + budget + `}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
		},
		// Opus 4.6 and Sonnet 4.6 think adaptively with an effort and still
		// take a thinking budget, so On alone is the 4,096 token budget.
		"claude 4.6": {
			routes: claude("claude-sonnet-4-6", "claude-opus-4-6", "us.anthropic.claude-sonnet-4-6", "claude-opus-4-6@20260205"),
			effort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, on: `{` + budget + `}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
		},
		// The full class refuses a thinking budget, so On alone is adaptive
		// thinking with no effort named. Haiku 5.5 and Mythos 5 are in this
		// class: Haiku 5.5 used to be sent a budget for every effort.
		"claude adaptive": {
			routes: claude("claude-opus-4-7", "claude-opus-4-8", "claude-opus-5-5", "claude-sonnet-5", "claude-haiku-5-5", "claude-mythos-5", "claude-fable-5-1",
				"us.anthropic.claude-haiku-5-5", "claude-haiku-5-5@20261001"),
			effort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, on: `{"thinking":{"type":"adaptive"}}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
		},
		// Sonnet 5.5 refuses disabled and names between_tools as its Off.
		"claude sonnet 5.5": {
			routes: claude("claude-sonnet-5-5", "us.anthropic.claude-sonnet-5-5", "claude-sonnet-5-5@20261001"),
			effort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, on: `{"thinking":{"type":"adaptive"}}`, off: `{"thinking":{"type":"between_tools"}}`,
			onWithEffort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, offEffort: `{"thinking":{"type":"between_tools"}}`,
		},
	} {
		for _, route := range tc.routes {
			for fields, want := range map[string]string{wireEffortOnly: tc.effort, wireOnOnly: tc.on, wireOffOnly: tc.off, wireOnEffort: tc.onWithEffort, wireOffEffort: tc.offEffort} {
				if got := reasoningWire(t, route, fields); got != want {
					t.Errorf("%s (%s %s) %s:\n got %s\nwant %s", name, route.provider, route.upstream, fields, got, want)
				}
				for _, spelling := range wireSwitchSpellings[fields] {
					if got := reasoningWire(t, route, spelling); got != want {
						t.Errorf("%s (%s %s) %s:\n got %s\nwant %s", name, route.provider, route.upstream, spelling, got, want)
					}
				}
			}
		}
	}
}

// wireHost is a provider serving a model with no contract of its own. Phala
// and NEAR AI serve only models in their reviewed maps.
func wireHost(provider string) wireRoute {
	model := "m"
	if provider == "phala" || provider == "near-ai" {
		model = "openai/gpt-oss-120b"
	}
	return wireRoute{kind: "chat", provider: provider, model: model, upstream: model}
}

// TestCanonicalReasoningRequestsOnProviderWires records what the canonical
// reasoning fields put on a few provider wires today. Like the table above it
// records current behavior, not a rule.
func TestCanonicalReasoningRequestsOnProviderWires(t *testing.T) {
	for _, tc := range []struct {
		route        wireRoute
		fields, want string
	}{
		{wireRoute{kind: "chat", provider: "together", model: "m", upstream: "m"}, `"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		{wireRoute{kind: "chat", provider: "together", model: "m", upstream: "m"}, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning":{"effort":"high","enabled":true}}`},
		{wireRoute{kind: "chat", provider: "together", model: "m", upstream: "m"}, `"reasoning":{"enabled":true},"reasoning_effort":"high"`, `{"reasoning":{"enabled":true},"reasoning_effort":"high"}`},
		{wireRoute{kind: "chat", provider: "together", model: "m", upstream: "m"}, `"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}`, `{"reasoning":{"effort":"high","enabled":true}}`},
		{wireRoute{kind: "chat", provider: "mistral", model: "m", upstream: "m"}, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning_effort":"high"}`},
		{wireRoute{kind: "chat", provider: "zai", model: "z-ai/glm-5.3", upstream: "glm-5.3"}, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning_effort":"high","thinking":{"type":"enabled"}}`},
		{wireRoute{kind: "chat", provider: "fireworks", model: "m", upstream: "m"}, `"reasoning":{"enabled":false,"effort":"high"}`, `{"reasoning_effort":"none"}`},
	} {
		if got := reasoningWire(t, tc.route, tc.fields); got != tc.want {
			t.Errorf("%s %s: got %s, want %s", tc.route.provider, tc.fields, got, tc.want)
		}
	}
}

// TestClaudeThinkingSwitchWithEffortIsTheReasoningObject records that on a
// Claude model a switch beside an effort is the reasoning object holding
// both, and what that object sends: the effort ladder of the model's class,
// as docs/reasoning-output.md states it under "Claude models".
func TestClaudeThinkingSwitchWithEffortIsTheReasoningObject(t *testing.T) {
	for _, upstream := range []string{"claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-5", "claude-sonnet-4-6", "claude-opus-4-8", "claude-opus-5-5", "claude-haiku-5-5", "claude-sonnet-5-5"} {
		route := wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/" + upstream, upstream: upstream}
		for _, effort := range []string{"minimal", "low", "medium", "high", "xhigh", "max", "ultra"} {
			object := reasoningWire(t, route, `"reasoning":{"enabled":true,"effort":"`+effort+`"}`)
			for _, on := range []string{`"thinking":{"type":"enabled"}`, `"thinking":{"type":"adaptive"}`, `"enable_thinking":true`, `"chat_template_kwargs":{"thinking":true}`} {
				if got := reasoningWire(t, route, on+`,"reasoning_effort":"`+effort+`"`); got != object {
					t.Errorf("%s %s effort=%s: got %s, the reasoning object sends %s", upstream, on, effort, got, object)
				}
			}
		}
	}
	// An effort the model does not have is the nearest one it has. On a
	// budget-only model max is the 8,192 budget. Opus 4.5 is sent an effort
	// it accepts: max and xhigh are high, minimal is low. An unknown effort
	// is still sent as written. These requests all carry On, and On always
	// turns thinking on: beside minimal it is the smallest budget, 1,024
	// tokens, and beside an unknown effort it is the 4,096 of On alone.
	for _, tc := range []struct{ upstream, effort, want string }{
		{"claude-sonnet-4-5", "max", `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-sonnet-4-5", "minimal", `{"thinking":{"budget_tokens":1024,"type":"enabled"}}`},
		{"claude-haiku-4-5", "ultra", `{"thinking":{"budget_tokens":4096,"type":"enabled"}}`},
		{"claude-haiku-4-5", "high", `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-opus-4-5", "max", `{"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-opus-4-5", "minimal", `{"output_config":{"effort":"low"},"thinking":{"budget_tokens":1024,"type":"enabled"}}`},
		{"claude-opus-4-5", "ultra", `{"output_config":{"effort":"ultra"},"thinking":{"budget_tokens":4096,"type":"enabled"}}`},
		{"claude-opus-4-5", "xhigh", `{"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-sonnet-4-6", "xhigh", `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`},
		{"claude-sonnet-4-6", "minimal", `{"output_config":{"effort":"low"},"thinking":{"type":"adaptive"}}`},
		{"claude-sonnet-4-6", "max", `{"output_config":{"effort":"max"},"thinking":{"type":"adaptive"}}`},
		{"claude-opus-4-8", "xhigh", `{"output_config":{"effort":"xhigh"},"thinking":{"type":"adaptive"}}`},
		{"claude-opus-4-8", "minimal", `{"output_config":{"effort":"low"},"thinking":{"type":"adaptive"}}`},
		{"claude-haiku-5-5", "high", `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`},
		{"claude-haiku-5-5", "minimal", `{"output_config":{"effort":"low"},"thinking":{"type":"adaptive"}}`},
		{"claude-haiku-5-5", "ultra", `{"output_config":{"effort":"ultra"},"thinking":{"type":"adaptive"}}`},
	} {
		route := wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/" + tc.upstream, upstream: tc.upstream}
		if got := reasoningWire(t, route, `"thinking":{"type":"enabled"},"reasoning_effort":"`+tc.effort+`"`); got != tc.want {
			t.Errorf("%s On + %s: got %s, want %s", tc.upstream, tc.effort, got, tc.want)
		}
	}
}

// claudeRequestWire parses a whole chat request as the gateway does and
// returns what it sends a Claude model: the reasoning controls, max_tokens,
// the sampling fields and the tool choice, as compact JSON with sorted keys.
func claudeRequestWire(t *testing.T, upstream, messages, fields string) string {
	t.Helper()
	req, err := parseChatRequest([]byte(`{"model":"anthropic/` + upstream + `","messages":` + messages + `,` + fields + `}`))
	if err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(llm.BuildAnthropicRequestShape(upstream, req, body))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	controls := map[string]any{}
	for _, key := range []string{"thinking", "output_config", "max_tokens", "temperature", "top_p", "top_k", "tool_choice"} {
		if wire[key] != nil {
			controls[key] = wire[key]
		}
	}
	out, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestClaudeEffortLadderWireTable pins what a reasoning request sends each
// class of Claude model. Unlike the tables above it states a rule: an effort
// is a request for depth, so it never fails a Claude request and is never
// ignored. See "Claude models" in docs/reasoning-output.md.
func TestClaudeEffortLadderWireTable(t *testing.T) {
	const (
		user     = `[{"role":"user","content":"test"}]`
		prefill  = `[{"role":"user","content":"test"},{"role":"assistant","content":"{"}]`
		tools    = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}]`
		required = `"tool_choice":"required",` + tools
		named    = `"tool_choice":{"type":"function","function":{"name":"lookup"}},` + tools
		budget   = "claude-haiku-4-5"
		opus45   = "claude-opus-4-5"
		v46      = "claude-sonnet-4-6"
		full     = "claude-opus-5"
		sonnet55 = "claude-sonnet-5-5"
		haiku55  = "claude-haiku-5-5"
		// A Claude ID no table names is in the full class. Sonnet 4 is one of
		// the 4.0 models, matched by what follows the 4.
		future  = "claude-opus-6"
		sonnet4 = "claude-sonnet-4"
	)
	think := func(tokens string) string { return `"thinking":{"budget_tokens":` + tokens + `,"type":"enabled"}` }
	adaptive := func(effort string) string {
		return `{"max_tokens":32000,"output_config":{"effort":"` + effort + `"},"thinking":{"type":"adaptive"}}`
	}
	const disabled = `{"max_tokens":4096,"thinking":{"type":"disabled"}}`
	for _, tc := range []struct {
		name, messages, fields string
		want                   map[string]string
	}{
		// The ladder: each effort is the nearest one the model has.
		{"minimal", user, `"reasoning_effort":"minimal"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"}}`,
			v46: adaptive("low"), full: adaptive("low"), haiku55: adaptive("low"), sonnet55: adaptive("low"),
		}},
		{"low", user, `"reasoning_effort":"low"`, map[string]string{
			budget: `{"max_tokens":4096,` + think("1024") + `}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},` + think("1024") + `}`,
			v46: adaptive("low"), full: adaptive("low"), haiku55: adaptive("low"),
		}},
		{"medium", user, `"reasoning_effort":"medium"`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, opus45: `{"max_tokens":8192,"output_config":{"effort":"medium"},` + think("4096") + `}`,
			v46: adaptive("medium"), full: adaptive("medium"), haiku55: adaptive("medium"),
		}},
		{"high", user, `"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
			v46: adaptive("high"), full: adaptive("high"), haiku55: adaptive("high"),
			future: adaptive("high"), sonnet4: `{"max_tokens":12288,` + think("8192") + `}`,
		}},
		{"xhigh", user, `"reasoning_effort":"xhigh"`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
			v46: adaptive("high"), full: adaptive("xhigh"), haiku55: adaptive("xhigh"),
		}},
		{"max", user, `"reasoning_effort":"max"`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
			v46: adaptive("max"), full: adaptive("max"), haiku55: adaptive("max"),
		}},
		{"an effort the gateway does not know", user, `"reasoning_effort":"ultra"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"ultra"}}`,
			v46: adaptive("ultra"), full: adaptive("ultra"),
		}},
		// Off governs, and max_tokens keeps no room for the discarded budget.
		{"Off object beside an effort", user, `"reasoning":{"enabled":false},"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled, haiku55: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"Off object holding an effort", user, `"reasoning":{"enabled":false,"effort":"high"}`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"Off object beside an effort, with a cap", user, `"reasoning":{"enabled":false},"reasoning_effort":"high","max_tokens":512`, map[string]string{
			budget: `{"max_tokens":512}`, opus45: `{"max_tokens":512,"thinking":{"type":"disabled"}}`,
		}},
		{"Off switch alone", user, `"thinking":{"type":"disabled"}`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, full: disabled, sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		// Every other spelling of Off that reaches a Claude model governs too.
		{"bare reasoning false", user, `"reasoning":false`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled, haiku55: disabled, future: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"bare reasoning false beside an effort", user, `"reasoning":false,"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"reasoning.type disabled beside an effort", user, `"reasoning":{"type":"disabled"},"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"effort off", user, `"reasoning_effort":"off"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled, haiku55: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"effort disabled in the object", user, `"reasoning":{"effort":"disabled"}`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled,
		}},
		{"effort none", user, `"reasoning_effort":"none"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled,
			sonnet55: `{"max_tokens":4096,"thinking":{"type":"between_tools"}}`,
		}},
		{"On object beside effort off", user, `"reasoning":{"enabled":true},"reasoning_effort":"off"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled,
		}},
		{"an Off word in the object beside a top-level effort", user, `"reasoning":{"effort":"none"},"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled, v46: disabled, full: disabled,
		}},
		// On beside an effort is that effort, wherever the effort is written.
		{"On object beside low", user, `"reasoning":{"enabled":true},"reasoning_effort":"low"`, map[string]string{
			budget: `{"max_tokens":4096,` + think("1024") + `}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},` + think("1024") + `}`,
			v46: adaptive("low"), full: adaptive("low"),
		}},
		{"On object beside high", user, `"reasoning":{"enabled":true},"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
		}},
		{"On object beside max", user, `"reasoning":{"enabled":true},"reasoning_effort":"max"`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
		}},
		// On always turns thinking on. Beside minimal, which alone sets no
		// budget, it is the smallest budget. Beside an effort the gateway does
		// not know it is the 4,096 tokens of On alone.
		{"On object beside minimal", user, `"reasoning":{"enabled":true},"reasoning_effort":"minimal"`, map[string]string{
			budget: `{"max_tokens":4096,` + think("1024") + `}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},` + think("1024") + `}`,
			v46: adaptive("low"), full: adaptive("low"), haiku55: adaptive("low"),
		}},
		{"On object holding minimal", user, `"reasoning":{"enabled":true,"effort":"minimal"}`, map[string]string{
			budget: `{"max_tokens":4096,` + think("1024") + `}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},` + think("1024") + `}`,
		}},
		{"On switch beside minimal", user, `"thinking":{"type":"enabled"},"reasoning_effort":"minimal"`, map[string]string{
			budget: `{"max_tokens":4096,` + think("1024") + `}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},` + think("1024") + `}`,
		}},
		{"On object beside an unknown effort", user, `"reasoning":{"enabled":true},"reasoning_effort":"ultra"`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, opus45: `{"max_tokens":8192,"output_config":{"effort":"ultra"},` + think("4096") + `}`,
			v46: adaptive("ultra"), full: adaptive("ultra"),
		}},
		{"On switch beside an unknown effort", user, `"enable_thinking":true,"reasoning_effort":"ultra"`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, opus45: `{"max_tokens":8192,"output_config":{"effort":"ultra"},` + think("4096") + `}`,
		}},
		{"On + minimal + required tool", user, `"thinking":{"type":"enabled"},"reasoning_effort":"minimal",` + required, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},"tool_choice":{"type":"any"}}`,
		}},
		{"On + minimal + sampling", user, `"reasoning":{"enabled":true,"effort":"minimal"},"temperature":0.2,"top_k":40,"top_p":0.5`, map[string]string{
			budget: `{"max_tokens":4096,` + think("1024") + `}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},` + think("1024") + `}`,
		}},
		{"On beside none is Off", user, `"reasoning":{"enabled":true},"reasoning_effort":"none"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: disabled,
		}},
		// On alone is adaptive thinking with no effort on the full class, which
		// refuses a thinking budget, and the 4,096 token budget elsewhere.
		{"On alone", user, `"reasoning":{"enabled":true}`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, opus45: `{"max_tokens":8192,` + think("4096") + `}`, v46: `{"max_tokens":8192,` + think("4096") + `}`,
			full: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, haiku55: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, sonnet55: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`,
		}},
		{"On alone, bare true", user, `"reasoning":true`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, v46: `{"max_tokens":8192,` + think("4096") + `}`,
			full: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, haiku55: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`,
			future: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, sonnet4: `{"max_tokens":8192,` + think("4096") + `}`,
		}},
		{"On alone, reasoning.type", user, `"reasoning":{"type":"enabled"}`, map[string]string{
			opus45: `{"max_tokens":8192,` + think("4096") + `}`, v46: `{"max_tokens":8192,` + think("4096") + `}`,
			full: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, haiku55: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`,
		}},
		{"On switch alone", user, `"thinking":{"type":"enabled"}`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, v46: `{"max_tokens":8192,` + think("4096") + `}`,
			full: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, haiku55: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`, sonnet55: `{"max_tokens":32000,"thinking":{"type":"adaptive"}}`,
		}},
		{"On alone with a cap", user, `"reasoning":{"enabled":true},"max_tokens":512`, map[string]string{
			v46: `{"max_tokens":4608,` + think("4096") + `}`, full: `{"max_tokens":512,"thinking":{"type":"adaptive"}}`, haiku55: `{"max_tokens":512,"thinking":{"type":"adaptive"}}`,
		}},
		{"On alone with sampling", user, `"reasoning":{"enabled":true},"temperature":0.2,"top_k":40,"top_p":0.5`, map[string]string{
			full: `{"max_tokens":32000,"thinking":{"type":"adaptive"},"top_k":40}`, haiku55: `{"max_tokens":32000,"thinking":{"type":"adaptive"},"top_k":40}`,
		}},
		// A token budget the caller names is still sent to the full class as
		// written. Those models refuse it: the provider judges.
		{"explicit budget on an adaptive model", user, `"thinking":{"type":"enabled","budget_tokens":2048}`, map[string]string{
			full: `{"max_tokens":4096,` + think("2048") + `}`, haiku55: `{"max_tokens":4096,` + think("2048") + `}`, v46: `{"max_tokens":4096,` + think("2048") + `}`,
		}},
		{"reasoning.max_tokens on an adaptive model", user, `"reasoning":{"max_tokens":2048}`, map[string]string{
			full: `{"max_tokens":4096,` + think("2048") + `}`, haiku55: `{"max_tokens":4096,` + think("2048") + `}`,
		}},
		// Budget thinking is sent without the sampling Anthropic refuses beside it.
		{"effort + temperature 0.2", user, `"reasoning_effort":"high","temperature":0.2`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
		}},
		{"effort + temperature 1", user, `"reasoning_effort":"high","temperature":1`, map[string]string{
			budget: `{"max_tokens":12288,"temperature":1,` + think("8192") + `}`,
		}},
		{"effort + top_k", user, `"reasoning_effort":"high","top_k":40`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
		}},
		{"effort + top_p 0.5", user, `"reasoning_effort":"high","top_p":0.5`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `}`,
		}},
		{"effort + top_p 0.97", user, `"reasoning_effort":"high","top_p":0.97`, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `,"top_p":0.97}`, opus45: `{"max_tokens":12288,"output_config":{"effort":"high"},` + think("8192") + `,"top_p":0.97}`,
		}},
		{"On + temperature", user, `"thinking":{"type":"enabled"},"temperature":0.2,"top_k":40,"top_p":0.5`, map[string]string{
			budget: `{"max_tokens":8192,` + think("4096") + `}`, opus45: `{"max_tokens":8192,` + think("4096") + `}`,
		}},
		{"explicit budget + temperature", user, `"thinking":{"type":"enabled","budget_tokens":2048},"temperature":0.2`, map[string]string{
			budget: `{"max_tokens":4096,` + think("2048") + `}`, opus45: `{"max_tokens":4096,` + think("2048") + `}`,
		}},
		{"no thinking keeps its sampling", user, `"temperature":0.2,"top_k":40,"top_p":0.5`, map[string]string{
			budget: `{"max_tokens":4096,"temperature":0.2,"top_k":40,"top_p":0.5}`, opus45: `{"max_tokens":4096,"temperature":0.2,"top_k":40,"top_p":0.5}`,
		}},
		{"minimal keeps its sampling", user, `"reasoning_effort":"minimal","temperature":0.2,"top_k":40`, map[string]string{
			budget: `{"max_tokens":4096,"temperature":0.2,"top_k":40}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"low"},"temperature":0.2,"top_k":40}`,
		}},
		// A forced tool choice or a prefill beats an effort.
		{"effort + required tool", user, `"reasoning_effort":"high",` + required, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"high"},"tool_choice":{"type":"any"}}`,
		}},
		{"effort + named tool", user, `"reasoning_effort":"max",` + named, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"name":"lookup","type":"tool"}}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"high"},"tool_choice":{"name":"lookup","type":"tool"}}`,
		}},
		{"effort + required tool keeps its sampling", user, `"reasoning_effort":"high","temperature":0.2,` + required, map[string]string{
			budget: `{"max_tokens":4096,"temperature":0.2,"tool_choice":{"type":"any"}}`,
		}},
		{"effort + auto tool choice still thinks", user, `"reasoning_effort":"high","tool_choice":"auto",` + tools, map[string]string{
			budget: `{"max_tokens":12288,` + think("8192") + `,"tool_choice":{"type":"auto"}}`,
		}},
		{"effort + prefill", prefill, `"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"high"}}`,
		}},
		{"effort + cap + prefill", prefill, `"reasoning_effort":"high","max_tokens":512`, map[string]string{
			budget: `{"max_tokens":512}`, opus45: `{"max_tokens":512,"output_config":{"effort":"high"}}`,
		}},
		// Only a budget the caller named in tokens is left for the provider.
		{"explicit budget + required tool", user, `"thinking":{"type":"enabled","budget_tokens":2048},` + required, map[string]string{
			budget: `{"max_tokens":4096,` + think("2048") + `,"tool_choice":{"type":"any"}}`, opus45: `{"max_tokens":4096,` + think("2048") + `,"tool_choice":{"type":"any"}}`,
		}},
		{"explicit budget + prefill", prefill, `"reasoning":{"max_tokens":2048}`, map[string]string{
			budget: `{"max_tokens":4096,` + think("2048") + `}`, opus45: `{"max_tokens":4096,` + think("2048") + `}`,
		}},
		// A forced tool choice or a prefill beats every budget the gateway
		// chose, the ones that come from On included.
		{"On switch + required tool", user, `"thinking":{"type":"enabled"},` + required, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`, opus45: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`,
			sonnet4: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`,
		}},
		{"On switch + prefill", prefill, `"thinking":{"type":"enabled"}`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: `{"max_tokens":4096}`,
		}},
		{"On switch + effort + required tool", user, `"thinking":{"type":"enabled"},"reasoning_effort":"high",` + required, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"high"},"tool_choice":{"type":"any"}}`,
		}},
		{"On switch + max + required tool", user, `"thinking":{"type":"enabled"},"reasoning_effort":"max",` + required, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"type":"any"}}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"high"},"tool_choice":{"type":"any"}}`,
		}},
		{"On switch + unknown effort + named tool", user, `"enable_thinking":true,"reasoning_effort":"ultra",` + named, map[string]string{
			budget: `{"max_tokens":4096,"tool_choice":{"name":"lookup","type":"tool"}}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"ultra"},"tool_choice":{"name":"lookup","type":"tool"}}`,
		}},
		{"On switch + effort + prefill", prefill, `"thinking":{"type":"enabled"},"reasoning_effort":"high"`, map[string]string{
			budget: `{"max_tokens":4096}`, opus45: `{"max_tokens":4096,"output_config":{"effort":"high"}}`,
		}},
		// The adaptive classes are not changed: adaptive thinking is sent
		// beside a forced tool choice, which Haiku 5.5 was seen to accept.
		{"adaptive effort + required tool", user, `"reasoning_effort":"high",` + required, map[string]string{
			full:    `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"},"tool_choice":{"type":"any"}}`,
			haiku55: `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"},"tool_choice":{"type":"any"}}`,
			future:  `{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"},"tool_choice":{"type":"any"}}`,
		}},
	} {
		for upstream, want := range tc.want {
			// The class is read from the ID, so the Bedrock and Vertex
			// spellings of a model are sent what its Anthropic ID is sent.
			spellings := []string{upstream, "us.anthropic." + upstream, upstream + "@20261001"}
			for _, spelling := range spellings {
				if got := claudeRequestWire(t, spelling, tc.messages, tc.fields); got != want {
					t.Errorf("%s (%s):\n got %s\nwant %s", tc.name, spelling, got, want)
				}
			}
		}
	}
}

// TestClaudeOffSpellingsThatReachDispatch records which contradictions the
// contract layer stops and which reach a Claude model, where Off governs. A
// switch turned on beside an effort that means Off is refused before billing
// authorization, and so is any switch beside the reasoning object. The same
// contradiction written with the reasoning object is not validated, so it
// reaches the dispatch.
func TestClaudeOffSpellingsThatReachDispatch(t *testing.T) {
	route := wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/claude-haiku-4-5", upstream: "claude-haiku-4-5"}
	for _, word := range []string{"none", "off", "disable", "disabled"} {
		for field, on := range map[string]string{
			"thinking":             `"thinking":{"type":"enabled"}`,
			"enable_thinking":      `"enable_thinking":true`,
			"chat_template_kwargs": `"chat_template_kwargs":{"enable_thinking":true}`,
		} {
			if got := reasoningWire(t, route, on+`,"reasoning_effort":"`+word+`"`); got != "refused at "+field {
				t.Errorf("%s beside %s: got %s, want a refusal", on, word, got)
			}
		}
		for _, fields := range []string{
			`"reasoning":{"enabled":true},"reasoning_effort":"` + word + `"`,
			`"reasoning":{"enabled":true,"effort":"` + word + `"}`,
			`"reasoning":true,"reasoning_effort":"` + word + `"`,
			`"reasoning_effort":"` + word + `"`,
			`"reasoning":{"effort":"` + word + `"}`,
			`"reasoning":{"effort":"` + word + `"},"reasoning_effort":"high"`,
		} {
			if got := reasoningWire(t, route, fields); got != `{}` {
				t.Errorf("%s: got %s, want it to reach the model with no thinking", fields, got)
			}
		}
	}
	for _, fields := range []string{`"reasoning":false`, `"reasoning":false,"reasoning_effort":"high"`, `"reasoning":{"type":"disabled"}`, `"reasoning":{"type":"disabled"},"reasoning_effort":"high"`, `"reasoning":{"enabled":false,"max_tokens":2048}`} {
		if got := reasoningWire(t, route, fields); got != `{}` {
			t.Errorf("%s: got %s, want it to reach the model with no thinking", fields, got)
		}
	}
	// A switch beside the reasoning object never reaches a model.
	for _, fields := range []string{`"thinking":{"type":"enabled"},"reasoning":{"effort":"none"}`, `"enable_thinking":false,"reasoning":{"enabled":true}`, `"thinking":{"type":"disabled"},"reasoning":false`} {
		if got := reasoningWire(t, route, fields); !strings.HasPrefix(got, "refused at ") {
			t.Errorf("%s: got %s, want a refusal", fields, got)
		}
	}
}
