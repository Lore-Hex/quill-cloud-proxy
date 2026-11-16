package main

import (
	"encoding/json"
	"errors"
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
	return wireControls(t, encoded, keys)
}

// wireControls returns the named members of a provider request as compact JSON.
func wireControls(t *testing.T, encoded []byte, keys []string) string {
	t.Helper()
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
// top-level. The six such hosts that were probed are sent it in both places.
// See "Hosts outside the effort list" in docs/reasoning-output.md.
func TestChatThinkingSwitchWireTable(t *testing.T) {
	const (
		effortField  = `{"reasoning_effort":"high"}`
		budget       = `"thinking":{"budget_tokens":4096,"type":"enabled"}`
		reasoningOn  = `"reasoning":{"enabled":true}`
		reasoningOff = `{"reasoning":{"enabled":false}}`
		// The reasoning object holding the switch and the effort.
		effortObject = `{"reasoning":{"effort":"high","enabled":true}}`
		// The same object and the effort again top-level, where every probed
		// host reads it.
		objectAndEffort = `{"reasoning":{"effort":"high","enabled":true},"reasoning_effort":"high"}`
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
			routes: hosts("groq", "siliconflow", "venice", "phala", "near-ai", "gmi", "friendli", "wafer", "minimax", "chutes", "cloudflare-workers-ai", "azure", "nvidia-nim", "sambanova", "huggingface", "openrouter", "perplexity", "neurometric", "engy", "hixtube"),
			effort: effortField, on: `{` + reasoningOn + `,` + budget + `}`, off: reasoningOff,
			onWithEffort: effortObject, offEffort: reasoningOff,
		},
		// The six of those hosts that were probed. They take the same fields,
		// and the effort is also sent top-level, as an effort alone is.
		"probed generic hosts": {
			routes: hosts("together", "deepinfra", "novita", "parasail", "nebius", "io-net"),
			effort: effortField, on: `{` + reasoningOn + `,` + budget + `}`, off: reasoningOff,
			onWithEffort: objectAndEffort, offEffort: reasoningOff,
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
			onWithEffort: effortObject, offEffort: reasoningOff,
		},
		"claude budget-only": {
			routes: claude("claude-haiku-4-5", "claude-sonnet-4-5"),
			effort: `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`, on: `{` + budget + `}`, off: `{}`,
			onWithEffort: `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`, offEffort: `{}`,
		},
		"claude opus 4.5": {
			routes: claude("claude-opus-4-5"),
			effort: `{"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`, on: `{` + budget + `}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
		},
		"claude adaptive": {
			routes: claude("claude-sonnet-4-6", "claude-opus-4-8", "claude-opus-5-5", "claude-sonnet-5"),
			effort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, on: `{` + budget + `}`, off: `{"thinking":{"type":"disabled"}}`,
			onWithEffort: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`, offEffort: `{"thinking":{"type":"disabled"}}`,
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
// records current behavior, not a rule. On a probed generic host (Together
// here) an effort of low, medium or high written only inside the reasoning
// object is also sent top-level, unless the object says enabled=false. On any
// other generic host (OpenRouter and GMI here) the fields go as the request
// holds them.
func TestCanonicalReasoningRequestsOnProviderWires(t *testing.T) {
	together := wireRoute{kind: "chat", provider: "together", model: "m", upstream: "m"}
	openrouter := wireRoute{kind: "chat", provider: "openrouter", model: "m", upstream: "m"}
	for _, tc := range []struct {
		route        wireRoute
		fields, want string
	}{
		{together, `"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`},
		{together, `"reasoning":{"effort":"medium"}`, `{"reasoning":{"effort":"medium"},"reasoning_effort":"medium"}`},
		{together, `"reasoning":{"effort":"low"}`, `{"reasoning":{"effort":"low"},"reasoning_effort":"low"}`},
		{together, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning":{"effort":"high","enabled":true},"reasoning_effort":"high"}`},
		{together, `"reasoning":{"enabled":true},"reasoning_effort":"high"`, `{"reasoning":{"enabled":true},"reasoning_effort":"high"}`},
		{together, `"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}`, `{"reasoning":{"effort":"high","enabled":true},"reasoning_effort":"high"}`},
		{together, `"output_config":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`},
		{together, `"reasoning":{"enabled":false,"effort":"high"}`, `{"reasoning":{"effort":"high","enabled":false}}`},
		{together, `"reasoning":{"enabled":false},"reasoning_effort":"high"`, `{"reasoning":{"enabled":false},"reasoning_effort":"high"}`},
		{together, `"reasoning":{"effort":"low"},"reasoning_effort":"high"`, `{"reasoning":{"effort":"low"},"reasoning_effort":"high"}`},
		// Only low, medium and high are copied top-level.
		{together, `"reasoning":{"effort":"none"}`, `{"reasoning":{"effort":"none"}}`},
		{together, `"reasoning":{"effort":"minimal"}`, `{"reasoning":{"effort":"minimal"}}`},
		{together, `"reasoning":{"effort":"xhigh"}`, `{"reasoning":{"effort":"xhigh"}}`},
		{together, `"reasoning":{"effort":"max"}`, `{"reasoning":{"effort":"max"}}`},
		{together, `"reasoning":{"effort":"ultra"}`, `{"reasoning":{"effort":"ultra"}}`},
		{together, `"thinking":{"type":"enabled"},"reasoning_effort":"max"`, `{"reasoning":{"effort":"max","enabled":true}}`},
		{together, `"output_config":{"effort":"xhigh"}`, `{"reasoning":{"effort":"xhigh"}}`},
		// A generic host that was not probed.
		{openrouter, `"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		{openrouter, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning":{"effort":"high","enabled":true}}`},
		{openrouter, `"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}`, `{"reasoning":{"effort":"high","enabled":true}}`},
		{openrouter, `"output_config":{"effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		{openrouter, `"thinking":{"type":"enabled"},"reasoning_effort":"high"`, `{"reasoning":{"effort":"high","enabled":true}}`},
		{openrouter, `"reasoning_effort":"high"`, `{"reasoning_effort":"high"}`},
		{wireRoute{kind: "chat", provider: "gmi", model: "openai/gpt-5.5", upstream: "gpt-5.5", tools: true}, `"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		{wireRoute{kind: "chat", provider: "mistral", model: "m", upstream: "m"}, `"reasoning":{"effort":"high"}`, `{"reasoning_effort":"high"}`},
		{wireRoute{kind: "chat", provider: "mistral", model: "m", upstream: "m"}, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning_effort":"high"}`},
		{wireRoute{kind: "chat", provider: "zai", model: "z-ai/glm-5.3", upstream: "glm-5.3"}, `"reasoning":{"enabled":true,"effort":"high"}`, `{"reasoning_effort":"high","thinking":{"type":"enabled"}}`},
		{wireRoute{kind: "chat", provider: "fireworks", model: "m", upstream: "m"}, `"reasoning":{"enabled":false,"effort":"high"}`, `{"reasoning_effort":"none"}`},
	} {
		if got := reasoningWire(t, tc.route, tc.fields); got != tc.want {
			t.Errorf("%s %s: got %s, want %s", tc.route.provider, tc.fields, got, tc.want)
		}
	}
}

// TestResponsesEffortOnProviderWires records where the effort of a Responses
// API request goes on a chat completions wire. Responses carries the effort
// inside the reasoning object. A probed generic host is sent low, medium or
// high there and top-level, any other generic host inside the object alone,
// and a provider on the effort list top-level only.
func TestResponsesEffortOnProviderWires(t *testing.T) {
	for _, tc := range []struct{ provider, fields, want string }{
		{"together", `,"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`},
		{"together", `,"reasoning":{"effort":"high","summary":"auto"}`, `{"reasoning":{"effort":"high","summary":"auto"},"reasoning_effort":"high"}`},
		{"together", `,"reasoning":{"effort":"minimal"}`, `{"reasoning":{"effort":"minimal"}}`},
		{"together", `,"reasoning":{"effort":"none"}`, `{"reasoning":{"effort":"none"}}`},
		{"together", ``, `{}`},
		{"openrouter", `,"reasoning":{"effort":"high","summary":"auto"}`, `{"reasoning":{"effort":"high","summary":"auto"}}`},
		{"groq", `,"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		{"mistral", `,"reasoning":{"effort":"high","summary":"auto"}`, `{"reasoning_effort":"high"}`},
	} {
		responses, err := parseResponsesRequest([]byte(`{"model":"m","input":"test"` + tc.fields + `}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.fields, err)
		}
		req, err := adapter.ResponsesToChat(responses)
		if err != nil {
			t.Fatalf("%s: %v", tc.fields, err)
		}
		body, err := adapter.ToAnthropic(req, req.Model)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := llm.PrepareChatRequest(tc.provider, "m", req, body, []llm.ChatMessage{{Role: "user", Content: "test"}}, llm.ChatPreparationOptions{})
		if err != nil {
			t.Fatalf("%s %s: %v", tc.provider, tc.fields, err)
		}
		if got := wireControls(t, prepared.Bytes, []string{"reasoning", "reasoning_effort", "thinking"}); got != tc.want {
			t.Errorf("%s %s: got %s, want %s", tc.provider, tc.fields, got, tc.want)
		}
	}
}

// TestClaudeThinkingSwitchWithEffortIsTheReasoningObject records that on a
// Claude model a switch beside an effort is the reasoning object holding
// both, and what that object sends today. It records current behavior, not a
// rule: the second half is the known limits docs/reasoning-output.md states.
func TestClaudeThinkingSwitchWithEffortIsTheReasoningObject(t *testing.T) {
	for _, upstream := range []string{"claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-5", "claude-sonnet-4-6", "claude-opus-4-8", "claude-opus-5-5"} {
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
	// On the budget path max, minimal and an unknown effort set no thinking
	// even beside On, and Opus 4.5 is sent the effort as written.
	for _, tc := range []struct{ upstream, effort, want string }{
		{"claude-sonnet-4-5", "max", `{}`},
		{"claude-sonnet-4-5", "minimal", `{}`},
		{"claude-haiku-4-5", "ultra", `{}`},
		{"claude-haiku-4-5", "high", `{"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-opus-4-5", "max", `{"output_config":{"effort":"max"}}`},
		{"claude-opus-4-5", "minimal", `{"output_config":{"effort":"minimal"}}`},
		{"claude-opus-4-5", "ultra", `{"output_config":{"effort":"ultra"}}`},
		{"claude-opus-4-5", "xhigh", `{"output_config":{"effort":"xhigh"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
	} {
		route := wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/" + tc.upstream, upstream: tc.upstream}
		if got := reasoningWire(t, route, `"thinking":{"type":"enabled"},"reasoning_effort":"`+tc.effort+`"`); got != tc.want {
			t.Errorf("%s On + %s: got %s, want %s", tc.upstream, tc.effort, got, tc.want)
		}
	}
}
