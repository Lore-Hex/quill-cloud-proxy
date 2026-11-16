package llm

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// parsedChatFields parses chat fields the way the gateway does and returns the
// request and its shared projection.
func parsedChatFields(t *testing.T, model, fields string) (*qtypes.OpenAIChatRequest, *qtypes.AnthropicMessagesRequest) {
	t.Helper()
	payload := `{"model":"` + model + `","messages":[{"role":"user","content":"test"}]`
	if fields != "" {
		payload += "," + fields
	}
	payload += "}"
	var raw map[string]json.RawMessage
	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatal(err)
	}
	validation, err := adapter.ValidateChatRequestFields(raw)
	if err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	// As parseChatRequest applies a thinking switch.
	if validation.ReasoningAlias != nil {
		req.Reasoning = validation.ReasoningAlias
		req.ReasoningEffort = ""
	}
	body, err := adapter.ToAnthropic(&req, model)
	if err != nil {
		t.Fatal(err)
	}
	return &req, body
}

// preparedReasoningWire parses chat fields the way the gateway does, prepares
// the provider request, and returns the reasoning controls on the wire as
// compact JSON. It fails the test if preparation changes the request.
func preparedReasoningWire(t *testing.T, provider, model, fields string) string {
	t.Helper()
	req, body := parsedChatFields(t, model, fields)
	options := ChatPreparationOptions{}
	if provider == "privatemode" {
		private := &openAICompatibleRequest{Model: model}
		if err := preparePrivatemodeWire(req, body, private, "workspace"); err != nil {
			t.Fatalf("%s: %v", fields, err)
		}
		options = ChatPreparationOptions{ProviderCacheScope: "workspace", privateWire: private}
	}
	before, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareChatRequest(provider, model, req, body, []ChatMessage{{Role: "user", Content: "test"}}, options)
	if err != nil {
		t.Fatalf("%s %s: %v", provider, fields, err)
	}
	if after, _ := json.Marshal(req); !bytes.Equal(before, after) {
		t.Fatalf("%s %s: preparation changed the request", provider, fields)
	}
	var wire map[string]any
	if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
		t.Fatal(err)
	}
	controls := map[string]any{}
	for _, key := range []string{"reasoning", "reasoning_effort", "thinking", "enable_thinking", "chat_template_kwargs"} {
		if wire[key] != nil {
			controls[key] = wire[key]
		}
	}
	encoded, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// probedEffortHosts are the hosts outside the effort list that are sent an
// effort top-level as well, under every slug the gateway normalizes to them.
var probedEffortHosts = []string{
	"deepinfra", "deep-infra", "deep_infra", "novita", "novita-ai", "parasail", "parasail-ai", "parasail-io",
	"together", "Together", "nebius", "nebius-ai", "nebius-ai-studio", "tokenfactory", "token-factory", "io-net", "io_net",
}

// otherGenericHosts are outside the effort list and were not probed.
var otherGenericHosts = []string{
	"openrouter", "groq", "maple", "chutes", "hixtube", "perplexity", "neurometric", "azure", "engy", "lightning",
	"phala", "near-ai", "venice", "gmi", "siliconflow", "minimax", "cohere", "databricks", "a-host-added-later",
}

// The six probed hosts are sent an effort of low, medium or high top-level as
// well as inside the reasoning object, which stays as the request holds it.
// Beside enabled=false nothing is added, an effort that is already top-level
// is left alone (even beside enabled=false), any other effort word stays
// inside the object alone, and no effort adds nothing.
//
// Every other host outside the effort list is sent what it was sent before
// any host got a top-level copy. That wire is the parent column; where it is
// empty the two wires are the same.
func TestProbedHostEffortGoesTopLevelAndKeepsTheReasoningObject(t *testing.T) {
	const (
		budget = `"thinking":{"budget_tokens":4096,"type":"enabled"}`
		object = `{"reasoning":{"effort":"high","enabled":true}}`
		both   = `{"reasoning":{"effort":"high","enabled":true},"reasoning_effort":"high"}`
	)
	for _, tc := range []struct{ name, fields, probed, parent string }{
		// The effort is low, medium or high and only inside the object: a
		// probed host is also sent it top-level.
		{"object effort high", `"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		{"object effort medium", `"reasoning":{"effort":"medium"}`, `{"reasoning":{"effort":"medium"},"reasoning_effort":"medium"}`, `{"reasoning":{"effort":"medium"}}`},
		{"object effort low", `"reasoning":{"effort":"low"}`, `{"reasoning":{"effort":"low"},"reasoning_effort":"low"}`, `{"reasoning":{"effort":"low"}}`},
		{"object effort with enabled true", `"reasoning":{"effort":"high","enabled":true}`, both, object},
		{"object effort beside other members", `"reasoning":{"effort":"low","summary":"auto"}`, `{"reasoning":{"effort":"low","summary":"auto"},"reasoning_effort":"low"}`, `{"reasoning":{"effort":"low","summary":"auto"}}`},
		{"object effort beside a token budget", `"reasoning":{"effort":"high","max_tokens":2048}`, `{"reasoning":{"effort":"high","max_tokens":2048},"reasoning_effort":"high"}`, `{"reasoning":{"effort":"high","max_tokens":2048}}`},
		// The top-level copy is lower case without spaces. The object keeps
		// the caller's spelling.
		{"object effort is normalized top-level only", `"reasoning":{"effort":" High "}`, `{"reasoning":{"effort":" High "},"reasoning_effort":"high"}`, `{"reasoning":{"effort":" High "}}`},
		{"switch with an upper case effort", `"thinking":{"type":"enabled"},"reasoning_effort":"HIGH"`, `{"reasoning":{"effort":"HIGH","enabled":true},"reasoning_effort":"high"}`, `{"reasoning":{"effort":"HIGH","enabled":true}}`},
		// A blank top-level field names no effort, as when it is omitted.
		{"object effort beside a blank top-level", `"reasoning":{"effort":"high"},"reasoning_effort":" "`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":" "}`},
		{"output_config effort", `"output_config":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`, `{"reasoning":{"effort":"high"}}`},
		// A switch beside an effort, through the real composition.
		{"thinking enabled with effort", `"thinking":{"type":"enabled"},"reasoning_effort":"high"`, both, object},
		{"thinking adaptive with effort", `"thinking":{"type":"adaptive"},"reasoning_effort":"high"`, both, object},
		{"enable_thinking with effort", `"enable_thinking":true,"reasoning_effort":"high"`, both, object},
		{"chat_template_kwargs with effort", `"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"high"`, both, object},
		{"adaptive thinking with output_config effort", `"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}`, both, object},
		// Any other effort word was not observed: it stays inside the object
		// alone, on every host.
		{"object effort none", `"reasoning":{"effort":"none"}`, `{"reasoning":{"effort":"none"}}`, ""},
		{"object effort none with enabled true", `"reasoning":{"effort":"none","enabled":true}`, `{"reasoning":{"effort":"none","enabled":true}}`, ""},
		{"object effort off", `"reasoning":{"effort":"off"}`, `{"reasoning":{"effort":"off"}}`, ""},
		{"object effort minimal", `"reasoning":{"effort":"minimal"}`, `{"reasoning":{"effort":"minimal"}}`, ""},
		{"object effort xhigh", `"reasoning":{"effort":"xhigh"}`, `{"reasoning":{"effort":"xhigh"}}`, ""},
		{"object effort max", `"reasoning":{"effort":"max"}`, `{"reasoning":{"effort":"max"}}`, ""},
		{"object effort auto", `"reasoning":{"effort":"auto"}`, `{"reasoning":{"effort":"auto"}}`, ""},
		{"object effort unknown word", `"reasoning":{"effort":"ultra"}`, `{"reasoning":{"effort":"ultra"}}`, ""},
		{"switch with effort max", `"thinking":{"type":"enabled"},"reasoning_effort":"max"`, `{"reasoning":{"effort":"max","enabled":true}}`, ""},
		{"switch with effort minimal", `"enable_thinking":true,"reasoning_effort":"minimal"`, `{"reasoning":{"effort":"minimal","enabled":true}}`, ""},
		{"switch with effort xhigh", `"chat_template_kwargs":{"thinking":true},"reasoning_effort":"xhigh"`, `{"reasoning":{"effort":"xhigh","enabled":true}}`, ""},
		{"output_config effort max", `"output_config":{"effort":"max"}`, `{"reasoning":{"effort":"max"}}`, ""},
		{"output_config effort xhigh", `"output_config":{"effort":"xhigh"}`, `{"reasoning":{"effort":"xhigh"}}`, ""},
		// Already top-level: unchanged.
		{"top-level alone", `"reasoning_effort":"high"`, `{"reasoning_effort":"high"}`, ""},
		{"top-level is sent as written", `"reasoning_effort":"HIGH"`, `{"reasoning_effort":"HIGH"}`, ""},
		{"top-level none", `"reasoning_effort":"none"`, `{"reasoning_effort":"none"}`, ""},
		{"top-level beside an On object", `"reasoning":{"enabled":true},"reasoning_effort":"high"`, `{"reasoning":{"enabled":true},"reasoning_effort":"high"}`, ""},
		{"top-level beside an object effort", `"reasoning":{"effort":"low"},"reasoning_effort":"high"`, `{"reasoning":{"effort":"low"},"reasoning_effort":"high"}`, ""},
		// Off beside an effort: unchanged.
		{"object off with object effort", `"reasoning":{"enabled":false,"effort":"high"}`, `{"reasoning":{"effort":"high","enabled":false}}`, ""},
		{"object off with top-level effort", `"reasoning":{"enabled":false},"reasoning_effort":"high"`, `{"reasoning":{"enabled":false},"reasoning_effort":"high"}`, ""},
		{"disabled switch with effort", `"thinking":{"type":"disabled"},"reasoning_effort":"high"`, `{"reasoning":{"enabled":false}}`, ""},
		// No effort: unchanged.
		{"no reasoning fields", ``, `{}`, ""},
		{"on alone", `"reasoning":{"enabled":true}`, `{"reasoning":{"enabled":true},` + budget + `}`, ""},
		{"off alone", `"reasoning":{"enabled":false}`, `{"reasoning":{"enabled":false}}`, ""},
		{"token budget alone", `"reasoning":{"max_tokens":4096}`, `{"reasoning":{"max_tokens":4096},` + budget + `}`, ""},
	} {
		for _, provider := range probedEffortHosts {
			if got := preparedReasoningWire(t, provider, "m", tc.fields); got != tc.probed {
				t.Errorf("%s (probed host %s) %s:\n got %s\nwant %s", tc.name, provider, tc.fields, got, tc.probed)
			}
		}
		parent := tc.parent
		if parent == "" {
			parent = tc.probed
		}
		for _, provider := range otherGenericHosts {
			model := "m"
			if provider == "phala" || provider == "near-ai" {
				model = "openai/gpt-oss-120b" // These serve only models in their reviewed maps.
			}
			if got := preparedReasoningWire(t, provider, model, tc.fields); got != parent {
				t.Errorf("%s (unprobed host %s) %s:\n got %s\nwant the parent wire %s", tc.name, provider, tc.fields, got, parent)
			}
		}
	}
}

// frozenParentChatReasoningEffort is applyChatReasoningEffort as of cff41e98,
// before any host outside the effort list was sent a top-level copy.
func frozenParentChatReasoningEffort(provider string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, wire *openAICompatibleRequest) {
	effort := chatReasoningEffort(req)
	if effort == "" {
		return
	}
	dropSynthesizedThinkingBudget(body, wire)
	switch normalizeDirectProvider(provider) {
	case "meta", "openai", "gemini", "google-ai-studio", "deepseek", "zai", "kimi", "mistral", "alibaba", "tencent", "tinfoil", "grok", "baseten", "crusoe", "cerebras", "fireworks":
		wire.ReasoningEffort = effort
		wire.Reasoning = nil
	}
}

// knownProviderSlugs returns every provider spelling the enclave knows: the
// direct provider registry, and every string a source file of this package
// matches a provider against. That takes in the dispatch switch in multi.go,
// the alias table, the base URL table and each per-provider contract. It reads
// the source, whatever the build tags, so a provider added later is covered
// without anyone naming it in a test.
func knownProviderSlugs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, spec := range directproviders.All() {
		seen[spec.Provider] = true
	}
	var isProvider func(ast.Expr) bool
	isProvider = func(expr ast.Expr) bool {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			return isProvider(e.X)
		case *ast.Ident:
			return e.Name == "provider" || e.Name == "slug" || e.Name == "normalizedProvider"
		case *ast.SelectorExpr:
			return e.Sel.Name == "provider" || e.Sel.Name == "Provider"
		case *ast.CallExpr:
			name, ok := e.Fun.(*ast.Ident)
			return ok && name.Name == "normalizeDirectProvider"
		}
		return false
	}
	add := func(expr ast.Expr) {
		if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			if value, err := strconv.Unquote(literal.Value); err == nil && value != "" {
				seen[value] = true
			}
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed++
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.SwitchStmt:
				if n.Tag == nil || !isProvider(n.Tag) {
					break
				}
				for _, clause := range n.Body.List {
					for _, label := range clause.(*ast.CaseClause).List {
						add(label)
					}
				}
			case *ast.BinaryExpr:
				if n.Op != token.EQL && n.Op != token.NEQ {
					break
				}
				if isProvider(n.X) {
					add(n.Y)
				}
				if isProvider(n.Y) {
					add(n.X)
				}
			}
			return true
		})
	}
	// A harvest that silently finds nothing would let the comparison pass on
	// a handful of hand-named hosts. These spellings come from the registry,
	// the dispatch switch and the alias table in turn.
	for _, anchor := range []string{"io-net", "hixtube", "openrouter-exclusive", "cloudflare-workers-ai", "novita-ai", "token-factory"} {
		if !seen[anchor] {
			t.Fatalf("provider harvest lost %q: the source or the registry moved, fix the harvest", anchor)
		}
	}
	if parsed < 20 || len(seen) < 150 {
		t.Fatalf("provider harvest read %d files and found %d spellings: too few to trust", parsed, len(seen))
	}
	slugs := make([]string, 0, len(seen))
	for slug := range seen {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}

// Against the frozen parent rule, byte for byte: a host that was not probed is
// sent exactly what the parent sent for every request shape, and a probed host
// differs only by a top-level effort of low, medium or high that the parent
// left blank. It runs over every provider spelling the enclave knows, so the
// list of probed hosts cannot grow past these six without this test failing.
func TestOnlyProbedHostsDifferFromTheParentEffortRule(t *testing.T) {
	probed := map[string]bool{"deepinfra": true, "io-net": true, "nebius": true, "novita": true, "parasail": true, "together": true}
	type request struct {
		name   string
		req    *qtypes.OpenAIChatRequest
		body   *qtypes.AnthropicMessagesRequest
		native bool // A native Messages request, passed through on every host.
	}
	var requests []request
	for _, fields := range []string{
		``, `"reasoning_effort":"high"`, `"reasoning_effort":"HIGH"`, `"reasoning_effort":"none"`, `"reasoning_effort":"max"`, `"reasoning_effort":" "`,
		`"reasoning":{"effort":"high"}`, `"reasoning":{"effort":"medium"}`, `"reasoning":{"effort":"low"}`, `"reasoning":{"effort":" High "}`,
		`"reasoning":{"effort":"none"}`, `"reasoning":{"effort":"off"}`, `"reasoning":{"effort":"minimal"}`, `"reasoning":{"effort":"xhigh"}`,
		`"reasoning":{"effort":"max"}`, `"reasoning":{"effort":"auto"}`, `"reasoning":{"effort":"ultra"}`, `"reasoning":{"effort":""}`, `"reasoning":{"effort":7}`,
		`"reasoning":{"effort":"high","enabled":true}`, `"reasoning":{"effort":"high","enabled":false}`, `"reasoning":{"effort":"none","enabled":true}`,
		`"reasoning":{"effort":"high","enabled":"false"}`, `"reasoning":{"effort":"high","enabled":null}`, `"reasoning":{"effort":"high","max_tokens":2048}`,
		`"reasoning":{"effort":"high","summary":"auto"}`, `"reasoning":{"effort":"high","exclude":true}`,
		`"reasoning":{"enabled":true}`, `"reasoning":{"enabled":false}`, `"reasoning":{}`, `"reasoning":{"max_tokens":2048}`, `"reasoning":true`, `"reasoning":"high"`,
		`"reasoning":{"enabled":true},"reasoning_effort":"high"`, `"reasoning":{"enabled":false},"reasoning_effort":"high"`,
		`"reasoning":{"effort":"low"},"reasoning_effort":"high"`, `"reasoning":{"effort":"high"},"reasoning_effort":" "`, `"reasoning":{"effort":"max"},"reasoning_effort":" "`,
		`"thinking":{"type":"enabled"}`, `"thinking":{"type":"disabled"}`, `"thinking":{"type":"enabled","budget_tokens":4096}`,
		`"thinking":{"type":"enabled"},"reasoning_effort":"high"`, `"thinking":{"type":"enabled"},"reasoning_effort":"medium"`, `"thinking":{"type":"enabled"},"reasoning_effort":"low"`,
		`"thinking":{"type":"enabled"},"reasoning_effort":"max"`, `"thinking":{"type":"enabled"},"reasoning_effort":"minimal"`, `"thinking":{"type":"enabled"},"reasoning_effort":"xhigh"`,
		`"thinking":{"type":"adaptive"},"reasoning_effort":"high"`, `"thinking":{"type":"disabled"},"reasoning_effort":"high"`,
		`"enable_thinking":true,"reasoning_effort":"high"`, `"enable_thinking":false,"reasoning_effort":"high"`,
		`"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"high"`, `"chat_template_kwargs":{"thinking":false},"reasoning_effort":"high"`,
		`"output_config":{"effort":"high"}`, `"output_config":{"effort":"medium"}`, `"output_config":{"effort":"max"}`, `"output_config":{"effort":"xhigh"}`,
		`"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}`, `"output_config":{"effort":"max"},"thinking":{"type":"adaptive"}`,
		`"output_config":{"effort":"high"},"thinking":{"type":"enabled","budget_tokens":4096}`,
	} {
		req, body := parsedChatFields(t, "m", fields)
		requests = append(requests, request{"chat " + fields, req, body, false})
	}
	for _, thinking := range []string{`{"type":"enabled","budget_tokens":2048}`, `{"type":"enabled","budget_tokens":2048,"effort":"high"}`, `{"type":"adaptive","effort":"low"}`} {
		var native adapter.AnthropicNativeRequest
		if err := json.Unmarshal([]byte(`{"model":"m","max_tokens":64,"messages":[{"role":"user","content":"test"}],"output_config":{"effort":"high"},"thinking":`+thinking+`}`), &native); err != nil {
			t.Fatal(err)
		}
		body, err := adapter.MessagesToAnthropic(&native)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request{"messages " + thinking, adapter.MessagesToChatShim(&native), body, true})
	}
	providers := append(append([]string{}, probedEffortHosts...), otherGenericHosts...)
	providers = append(providers, "privatemode", "meta", "openai", "gemini", "google-ai-studio", "deepseek", "zai", "kimi", "mistral", "alibaba", "tencent", "tinfoil", "grok", "baseten", "crusoe", "cerebras", "fireworks")
	providers = append(providers, knownProviderSlugs(t)...)
	changed := map[string]int{}
	for _, provider := range providers {
		for _, r := range requests {
			// What the shared builder holds when it applies the effort rule.
			start := openAICompatibleRequest{Model: "m", Reasoning: r.req.Reasoning, ReasoningEffort: r.req.ReasoningEffort, Thinking: r.body.Thinking}
			live, parent := start, start
			applyChatReasoningEffort(provider, r.req, r.body, &live)
			frozenParentChatReasoningEffort(provider, r.req, r.body, &parent)
			liveBytes, err := json.Marshal(live)
			if err != nil {
				t.Fatal(err)
			}
			parentBytes, err := json.Marshal(parent)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(liveBytes, parentBytes) {
				continue
			}
			slug := normalizeDirectProvider(provider)
			if !probed[slug] || r.native {
				t.Errorf("%s %s: differs from the parent, on a host that was not probed or for a native request:\n got %s\nwant %s", provider, r.name, liveBytes, parentBytes)
				continue
			}
			if strings.TrimSpace(parent.ReasoningEffort) != "" || (live.ReasoningEffort != "low" && live.ReasoningEffort != "medium" && live.ReasoningEffort != "high") {
				t.Errorf("%s %s: top-level effort went from %q to %q", provider, r.name, parent.ReasoningEffort, live.ReasoningEffort)
			}
			parent.ReasoningEffort = live.ReasoningEffort
			if withField, _ := json.Marshal(parent); !bytes.Equal(liveBytes, withField) {
				t.Errorf("%s %s: more than the top-level effort differs from the parent:\n got %s\nwant %s", provider, r.name, liveBytes, withField)
			}
			changed[slug]++
		}
	}
	// Without a changed wire on each probed host the comparison proves nothing.
	for slug := range probed {
		if changed[slug] == 0 {
			t.Errorf("%s: no wire differs from the parent", slug)
		}
	}
	t.Logf("compared %d provider spellings on %d requests", len(providers), len(requests))
}

// The top-level copy is for the probed hosts only. Providers with a reviewed
// reasoning contract are sent what they were sent before.
func TestEffortInsideTheReasoningObjectLeavesReviewedProvidersAlone(t *testing.T) {
	const (
		object      = `"reasoning":{"effort":"high"}`
		objectOn    = `"reasoning":{"effort":"high","enabled":true}`
		objectOff   = `"reasoning":{"effort":"high","enabled":false}`
		switchOn    = `"thinking":{"type":"enabled"},"reasoning_effort":"high"`
		effortField = `{"reasoning_effort":"high"}`
		tools       = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}],`
	)
	for _, tc := range []struct{ name, provider, model, fields, want string }{
		{"effort list", "mistral", "m", object, effortField},
		{"effort list", "mistral", "m", objectOn, effortField},
		{"effort list", "mistral", "m", switchOn, effortField},
		{"effort list", "cerebras", "m", objectOn, effortField},
		{"effort list", "openai", "gpt-5.5", objectOn, effortField},
		{"effort list off", "mistral", "m", objectOff, effortField},
		{"hybrid", "zai", "glm-5.3", object, effortField},
		{"hybrid", "zai", "glm-5.3", objectOn, `{"reasoning_effort":"high","thinking":{"type":"enabled"}}`},
		{"hybrid", "deepseek", "deepseek-v4.1-flash", switchOn, `{"reasoning_effort":"high","thinking":{"type":"enabled"}}`},
		{"hybrid off", "zai", "glm-5.3", objectOff, `{"thinking":{"type":"disabled"}}`},
		{"hybrid off", "kimi", "kimi-k2.6", objectOff, `{"thinking":{"type":"disabled"}}`},
		{"fireworks", "fireworks", "m", objectOn, effortField},
		{"fireworks off", "fireworks", "m", objectOff, `{"reasoning_effort":"none"}`},
		{"gemini", "google-ai-studio", "gemini-3.5-flash", objectOn, effortField},
		{"privatemode", "privatemode", "gpt-oss-120b", object, effortField},
		{"privatemode", "privatemode", "glm-5.3", objectOn, effortField},
		{"privatemode", "privatemode", "glm-5.3", switchOn, effortField},
		{"privatemode off", "privatemode", "glm-5.3", `"reasoning":{"enabled":false}`, `{"reasoning_effort":"none"}`},
		{"responses tool route", "openai", "gpt-5.5", tools + objectOn, `{"reasoning":{"effort":"high","summary":"auto"}}`},
	} {
		if got := preparedReasoningWire(t, tc.provider, tc.model, tc.fields); got != tc.want {
			t.Errorf("%s (%s %s) %s:\n got %s\nwant %s", tc.name, tc.provider, tc.model, tc.fields, got, tc.want)
		}
	}
	// Privatemode's reasoning fields come from preparePrivatemodeWire. The
	// shared builder adds nothing of its own for it.
	req := &qtypes.OpenAIChatRequest{Model: "gpt-oss-120b", Reasoning: map[string]any{"effort": "high"}}
	if wire := buildOpenAICompatibleRequest("privatemode", "gpt-oss-120b", req, nil, nil); wire.ReasoningEffort != "" {
		t.Errorf("shared builder set a Privatemode effort: %q", wire.ReasoningEffort)
	}
}

// A native Messages request is passed through. Nothing is derived from its
// thinking object, even one that carries an effort member Anthropic does not
// define, and its output_config is not an OpenAI-compatible field.
func TestProbedHostEffortLeavesNativeMessagesAlone(t *testing.T) {
	for _, thinking := range []string{
		`{"type":"enabled","budget_tokens":2048}`,
		`{"type":"enabled","budget_tokens":2048,"effort":"high"}`,
		`{"type":"adaptive","effort":"high"}`,
	} {
		var native adapter.AnthropicNativeRequest
		payload := `{"model":"m","max_tokens":64,"messages":[{"role":"user","content":"test"}],"output_config":{"effort":"high"},"thinking":` + thinking + `}`
		if err := json.Unmarshal([]byte(payload), &native); err != nil {
			t.Fatal(err)
		}
		body, err := adapter.MessagesToAnthropic(&native)
		if err != nil {
			t.Fatal(err)
		}
		req := adapter.MessagesToChatShim(&native)
		var object any
		if err := json.Unmarshal([]byte(thinking), &object); err != nil {
			t.Fatal(err)
		}
		// As before: the thinking object as written, in both fields.
		want, err := json.Marshal(map[string]any{"reasoning": object, "thinking": object})
		if err != nil {
			t.Fatal(err)
		}
		for _, provider := range append([]string{"openrouter", "a-host-added-later"}, probedEffortHosts...) {
			prepared, err := PrepareChatRequest(provider, "m", req, body, []ChatMessage{{Role: "user", Content: "test"}}, ChatPreparationOptions{})
			if err != nil {
				t.Fatalf("%s %s: %v", provider, thinking, err)
			}
			var wire map[string]any
			if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
				t.Fatal(err)
			}
			controls := map[string]any{}
			for _, key := range []string{"reasoning", "reasoning_effort", "thinking", "output_config"} {
				if wire[key] != nil {
					controls[key] = wire[key]
				}
			}
			if got, _ := json.Marshal(controls); string(got) != string(want) {
				t.Errorf("%s %s:\n got %s\nwant %s", provider, thinking, got, want)
			}
		}
	}
}

// applyChatReasoningEffort must not write into the caller's reasoning object,
// and the object on the wire is the one the request holds.
func TestProbedHostEffortDoesNotRewriteTheReasoningObject(t *testing.T) {
	reasoning := map[string]any{"effort": "high", "enabled": true}
	req := &qtypes.OpenAIChatRequest{Model: "m", Reasoning: reasoning}
	wire := buildOpenAICompatibleRequest("together", "m", req, nil, nil)
	if wire.ReasoningEffort != "high" {
		t.Fatalf("top-level effort = %q", wire.ReasoningEffort)
	}
	held, ok := wire.Reasoning.(map[string]any)
	if !ok || len(held) != 2 || held["effort"] != "high" || held["enabled"] != true {
		t.Fatalf("reasoning object on the wire = %#v", wire.Reasoning)
	}
	if len(reasoning) != 2 || req.ReasoningEffort != "" {
		t.Fatalf("request changed: reasoning=%#v effort=%q", reasoning, req.ReasoningEffort)
	}
}

func TestHybridReasoningNativeWire(t *testing.T) {
	for _, provider := range []string{"zai", "deepseek", "kimi"} {
		for _, enabled := range []bool{false, true} {
			mode := "disabled"
			if enabled {
				mode = "enabled"
			}
			t.Run(provider+"/"+mode, func(t *testing.T) {
				zero := 0.0
				model := map[string]string{"zai": "glm-5.2", "deepseek": "deepseek-v4-flash", "kimi": "kimi-k2.6"}[provider]
				req := &qtypes.OpenAIChatRequest{Model: model, Reasoning: map[string]any{"enabled": enabled}, ReasoningEffort: "high"}
				body := &qtypes.AnthropicMessagesRequest{
					Temperature: &zero, Thinking: map[string]any{"type": "enabled", "budget_tokens": 4096},
					Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Hello"}},
				}
				calls := 0
				httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					thinking, ok := wire["thinking"].(map[string]any)
					if !ok || thinking["type"] != mode || len(thinking) != 1 {
						t.Fatalf("thinking = %#v", wire["thinking"])
					}
					if _, present := wire["reasoning"]; present {
						t.Fatal("generic reasoning leaked to native endpoint")
					}
					if !enabled && wire["reasoning_effort"] != nil {
						t.Fatal("Off still has an enabling effort")
					}
					if provider != "kimi" && wire["temperature"] != float64(0) {
						t.Fatalf("temperature zero lost: %#v", wire["temperature"])
					}
					if provider == "kimi" && wire["temperature"] != nil {
						t.Fatal("Kimi fixed sampling contract changed")
					}
					if r.Header.Get("Authorization") != "Bearer test-key" || r.URL.Path != "/v1/chat/completions" {
						t.Fatal("request transport changed")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))}, nil
				})}
				err := invokeOpenAICompatibleStreamingWithClientOptions(t.Context(), httpc, provider, "https://provider.test/v1", "test-key", req, body, io.Discard, model, openAICompatibleInvocationOptions{})
				if err != nil || calls != 1 {
					t.Fatalf("calls=%d error=%v", calls, err)
				}
			})
		}
	}
}

func TestCerebrasNestedReasoningUsesNativeEffort(t *testing.T) {
	for _, model := range []string{"gpt-oss-120b", "qwen-3.8-27b"} {
		t.Run(model, func(t *testing.T) {
			reasoning := map[string]any{"effort": "low"}
			req := &qtypes.OpenAIChatRequest{Model: model, Reasoning: reasoning}
			body := &qtypes.AnthropicMessagesRequest{
				Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Hello"}},
				Thinking: map[string]any{"type": "enabled", "budget_tokens": 4096},
			}
			calls := 0
			httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var wire map[string]any
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire["reasoning_effort"] != "low" || wire["reasoning"] != nil || wire["thinking"] != nil {
					t.Fatalf("unsupported reasoning wire: effort=%v reasoning=%v thinking=%v", wire["reasoning_effort"], wire["reasoning"], wire["thinking"])
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))}, nil
			})}
			err := invokeOpenAICompatibleStreamingWithClientOptions(t.Context(), httpc, "cerebras", "https://provider.test/v1", "test-key", req, body, io.Discard, model, openAICompatibleInvocationOptions{})
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if reasoning["effort"] != "low" || len(reasoning) != 1 {
				t.Fatal("mutated caller reasoning")
			}
		})
	}
}

func TestHybridReasoningLeavesUnspecifiedAndOtherProvidersAlone(t *testing.T) {
	for _, provider := range []string{"zai", "deepseek", "kimi", "openai", "together", "azure"} {
		for _, reasoning := range []any{nil, map[string]any{"effort": "low"}, map[string]any{"enabled": "false"}} {
			wire := openAICompatibleRequest{Thinking: "sentinel"}
			applyHybridReasoningControl(provider, &qtypes.OpenAIChatRequest{Reasoning: reasoning}, &wire)
			if wire.Thinking != "sentinel" {
				t.Fatalf("%s changed unspecified control", provider)
			}
		}
	}
	wire := openAICompatibleRequest{Thinking: "sentinel"}
	applyHybridReasoningControl("openai", &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}}, &wire)
	if wire.Thinking != "sentinel" {
		t.Fatal("changed unrelated provider")
	}
	applyHybridReasoningControl("zai", nil, &wire)
}

func TestKimiExplicitReasoningOnWithToolsDoesNotSilentlyTurnOff(t *testing.T) {
	called := false
	httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		t.Fatal("conflicting request reached provider")
		return nil, nil
	})}
	req := &qtypes.OpenAIChatRequest{Model: "moonshotai/kimi-k2.6", Reasoning: map[string]any{"enabled": true}, Tools: []any{map[string]any{"type": "function"}}}
	err := invokeOpenAICompatibleStreamingWithClientOptions(t.Context(), httpc, "kimi", "https://provider.test/v1", "test-key", req, &qtypes.AnthropicMessagesRequest{}, io.Discard, "kimi-k2.6", openAICompatibleInvocationOptions{})
	if called || err == nil {
		t.Fatalf("called=%v err=%v", called, err)
	}
	upstream, ok := err.(*upstreamHTTPError)
	if !ok || upstream.status != http.StatusBadRequest {
		t.Fatalf("wrong error: %v", err)
	}
}
