package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// preparedReasoningWire parses chat fields the way the gateway does, prepares
// the provider request, and returns the reasoning controls on the wire as
// compact JSON. It fails the test if preparation changes the request.
func preparedReasoningWire(t *testing.T, provider, model, fields string) string {
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
	options := ChatPreparationOptions{}
	if provider == "privatemode" {
		private := &openAICompatibleRequest{Model: model}
		if err := preparePrivatemodeWire(&req, body, private, "workspace"); err != nil {
			t.Fatalf("%s: %v", fields, err)
		}
		options = ChatPreparationOptions{ProviderCacheScope: "workspace", privateWire: private}
	}
	before, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareChatRequest(provider, model, &req, body, []ChatMessage{{Role: "user", Content: "test"}}, options)
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

// A host outside the effort list is sent an effort top-level as well as inside
// the reasoning object, which stays as the request holds it. Off governs, an
// effort that is already top-level is left alone, and no effort adds nothing.
func TestGenericHostEffortGoesTopLevelAndKeepsTheReasoningObject(t *testing.T) {
	const (
		budget = `"thinking":{"budget_tokens":4096,"type":"enabled"}`
		both   = `{"reasoning":{"effort":"high","enabled":true},"reasoning_effort":"high"}`
	)
	for _, tc := range []struct{ name, fields, want string }{
		// The effort is only inside the object: it is also sent top-level.
		{"object effort alone", `"reasoning":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`},
		{"object effort with enabled true", `"reasoning":{"effort":"high","enabled":true}`, both},
		{"object effort beside other members", `"reasoning":{"effort":"low","summary":"auto"}`, `{"reasoning":{"effort":"low","summary":"auto"},"reasoning_effort":"low"}`},
		{"object effort is normalized top-level only", `"reasoning":{"effort":" High "}`, `{"reasoning":{"effort":" High "},"reasoning_effort":"high"}`},
		// An effort of none is an effort, not the enabled=false switch.
		{"object effort none", `"reasoning":{"effort":"none"}`, `{"reasoning":{"effort":"none"},"reasoning_effort":"none"}`},
		// A blank top-level field names no effort, as when it is omitted.
		{"object effort beside a blank top-level", `"reasoning":{"effort":"high"},"reasoning_effort":" "`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`},
		{"output_config effort", `"output_config":{"effort":"high"}`, `{"reasoning":{"effort":"high"},"reasoning_effort":"high"}`},
		// A switch beside an effort, through the real composition.
		{"thinking enabled with effort", `"thinking":{"type":"enabled"},"reasoning_effort":"high"`, both},
		{"thinking adaptive with effort", `"thinking":{"type":"adaptive"},"reasoning_effort":"high"`, both},
		{"enable_thinking with effort", `"enable_thinking":true,"reasoning_effort":"high"`, both},
		{"chat_template_kwargs with effort", `"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"high"`, both},
		{"adaptive thinking with output_config effort", `"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}`, both},
		// Already top-level: unchanged.
		{"top-level alone", `"reasoning_effort":"high"`, `{"reasoning_effort":"high"}`},
		{"top-level is sent as written", `"reasoning_effort":"HIGH"`, `{"reasoning_effort":"HIGH"}`},
		{"top-level beside an On object", `"reasoning":{"enabled":true},"reasoning_effort":"high"`, `{"reasoning":{"enabled":true},"reasoning_effort":"high"}`},
		{"top-level beside an object effort", `"reasoning":{"effort":"low"},"reasoning_effort":"high"`, `{"reasoning":{"effort":"low"},"reasoning_effort":"high"}`},
		// Off beside an effort: unchanged.
		{"object off with object effort", `"reasoning":{"enabled":false,"effort":"high"}`, `{"reasoning":{"effort":"high","enabled":false}}`},
		{"object off with top-level effort", `"reasoning":{"enabled":false},"reasoning_effort":"high"`, `{"reasoning":{"enabled":false},"reasoning_effort":"high"}`},
		{"disabled switch with effort", `"thinking":{"type":"disabled"},"reasoning_effort":"high"`, `{"reasoning":{"enabled":false}}`},
		// No effort: unchanged.
		{"no reasoning fields", ``, `{}`},
		{"on alone", `"reasoning":{"enabled":true}`, `{"reasoning":{"enabled":true},` + budget + `}`},
		{"off alone", `"reasoning":{"enabled":false}`, `{"reasoning":{"enabled":false}}`},
		{"token budget alone", `"reasoning":{"max_tokens":4096}`, `{"reasoning":{"max_tokens":4096},` + budget + `}`},
	} {
		for _, provider := range []string{"together", "nebius", "parasail", "deepinfra", "novita", "io-net", "groq", "azure", "chutes", "maple", "openrouter", "perplexity", "a-host-added-later"} {
			if got := preparedReasoningWire(t, provider, "m", tc.fields); got != tc.want {
				t.Errorf("%s (%s) %s:\n got %s\nwant %s", tc.name, provider, tc.fields, got, tc.want)
			}
		}
	}
}

// The top-level copy is for generic hosts only. Providers with a reviewed
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
func TestGenericHostEffortLeavesNativeMessagesAlone(t *testing.T) {
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
		for _, provider := range []string{"together", "nebius", "a-host-added-later"} {
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
func TestGenericHostEffortDoesNotRewriteTheReasoningObject(t *testing.T) {
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
