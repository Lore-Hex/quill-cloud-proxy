package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestChatThinkingAlias(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  map[string]any
	}{
		{`"thinking":{"type":"disabled"}`, map[string]any{"enabled": false}},
		{`"thinking":{"type":"enabled"}`, map[string]any{"enabled": true}},
		{`"thinking":{"type":"enabled","budget_tokens":4096}`, map[string]any{"enabled": true, "max_tokens": float64(4096)}},
		{`"enable_thinking":false`, map[string]any{"enabled": false}},
		{`"enable_thinking":true`, map[string]any{"enabled": true}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			req, err := parseChatRequest([]byte(`{"model":"z-ai/glm-5.3","messages":[{"role":"user","content":"test"}],"temperature":0,` + tc.field + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(req.Reasoning, tc.want) || !reflect.DeepEqual(req.RequestedParameters, []string{"reasoning", "temperature"}) {
				t.Fatalf("reasoning=%#v parameters=%v", req.Reasoning, req.RequestedParameters)
			}
			if req.Temperature == nil || *req.Temperature != 0 {
				t.Fatal("normalization changed temperature")
			}
			encoded, err := json.Marshal(req)
			if err != nil || strings.Contains(string(encoded), `"thinking":`) || strings.Contains(string(encoded), `"enable_thinking":`) {
				t.Fatalf("alias leaked into normalized request: %s, %v", encoded, err)
			}
		})
	}
}

func TestChatThinkingAliasReachesProviderWire(t *testing.T) {
	for provider, model := range map[string]string{"zai": "glm-5.3", "deepseek": "deepseek-v4.1-flash", "kimi": "kimi-k2.6"} {
		for _, field := range []string{`"thinking":{"type":"disabled"}`, `"enable_thinking":false`} {
			t.Run(provider+field, func(t *testing.T) {
				req, err := parseChatRequest([]byte(`{"model":"` + model + `","messages":[{"role":"user","content":"test"}],"temperature":0,` + field + `}`))
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := llm.PrepareChatRequest(provider, model, req, &types.AnthropicMessagesRequest{Temperature: req.Temperature}, []llm.ChatMessage{{Role: "user", Content: "test"}}, llm.ChatPreparationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				var wire map[string]any
				if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(wire["thinking"], map[string]any{"type": "disabled"}) || wire["enable_thinking"] != nil || wire["reasoning"] != nil {
					t.Fatalf("incorrect provider controls: %s", prepared.Bytes)
				}
				if provider != "kimi" && wire["temperature"] != float64(0) {
					t.Fatal("temperature zero lost with thinking off")
				}
			})
		}
	}
}

func TestChatThinkingAliasRejectsAmbiguity(t *testing.T) {
	for _, field := range []string{
		`"thinking":true`,
		`"thinking":{}`,
		`"thinking":{"type":"unknown"}`,
		`"thinking":{"type":"disabled","budget_tokens":4096}`,
		`"thinking":{"type":"enabled","budget_tokens":1.5}`,
		`"thinking":{"type":"enabled","budget_tokens":0}`,
		`"thinking":{"type":"enabled","extra":"private"}`,
		`"thinking":{"type":"enabled"},"reasoning":{"enabled":false}`,
		`"thinking":{"type":"enabled"},"reasoning_effort":"none"`,
		`"thinking":{"type":"disabled"},"enable_thinking":true`,
		`"enable_thinking":"false"`,
		`"enable_thinking":false,"reasoning":{"enabled":true}`,
	} {
		t.Run(field, func(t *testing.T) {
			_, err := parseChatRequest([]byte(`{"model":"m",` + field + `}`))
			var rejected *adapter.AdapterError
			if !errors.As(err, &rejected) || rejected.Status != 400 || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe or missing rejection: %v", err)
			}
		})
	}
	for _, field := range []string{`"thinking":null`, `"enable_thinking":null`} {
		if _, err := parseChatRequest([]byte(`{"model":"m",` + field + `}`)); err != nil {
			t.Fatal(err)
		}
	}
}

func parseChatFields(t *testing.T, fields string) *types.OpenAIChatRequest {
	t.Helper()
	req, err := parseChatRequest([]byte(`{"model":"z-ai/glm-5.3","messages":[{"role":"user","content":"test"}],"temperature":0,` + fields + `}`))
	if err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	return req
}

func TestChatThinkingSwitchComposesWithReasoningEffort(t *testing.T) {
	for _, tc := range []struct{ fields, reasoning string }{
		// On keeps the effort: the switch and the depth are both honored.
		{`"thinking":{"type":"enabled"},"reasoning_effort":"high"`, `{"enabled":true,"effort":"high"}`},
		{`"thinking":{"type":"adaptive"},"reasoning_effort":"max"`, `{"enabled":true,"effort":"max"}`},
		{`"enable_thinking":true,"reasoning_effort":"low"`, `{"enabled":true,"effort":"low"}`},
		{`"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"medium"`, `{"enabled":true,"effort":"medium"}`},
		{`"chat_template_kwargs":{"thinking":true},"reasoning_effort":"minimal"`, `{"enabled":true,"effort":"minimal"}`},
		// Off governs: the effort is dropped, not sent beside a disabled switch.
		{`"thinking":{"type":"disabled"},"reasoning_effort":"high"`, `{"enabled":false}`},
		{`"thinking":{"type":"disabled"},"reasoning_effort":"none"`, `{"enabled":false}`},
		{`"enable_thinking":false,"reasoning_effort":"high"`, `{"enabled":false}`},
		{`"chat_template_kwargs":{"enable_thinking":false},"reasoning_effort":"high"`, `{"enabled":false}`},
		{`"chat_template_kwargs":{"thinking":false},"reasoning_effort":"xhigh"`, `{"enabled":false}`},
		// A blank or null effort names no depth.
		{`"thinking":{"type":"enabled"},"reasoning_effort":""`, `{"enabled":true}`},
		{`"thinking":{"type":"enabled"},"reasoning_effort":null`, `{"enabled":true}`},
		{`"thinking":{"type":"enabled","budget_tokens":4096},"reasoning_effort":" "`, `{"enabled":true,"max_tokens":4096}`},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			req := parseChatFields(t, tc.fields)
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.reasoning), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(req.Reasoning, want) || req.ReasoningEffort != "" || !reflect.DeepEqual(req.RequestedParameters, []string{"reasoning", "temperature"}) {
				t.Fatalf("reasoning=%#v effort=%q parameters=%v", req.Reasoning, req.ReasoningEffort, req.RequestedParameters)
			}
			// The same request the canonical reasoning object alone builds.
			if canonical := parseChatFields(t, `"reasoning":`+tc.reasoning); !reflect.DeepEqual(req, canonical) {
				t.Fatalf("composed request differs from the canonical one:\n%+v\n%+v", req, canonical)
			}
			encoded, err := json.Marshal(req)
			for _, alias := range []string{`"thinking":`, `"enable_thinking":`, `"chat_template_kwargs":`, `"reasoning_effort":`} {
				if err != nil || strings.Contains(string(encoded), alias) {
					t.Fatalf("alias leaked into normalized request: %s, %v", encoded, err)
				}
			}
		})
	}
	// Without a switch the effort is untouched.
	for _, fields := range []string{`"reasoning_effort":"high"`, `"reasoning_effort":"high","chat_template_kwargs":{}`, `"reasoning_effort":"high","chat_template_kwargs":null,"thinking":null,"enable_thinking":null`} {
		if req := parseChatFields(t, fields); req.Reasoning != nil || req.ReasoningEffort != "high" || !reflect.DeepEqual(req.RequestedParameters, []string{"reasoning", "temperature"}) {
			t.Fatalf("%s: reasoning=%#v effort=%q parameters=%v", fields, req.Reasoning, req.ReasoningEffort, req.RequestedParameters)
		}
	}
}

func TestChatThinkingSwitchWithEffortReachesProviderWire(t *testing.T) {
	for _, tc := range []struct {
		fields   string
		thinking string
		effort   any
	}{
		{`"thinking":{"type":"enabled"},"reasoning_effort":"high"`, "enabled", "high"},
		{`"enable_thinking":true,"reasoning_effort":"high"`, "enabled", "high"},
		{`"chat_template_kwargs":{"thinking":true},"reasoning_effort":"high"`, "enabled", "high"},
		{`"thinking":{"type":"disabled"},"reasoning_effort":"high"`, "disabled", nil},
		{`"chat_template_kwargs":{"enable_thinking":false},"reasoning_effort":"high"`, "disabled", nil},
		{`"chat_template_kwargs":{"enable_thinking":false}`, "disabled", nil},
	} {
		for provider, model := range map[string]string{"zai": "glm-5.3", "deepseek": "deepseek-v4.1-flash"} {
			t.Run(provider+tc.fields, func(t *testing.T) {
				req, err := parseChatRequest([]byte(`{"model":"` + model + `","messages":[{"role":"user","content":"test"}],` + tc.fields + `}`))
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := llm.PrepareChatRequest(provider, model, req, &types.AnthropicMessagesRequest{}, []llm.ChatMessage{{Role: "user", Content: "test"}}, llm.ChatPreparationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				var wire map[string]any
				if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
					t.Fatal(err)
				}
				// These APIs take the switch and the depth as two fields.
				if !reflect.DeepEqual(wire["thinking"], map[string]any{"type": tc.thinking}) || wire["reasoning_effort"] != tc.effort ||
					wire["reasoning"] != nil || wire["enable_thinking"] != nil || wire["chat_template_kwargs"] != nil {
					t.Fatalf("incorrect provider controls: %s", prepared.Bytes)
				}
			})
		}
	}
}

func TestChatThinkingSwitchRejectsContradictions(t *testing.T) {
	for _, tc := range []struct{ fields, param string }{
		// On with an effort that means Off.
		{`"thinking":{"type":"enabled"},"reasoning_effort":"none"`, "thinking"},
		{`"thinking":{"type":"enabled"},"reasoning_effort":" OFF "`, "thinking"},
		{`"thinking":{"type":"adaptive"},"reasoning_effort":"disabled"`, "thinking"},
		{`"enable_thinking":true,"reasoning_effort":"none"`, "enable_thinking"},
		{`"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"none"`, "chat_template_kwargs"},
		{`"chat_template_kwargs":{"thinking":true},"reasoning_effort":"disable"`, "chat_template_kwargs"},
		// Two depth controls.
		{`"thinking":{"type":"enabled","budget_tokens":4096},"reasoning_effort":"high"`, "thinking"},
		// Two switches, or a switch beside the reasoning object.
		{`"thinking":{"type":"enabled"},"enable_thinking":true`, "thinking"},
		{`"thinking":{"type":"enabled"},"enable_thinking":true,"reasoning_effort":"high"`, "thinking"},
		{`"thinking":{"type":"enabled"},"chat_template_kwargs":{"enable_thinking":true}`, "thinking"},
		{`"thinking":{"type":"enabled"},"reasoning":{"effort":"high"}`, "thinking"},
		{`"thinking":{"type":"enabled"},"reasoning":{"effort":"high"},"reasoning_effort":"high"`, "thinking"},
		{`"thinking":{"type":"disabled"},"reasoning":{"exclude":true}`, "thinking"},
		{`"enable_thinking":true,"reasoning":{"effort":"high"}`, "enable_thinking"},
		{`"enable_thinking":true,"reasoning":{"effort":"high"},"reasoning_effort":"high"`, "enable_thinking"},
		{`"chat_template_kwargs":{"thinking":true},"reasoning":{"effort":"high"}`, "chat_template_kwargs"},
		{`"chat_template_kwargs":{"enable_thinking":true},"enable_thinking":false`, "chat_template_kwargs"},
		{`"chat_template_kwargs":{"enable_thinking":true,"thinking":false}`, "chat_template_kwargs"},
		// Adaptive still needs an effort, and one spelling of it.
		{`"thinking":{"type":"adaptive"}`, "thinking"},
		{`"thinking":{"type":"adaptive"},"reasoning_effort":""`, "thinking"},
		{`"thinking":{"type":"adaptive"},"output_config":{"effort":"high"},"reasoning_effort":"high"`, "output_config.effort"},
		{`"thinking":{"type":"enabled"},"output_config":{"effort":"high"},"reasoning_effort":"high"`, "output_config.effort"},
		{`"chat_template_kwargs":{"enable_thinking":false},"output_config":{"effort":"high"}`, "output_config.effort"},
		// The effort is still checked when the switch drops it.
		{`"thinking":{"type":"disabled"},"reasoning_effort":["private-value"]`, "reasoning_effort"},
		{`"thinking":{"type":"enabled"},"reasoning_effort":5`, "reasoning_effort"},
		{`"enable_thinking":false,"reasoning_effort":{"level":"private-value"}`, "reasoning_effort"},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			_, err := parseChatRequest([]byte(`{"model":"m",` + tc.fields + `}`))
			var rejected *adapter.AdapterError
			if !errors.As(err, &rejected) || rejected.Status != 400 || rejected.Context != tc.param || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("want 400 at %s without request values, got %v", tc.param, err)
			}
		})
	}
}

func TestChatTemplateKwargsThinkingSwitch(t *testing.T) {
	for _, tc := range []struct {
		fields string
		same   string
	}{
		{`"chat_template_kwargs":{"enable_thinking":false}`, `"enable_thinking":false`},
		{`"chat_template_kwargs":{"enable_thinking":true}`, `"enable_thinking":true`},
		{`"chat_template_kwargs":{"thinking":false}`, `"enable_thinking":false`},
		{`"chat_template_kwargs":{"thinking":true}`, `"enable_thinking":true`},
		{`"chat_template_kwargs":{"enable_thinking":false,"thinking":false}`, `"enable_thinking":false`},
		{`"chat_template_kwargs":{"enable_thinking":null,"thinking":true}`, `"enable_thinking":true`},
		{`"chat_template_kwargs":{"enable_thinking":true},"enable_thinking":true`, `"enable_thinking":true`},
		// No switch is nothing at all.
		{`"chat_template_kwargs":{}`, `"enable_thinking":null`},
		{`"chat_template_kwargs":null`, `"enable_thinking":null`},
		{`"chat_template_kwargs":{"enable_thinking":null,"thinking":null}`, `"enable_thinking":null`},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			req, same := parseChatFields(t, tc.fields), parseChatFields(t, tc.same)
			if !reflect.DeepEqual(req, same) {
				t.Fatalf("not the request %s builds:\n%+v\n%+v", tc.same, req, same)
			}
			want := []string{"reasoning", "temperature"}
			if strings.HasSuffix(tc.same, "null") {
				want = []string{"temperature"}
			}
			if (req.Reasoning == nil) != strings.HasSuffix(tc.same, "null") || !reflect.DeepEqual(req.RequestedParameters, want) {
				t.Fatalf("reasoning=%#v parameters=%v", req.Reasoning, req.RequestedParameters)
			}
			encoded, err := json.Marshal(req)
			if err != nil || strings.Contains(string(encoded), "chat_template_kwargs") {
				t.Fatalf("raw object leaked into normalized request: %s, %v", encoded, err)
			}
		})
	}
}

func TestChatTemplateKwargsRejectsWhatItCannotHonor(t *testing.T) {
	const unknown = "unknown request parameter"
	for _, tc := range []struct{ fields, param, message string }{
		{`"chat_template_kwargs":"private-value"`, "chat_template_kwargs", "chat_template_kwargs must be an object"},
		{`"chat_template_kwargs":["private-value"]`, "chat_template_kwargs", "chat_template_kwargs must be an object"},
		{`"chat_template_kwargs":[]`, "chat_template_kwargs", "chat_template_kwargs must be an object"},
		{`"chat_template_kwargs":true`, "chat_template_kwargs", "chat_template_kwargs must be an object"},
		{`"chat_template_kwargs":{"enable_thinking":"false"}`, "chat_template_kwargs.enable_thinking", "chat_template_kwargs.enable_thinking must be a boolean"},
		{`"chat_template_kwargs":{"enable_thinking":0}`, "chat_template_kwargs.enable_thinking", "chat_template_kwargs.enable_thinking must be a boolean"},
		{`"chat_template_kwargs":{"thinking":{"type":"enabled"}}`, "chat_template_kwargs.thinking", "chat_template_kwargs.thinking must be a boolean"},
		{`"chat_template_kwargs":{"thinking":{}}`, "chat_template_kwargs.thinking", "chat_template_kwargs.thinking must be a boolean"},
		{`"chat_template_kwargs":{"thinking":"private-value"}`, "chat_template_kwargs.thinking", "chat_template_kwargs.thinking must be a boolean"},
		// Any other key is named, even beside a valid switch or when null.
		{`"chat_template_kwargs":{"add_generation_prompt":true}`, "chat_template_kwargs.add_generation_prompt", unknown},
		{`"chat_template_kwargs":{"enable_thinking":false,"reasoning_effort":"high"}`, "chat_template_kwargs.reasoning_effort", unknown},
		{`"chat_template_kwargs":{"enable_thinking":false,"preserve_thinking":null}`, "chat_template_kwargs.preserve_thinking", unknown},
		{`"chat_template_kwargs":{"zeta":"private-value","documents":["private-value"],"thinking":"private-value"}`, "chat_template_kwargs.documents", unknown},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			_, err := parseChatRequest([]byte(`{"model":"m",` + tc.fields + `}`))
			var rejected *adapter.AdapterError
			if !errors.As(err, &rejected) || rejected.Status != 400 || rejected.Context != tc.param || rejected.Message != tc.message {
				t.Fatalf("want 400 at %s (%s), got %v", tc.param, tc.message, err)
			}
		})
	}
}
