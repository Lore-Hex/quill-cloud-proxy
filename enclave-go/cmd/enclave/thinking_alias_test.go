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
