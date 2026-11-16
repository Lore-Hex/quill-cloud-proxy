package llm

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Models on the Responses tool route that document reasoning.effort none, and
// models that do not: Astra and 6.1 Sol reject it, no pro page documents it,
// and an unknown future member of the family is not assumed to take it.
var (
	responsesModelsWithOff    = []string{"gpt-5.5", "gpt-5.5-2026-04-23", "gpt-5.6-sol", "gpt-5.6-luna", "gpt-5.6-terra", "gpt-6-sol", "gpt-6-luna", "gpt-6.1-terra"}
	responsesModelsWithoutOff = []string{"gpt-6-astra", "gpt-6.1-sol", "gpt-6-sol-pro", "gpt-5.6-luna-pro", "gpt-6-astra-pro", "gpt-6.1-terra-pro", "gpt-6.2", "gpt-5.6-future", "gpt-5.5-mini", "gpt-6-sol-2026"}
)

// responsesToolWire prepares a chat request with tools for the first-party
// route exactly as dispatch does, and returns the Responses wire.
func responsesToolWire(t *testing.T, model string, reasoning any, effort string) (map[string]any, error) {
	t.Helper()
	req := &qtypes.OpenAIChatRequest{Model: "openai/" + model, Reasoning: reasoning, ReasoningEffort: effort, Tools: responsesTestTool(),
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "weather"}}}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareChatRequest("openai", model, req, body, []ChatMessage{{Role: "user", Content: "weather"}}, ChatPreparationOptions{})
	if err != nil {
		return nil, err
	}
	if !prepared.NativeResponses || prepared.Path != "/responses" {
		t.Fatalf("%s did not use the Responses tool route", model)
	}
	var wire map[string]any
	if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"thinking", "reasoning_effort", "enable_thinking", "chat_template_kwargs"} {
		if wire[field] != nil {
			t.Fatalf("%s reached the Responses wire: %s", field, prepared.Bytes)
		}
	}
	return wire, nil
}

func TestOpenAIResponsesHonorsReasoningSwitch(t *testing.T) {
	for _, model := range append(append([]string{}, responsesModelsWithOff...), responsesModelsWithoutOff...) {
		plain, err := responsesToolWire(t, model, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		// On alone is the request without a reasoning option: these models
		// reason by default, at their own default effort.
		on, err := responsesToolWire(t, model, map[string]any{"enabled": true}, "")
		if err != nil || !reflect.DeepEqual(on, plain) || !reflect.DeepEqual(on["reasoning"], map[string]any{"summary": "auto"}) {
			t.Fatalf("%s: On alone = %v (%v), want the request without it %v", model, on["reasoning"], err, plain["reasoning"])
		}
		for _, effort := range []string{"low", "medium", "high", "xhigh"} {
			want, err := responsesToolWire(t, model, nil, effort)
			if err != nil {
				t.Fatal(err)
			}
			// On with an effort is that effort, wherever the effort was sent.
			for name, got := range map[string]func() (map[string]any, error){
				"effort beside": func() (map[string]any, error) {
					return responsesToolWire(t, model, map[string]any{"enabled": true}, effort)
				},
				"effort inside": func() (map[string]any, error) {
					return responsesToolWire(t, model, map[string]any{"enabled": true, "effort": effort}, "")
				},
			} {
				wire, err := got()
				if err != nil || !reflect.DeepEqual(wire, want) || !reflect.DeepEqual(wire["reasoning"], map[string]any{"effort": effort, "summary": "auto"}) {
					t.Fatalf("%s On + %s (%s) = %v (%v), want %v", model, effort, name, wire["reasoning"], err, want["reasoning"])
				}
			}
		}
	}
}

func TestOpenAIResponsesMapsOffToEffortNone(t *testing.T) {
	for _, model := range responsesModelsWithOff {
		want, err := responsesToolWire(t, model, nil, "none")
		if err != nil || !reflect.DeepEqual(want["reasoning"], map[string]any{"effort": "none"}) {
			t.Fatalf("%s effort none = %v (%v)", model, want["reasoning"], err)
		}
		for _, tc := range []struct {
			reasoning map[string]any
			effort    string
		}{
			{map[string]any{"enabled": false}, ""},
			// Off governs an effort sent beside it or inside the object.
			{map[string]any{"enabled": false}, "high"},
			{map[string]any{"enabled": false, "effort": "high"}, ""},
		} {
			wire, err := responsesToolWire(t, model, tc.reasoning, tc.effort)
			if err != nil || !reflect.DeepEqual(wire, want) {
				t.Fatalf("%s Off %v effort=%q = %v (%v), want effort none", model, tc.reasoning, tc.effort, wire["reasoning"], err)
			}
		}
		// An explicit summary is still left for the provider to judge.
		wire, err := responsesToolWire(t, model, map[string]any{"enabled": false, "summary": "detailed"}, "")
		if err != nil || !reflect.DeepEqual(wire["reasoning"], map[string]any{"effort": "none", "summary": "detailed"}) {
			t.Fatalf("%s Off with a summary = %v (%v)", model, wire["reasoning"], err)
		}
	}
}

func TestOpenAIResponsesRefusesWhatTheModelCannotHonor(t *testing.T) {
	refused := func(t *testing.T, model string, reasoning map[string]any, effort, want string) {
		t.Helper()
		_, err := responsesToolWire(t, model, reasoning, effort)
		var upstream *upstreamHTTPError
		if !errors.As(err, &upstream) || upstream.status != http.StatusBadRequest || !strings.Contains(upstream.body, want) || strings.Contains(upstream.body, "PRIVATE") {
			t.Fatalf("%s %v effort=%q: want a 400 saying %q, got %v", model, reasoning, effort, want, err)
		}
	}
	for _, model := range responsesModelsWithoutOff {
		refused(t, model, map[string]any{"enabled": false}, "", "cannot turn reasoning off")
		refused(t, model, map[string]any{"enabled": false}, "high", "cannot turn reasoning off")
		refused(t, model, map[string]any{"enabled": false, "effort": "low"}, "", "cannot turn reasoning off")
	}
	for _, model := range append(append([]string{}, responsesModelsWithOff...), responsesModelsWithoutOff...) {
		// These models take an effort, never a thinking token budget.
		for _, key := range []string{"max_tokens", "thinking_budget", "budget_tokens"} {
			refused(t, model, map[string]any{"enabled": true, key: float64(4096)}, "", "token budget")
			refused(t, model, map[string]any{key: float64(4096)}, "high", "token budget")
		}
		// Anything else in the object is still refused by name, without its value.
		refused(t, model, map[string]any{"enabled": "PRIVATE"}, "", "reasoning option")
		refused(t, model, map[string]any{"enabled": true, "unknown": "PRIVATE"}, "", "reasoning option")
	}
}

// What the route cannot honor is the failure every switch was before: an
// upstream-style 400 from preparation, never an adapter rejection or a client
// input error. Dispatch treats that class as retryable, so the next
// authorized candidate for the model is still tried.
func TestOpenAIResponsesUnhonoredReasoningFailsAsBefore(t *testing.T) {
	// An unknown reasoning key failed this way before the switch was honored
	// and still does: the reference for the error's class.
	_, reference := responsesToolWire(t, "gpt-5.5", map[string]any{"unknown": "PRIVATE"}, "")
	var before *upstreamHTTPError
	if !errors.As(reference, &before) || before.status != http.StatusBadRequest {
		t.Fatalf("reference failure changed: %v", reference)
	}
	checked := 0
	for _, model := range append(append([]string{}, responsesModelsWithOff...), responsesModelsWithoutOff...) {
		for _, reasoning := range []map[string]any{
			{"enabled": false}, {"enabled": false, "effort": "high"}, {"enabled": true, "max_tokens": float64(4096)},
			{"max_tokens": float64(4096)}, {"enabled": false, "budget_tokens": float64(2048)},
		} {
			_, err := responsesToolWire(t, model, reasoning, "")
			if err == nil {
				continue // Off where the model documents none is honored.
			}
			var upstream *upstreamHTTPError
			var rejected *adapter.AdapterError
			var clientInput interface{ ClientInputMessage() string }
			if !errors.As(err, &upstream) || upstream.status != before.status || errors.As(err, &rejected) || errors.As(err, &clientInput) {
				t.Fatalf("%s %v: failure is not the preparation 400 it was: %v", model, reasoning, err)
			}
			if status, ok := HTTPStatusFromError(err); !ok || status != http.StatusBadRequest {
				t.Fatalf("%s %v: status %d", model, reasoning, status)
			}
			checked++
		}
	}
	if checked < 50 {
		t.Fatalf("checked %d failures", checked)
	}
}
