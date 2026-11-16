package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const responsesSwitchTools = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}]`

// prepareChatFor parses a chat request as the gateway does and prepares it for
// one provider the way dispatch does after authorization. A parse error is
// fatal: the callers hold only requests the gateway accepts.
func prepareChatFor(t *testing.T, provider, upstream, body string) (map[string]any, error) {
	t.Helper()
	req, err := parseChatRequest([]byte(body))
	if err != nil {
		t.Fatalf("refused before authorization: %s: %v", body, err)
	}
	anthropicReq, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := llm.PrepareChatRequest(provider, upstream, req, anthropicReq, []llm.ChatMessage{{Role: "user", Content: "test"}}, llm.ChatPreparationOptions{})
	if err != nil {
		return nil, err
	}
	if prepared.NativeResponses != (provider == "openai") {
		t.Fatalf("%s %s: Responses route = %t", provider, upstream, prepared.NativeResponses)
	}
	var wire map[string]any
	if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
		t.Fatal(err)
	}
	return wire, nil
}

// Every thinking switch a chat request can carry, on every model of the
// Responses tool route. None is refused before authorization: this route
// refuses nothing it did not refuse before. What the route can honor it now
// prepares. What it cannot (Off where the model documents no none, a token
// budget) fails at preparation with the retryable 400 every switch was, and
// another host of the same model still prepares the request as it did.
func TestChatThinkingSwitchOnOpenAIResponsesToolRoute(t *testing.T) {
	type control struct {
		fields      string
		off, budget bool
		other       string // the reasoning object another host is sent
	}
	controls := []control{
		{fields: `"thinking":{"type":"enabled"}`, other: `{"enabled":true}`},
		{fields: `"enable_thinking":true`, other: `{"enabled":true}`},
		{fields: `"chat_template_kwargs":{"enable_thinking":true}`, other: `{"enabled":true}`},
		{fields: `"chat_template_kwargs":{"thinking":true}`, other: `{"enabled":true}`},
		{fields: `"reasoning":{"enabled":true}`, other: `{"enabled":true}`},
		{fields: `"thinking":{"type":"disabled"}`, off: true, other: `{"enabled":false}`},
		{fields: `"enable_thinking":false`, off: true, other: `{"enabled":false}`},
		{fields: `"chat_template_kwargs":{"enable_thinking":false}`, off: true, other: `{"enabled":false}`},
		{fields: `"chat_template_kwargs":{"thinking":false}`, off: true, other: `{"enabled":false}`},
		{fields: `"reasoning":{"enabled":false}`, off: true, other: `{"enabled":false}`},
		{fields: `"thinking":{"type":"enabled","budget_tokens":4096}`, budget: true, other: `{"enabled":true,"max_tokens":4096}`},
		{fields: `"reasoning":{"enabled":true,"max_tokens":4096}`, budget: true, other: `{"enabled":true,"max_tokens":4096}`},
	}
	// Whether the model documents reasoning.effort none.
	models := map[string]bool{
		"gpt-5.5": true, "gpt-5.5-2026-04-23": true, "gpt-5.6-sol": true, "gpt-5.6-luna": true, "gpt-5.6-terra": true,
		"gpt-6-sol": true, "gpt-6-luna": true, "gpt-6.1-terra": true,
		"gpt-6-astra": false, "gpt-6.1-sol": false, "gpt-6-sol-pro": false, "gpt-6.1-terra-pro": false, "gpt-6.2": false,
	}
	honored, failedOver := 0, 0
	for model, canDisable := range models {
		for _, c := range controls {
			for _, effort := range []string{"", "low", "medium", "high", "xhigh"} {
				fields := c.fields
				if effort != "" {
					if c.budget || strings.HasPrefix(c.fields, `"reasoning"`) {
						continue // A budget or the reasoning object beside an effort is a different request.
					}
					fields += `,"reasoning_effort":"` + effort + `"`
				}
				name := fmt.Sprintf("%s %s", model, fields)
				body := `{"model":"openai/` + model + `","messages":[{"role":"user","content":"test"}],` + responsesSwitchTools + `,` + fields + `}`
				wire, err := prepareChatFor(t, "openai", model, body)
				if c.budget || (c.off && !canDisable) {
					// The failure every switch was on this route: an upstream-style
					// 400 that dispatch retries on the next authorized candidate.
					status, ok := llm.HTTPStatusFromError(err)
					if err == nil || !ok || status != 400 || !retryableInvokeError(err) || isClientInputError(err) {
						t.Fatalf("%s: want the retryable preparation 400, got %v", name, err)
					}
					// Another host of the model takes the request as before.
					other, err := prepareChatFor(t, "gmi", model, body)
					var want any
					if jsonErr := json.Unmarshal([]byte(c.other), &want); jsonErr != nil {
						t.Fatal(jsonErr)
					}
					if err != nil || !reflect.DeepEqual(other["reasoning"], want) {
						t.Fatalf("%s: the next candidate got reasoning %v (%v), want %s", name, other["reasoning"], err, c.other)
					}
					failedOver++
					continue
				}
				if err != nil {
					t.Fatalf("%s: a control the route honors failed at preparation: %v", name, err)
				}
				want := map[string]any{"summary": "auto"}
				switch {
				case c.off:
					want = map[string]any{"effort": "none"}
				case effort != "":
					want["effort"] = effort
				}
				if !reflect.DeepEqual(wire["reasoning"], want) || wire["thinking"] != nil || wire["reasoning_effort"] != nil {
					t.Fatalf("%s: reasoning = %v, want %v", name, wire["reasoning"], want)
				}
				honored++
			}
		}
	}
	if honored < 300 || failedOver < 100 {
		t.Fatalf("honored %d and failed over %d requests", honored, failedOver)
	}
}

// preparingLLM stands in for the provider clients. It prepares each attempt's
// request for that attempt's provider exactly as dispatch does, fails the
// attempt with the preparation error, and otherwise answers.
type preparingLLM struct {
	mu       sync.Mutex
	attempts []preparedAttempt
}

type preparedAttempt struct {
	provider  string
	err       error
	reasoning any
	responses bool
}

func (p *preparingLLM) InvokeStreaming(_ context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	option := options[0]
	prepared, err := llm.PrepareChatRequest(option.Provider, option.UpstreamModel, req, body, []llm.ChatMessage{{Role: "user", Content: "test"}}, llm.ChatPreparationOptions{})
	attempt := preparedAttempt{provider: option.Provider, err: err, responses: prepared.NativeResponses}
	if err == nil {
		var wire map[string]any
		if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
			return err
		}
		attempt.reasoning = wire["reasoning"]
	}
	p.mu.Lock()
	p.attempts = append(p.attempts, attempt)
	p.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"m\",\"stop_reason\":null,\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n"+
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"served\"}}\n\n"+
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n"+
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return err
}

// A request the Responses tool route cannot honor is authorized, fails at that
// route's preparation, and is served by the next candidate for the model, as
// it was before the route honored any switch. It is never refused first.
func TestServeOpenAIResponsesUnhonoredReasoningFailsOver(t *testing.T) {
	const chatTools = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}]`
	const responsesTools = `"tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{}}}]`
	for _, tc := range []struct {
		route, model, fields string
		// What the first-party route says, and what the next host is sent.
		refusal, next string
	}{
		{"/v1/chat/completions", "gpt-6-astra", `"messages":[{"role":"user","content":"private-content"}],` + chatTools + `,"thinking":{"type":"disabled"}`,
			"this model cannot turn reasoning off", `{"enabled":false}`},
		{"/v1/chat/completions", "gpt-6.1-sol", `"messages":[{"role":"user","content":"private-content"}],` + chatTools + `,"enable_thinking":false,"reasoning_effort":"high"`,
			"this model cannot turn reasoning off", `{"enabled":false}`},
		{"/v1/chat/completions", "gpt-5.5", `"messages":[{"role":"user","content":"private-content"}],` + chatTools + `,"thinking":{"type":"enabled","budget_tokens":4096}`,
			"this model takes a reasoning effort, not a thinking token budget", `{"enabled":true,"max_tokens":4096}`},
		{"/v1/responses", "gpt-6-astra", `"input":"private-content",` + responsesTools + `,"reasoning":{"enabled":false}`,
			"this model cannot turn reasoning off", `{"enabled":false}`},
		// Honored by the first candidate: no failover is needed.
		{"/v1/chat/completions", "gpt-5.5", `"messages":[{"role":"user","content":"private-content"}],` + chatTools + `,"thinking":{"type":"disabled"}`, "", `{"effort":"none"}`},
		{"/v1/chat/completions", "gpt-6-astra", `"messages":[{"role":"user","content":"private-content"}],` + chatTools + `,"thinking":{"type":"enabled"},"reasoning_effort":"high"`, "", `{"effort":"high","summary":"auto"}`},
		{"/v1/responses", "gpt-5.5", `"input":"private-content",` + responsesTools + `,"reasoning":{"enabled":false}`, "", `{"effort":"none"}`},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/%t/%s", tc.route, tc.model, stream, tc.refusal), func(t *testing.T) {
				var authorize, settle, validate, unexpected atomic.Int32
				control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					if strings.Contains(string(body), "private-content") {
						t.Error("prompt reached control plane")
					}
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						authorize.Add(1)
						candidate := func(provider string) string {
							return fmt.Sprintf(`{"model":"openai/%[1]s","upstream_model":"%[1]s","endpoint_id":"openai/%[1]s@%[2]s/prepaid","provider":"%[2]s","usage_type":"Credits"}`, tc.model, provider)
						}
						_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_failover","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/%[1]s","upstream_model":"%[1]s","endpoint_id":"openai/%[1]s@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[%s,%s]}}`,
							tc.model, candidate("openai"), candidate("gmi"))
					case "/internal/gateway/settle":
						settle.Add(1)
						_, _ = fmt.Fprintf(w, `{"data":{"settled":true,"generation_id":"gen_failover","cost_microdollars":12,"model":"openai/%s","provider":"gmi","region":"us-central1"}}`, tc.model)
					case "/internal/gateway/validate":
						validate.Add(1)
						_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
					default:
						unexpected.Add(1)
						w.WriteHeader(500)
					}
				}))
				defer control.Close()
				body := fmt.Sprintf(`{"model":"openai/%s","stream":%t,%s}`, tc.model, stream, tc.fields)
				conn := newScriptedConn(fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", tc.route, len(body), body), nil)
				provider := &preparingLLM{}
				serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, trustedrouter.New(control.URL, "internal-test", control.Client()), nil)
				resp, responseBody := readRawHTTPResponse(t, conn.writes.Bytes())
				// Authorized and served: never a refusal before authorization, which
				// would validate identity only and take no hold.
				if resp.StatusCode != 200 || authorize.Load() != 1 || settle.Load() != 1 || validate.Load() != 0 || unexpected.Load() != 0 {
					t.Fatalf("status=%d authorize=%d settle=%d validate=%d unexpected=%d body=%s", resp.StatusCode, authorize.Load(), settle.Load(), validate.Load(), unexpected.Load(), responseBody)
				}
				var next any
				if err := json.Unmarshal([]byte(tc.next), &next); err != nil {
					t.Fatal(err)
				}
				attempts := provider.attempts
				if tc.refusal == "" {
					if len(attempts) != 1 || attempts[0].provider != "openai" || !attempts[0].responses || !reflect.DeepEqual(attempts[0].reasoning, next) {
						t.Fatalf("attempts = %+v, want one honored by the Responses tool route with %s", attempts, tc.next)
					}
					return
				}
				if len(attempts) != 2 || attempts[0].provider != "openai" || attempts[1].provider != "gmi" {
					t.Fatalf("attempts = %+v, want the first-party route then the next candidate", attempts)
				}
				status, ok := llm.HTTPStatusFromError(attempts[0].err)
				if !ok || status != 400 || !strings.Contains(attempts[0].err.Error(), "OpenAI Responses tool route: "+tc.refusal) {
					t.Fatalf("first-party failure = %v, want the preparation 400 saying %q", attempts[0].err, tc.refusal)
				}
				if attempts[1].err != nil || attempts[1].responses || !reflect.DeepEqual(attempts[1].reasoning, next) {
					t.Fatalf("next candidate = %+v, want it sent reasoning %s", attempts[1], tc.next)
				}
			})
		}
	}
}
