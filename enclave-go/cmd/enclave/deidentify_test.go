package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/deidentify"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type privacyTestRunner struct {
	calls int
	fail  bool
	seen  []string
}

func (r *privacyTestRunner) Protect(_ context.Context, texts []string) (deidentify.Result, error) {
	r.calls++
	r.seen = append(r.seen, texts...)
	if r.fail {
		return deidentify.Result{}, deidentify.ErrUnavailable
	}
	const token = "[TRABCDEFGHIJKLMNOP_EMAIL_1]"
	result := deidentify.Result{Texts: make([]string, len(texts)), Replacements: map[string]string{token: "alice@example.com"}}
	for i, s := range texts {
		result.Texts[i] = strings.ReplaceAll(s, "alice@example.com", token)
	}
	return result, nil
}

type privacyEchoProvider struct {
	seen  string
	calls int
	tool  bool
	fail  int
}

func (p *privacyEchoProvider) InvokeStreaming(_ context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	p.calls++
	b, _ := json.Marshal([]any{req, body})
	p.seen = string(b)
	if p.calls <= p.fail {
		return errors.New("synthetic pre-response failure")
	}
	text, _ := req.Messages[len(req.Messages)-1].Content.(string)
	block := map[string]any{"type": "text", "text": ""}
	deltaType, deltaField, stop := "text_delta", "text", "end_turn"
	if p.tool {
		block = map[string]any{"type": "tool_use", "id": "call_private", "name": "send_email", "input": map[string]any{}}
		deltaType, deltaField, stop = "input_json_delta", "partial_json", "tool_use"
		args, _ := json.Marshal(map[string]string{"email": text})
		text = string(args)
	}
	events := []map[string]any{
		{"type": "message_start", "message": map[string]any{"id": "msg_private", "type": "message", "role": "assistant", "model": "claude", "content": []any{}, "usage": map[string]any{"input_tokens": 12, "output_tokens": 0}}},
		{"type": "content_block_start", "index": 0, "content_block": block},
	}
	// Split every character, including inside the placeholder.
	for _, r := range text {
		events = append(events, map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": deltaType, deltaField: string(r)}})
	}
	events = append(events, map[string]any{"type": "content_block_stop", "index": 0}, map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop}, "usage": map[string]any{"output_tokens": 8}}, map[string]any{"type": "message_stop"})
	for _, event := range events {
		b, _ := json.Marshal(event)
		if _, err := fmt.Fprintf(out, "event: %s\ndata: %s\n\n", event["type"], b); err != nil {
			return err
		}
	}
	return nil
}

func privacyRoundTrip(t *testing.T, path, body string, p *privacyEchoProvider) (int, string) {
	t.Helper()
	digest := sha256.Sum256([]byte("local-test"))
	reg := auth.New([]types.DeviceConfig{{KeyHash: hex.EncodeToString(digest[:]), Owner: "test", DeviceID: "privacy"}})
	server, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(40 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); serveOne(context.Background(), server, reg, p, nil, nil, nil, nil) }()
	if _, err := fmt.Fprintf(client, "POST %s HTTP/1.1\r\nAuthorization: Bearer local-test\r\nContent-Length: %d\r\n\r\n%s", path, len(body), body); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	<-done
	return response.StatusCode, string(data)
}

func testPrivacySurfaces(t *testing.T, enabled bool) {
	t.Helper()
	for _, route := range []string{"chat/completions", "responses", "messages"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", route, stream), func(t *testing.T) {
				body := map[string]any{"model": "anthropic/claude-opus-5.5", "stream": stream, "max_tokens": 256, "deidentify": enabled}
				if route == "responses" {
					body["input"] = "alice@example.com"
				} else {
					body["messages"] = []any{map[string]any{"role": "user", "content": "alice@example.com"}}
				}
				raw, _ := json.Marshal(body)
				provider := &privacyEchoProvider{}
				status, response := privacyRoundTrip(t, "/v1/"+route, string(raw), provider)
				if status != 200 {
					t.Fatalf("status %d %s", status, response)
				}
				if provider.calls != 1 || strings.Contains(provider.seen, "alice@example.com") == enabled {
					t.Fatalf("provider input wrong: %s", provider.seen)
				}
				if strings.Contains(provider.seen, `"deidentify"`) {
					t.Fatal("privacy flag forwarded upstream")
				}
				// Streaming deltas may separate original characters; parse their text.
				if stream {
					var joined strings.Builder
					for _, line := range strings.Split(response, "\n") {
						if !strings.HasPrefix(line, "data: ") || strings.Contains(line, "[DONE]") {
							continue
						}
						var value map[string]any
						if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &value) != nil {
							continue
						}
						if route == "chat/completions" {
							if choices, ok := value["choices"].([]any); ok && len(choices) > 0 {
								d, _ := choices[0].(map[string]any)["delta"].(map[string]any)
								if text, ok := d["content"].(string); ok {
									joined.WriteString(text)
								}
							}
						} else if route == "messages" {
							if d, ok := value["delta"].(map[string]any); ok {
								if text, ok := d["text"].(string); ok {
									joined.WriteString(text)
								}
							}
						} else if value["type"] == "response.output_text.delta" {
							joined.WriteString(value["delta"].(string))
						}
					}
					if joined.String() != "alice@example.com" {
						t.Fatalf("restored text %q: %s", joined.String(), response)
					}
				} else if !strings.Contains(response, "alice@example.com") {
					t.Fatalf("not restored: %s", response)
				}
				if strings.Contains(response, "TRABCDEFGHIJKLMNOP") {
					t.Fatal("placeholder leaked to caller")
				}
			})
		}
	}
}

func TestDeidentifyEndToEnd(t *testing.T) {
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	runner := &privacyTestRunner{}
	rampartRunner = runner
	testPrivacySurfaces(t, true)
	if runner.calls != 6 {
		t.Fatalf("model calls %d", runner.calls)
	}
	runner.fail = true
	testPrivacySurfaces(t, false)
	if runner.calls != 6 {
		t.Fatal("disabled path called model")
	}
	provider := &privacyEchoProvider{}
	status, _ := privacyRoundTrip(t, "/v1/chat/completions", `{"model":"anthropic/claude-opus-5.5","deidentify":true,"messages":[{"role":"user","content":"alice@example.com"}]}`, provider)
	if status != 503 || provider.calls != 0 {
		t.Fatal("failed open")
	}
}

func TestDeidentifyRealModelEndToEnd(t *testing.T) {
	node := os.Getenv("TR_RAMPART_TEST_NODE")
	if node == "" {
		t.Skip("set TR_RAMPART_TEST_NODE for local pinned-model integration")
	}
	script, err := filepath.Abs("../../rampart/worker.mjs")
	if err != nil {
		t.Fatal(err)
	}
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	rampartRunner = deidentify.NewWorker(node, script)
	testPrivacySurfaces(t, true)
}

func TestDeidentifyClientCompatibility(t *testing.T) {
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	for _, tc := range []struct {
		name, route string
		extra       map[string]any
	}{
		{"client_metadata_object", "responses", map[string]any{"client_metadata": map[string]any{"session": "metadata-only@example.com", "nested": map[string]any{"name": "Never forward"}}}},
		{"client_metadata_null", "responses", map[string]any{"client_metadata": nil}},
		{"replayed_namespace", "responses", map[string]any{"input": []any{
			map[string]any{"type": "function_call", "namespace": "functions", "name": "send", "call_id": "call_1", "arguments": `{"email":"alice@example.com"}`},
			map[string]any{"type": "function_call_output", "call_id": "call_1", "output": "alice@example.com"},
			map[string]any{"role": "user", "content": "alice@example.com"},
		}}},
		{"template_on", "chat/completions", map[string]any{"chat_template_kwargs": map[string]any{"enable_thinking": true}, "reasoning_effort": "high"}},
		{"template_off", "chat/completions", map[string]any{"chat_template_kwargs": map[string]any{"thinking": false}, "reasoning_effort": "high"}},
		{"thinking_with_effort", "chat/completions", map[string]any{"thinking": map[string]any{"type": "enabled"}, "reasoning_effort": "high"}},
	} {
		for _, enabled := range []bool{false, true} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/on=%v/stream=%v", tc.name, enabled, stream), func(t *testing.T) {
					runner := &privacyTestRunner{fail: !enabled}
					rampartRunner = runner
					body := map[string]any{"model": "anthropic/claude-opus-5.5", "stream": stream, "max_tokens": 256, "deidentify": enabled}
					if tc.route == "responses" {
						body["input"] = "alice@example.com"
					} else {
						body["messages"] = []any{map[string]any{"role": "user", "content": "alice@example.com"}}
					}
					for key, value := range tc.extra {
						body[key] = value
					}
					raw, _ := json.Marshal(body)
					provider := &privacyEchoProvider{}
					status, response := privacyRoundTrip(t, "/v1/"+tc.route, string(raw), provider)
					wantCalls := 0
					if enabled {
						wantCalls = 1
					}
					if status != 200 || provider.calls != 1 || runner.calls != wantCalls {
						t.Fatalf("status=%d provider=%d scanner=%d response=%s", status, provider.calls, runner.calls, response)
					}
					if strings.Contains(provider.seen, "alice@example.com") == enabled || strings.Contains(provider.seen, "client_metadata") || strings.Contains(provider.seen, "metadata-only") {
						t.Fatalf("provider input escaped privacy contract: %s", provider.seen)
					}
					if strings.Contains(strings.Join(runner.seen, " "), "metadata-only") || strings.Contains(response, "TRABCDEFGHIJKLMNOP") {
						t.Fatal("client metadata reached scanner or placeholder reached caller")
					}
					if !stream && !strings.Contains(response, "alice@example.com") {
						t.Fatal("answer not restored")
					}
				})
			}
		}
	}
}

func TestDeidentifyRejectsOrchestrationInEveryRoutingPosition(t *testing.T) {
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	for _, model := range []string{"trustedrouter/subagent", "trustedrouter/advisor", polyphemusModel, " trustedrouter/subagent ", "nyte/subagent"} {
		for _, position := range []string{"primary", "promoted", "fallback"} {
			t.Run(model+"/"+position, func(t *testing.T) {
				runner := &privacyTestRunner{}
				rampartRunner = runner
				body := map[string]any{"deidentify": true, "messages": []any{map[string]any{"role": "user", "content": "alice@example.com"}}}
				switch position {
				case "primary":
					body["model"] = model
				case "promoted":
					body["models"] = []string{model}
					body["allow_fallbacks"] = false
				case "fallback":
					body["model"] = "anthropic/claude-opus-5.5"
					body["models"] = []string{model}
				}
				raw, _ := json.Marshal(body)
				provider := &privacyEchoProvider{}
				status, _ := privacyRoundTrip(t, "/v1/chat/completions", string(raw), provider)
				if status != 400 || provider.calls != 0 || runner.calls != 0 {
					t.Fatalf("not rejected before scanning/invocation: status=%d provider=%d scanner=%d", status, provider.calls, runner.calls)
				}
			})
		}
	}
}

func TestDeidentifyRejectsHostedSearchBeforeAnyInvocation(t *testing.T) {
	previousRunner, previousExa, previousContext := rampartRunner, enclaveWebSearchClient, enclaveContextSearchClient
	t.Cleanup(func() {
		rampartRunner, enclaveWebSearchClient, enclaveContextSearchClient = previousRunner, previousExa, previousContext
	})
	for _, engine := range []string{"exa", "context", "context.dev"} {
		for _, shape := range []string{"chat_tool", "chat_openrouter_tool", "chat_plugin", "responses_tool"} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stream=%t", engine, shape, stream), func(t *testing.T) {
					runner := &privacyTestRunner{}
					exa, contextSearch := &fakeResponsesWebSearcher{}, &fakeResponsesWebSearcher{}
					rampartRunner, enclaveWebSearchClient, enclaveContextSearchClient = runner, exa, contextSearch
					body := map[string]any{"model": "anthropic/claude-opus-5.5", "deidentify": true, "stream": stream}
					route := "chat/completions"
					body["messages"] = []any{map[string]any{"role": "user", "content": "Find alice@example.com"}}
					switch shape {
					case "chat_plugin":
						body["plugins"] = []any{map[string]any{"id": "web", "engine": engine}}
					case "chat_openrouter_tool":
						body["tools"] = []any{map[string]any{"type": "openrouter:web_search", "parameters": map[string]any{"engine": engine}}}
					default:
						body["tools"] = []any{map[string]any{"type": "web_search", "engine": engine}}
						if shape == "responses_tool" {
							route = "responses"
							delete(body, "messages")
							body["input"] = "Find alice@example.com"
						}
					}
					raw, _ := json.Marshal(body)
					provider := &privacyEchoProvider{}
					status, response := privacyRoundTrip(t, "/v1/"+route, string(raw), provider)
					wantStatus, wantCode := 400, "deidentify_unsupported"
					if engine == "context" {
						wantStatus, wantCode = 501, "not_supported_in_alpha"
					}
					if status != wantStatus || !strings.Contains(response, wantCode) ||
						provider.calls != 0 || runner.calls != 0 || len(exa.queries) != 0 || len(contextSearch.queries) != 0 {
						t.Fatalf("hosted search escaped privacy rejection: status=%d provider=%d scanner=%d exa=%d context=%d response=%s",
							status, provider.calls, runner.calls, len(exa.queries), len(contextSearch.queries), response)
					}
				})
			}
		}
	}
}

func TestDeidentifyFlagStrictAndDisabledNoAllocation(t *testing.T) {
	for _, value := range []string{`null`, `1`, `"true"`, `{}`, `[]`} {
		if _, err := parseChatRequest([]byte(`{"model":"test","messages":[],"deidentify":` + value + `}`)); err == nil {
			t.Fatal("accepted", value)
		}
		if _, err := parseResponsesRequest([]byte(`{"model":"test","input":"hi","deidentify":` + value + `}`)); err == nil {
			t.Fatal("accepted", value)
		}
		var native struct {
			Deidentify types.DeidentifyFlag `json:"deidentify"`
		}
		if json.Unmarshal([]byte(`{"deidentify":`+value+`}`), &native) == nil {
			t.Fatal("accepted", value)
		}
	}
	body := []byte("unchanged")
	provider := &privacyEchoProvider{}
	ctx := context.Background()
	if n := testing.AllocsPerRun(1000, func() {
		safe, br, err := prepareDeidentified(ctx, false, body, "chat.completions", provider)
		if err != nil || !bytes.Equal(safe, body) || &safe[0] != &body[0] || br != provider {
			panic("disabled changed request")
		}
	}); n != 0 {
		t.Fatalf("disabled allocated %v", n)
	}
}

func BenchmarkDeidentifyDisabled(b *testing.B) {
	body := []byte("unchanged")
	provider := &privacyEchoProvider{}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = prepareDeidentified(ctx, false, body, "chat.completions", provider)
	}
}

func TestDeidentifyReceiptBindsOriginalRequestAndRestoredResponse(t *testing.T) {
	enableReceiptEmissionForTest(t)
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	rampartRunner = &privacyTestRunner{}
	for _, stream := range []bool{false, true} {
		body := fmt.Sprintf(`{"model":"anthropic/claude-opus-5.5","deidentify":true,"messages":[{"role":"user","content":"alice@example.com"}],"stream":%v}`, stream)
		raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nx-inference-receipt: true\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		conn := newScriptedConn(raw, nil)
		serveOne(context.Background(), conn, registryForBearer("receipt-key"), &privacyEchoProvider{}, nil, nil, nil, nil)
		response, data := readRawHTTPResponse(t, conn.writes.Bytes())
		if response.StatusCode != 200 {
			t.Fatalf("%d %s", response.StatusCode, data)
		}
		serialized := []byte(response.Header.Get("x-inference-receipt"))
		digest := sha256.Sum256(data)
		if stream {
			var index int
			var events []capturedSSEEvent
			serialized, index, events = capturedStreamingReceipt(t, data)
			digest, _ = recomputeCapturedSSEHash(t, events[:index], "sse-data-v1")
		}
		if err := receipt.Verify(serialized); err != nil {
			t.Fatal(err)
		}
		claims := decodeReceiptClaims(t, serialized)
		requestDigest := sha256.Sum256([]byte(body))
		if claims.Request.Hash != base64.RawURLEncoding.EncodeToString(requestDigest[:]) || claims.Response.Hash != base64.RawURLEncoding.EncodeToString(digest[:]) {
			t.Fatal("receipt bound wrong bytes")
		}
	}
}

func TestDeidentifyToolArgumentsEndToEnd(t *testing.T) {
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	rampartRunner = &privacyTestRunner{}
	for _, route := range []string{"chat/completions", "responses", "messages"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", route, stream), func(t *testing.T) {
				body := map[string]any{"model": "anthropic/claude-opus-5.5", "stream": stream, "max_tokens": 256, "deidentify": true}
				if route == "responses" {
					body["input"] = "alice@example.com"
				} else {
					body["messages"] = []any{map[string]any{"role": "user", "content": "alice@example.com"}}
				}
				raw, _ := json.Marshal(body)
				provider := &privacyEchoProvider{tool: true}
				status, response := privacyRoundTrip(t, "/v1/"+route, string(raw), provider)
				if status != 200 || strings.Contains(provider.seen, "alice@example.com") || strings.Contains(response, "TRABCDEFGHIJKLMNOP") {
					t.Fatalf("tool privacy failed: %d %s %s", status, provider.seen, response)
				}
				if !stream {
					if !strings.Contains(response, "alice@example.com") {
						t.Fatal("tool value not restored", response)
					}
					return
				}
				var args strings.Builder
				for _, line := range strings.Split(response, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var event map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) != nil {
						continue
					}
					switch route {
					case "messages":
						if delta, ok := event["delta"].(map[string]any); ok {
							if text, ok := delta["partial_json"].(string); ok {
								args.WriteString(text)
							}
						}
					case "responses":
						if event["type"] == "response.function_call_arguments.delta" {
							args.WriteString(event["delta"].(string))
						}
					default:
						if choices, ok := event["choices"].([]any); ok && len(choices) > 0 {
							delta, _ := choices[0].(map[string]any)["delta"].(map[string]any)
							if calls, ok := delta["tool_calls"].([]any); ok {
								for _, call := range calls {
									function, _ := call.(map[string]any)["function"].(map[string]any)
									if text, ok := function["arguments"].(string); ok {
										args.WriteString(text)
									}
								}
							}
						}
					}
				}
				var decoded map[string]string
				if json.Unmarshal([]byte(args.String()), &decoded) != nil || decoded["email"] != "alice@example.com" {
					t.Fatalf("invalid restored arguments %q", args.String())
				}
			})
		}
	}
}

func TestDeidentifyRepeatedInvocationsRemainMasked(t *testing.T) {
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	runner := &privacyTestRunner{}
	rampartRunner = runner
	provider := &privacyEchoProvider{fail: 1}
	raw := []byte(`{"model":"anthropic/claude-opus-5.5","deidentify":true,"messages":[{"role":"user","content":"alice@example.com"}]}`)
	safe, client, err := prepareDeidentified(context.Background(), true, raw, "chat.completions", provider)
	if err != nil {
		t.Fatal(err)
	}
	req, err := parseChatRequest(safe)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		var out bytes.Buffer
		err := client.InvokeStreaming(context.Background(), req, nil, &out)
		if strings.Contains(provider.seen, "alice@example.com") || (err != nil) != (attempt == 0) {
			t.Fatalf("attempt %d: %s %v", attempt, provider.seen, err)
		}
		if attempt > 0 && !strings.Contains(out.String(), "alice@example.com") {
			t.Fatal("replacement invocation not restored")
		}
	}
	if runner.calls != 1 || provider.calls != 3 {
		t.Fatal("invocation did not reuse private request state")
	}
}
