package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

const refusalBody = `{"error":{"message":"Request refused by policy","type":"content_policy_error","code":"content_filter","param":"messages"}}`

func refusalError() error { return &upstreamerror.Error{Status: 400, Body: refusalBody} }

func expectedRefusal(hidden bool) map[string]any {
	if hidden {
		return map[string]any{"message": "upstream provider error", "type": "provider_error", "code": nil, "param": nil, "status": 400, "source": "provider"}
	}
	return map[string]any{"message": "Request refused by policy", "type": "content_policy_error", "code": "content_filter", "param": "messages", "status": 400, "source": "provider", "metadata": map[string]any{"provider_name": "anthropic", "raw": refusalBody}}
}

func assertJSONFailure(t *testing.T, wire string, status int, body map[string]any) {
	t.Helper()
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(wire)), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(body)
	headers := http.Header{"Content-Type": {"application/json"}, "Content-Length": {strconv.Itoa(len(want))}}
	if response.StatusCode != status || !response.Close || !reflect.DeepEqual(response.Header, headers) || len(response.TransferEncoding) != 0 || string(got) != string(want) {
		t.Fatalf("got status=%d headers=%v body=%s; want status=%d headers=%v body=%s", response.StatusCode, response.Header, got, status, headers, want)
	}
}

func errorTestGateway(t *testing.T, fallback, hidden bool) (*trustedrouter.Client, *trustedrouter.Authorization, []llm.InvokeOptions, *int) {
	t.Helper()
	auth := &trustedrouter.Authorization{AuthorizationID: "errors-auth", Model: "model-a", Provider: "anthropic", EndpointID: "first", UsageType: "Credits", HidePublicMetadata: hidden}
	options := []llm.InvokeOptions{{Model: "model-a", Provider: "anthropic", EndpointID: "first"}}
	if fallback {
		auth.RouteCandidates = []trustedrouter.RouteCandidate{{Model: "model-a", Provider: "anthropic", EndpointID: "first", UsageType: "Credits"}, {Model: "model-a", Provider: "openai", EndpointID: "last", UsageType: "Credits"}}
		options = append(options, llm.InvokeOptions{Model: "model-a", Provider: "openai", EndpointID: "last"})
	}
	refunds := 0
	gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"data":{"refunded":true}}`
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			encoded, _ := json.Marshal(map[string]any{"data": auth})
			body = string(encoded)
		case "/internal/gateway/refund":
			refunds++
		default:
			t.Errorf("unexpected control request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})})
	return gateway, auth, options, &refunds
}

func serveErrorTestRoute(ctx context.Context, route string, stream bool, out io.Writer, client llm.Client, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, options []llm.InvokeOptions) {
	req := &types.OpenAIChatRequest{Model: "model-a", Stream: stream, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}
	native := &types.AnthropicMessagesRequest{}
	switch {
	case route == "messages":
		serveMessages(ctx, out, client, []byte(fmt.Sprintf(`{"model":"model-a","max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"hi"}]}`, stream)), gateway, nil, "test-key", "", "error-test", requestAttributionHeaders{})
	case stream:
		serveStreaming(ctx, out, client, req, native, options, gateway, auth, nil, time.Now(), nil, route, "error-test", "model-a")
	case route == "responses":
		serveResponsesNonStreaming(ctx, out, client, req, native, options, gateway, auth, nil, time.Now(), nil, "error-test", "model-a")
	default:
		serveChatNonStreaming(ctx, out, client, req, native, options, gateway, auth, nil, time.Now(), nil, "error-test", "model-a")
	}
}

func TestUpstreamFailureHTTPAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		for _, stream := range []bool{false, true} {
			for _, fallback := range []bool{false, true} {
				for _, hidden := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/stream=%t/fallback=%t/hidden=%t", route, stream, fallback, hidden), func(t *testing.T) {
						gateway, auth, options, refunds := errorTestGateway(t, fallback, hidden)
						client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, _ io.Writer) error {
							if option.EndpointID == "last" {
								return &upstreamerror.Error{Status: 400, Body: `{"code":400,"msg":"bad request"}`}
							}
							return refusalError()
						}}
						var out bytes.Buffer
						serveErrorTestRoute(context.Background(), route, stream, &out, client, gateway, auth, options)
						detail := expectedRefusal(hidden)
						body := map[string]any{"error": detail}
						if route == "messages" {
							body["type"] = "error"
							if hidden {
								detail["type"] = "invalid_request_error"
							}
						}
						assertJSONFailure(t, out.String(), 400, body)
						wantAttempts := []string{"first"}
						if fallback {
							wantAttempts = append(wantAttempts, "last")
						}
						if *refunds != 1 || !reflect.DeepEqual(client.endpoints(), wantAttempts) {
							t.Fatalf("refunds=%d attempts=%v", *refunds, client.endpoints())
						}
					})
				}
			}
		}
	}
}

func TestFallbackErrorSelection(t *testing.T) {
	cases := []struct {
		name        string
		first, last error
		wantFirst   bool
	}{
		{"refusal before generic client error", refusalError(), &upstreamerror.Error{Status: 400, Body: `{"msg":"bad request"}`}, true},
		{"refusal before server error", refusalError(), &upstreamerror.Error{Status: 503, Body: `{"message":"unavailable"}`}, true},
		{"plain client error not parsed", &upstreamerror.Error{Status: 400, Body: "plain refusal"}, &upstreamerror.Error{Status: 503, Body: `{"message":"last"}`}, false},
		{"empty parsed message", &upstreamerror.Error{Status: 400, Body: `{"message":""}`}, refusalError(), false},
		{"408 not preferred", &upstreamerror.Error{Status: 408, Body: `{"message":"timeout"}`}, refusalError(), false},
		{"429 not preferred", &upstreamerror.Error{Status: 429, Body: `{"message":"limited"}`}, refusalError(), false},
		{"server not preferred", &upstreamerror.Error{Status: 500, Body: `{"message":"server"}`}, refusalError(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, _ io.Writer) error {
				if option.EndpointID == "first" {
					return tc.first
				}
				return tc.last
			}}
			pr, pw := io.Pipe()
			tracker := newSelectedRouteTracker()
			options := []llm.InvokeOptions{{Model: "a", Provider: "anthropic", EndpointID: "first"}, {Model: "b", Provider: "openai", EndpointID: "last"}}
			go invokeProviderStream(context.Background(), client, &types.OpenAIChatRequest{Model: "a"}, nil, pw, options, true, nil, tracker, "selection", false, false)
			body, err := io.ReadAll(pr)
			want, wantEndpoint := tc.last, "last"
			if tc.wantFirst {
				want, wantEndpoint = tc.first, "first"
			}
			option, ok := invokeAttemptOption(err)
			if len(body) != 0 || err == nil || !reflect.DeepEqual(upstreamerror.Parse(err), upstreamerror.Parse(want)) || !ok || option.EndpointID != wantEndpoint || !reflect.DeepEqual(client.endpoints(), []string{"first", "last"}) {
				t.Fatalf("body=%q err=%v option=%#v", body, err, option)
			}
		})
	}
}

type errorHeadWriter struct {
	synchronizedBuffer
	head chan struct{}
	once sync.Once
}

func (w *errorHeadWriter) Write(p []byte) (int, error) {
	n, err := w.synchronizedBuffer.Write(p)
	if bytes.Contains(p, []byte("\r\n\r\n")) {
		w.once.Do(func() { close(w.head) })
	}
	return n, err
}

func TestAcceptedStreamFailuresAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/partial=%t", route, partial), func(t *testing.T) {
				gateway, auth, options, refunds := errorTestGateway(t, true, false)
				out := &errorHeadWriter{head: make(chan struct{})}
				client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
					upstreamerror.Open(w)
					select {
					case <-out.head:
					case <-time.After(time.Second):
						return fmt.Errorf("head waited for first token")
					}
					if partial {
						if _, err := io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"); err != nil {
							return err
						}
					}
					return refusalError()
				}}
				serveErrorTestRoute(context.Background(), route, true, out, client, gateway, auth, options)
				response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(out.String())), nil)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				headers := http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-cache"}, "X-Accel-Buffering": {"no"}}
				if response.StatusCode != 200 || !response.Close || !reflect.DeepEqual(response.Header, headers) || !reflect.DeepEqual(response.TransferEncoding, []string{"chunked"}) {
					t.Fatalf("status=%d headers=%v transfer=%v", response.StatusCode, response.Header, response.TransferEncoding)
				}
				assertErrorStreamBody(t, route, string(raw), partial)
				if *refunds != 1 || !reflect.DeepEqual(client.endpoints(), []string{"first"}) {
					t.Fatalf("refunds=%d attempts=%v", *refunds, client.endpoints())
				}
			})
		}
	}
}

func assertErrorStreamBody(t *testing.T, route, body string, partial bool) {
	t.Helper()
	suffix := "empty"
	if partial {
		suffix = "partial"
	}
	assertErrorStreamFixture(t, route+"-"+suffix+".json", body)
}

func assertErrorStreamFixture(t *testing.T, fixture, body string) {
	t.Helper()
	// IDs and creation times are generated per request; normalize only those fields.
	events := strings.Split(strings.TrimSuffix(body, "\n\n"), "\n\n")
	normalized := make([]any, 0, len(events))
	var normalize func(any)
	normalize = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				if k == "id" || k == "response_id" || k == "item_id" {
					v[k] = "ID"
				} else if k == "created" || k == "created_at" {
					v[k] = float64(0)
				} else {
					normalize(x)
				}
			}
		case []any:
			for _, x := range v {
				normalize(x)
			}
		}
	}
	for _, event := range events {
		if event == "data: [DONE]" {
			normalized = append(normalized, "[DONE]")
			continue
		}
		name := ""
		data := event
		if strings.HasPrefix(event, "event: ") {
			parts := strings.SplitN(event, "\n", 2)
			name = strings.TrimPrefix(parts[0], "event: ")
			data = parts[1]
		}
		var value any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(data, "data: ")), &value); err != nil {
			t.Fatalf("bad event %q: %v", event, err)
		}
		normalize(value)
		normalized = append(normalized, map[string]any{"event": name, "data": value})
	}
	got, _ := json.Marshal(normalized)
	want, err := os.ReadFile("testdata/upstream_errors/" + fixture)
	if err != nil {
		t.Fatalf("fixture: %v; actual=%s", err, got)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	if string(got) != compact.String() {
		t.Fatalf("stream body mismatch\ngot: %s\nwant: %s", got, want)
	}
}

func TestAcceptedFailureBeforePendingHead(t *testing.T) {
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		t.Run(route, func(t *testing.T) {
			gateway, auth, options, refunds := errorTestGateway(t, false, false)
			client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error { upstreamerror.Open(w); return refusalError() }}
			invocation := startProviderInvocation(context.Background(), client, &types.OpenAIChatRequest{Model: "model-a", Stream: true}, nil, options, true, auth, "pending-head")
			<-invocation.done
			var out bytes.Buffer
			serveErrorTestRoute(withProviderInvocation(context.Background(), invocation), route, true, &out, client, gateway, auth, options)
			body := map[string]any{"error": expectedRefusal(false)}
			if route == "messages" {
				body["type"] = "error"
			}
			assertJSONFailure(t, out.String(), 400, body)
			if *refunds != 1 || !reflect.DeepEqual(client.endpoints(), []string{"first"}) {
				t.Fatalf("refunds=%d attempts=%v", *refunds, client.endpoints())
			}
		})
	}
}

func TestAcceptedFailureWinsOverEarlierRefusal(t *testing.T) {
	gateway, auth, options, refunds := errorTestGateway(t, true, false)
	client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, w io.Writer) error {
		if option.EndpointID == "first" {
			return refusalError()
		}
		upstreamerror.Open(w)
		return &upstreamerror.Error{Status: 500, Body: `{"message":"Selected stream failed"}`}
	}}
	invocation := startProviderInvocation(context.Background(), client, &types.OpenAIChatRequest{Model: "model-a", Stream: true}, nil, options, true, auth, "accepted-failure")
	<-invocation.done
	var out bytes.Buffer
	serveErrorTestRoute(withProviderInvocation(context.Background(), invocation), "chat.completions", true, &out, client, gateway, auth, options)
	assertJSONFailure(t, out.String(), 500, map[string]any{"error": map[string]any{"message": "Selected stream failed", "type": "provider_error", "code": nil, "param": nil, "status": 500, "source": "provider", "metadata": map[string]any{"provider_name": "openai", "raw": `{"message":"Selected stream failed"}`}}})
	if *refunds != 1 || !reflect.DeepEqual(client.endpoints(), []string{"first", "last"}) {
		t.Fatalf("refunds=%d attempts=%v", *refunds, client.endpoints())
	}
}

func TestFailedAcceptedStreamSkipsStageDHeartbeat(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	refunds := 0
	gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/internal/gateway/refund" {
			t.Errorf("failed stream reached preheader heartbeat: %s", r.URL.Path)
		} else {
			refunds++
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"refunded":true}}`)), Request: r}, nil
	})
	auth := stageDStreamingAuthorization()
	options := []llm.InvokeOptions{{Model: "model-a", Provider: "anthropic", EndpointID: "anthropic/test"}}
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error { upstreamerror.Open(w); return refusalError() }}
	invocation := startProviderInvocation(context.Background(), client, &types.OpenAIChatRequest{Model: "model-a", Stream: true}, nil, options, true, auth, "failed-before-heartbeat")
	<-invocation.done
	var out bytes.Buffer
	serveErrorTestRoute(withProviderInvocation(context.Background(), invocation), "chat.completions", true, &out, client, gateway, auth, options)
	assertJSONFailure(t, out.String(), 400, map[string]any{"error": expectedRefusal(false)})
	if refunds != 1 {
		t.Fatalf("refunds=%d", refunds)
	}
}

type slowAcceptedErrorClient struct {
	opened  chan context.Context
	release chan struct{}
}

func (c *slowAcceptedErrorClient) InvokeStreaming(ctx context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, w io.Writer, _ ...llm.InvokeOptions) error {
	upstreamerror.Open(w)
	c.opened <- ctx
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.release:
		return refusalError()
	}
}

func TestAcceptedStreamEndsFallbackFirstByteBudget(t *testing.T) {
	oldBudget := firstByteBudget
	firstByteBudget = 50 * time.Millisecond
	defer func() { firstByteBudget = oldBudget }()
	gateway, auth, options, refunds := errorTestGateway(t, true, false)
	client := &slowAcceptedErrorClient{opened: make(chan context.Context, 1), release: make(chan struct{})}
	out := &errorHeadWriter{head: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveErrorTestRoute(context.Background(), "chat.completions", true, out, client, gateway, auth, options)
	}()
	providerCtx := <-client.opened
	// Keep the accepted upstream silent past the candidate fallback deadline.
	select {
	case <-providerCtx.Done():
		t.Errorf("accepted reasoning stream canceled by fallback timer: %v", providerCtx.Err())
	case <-time.After(2 * firstByteBudget):
	}
	select {
	case <-out.head:
	default:
		t.Error("head waited for reasoning content")
	}
	close(client.release)
	<-done
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(out.String())), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-cache"}, "X-Accel-Buffering": {"no"}}
	if response.StatusCode != 200 || !response.Close || !reflect.DeepEqual(response.Header, headers) || !reflect.DeepEqual(response.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("status=%d headers=%v transfer=%v", response.StatusCode, response.Header, response.TransferEncoding)
	}
	assertErrorStreamBody(t, "chat.completions", string(body), false)
	if *refunds != 1 {
		t.Fatalf("refunds=%d", *refunds)
	}
}
