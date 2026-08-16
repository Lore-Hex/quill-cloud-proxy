package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestUserModelSignatureMatchesDocumentedVector(t *testing.T) {
	body := []byte(`{"model":"demo","stream":false}`)
	got := signUserModelRequest("test-signing-secret", body, time.Unix(1_700_000_000, 0))
	want := "t=1700000000,v1=a7597e2bfa4bc480b058f31a24542b3ab0c99fe6231ae15aa0498fd5bd1d4304"
	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestBuildUserModelOwnerBodyIsAllowlistedAndForcesOwnerRouting(t *testing.T) {
	model := &trustedrouter.CustomModel{UpstreamModelID: "owner-private-model", SupportsStreaming: true}
	req := &types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	raw := map[string]any{
		"model": "trustedrouter/user-demo", "stream": false,
		"messages":    []any{map[string]any{"role": "user", "content": "hello"}},
		"temperature": 0.25, "metadata": map[string]any{"safe": "owner-visible"},
		"provider": map[string]any{"order": []string{"secret-route"}},
		"models":   []string{"fallback"}, "user": "caller-attribution", "trace": map[string]any{"id": "private"},
	}
	body, err := buildUserModelOwnerBody(t.Context(), req, raw, nil, model)
	if err != nil {
		t.Fatalf("buildUserModelOwnerBody: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["model"] != "owner-private-model" || decoded["stream"] != true {
		t.Fatalf("forced routing = %#v", decoded)
	}
	for _, forbidden := range []string{"provider", "models", "user", "trace", "session_id", "tags", "app"} {
		if _, ok := decoded[forbidden]; ok {
			t.Fatalf("owner body leaked %q: %s", forbidden, body)
		}
	}
	if decoded["temperature"] != 0.25 || decoded["metadata"] == nil {
		t.Fatalf("allowed fields missing: %s", body)
	}
}

func TestBuildUserModelOwnerBodyPreservesAllowedFieldsAfterNativeAdaptation(t *testing.T) {
	n := 2
	logprobs := true
	req := &types.OpenAIChatRequest{
		N: &n, Logprobs: &logprobs, Metadata: map[string]any{"safe": "owner-visible"},
		Provider: &types.ProviderRouting{}, Trace: map[string]any{"private": true},
	}
	anthropicReq := &types.AnthropicMessagesRequest{
		Messages: []types.AnthropicMessage{{Role: "user", Content: "hello"}}, MaxTokens: 32,
	}
	body, err := buildUserModelOwnerBody(
		t.Context(), req, nil, anthropicReq,
		&trustedrouter.CustomModel{UpstreamModelID: "owner-private-model"},
	)
	if err != nil {
		t.Fatalf("buildUserModelOwnerBody: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["n"] != float64(2) || decoded["logprobs"] != true || decoded["metadata"] == nil {
		t.Fatalf("adapted allowlist fields missing: %s", body)
	}
	if _, ok := decoded["provider"]; ok {
		t.Fatalf("adapted body leaked routing: %s", body)
	}
	if _, ok := decoded["trace"]; ok {
		t.Fatalf("adapted body leaked attribution: %s", body)
	}
}

func TestBuildUserModelOwnerBodyScopesStreamOptionsToStreamingOwners(t *testing.T) {
	for _, route := range []string{"messages", "responses"} {
		for _, ownerStreaming := range []bool{false, true} {
			for _, callerSupplied := range []bool{false, true} {
				name := fmt.Sprintf("%s/owner_stream=%v/caller_options=%v", route, ownerStreaming, callerSupplied)
				t.Run(name, func(t *testing.T) {
					req := &types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
					if callerSupplied {
						if route == "responses" {
							req.Response = &types.ResponseRequestMeta{StreamOptions: map[string]any{"include_usage": false, "sentinel": "caller"}}
						} else {
							req.StreamOptions = &types.ChatStreamOptions{IncludeUsage: false}
						}
					} else if route == "responses" {
						req.Response = &types.ResponseRequestMeta{}
					}
					anthropicReq := &types.AnthropicMessagesRequest{
						Messages: []types.AnthropicMessage{{Role: "user", Content: "hello"}}, MaxTokens: 32,
					}
					body, err := buildUserModelOwnerBody(t.Context(), req, nil, anthropicReq, &trustedrouter.CustomModel{
						UpstreamModelID: "owner-private", SupportsStreaming: ownerStreaming,
					})
					if err != nil {
						t.Fatalf("buildUserModelOwnerBody: %v", err)
					}
					var decoded map[string]any
					if err := json.Unmarshal(body, &decoded); err != nil {
						t.Fatal(err)
					}
					options, present := decoded["stream_options"].(map[string]any)
					if !ownerStreaming {
						if _, exists := decoded["stream_options"]; exists {
							t.Fatalf("buffered owner received stream_options: %s", body)
						}
						return
					}
					if !present {
						t.Fatalf("streaming owner omitted stream_options: %s", body)
					}
					if !callerSupplied && options["include_usage"] != true {
						t.Fatalf("default stream_options = %#v", options)
					}
					if callerSupplied && route == "responses" && options["sentinel"] != "caller" {
						t.Fatalf("caller stream_options were replaced: %#v", options)
					}
					if callerSupplied && route == "messages" {
						if _, overwritten := options["include_usage"]; overwritten {
							t.Fatalf("caller stream_options were replaced: %#v", options)
						}
					}
				})
			}
		}
	}
}

func TestTranslateUserModelSSEToAnthropicContract(t *testing.T) {
	owner := strings.Join([]string{
		`data: {"id":"owner-id","object":"chat.completion.chunk","model":"owner-private","choices":[{"delta":{"role":"assistant","content":"hel"},"finish_reason":null}]}`,
		"",
		`data: {"id":"owner-id","object":"chat.completion.chunk","model":"owner-private","choices":[{"delta":{"content":"lo"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")
	var internal bytes.Buffer
	if err := translateUserModelSSE(strings.NewReader(owner), &internal); err != nil {
		t.Fatalf("translateUserModelSSE: %v", err)
	}
	result, err := adapter.CollectAnthropicText(bytes.NewReader(internal.Bytes()))
	if err != nil {
		t.Fatalf("CollectAnthropicText: %v\n%s", err, internal.String())
	}
	if result.Text != "hello" || result.FinishReason != "stop" || result.Usage == nil || result.Usage.OutputTokens != 2 {
		t.Fatalf("result = %#v", result)
	}
	if strings.Contains(internal.String(), "owner-private") {
		t.Fatalf("upstream model leaked into internal stream: %s", internal.String())
	}
}

func TestTranslateUserModelSSEPreservesToolCalls(t *testing.T) {
	owner := strings.Join([]string{
		`data: {"object":"chat.completion.chunk","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":"}}]},"finish_reason":null}]}`,
		"",
		`data: {"object":"chat.completion.chunk","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"x\"}"}}]},"finish_reason":"tool_calls"}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")
	var internal bytes.Buffer
	if err := translateUserModelSSE(strings.NewReader(owner), &internal); err != nil {
		t.Fatalf("translateUserModelSSE: %v", err)
	}
	result, err := adapter.CollectAnthropicText(bytes.NewReader(internal.Bytes()))
	if err != nil {
		t.Fatalf("CollectAnthropicText: %v\n%s", err, internal.String())
	}
	if len(result.ToolCalls) != 1 || result.ToolCalls[0].ID != "call_1" ||
		result.ToolCalls[0].Name != "lookup" || result.ToolCalls[0].Arguments != `{"q":"x"}` ||
		result.FinishReason != "tool_calls" {
		t.Fatalf("tool result = %#v", result)
	}
}

func TestTranslateUserModelSSESkipsEmptyChoiceChunkWithoutUsage(t *testing.T) {
	owner := strings.Join([]string{
		`data: {"object":"chat.completion.chunk","choices":[]}`,
		"",
		`data: {"object":"chat.completion.chunk","choices":[{"delta":{"content":"answer"},"finish_reason":"stop"}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")
	var internal bytes.Buffer
	if err := translateUserModelSSE(strings.NewReader(owner), &internal); err != nil {
		t.Fatalf("translateUserModelSSE: %v", err)
	}
	result, err := adapter.CollectAnthropicText(bytes.NewReader(internal.Bytes()))
	if err != nil || result.Text != "answer" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

type countingUserModelReader struct {
	r io.Reader
	n int
}

func (r *countingUserModelReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func TestTranslateUserModelSSERejectsNewlineFreeLineAtBound(t *testing.T) {
	source := &countingUserModelReader{r: io.MultiReader(
		strings.NewReader("data: "),
		io.LimitReader(strings.NewReader(strings.Repeat("x", 4<<20)), 4<<20),
	)}
	err := translateUserModelSSE(source, io.Discard)
	var malformed *malformedUserModelResponse
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v, want malformed response", err)
	}
	if source.n > maxUserModelSSEEventBytes {
		t.Fatalf("reader consumed %d bytes, want at most %d", source.n, maxUserModelSSEEventBytes)
	}
}

func TestTranslateUserModelSSETotalReaderCapFailsIncompleteStream(t *testing.T) {
	source := &countingUserModelReader{r: strings.NewReader(strings.Repeat(": ping\n\n", 64))}
	err := translateUserModelSSE(limitUserModelResponse(source, 128), io.Discard)
	var malformed *malformedUserModelResponse
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v, want malformed response", err)
	}
	if source.n > 129 {
		t.Fatalf("limited reader consumed %d bytes, want at most 129", source.n)
	}
}

func TestTranslateUserModelBufferedSynthesizesToolsAndUsage(t *testing.T) {
	owner := `{"id":"owner-id","object":"chat.completion","model":"owner-private","choices":[{"message":{"role":"assistant","content":"answer","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":8,"completion_tokens":3}}`
	var internal bytes.Buffer
	if err := translateUserModelBuffered(strings.NewReader(owner), &internal, "trustedrouter/user-demo", "msg_tr_request"); err != nil {
		t.Fatalf("translateUserModelBuffered: %v", err)
	}
	result, err := adapter.CollectAnthropicText(bytes.NewReader(internal.Bytes()))
	if err != nil {
		t.Fatalf("CollectAnthropicText: %v\n%s", err, internal.String())
	}
	if result.Text != "answer" || len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "lookup" || result.FinishReason != "tool_calls" {
		t.Fatalf("result = %#v", result)
	}
	if result.Usage == nil || result.Usage.InputTokens != 8 || result.Usage.OutputTokens != 3 {
		t.Fatalf("usage = %#v", result.Usage)
	}
	if !strings.Contains(internal.String(), `"model":"trustedrouter/user-demo"`) || strings.Contains(internal.String(), "owner-private") {
		t.Fatalf("response model masking failed: %s", internal.String())
	}
	if !strings.Contains(internal.String(), `"id":"msg_tr_request"`) || strings.Contains(internal.String(), "owner-id") {
		t.Fatalf("owner completion id leaked into message_start: %s", internal.String())
	}
}

func TestTranslateUserModelRejectsMalformedSSE(t *testing.T) {
	var out bytes.Buffer
	err := translateUserModelSSE(strings.NewReader("data: not-json\n\ndata: [DONE]\n\n"), &out)
	var malformed *malformedUserModelResponse
	if err == nil || !errors.As(err, &malformed) {
		t.Fatalf("error = %v", err)
	}
}

type gatedFirstUserModelWrite struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (w *gatedFirstUserModelWrite) Write(p []byte) (int, error) {
	w.mu.Lock()
	first := w.calls == 0
	w.calls++
	w.mu.Unlock()
	if first {
		close(w.entered)
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *gatedFirstUserModelWrite) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestSynchronizedUserModelWriterKeepsResponsesEventsAtomic(t *testing.T) {
	oldInterval := userModelKeepaliveInterval
	userModelKeepaliveInterval = time.Millisecond
	t.Cleanup(func() { userModelKeepaliveInterval = oldInterval })
	slow := &gatedFirstUserModelWrite{entered: make(chan struct{}), release: make(chan struct{})}
	w := &synchronizedUserModelWriter{w: slow}
	eventDone := make(chan error, 1)
	go func() {
		sequence := 0
		eventDone <- adapter.WriteResponsesEvent(w, &sequence, "response.output_text.delta", map[string]any{
			"type": "response.output_text.delta", "delta": "abc",
		})
	}()
	<-slow.entered
	dispatchDone := make(chan struct{})
	keepaliveDone := make(chan struct{})
	state := newUserModelDispatchState()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		writeUserModelKeepalives(state, dispatchDone, w, cancel)
		close(keepaliveDone)
	}()
	// Let a tiny-interval tick dequeue while the slow caller holds the event's
	// first Write. The keepalive must skip after that Write marks dataWritten.
	time.Sleep(10 * time.Millisecond)
	close(slow.release)
	if err := <-eventDone; err != nil {
		t.Fatal(err)
	}
	close(dispatchDone)
	<-keepaliveDone
	sequence := 1
	if err := adapter.WriteResponsesEvent(w, &sequence, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `{"q":1}`,
	}); err != nil {
		t.Fatal(err)
	}
	if output := slow.String(); strings.Contains(output, ": keepalive") || strings.Contains(output, "event: response.output_text.delta\n: keepalive") {
		t.Fatalf("keepalive split Responses event: %q", output)
	}
	if got := w.deliveredOutput(); got != `abc{"q":1}` {
		t.Fatalf("delivered semantic output = %q", got)
	}
}

type userModelFixedResolver []netip.Addr

func (r userModelFixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r...), nil
}

func TestDispatchUserModelClosesOwnerConnectionsHTTP1AndHTTP2(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", useHTTP2), func(t *testing.T) {
			oldClient := newUserModelHTTPClient
			t.Cleanup(func() { newUserModelHTTPClient = oldClient })
			var statesMu sync.Mutex
			states := map[net.Conn]http.ConnState{}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantMajor := 1
				if useHTTP2 {
					wantMajor = 2
				}
				if r.ProtoMajor != wantMajor {
					t.Errorf("protocol = %s, want HTTP/%d", r.Proto, wantMajor)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"object":"chat.completion","choices":[{"message":{"role":"assistant","content":"answer"},"finish_reason":"stop"}]}`)
			}))
			server.EnableHTTP2 = useHTTP2
			server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
				statesMu.Lock()
				states[conn] = state
				statesMu.Unlock()
			}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			newUserModelHTTPClient = func(endpoint string, options llm.EgressGuardOptions) (*http.Client, error) {
				options.RootCAs = roots
				options.Resolver = userModelFixedResolver{netip.MustParseAddr("8.8.8.8")}
				options.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				}
				return llm.NewGuardedHTTPClient(endpoint, options)
			}

			dek := bytes.Repeat([]byte{6}, 32)
			cache := byokcache.New(byokcache.Options{Unwrapper: &userModelTestUnwrapper{dek: dek}})
			model := &trustedrouter.CustomModel{
				ID: "trustedrouter/user-demo", Kind: "user_provided", UserModelKind: "machine",
				OwnerWorkspaceID: "owner-ws", EndpointURL: "https://example.com/v1", UpstreamModelID: "owner-private",
				SecretNamespace:        userModelSecretNamespace,
				SigningEncryptedSecret: sealUserModelTestSecret(t, dek, "owner-ws", userModelSigningSecretPurpose, "signing-secret"),
				SigningSecretPurpose:   userModelSigningSecretPurpose,
				ConnectTimeoutSeconds:  10, FirstByteTimeoutSeconds: 30, IdleTimeoutSeconds: 60, TotalTimeoutSeconds: 300,
			}
			if err := dispatchUserModel(
				t.Context(), newUserModelDispatchState(),
				&types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "prompt"}}},
				map[string]any{"messages": []any{map[string]any{"role": "user", "content": "prompt"}}},
				nil, model, cache, io.Discard,
			); err != nil {
				t.Fatalf("dispatchUserModel: %v", err)
			}

			deadline := time.Now().Add(time.Second)
			for {
				statesMu.Lock()
				open := 0
				for _, state := range states {
					if state != http.StateClosed && state != http.StateHijacked {
						open++
					}
				}
				statesMu.Unlock()
				if open == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%d owner connections remained open after dispatch", open)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

type userModelTestUnwrapper struct{ dek []byte }

func (u *userModelTestUnwrapper) UnwrapDEK(context.Context, string, []byte, []byte) ([]byte, error) {
	return append([]byte(nil), u.dek...), nil
}

func TestDispatchUserModelSendsSignedAllowlistedBodyAndAdaptsBothOwnerShapes(t *testing.T) {
	fixedNow := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	oldNow := userModelNow
	oldClient := newUserModelHTTPClient
	userModelNow = func() time.Time { return fixedNow }
	t.Cleanup(func() {
		userModelNow = oldNow
		newUserModelHTTPClient = oldClient
	})

	for _, supportsStreaming := range []bool{true, false} {
		t.Run(map[bool]string{true: "owner-sse", false: "owner-buffered"}[supportsStreaming], func(t *testing.T) {
			var received map[string]any
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/chat/completions" {
					t.Errorf("path = %s", r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read body: %v", err)
					return
				}
				if err := json.Unmarshal(body, &received); err != nil {
					t.Errorf("decode body: %v", err)
				}
				if r.Header.Get("Authorization") != "Bearer endpoint-secret" {
					t.Errorf("authorization = %q", r.Header.Get("Authorization"))
				}
				if got, want := r.Header.Get("TR-Signature"), signUserModelRequest("signing-secret", body, fixedNow); got != want {
					t.Errorf("signature = %q, want %q", got, want)
				}
				if supportsStreaming {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"owner answer\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"object":"chat.completion","model":"owner-private","choices":[{"message":{"role":"assistant","content":"owner answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`)
			}))
			defer server.Close()
			newUserModelHTTPClient = func(string, llm.EgressGuardOptions) (*http.Client, error) {
				client := server.Client()
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				return client, nil
			}

			dek := bytes.Repeat([]byte{7}, 32)
			cache := byokcache.New(byokcache.Options{Unwrapper: &userModelTestUnwrapper{dek: dek}})
			model := &trustedrouter.CustomModel{
				ID: "trustedrouter/user-demo", Kind: "user_provided", UserModelKind: "machine",
				OwnerWorkspaceID: "owner-ws", EndpointURL: server.URL + "/v1", UpstreamModelID: "owner-private",
				SupportsStreaming: supportsStreaming, SecretNamespace: userModelSecretNamespace,
				EndpointEncryptedSecret: sealUserModelTestSecret(t, dek, "owner-ws", userModelEndpointSecretPurpose, "endpoint-secret"),
				EndpointSecretPurpose:   userModelEndpointSecretPurpose,
				SigningEncryptedSecret:  sealUserModelTestSecret(t, dek, "owner-ws", userModelSigningSecretPurpose, "signing-secret"),
				SigningSecretPurpose:    userModelSigningSecretPurpose,
				ConnectTimeoutSeconds:   10, FirstByteTimeoutSeconds: 30, IdleTimeoutSeconds: 60, TotalTimeoutSeconds: 300,
			}
			req := &types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "prompt"}}}
			raw := map[string]any{
				"messages": []any{map[string]any{"role": "user", "content": "prompt"}},
				"provider": map[string]any{"order": []string{"private-route"}},
				"user":     "caller-attribution", "temperature": 0.2,
			}
			state := newUserModelDispatchState()
			var internal bytes.Buffer
			if err := dispatchUserModel(t.Context(), state, req, raw, nil, model, cache, &internal); err != nil {
				t.Fatalf("dispatchUserModel: %v", err)
			}
			result, err := adapter.CollectAnthropicText(bytes.NewReader(internal.Bytes()))
			if err != nil || result.Text != "owner answer" {
				t.Fatalf("internal result = %#v, err=%v\n%s", result, err, internal.String())
			}
			if received["model"] != "owner-private" || received["stream"] != supportsStreaming || received["temperature"] != 0.2 {
				t.Fatalf("owner body = %#v", received)
			}
			if _, ok := received["provider"]; ok {
				t.Fatalf("owner body leaked provider routing: %#v", received)
			}
			if _, ok := received["user"]; ok {
				t.Fatalf("owner body leaked caller attribution: %#v", received)
			}
			if state.firstTokenSeconds() <= 0 {
				t.Fatalf("first token seconds = %v", state.firstTokenSeconds())
			}
		})
	}
}

type userModelContextBody struct {
	ctx   context.Context
	first []byte
	sent  bool
}

func (b *userModelContextBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.first), nil
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (*userModelContextBody) Close() error { return nil }

func TestDispatchUserModelTotalBudgetCancelsOwnerRead(t *testing.T) {
	oldClient := newUserModelHTTPClient
	t.Cleanup(func() { newUserModelHTTPClient = oldClient })
	newUserModelHTTPClient = func(string, llm.EgressGuardOptions) (*http.Client, error) {
		return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: &userModelContextBody{ctx: req.Context(), first: []byte(
					"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"first\"},\"finish_reason\":null}]}\n\n",
				)},
				Request: req,
			}, nil
		})}, nil
	}

	dek := bytes.Repeat([]byte{8}, 32)
	cache := byokcache.New(byokcache.Options{Unwrapper: &userModelTestUnwrapper{dek: dek}})
	model := &trustedrouter.CustomModel{
		ID: "trustedrouter/user-demo", Kind: "user_provided", UserModelKind: "machine",
		OwnerWorkspaceID: "owner-ws", EndpointURL: "https://owner.example/v1", UpstreamModelID: "owner-private",
		SupportsStreaming: true, SecretNamespace: userModelSecretNamespace,
		SigningEncryptedSecret: sealUserModelTestSecret(t, dek, "owner-ws", userModelSigningSecretPurpose, "signing-secret"),
		SigningSecretPurpose:   userModelSigningSecretPurpose,
		ConnectTimeoutSeconds:  10, FirstByteTimeoutSeconds: 300, IdleTimeoutSeconds: 60, TotalTimeoutSeconds: 300,
	}
	state := newUserModelDispatchState()
	state.startedAt = time.Now().Add(-299900 * time.Millisecond)
	err := dispatchUserModel(
		t.Context(), state,
		&types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "prompt"}}},
		map[string]any{"messages": []any{map[string]any{"role": "user", "content": "prompt"}}},
		nil, model, cache, io.Discard,
	)
	var dispatchErr *userModelDispatchError
	if !errors.As(err, &dispatchErr) || dispatchErr.callerStatus != 504 || dispatchErr.refundType != "user_model_timeout" {
		t.Fatalf("dispatch error = %#v (%v)", dispatchErr, err)
	}
	if state.firstTokenSeconds() <= 0 {
		t.Fatal("total budget fired before the owner first byte was observed")
	}
}

func sealUserModelTestSecret(t *testing.T, dek []byte, workspaceID, purpose, plaintext string) *byokcache.EncryptedSecretEnvelope {
	t.Helper()
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	aad := userModelTestAAD(workspaceID, purpose)
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), aad)
	return &byokcache.EncryptedSecretEnvelope{
		Algorithm: byokcache.AlgorithmV2, KeyRef: "test-key",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped")),
		DEKNonce:     base64.URLEncoding.EncodeToString(nonce),
		Ciphertext:   base64.URLEncoding.EncodeToString(ciphertext),
		Nonce:        base64.URLEncoding.EncodeToString(nonce),
	}
}

func userModelTestAAD(workspaceID, purpose string) []byte {
	var out []byte
	for _, part := range []string{"trustedrouter/byok/v2", userModelSecretNamespace, workspaceID, purpose} {
		length := len(part)
		out = append(out, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
		out = append(out, part...)
	}
	return out
}
