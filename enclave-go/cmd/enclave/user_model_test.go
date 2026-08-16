package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestTranslateUserModelBufferedSynthesizesToolsAndUsage(t *testing.T) {
	owner := `{"id":"owner-id","object":"chat.completion","model":"owner-private","choices":[{"message":{"role":"assistant","content":"answer","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":8,"completion_tokens":3}}`
	var internal bytes.Buffer
	if err := translateUserModelBuffered(strings.NewReader(owner), &internal, "trustedrouter/user-demo"); err != nil {
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
}

func TestTranslateUserModelRejectsMalformedSSE(t *testing.T) {
	var out bytes.Buffer
	err := translateUserModelSSE(strings.NewReader("data: not-json\n\ndata: [DONE]\n\n"), &out)
	var malformed *malformedUserModelResponse
	if err == nil || !errors.As(err, &malformed) {
		t.Fatalf("error = %v", err)
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
