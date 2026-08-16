//go:build !cloud_aws

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type userModelIntegrationFixture struct {
	t              *testing.T
	model          *trustedrouter.CustomModel
	cache          *byokcache.Cache
	controlPlane   *httptest.Server
	owner          *httptest.Server
	gateway        *trustedrouter.Client
	mu             sync.Mutex
	ownerBodies    []map[string]any
	settleBodies   []map[string]any
	refundBodies   []map[string]any
	originalClient func(string, llm.EgressGuardOptions) (*http.Client, error)
}

func newUserModelIntegrationFixture(t *testing.T, ownerStreaming bool) *userModelIntegrationFixture {
	return newUserModelIntegrationFixtureWithResponder(t, ownerStreaming, nil)
}

func newUserModelIntegrationFixtureWithResponder(
	t *testing.T,
	ownerStreaming bool,
	responder func(http.ResponseWriter, *http.Request),
) *userModelIntegrationFixture {
	t.Helper()
	dek := bytes.Repeat([]byte{9}, 32)
	fixture := &userModelIntegrationFixture{t: t}
	fixture.owner = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("owner read: %v", err)
			return
		}
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Errorf("owner decode: %v", err)
			return
		}
		fixture.mu.Lock()
		fixture.ownerBodies = append(fixture.ownerBodies, decoded)
		fixture.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("TR-Signature"), "t=") {
			t.Errorf("missing TR-Signature")
		}
		if r.Header.Get("Authorization") != "Bearer endpoint-secret" {
			t.Errorf("owner authorization = %q", r.Header.Get("Authorization"))
		}
		if responder != nil {
			responder(w, r)
			return
		}
		if ownerStreaming {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"object\":\"chat.completion.chunk\",\"model\":\"owner-private\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Hello from owner\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"owner-id","object":"chat.completion","model":"owner-private","choices":[{"message":{"role":"assistant","content":"Hello from owner"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`)
	}))
	fixture.model = &trustedrouter.CustomModel{
		ID: "trustedrouter/user-demo", Name: "Demo", Kind: "user_provided", UserModelKind: "machine",
		OwnerWorkspaceID: "owner-ws", OwnerUserID: "owner-user", EndpointURL: fixture.owner.URL + "/v1",
		UpstreamModelID: "owner-private", Revision: 4, SupportsStreaming: ownerStreaming,
		SecretNamespace:         userModelSecretNamespace,
		EndpointEncryptedSecret: sealUserModelTestSecret(t, dek, "owner-ws", userModelEndpointSecretPurpose, "endpoint-secret"),
		EndpointSecretPurpose:   userModelEndpointSecretPurpose,
		SigningEncryptedSecret:  sealUserModelTestSecret(t, dek, "owner-ws", userModelSigningSecretPurpose, "signing-secret"),
		SigningSecretPurpose:    userModelSigningSecretPurpose,
		ConnectTimeoutSeconds:   10, FirstByteTimeoutSeconds: 30, IdleTimeoutSeconds: 60, TotalTimeoutSeconds: 300,
	}
	fixture.cache = byokcache.New(byokcache.Options{Unwrapper: &userModelTestUnwrapper{dek: dek}})
	fixture.controlPlane = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("control-plane decode %s: %v", r.URL.Path, err)
			return
		}
		switch r.URL.Path {
		case "/internal/gateway/resolve-custom-model":
			writeUserModelTestJSON(t, w, map[string]any{"data": map[string]any{
				"workspace_id": "caller-ws", "api_key_hash": "caller-key", "custom_model": fixture.model,
			}})
		case "/internal/gateway/authorize":
			writeUserModelTestJSON(t, w, map[string]any{"data": map[string]any{
				"authorization_id": "auth-user", "workspace_id": "caller-ws", "api_key_hash": "caller-key",
				"model": fixture.model.ID, "endpoint_id": fixture.model.ID + "@trustedrouter/credits",
				"provider": "trustedrouter", "usage_type": "Credits", "limit_usage_type": "Credits",
			}})
		case "/internal/gateway/settle":
			fixture.mu.Lock()
			fixture.settleBodies = append(fixture.settleBodies, body)
			fixture.mu.Unlock()
			writeUserModelTestJSON(t, w, map[string]any{"data": map[string]any{
				"settled": true, "generation_id": "gen-user", "cost_microdollars": 3,
				"model": fixture.model.ID, "provider": "trustedrouter", "region": "us-central1",
			}})
		case "/internal/gateway/refund":
			fixture.mu.Lock()
			fixture.refundBodies = append(fixture.refundBodies, body)
			fixture.mu.Unlock()
			writeUserModelTestJSON(t, w, map[string]any{"data": map[string]any{"settled": false}})
		default:
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	fixture.gateway = trustedrouter.New(fixture.controlPlane.URL, "internal", fixture.controlPlane.Client())
	fixture.originalClient = newUserModelHTTPClient
	newUserModelHTTPClient = func(string, llm.EgressGuardOptions) (*http.Client, error) {
		client := fixture.owner.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return client, nil
	}
	t.Cleanup(func() {
		newUserModelHTTPClient = fixture.originalClient
		fixture.owner.Close()
		fixture.controlPlane.Close()
	})
	return fixture
}

func writeUserModelTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func (f *userModelIntegrationFixture) request(path, body string) (*http.Response, []byte) {
	f.t.Helper()
	serverConn, clientConn := net.Pipe()
	go serveOne(
		context.Background(), serverConn, auth.New(nil), &panicStreamingLLM{t: f.t},
		nil, nil, f.gateway, f.cache,
	)
	header := "Authorization: Bearer caller-key"
	if path == "/v1/messages" {
		header = "x-api-key: caller-key"
	}
	_, err := fmt.Fprintf(
		clientConn,
		"POST %s HTTP/1.1\r\n%s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		path, header, len(body), body,
	)
	if err != nil {
		f.t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		f.t.Fatalf("read response: %v", err)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatalf("read response body: %v", err)
	}
	response.Body.Close()
	clientConn.Close()
	return response, payload
}

func (f *userModelIntegrationFixture) oneSettle(t *testing.T) map[string]any {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.settleBodies) == 1 {
			body := f.settleBodies[0]
			f.mu.Unlock()
			return body
		}
		f.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("settle was not received")
	return nil
}

func (f *userModelIntegrationFixture) oneRefund(t *testing.T) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.refundBodies) == 1 {
			body := f.refundBodies[0]
			f.mu.Unlock()
			return body
		}
		f.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refund was not received")
	return nil
}

func TestServeUserModelFourStreamingQuadrants(t *testing.T) {
	for _, ownerStreaming := range []bool{false, true} {
		for _, callerStreaming := range []bool{false, true} {
			name := fmt.Sprintf("owner_stream=%v/caller_stream=%v", ownerStreaming, callerStreaming)
			t.Run(name, func(t *testing.T) {
				fixture := newUserModelIntegrationFixture(t, ownerStreaming)
				body := fmt.Sprintf(`{"model":"trustedrouter/user-demo","stream":%v,"messages":[{"role":"user","content":"private prompt"}],"max_tokens":32,"provider":{"order":["private-route"]},"user":"caller-attribution"}`, callerStreaming)
				response, payload := fixture.request("/v1/chat/completions", body)
				if response.StatusCode != http.StatusOK {
					t.Fatalf("status = %d body=%s", response.StatusCode, payload)
				}
				if !bytes.Contains(payload, []byte("Hello from owner")) || !bytes.Contains(payload, []byte(`"model":"trustedrouter/user-demo"`)) {
					t.Fatalf("wrong response shape: %s", payload)
				}
				if bytes.Contains(payload, []byte("owner-private")) {
					t.Fatalf("upstream model leaked: %s", payload)
				}
				settle := fixture.oneSettle(t)
				if settle["selected_model"] != "trustedrouter/user-demo" || settle["selected_endpoint"] != "trustedrouter/user-demo@trustedrouter/credits" {
					t.Fatalf("settle route = %#v", settle)
				}
				if settle["streamed"] != callerStreaming || settle["first_token_seconds"].(float64) <= 0 {
					t.Fatalf("settle timing/stream = %#v", settle)
				}
				fixture.mu.Lock()
				ownerBody := fixture.ownerBodies[0]
				fixture.mu.Unlock()
				if ownerBody["stream"] != ownerStreaming || ownerBody["model"] != "owner-private" {
					t.Fatalf("owner routing = %#v", ownerBody)
				}
				for _, forbidden := range []string{"provider", "user", "models", "trace", "tags"} {
					if _, ok := ownerBody[forbidden]; ok {
						t.Fatalf("owner body leaked %s: %#v", forbidden, ownerBody)
					}
				}
			})
		}
	}
}

func TestServeUserModelResponsesAndMessagesUseNativeAdapters(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "responses", path: "/v1/responses",
			body: `{"model":"trustedrouter/user-demo","stream":false,"input":"private prompt","max_output_tokens":32}`,
			want: `"object":"response"`,
		},
		{
			name: "messages", path: "/v1/messages",
			body: `{"model":"trustedrouter/user-demo","stream":false,"max_tokens":32,"messages":[{"role":"user","content":"private prompt"}]}`,
			want: `"type":"message"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newUserModelIntegrationFixture(t, false)
			response, payload := fixture.request(test.path, test.body)
			if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(test.want)) {
				t.Fatalf("status=%d body=%s", response.StatusCode, payload)
			}
			if !bytes.Contains(payload, []byte(`"model":"trustedrouter/user-demo"`)) || bytes.Contains(payload, []byte("owner-private")) {
				t.Fatalf("model masking failed: %s", payload)
			}
			settle := fixture.oneSettle(t)
			if settle["route_type"] != strings.TrimPrefix(test.path, "/v1/") {
				t.Fatalf("route_type = %#v", settle)
			}
		})
	}
}

func TestServeUserModelRefundTaxonomy(t *testing.T) {
	tests := []struct {
		name         string
		responder    func(http.ResponseWriter, *http.Request)
		callerStatus int
		message      string
		refundStatus float64
		refundType   string
	}{
		{
			name: "owner 503", callerStatus: 502,
			message: "returned an upstream error (HTTP 503)", refundStatus: 503, refundType: "provider_error",
			responder: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) },
		},
		{
			name: "owner 401", callerStatus: 502,
			message: "returned an upstream error (HTTP 401)", refundStatus: 401, refundType: "upstream_client_error",
			responder: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) },
		},
		{
			name: "malformed", callerStatus: 502,
			message: "returned a malformed response", refundStatus: 502, refundType: "malformed_response",
			responder: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, "not-json")
			},
		},
		{
			name: "first byte timeout", callerStatus: 504,
			message: "exceeded its dispatch budget", refundStatus: 504, refundType: "user_model_timeout",
			responder: func(_ http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newUserModelIntegrationFixtureWithResponder(t, false, test.responder)
			if test.name == "first byte timeout" {
				fixture.model.FirstByteTimeoutSeconds = 1
				fixture.model.TotalTimeoutSeconds = 2
			}
			response, payload := fixture.request(
				"/v1/chat/completions",
				`{"model":"trustedrouter/user-demo","stream":false,"messages":[{"role":"user","content":"private prompt"}]}`,
			)
			if response.StatusCode != test.callerStatus || !bytes.Contains(payload, []byte(test.message)) {
				t.Fatalf("status=%d body=%s", response.StatusCode, payload)
			}
			refund := fixture.oneRefund(t)
			if refund["error_status"] != test.refundStatus || refund["error_type"] != test.refundType {
				t.Fatalf("refund = %#v", refund)
			}
			if refund["selected_model"] != "trustedrouter/user-demo" || refund["selected_endpoint"] != "trustedrouter/user-demo@trustedrouter/credits" {
				t.Fatalf("refund route = %#v", refund)
			}
		})
	}
}

func TestServeUserModelRedirectIsNotFollowed(t *testing.T) {
	fixture := newUserModelIntegrationFixtureWithResponder(t, false, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://redirect-target.example/private", http.StatusFound)
	})
	response, payload := fixture.request(
		"/v1/chat/completions",
		`{"model":"trustedrouter/user-demo","stream":false,"messages":[{"role":"user","content":"private prompt"}]}`,
	)
	if response.StatusCode != 502 || !bytes.Contains(payload, []byte("upstream error (HTTP 302)")) {
		t.Fatalf("status=%d body=%s", response.StatusCode, payload)
	}
	refund := fixture.oneRefund(t)
	if refund["error_status"] != float64(302) || refund["error_type"] != "upstream_client_error" {
		t.Fatalf("refund = %#v", refund)
	}
	fixture.mu.Lock()
	ownerCalls := len(fixture.ownerBodies)
	fixture.mu.Unlock()
	if ownerCalls != 1 {
		t.Fatalf("redirect was followed; owner calls = %d", ownerCalls)
	}
}

func TestServeUserModelEnclaveContractErrorRefundsWithoutOwnerStrikeType(t *testing.T) {
	fixture := newUserModelIntegrationFixture(t, false)
	fixture.model.SecretNamespace = "provider"
	response, payload := fixture.request(
		"/v1/chat/completions",
		`{"model":"trustedrouter/user-demo","stream":false,"messages":[{"role":"user","content":"private prompt"}]}`,
	)
	if response.StatusCode != 500 || !bytes.Contains(payload, []byte("failed inside the enclave")) {
		t.Fatalf("status=%d body=%s", response.StatusCode, payload)
	}
	refund := fixture.oneRefund(t)
	if refund["error_status"] != float64(500) || refund["error_type"] != "internal_error" {
		t.Fatalf("refund = %#v", refund)
	}
	fixture.mu.Lock()
	ownerCalls := len(fixture.ownerBodies)
	fixture.mu.Unlock()
	if ownerCalls != 0 {
		t.Fatalf("invalid contract reached owner %d times", ownerCalls)
	}
}

func TestServeUserModelPrivateIPAddressIsConnectionError(t *testing.T) {
	fixture := newUserModelIntegrationFixture(t, false)
	// Replace the successful-test transport with the production guard. The
	// httptest owner resolves to loopback and must be refused before any bytes
	// reach it.
	newUserModelHTTPClient = fixture.originalClient
	response, payload := fixture.request(
		"/v1/chat/completions",
		`{"model":"trustedrouter/user-demo","stream":false,"messages":[{"role":"user","content":"private prompt"}]}`,
	)
	if response.StatusCode != 502 || !bytes.Contains(payload, []byte("could not be reached")) {
		t.Fatalf("status=%d body=%s", response.StatusCode, payload)
	}
	refund := fixture.oneRefund(t)
	if refund["error_status"] != float64(502) || refund["error_type"] != "connection_error" {
		t.Fatalf("refund = %#v", refund)
	}
	fixture.mu.Lock()
	ownerCalls := len(fixture.ownerBodies)
	fixture.mu.Unlock()
	if ownerCalls != 0 {
		t.Fatalf("private owner was contacted %d times", ownerCalls)
	}
}

func TestServeUserModelKeepalivePrecedesOwnerByteWithoutBecomingTTFT(t *testing.T) {
	oldInterval := userModelKeepaliveInterval
	userModelKeepaliveInterval = 10 * time.Millisecond
	t.Cleanup(func() { userModelKeepaliveInterval = oldInterval })
	fixture := newUserModelIntegrationFixtureWithResponder(t, true, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"late answer\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	})
	response, payload := fixture.request(
		"/v1/chat/completions",
		`{"model":"trustedrouter/user-demo","stream":true,"messages":[{"role":"user","content":"private prompt"}]}`,
	)
	if response.StatusCode != 200 || !bytes.Contains(payload, []byte(": keepalive\n\n")) || !bytes.Contains(payload, []byte("late answer")) {
		t.Fatalf("status=%d body=%s", response.StatusCode, payload)
	}
	settle := fixture.oneSettle(t)
	if got, _ := settle["first_token_seconds"].(float64); got < 0.08 {
		t.Fatalf("keepalive was counted as first token: %#v", settle)
	}
}

func TestServeUserModelDisconnectBeforeFirstByteRefundsWithoutStrikeType(t *testing.T) {
	oldInterval := userModelKeepaliveInterval
	userModelKeepaliveInterval = 10 * time.Millisecond
	t.Cleanup(func() { userModelKeepaliveInterval = oldInterval })
	fixture := newUserModelIntegrationFixtureWithResponder(t, true, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	})

	serverConn, clientConn := net.Pipe()
	go serveOne(
		context.Background(), serverConn, auth.New(nil), &panicStreamingLLM{t: t},
		nil, nil, fixture.gateway, fixture.cache,
	)
	body := `{"model":"trustedrouter/user-demo","stream":true,"messages":[{"role":"user","content":"private prompt"}]}`
	_, _ = fmt.Fprintf(clientConn, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer caller-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response head: %v", err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("status = %d", response.StatusCode)
	}
	clientConn.Close()
	refund := fixture.oneRefund(t)
	if refund["error_status"] != float64(499) || refund["error_type"] != "client_closed" {
		t.Fatalf("refund = %#v", refund)
	}
}

func TestServeUserModelLateDisconnectSettlesPartialUsage(t *testing.T) {
	fixture := newUserModelIntegrationFixtureWithResponder(t, true, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"delivered text\"},\"finish_reason\":null}]}\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"too late\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	})

	serverConn, clientConn := net.Pipe()
	go serveOne(
		context.Background(), serverConn, auth.New(nil), &panicStreamingLLM{t: t},
		nil, nil, fixture.gateway, fixture.cache,
	)
	body := `{"model":"trustedrouter/user-demo","stream":true,"messages":[{"role":"user","content":"private prompt"}]}`
	_, _ = fmt.Fprintf(clientConn, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer caller-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response head: %v", err)
	}
	var delivered bytes.Buffer
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(time.Second)
	for !bytes.Contains(delivered.Bytes(), []byte("delivered text")) && time.Now().Before(deadline) {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			delivered.Write(buffer[:n])
		}
		if readErr != nil {
			t.Fatalf("stream read err=%v body=%s", readErr, delivered.Bytes())
		}
	}
	if !bytes.Contains(delivered.Bytes(), []byte("delivered text")) {
		t.Fatalf("first delivered stream omitted content: %s", delivered.Bytes())
	}
	clientConn.Close()

	settle := fixture.oneSettle(t)
	if settle["finish_reason"] != "client_closed" || settle["usage_estimated"] != true {
		t.Fatalf("partial settle = %#v", settle)
	}
	if output, _ := settle["actual_output_tokens"].(float64); output <= 0 {
		t.Fatalf("partial output tokens = %#v", settle)
	}
	fixture.mu.Lock()
	refundCount := len(fixture.refundBodies)
	fixture.mu.Unlock()
	if refundCount != 0 {
		t.Fatalf("late disconnect refunded instead of settling")
	}
}
