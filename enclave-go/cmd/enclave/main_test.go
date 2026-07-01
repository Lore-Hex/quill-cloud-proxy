package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestParseRequestTargetNonce(t *testing.T) {
	path, nonce, err := parseRequestTarget("/attestation?nonce=001122")
	if err != nil {
		t.Fatalf("parseRequestTarget returned error: %v", err)
	}
	if path != "/attestation" {
		t.Fatalf("path = %q, want /attestation", path)
	}
	if !bytes.Equal(nonce, []byte{0x00, 0x11, 0x22}) {
		t.Fatalf("nonce = %x, want 001122", nonce)
	}
}

func TestSettlementRetryQueueDropsOldestWhenFull(t *testing.T) {
	q := &settlementRetryQueue{
		jobs:        make(chan settlementRetryJob, 1),
		maxAttempts: 2,
		baseDelay:   time.Millisecond,
		maxDelay:    time.Millisecond,
	}
	if !q.Enqueue(settlementRetryJob{usage: trustedrouter.Usage{RequestID: "req_old"}}) {
		t.Fatal("first enqueue failed")
	}
	if !q.Enqueue(settlementRetryJob{usage: trustedrouter.Usage{RequestID: "req_new"}}) {
		t.Fatal("second enqueue failed")
	}
	got := <-q.jobs
	if got.usage.RequestID != "req_new" {
		t.Fatalf("queue kept %q, want newest request", got.usage.RequestID)
	}
}

func TestSettlementRetryQueueRetriesSettleAndBroadcast(t *testing.T) {
	var settleCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/settle" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		settleCalls++
		if settleCalls == 1 {
			http.Error(w, "temporarily down", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"generation_id":"gen_retry","cost_microdollars":2,"cost":0.000002,"usage_type":"Credits","model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
	}))
	defer server.Close()

	q := &settlementRetryQueue{
		jobs:        make(chan settlementRetryJob, 4),
		maxAttempts: 2,
		baseDelay:   time.Millisecond,
		maxDelay:    time.Millisecond,
	}
	authz := &trustedrouter.Authorization{
		AuthorizationID: "auth_retry",
		WorkspaceID:     "ws_1",
		APIKeyHash:      "key_hash",
		Model:           "openai/gpt-4o-mini",
		EndpointID:      "openai/gpt-4o-mini@openai/prepaid",
		Provider:        "openai",
		UsageType:       "Credits",
	}
	job := settlementRetryJob{
		trGateway:     trustedrouter.New(server.URL, "internal", server.Client()),
		authorization: authz,
		usage: trustedrouter.Usage{
			RequestID:      "chatcmpl_retry",
			InputTokens:    1,
			OutputTokens:   1,
			ElapsedSeconds: 0.01,
			FinishReason:   "stop",
			Streamed:       true,
			RouteType:      "chat.completions",
		},
		req: &types.OpenAIChatRequest{Model: "openai/gpt-4o-mini"},
	}
	q.process(context.Background(), job)
	retry := <-q.jobs
	if retry.attempt != 2 {
		t.Fatalf("retry attempt = %d, want 2", retry.attempt)
	}
	q.process(context.Background(), retry)
	if settleCalls != 2 {
		t.Fatalf("settle calls = %d, want 2", settleCalls)
	}
}

func TestResponseStatsConnCapturesStatusBytesAndOutcome(t *testing.T) {
	server, client := net.Pipe()
	stats := &responseStatsConn{Conn: server}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, client)
		_ = client.Close()
	}()

	writeError(stats, 429, "slow down")
	_ = stats.Close()
	<-done

	status, responseBytes := stats.Snapshot()
	if status != 429 {
		t.Fatalf("status = %d, want 429", status)
	}
	if responseBytes == 0 {
		t.Fatal("response bytes were not counted")
	}
	if got := outcomeForStatus(status); got != "client_error" {
		t.Fatalf("outcome = %q, want client_error", got)
	}
}

type selectedLeafTestConn struct {
	net.Conn
	leaf []byte
}

func (c *selectedLeafTestConn) SelectedLeafDER() []byte {
	return append([]byte(nil), c.leaf...)
}

func TestResponseStatsConnDelegatesSelectedLeafDER(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	want := []byte("leaf-der")
	stats := &responseStatsConn{Conn: &selectedLeafTestConn{Conn: server, leaf: want}}
	got := enclavetls.SelectedLeafDER(stats)
	if !bytes.Equal(got, want) {
		t.Fatalf("SelectedLeafDER = %q, want %q", got, want)
	}
	got[0] = 'x'
	if bytes.Equal(enclavetls.SelectedLeafDER(stats), got) {
		t.Fatal("SelectedLeafDER returned mutable storage")
	}
}

func TestParseHTTPStatusAndOutcomeFallbacks(t *testing.T) {
	if got := parseHTTPStatus([]byte("HTTP/1.1 503 Bad Gateway\r\nContent-Length: 0\r\n\r\n")); got != 503 {
		t.Fatalf("status = %d, want 503", got)
	}
	if got := parseHTTPStatus([]byte("not http")); got != 0 {
		t.Fatalf("status = %d, want 0", got)
	}
	if got := outcomeForStatus(0); got != "no_response" {
		t.Fatalf("outcome = %q, want no_response", got)
	}
	if got := outcomeForStatus(503); got != "server_error" {
		t.Fatalf("outcome = %q, want server_error", got)
	}
}

func TestRetryableInvokeErrorFailsOverOnAnyPreOutputError(t *testing.T) {
	// Fail over on EVERY pre-output error, including 4xx. A 400 "invalid
	// model" / 404 "model not found" / 401-403 most often means the top-ranked
	// provider just doesn't serve this model on our account — another
	// authorized candidate usually does. (invokeProviderStream only consults
	// this before any byte is written, so a retry never duplicates output.)
	for _, err := range []error{
		errors.New("llm/upstream: http 502: bad gateway"),
		errors.New("llm/upstream: http 503: service unavailable"),
		errors.New("llm/upstream: http 429: rate limited"),
		errors.New("llm/upstream: http 404: model not found"),
		errors.New("llm/upstream: http 401: unauthorized"),
		errors.New("llm/upstream: http 403: forbidden"),
		// 4xx that the PRIOR behavior declined — now retried, because in a
		// stale multi-provider catalog these usually mean "wrong provider for
		// this model", which the next candidate fixes.
		errors.New("llm/upstream: http 400: invalid model"),
		errors.New("llm/upstream: http 422: unprocessable entity"),
		errors.New("llm/together: http client unavailable: dial tcp: connection refused"),
		errors.New("unexpected EOF"),
		errors.New("context deadline exceeded"),
	} {
		if !retryableInvokeError(err) {
			t.Errorf("retryableInvokeError(%q) = false, want true (should fail over)", err)
		}
	}
	// Only a nil error (success) declines failover.
	if retryableInvokeError(nil) {
		t.Error("retryableInvokeError(nil) = true, want false")
	}
}

func TestServeOneResponsesNonStreamingReturnsResponseAndSettles(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeBody string
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			authorizeBody = string(body)
			if strings.Contains(authorizeBody, bearer) || strings.Contains(authorizeBody, "private response input") || strings.Contains(authorizeBody, "PRIVATE responses preamble") {
				t.Fatalf("authorize leaked sensitive material: %s", authorizeBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_resp","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[],"custom_model":{"id":"trustedrouter/user-resp1","name":"Responses model","base_model_id":"openai/gpt-4o-mini","hidden_prompt":"PRIVATE responses preamble","revision":4}}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, "Hello") || strings.Contains(settleBody, "private response input") || strings.Contains(settleBody, "PRIVATE responses preamble") {
				t.Fatalf("settle leaked content: %s", settleBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_resp","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fakeStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/user-resp1","input":"private response input","instructions":"be brief","max_output_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bodyBytes, &decoded); err != nil {
		t.Fatalf("decode response: %v body=%s", err, bodyBytes)
	}
	if decoded["object"] != "response" || decoded["status"] != "completed" {
		t.Fatalf("bad response envelope: %#v", decoded)
	}
	if decoded["model"] != "trustedrouter/user-resp1" {
		t.Fatalf("response model = %#v, want custom id", decoded["model"])
	}
	if !strings.Contains(string(bodyBytes), "Hello world") {
		t.Fatalf("missing output text: %s", bodyBytes)
	}
	deadline := time.Now().Add(time.Second)
	for settleBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(settleBody, `"route_type":"responses"`) || !strings.Contains(settleBody, `"streamed":false`) {
		t.Fatalf("settle body missing responses metadata: %s", settleBody)
	}
	if streamer.body == nil || streamer.body.System != "PRIVATE responses preamble\n\nbe brief" {
		serialized, _ := json.Marshal(streamer.body)
		t.Fatalf("bad transformed responses body: %s", serialized)
	}
}

func TestServeOneResponsesImageInputSendsOnlyModalitiesToControlPlane(t *testing.T) {
	bearer := "test-user-bearer"
	privateImageURL := "https://example.com/private-image.png"
	var authorizeBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			authorizeBody = string(body)
			if strings.Contains(authorizeBody, bearer) || strings.Contains(authorizeBody, privateImageURL) || strings.Contains(authorizeBody, "describe this") {
				t.Fatalf("authorize leaked request content: %s", authorizeBody)
			}
			if !strings.Contains(authorizeBody, `"input_modalities":["text","image"]`) {
				t.Fatalf("authorize did not include image modality: %s", authorizeBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_resp_img","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			if strings.Contains(string(body), privateImageURL) || strings.Contains(string(body), "describe this") {
				t.Fatalf("settle leaked request content: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_resp_img","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fakeStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/auto","input":[{"role":"user","content":[{"type":"input_text","text":"describe this"},{"type":"input_image","image_url":"https://example.com/private-image.png","detail":"low"}]}],"max_output_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if streamer.body == nil || len(streamer.body.Messages) != 1 {
		t.Fatalf("bad transformed body: %#v", streamer.body)
	}
	parts, ok := streamer.body.Messages[0].Content.([]types.ChatContentPart)
	if !ok || len(parts) != 2 || parts[1].ImageURL == nil || parts[1].ImageURL.URL != privateImageURL {
		t.Fatalf("image content was not preserved for provider path: %#v", streamer.body.Messages[0].Content)
	}
}

func TestServeOneChatNonStreamingReturnsJSONAndSettles(t *testing.T) {
	bearer := "test-user-bearer"
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			if strings.Contains(string(body), bearer) || strings.Contains(string(body), "private prompt") {
				t.Fatalf("authorize leaked sensitive material: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_chat","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, "Hello") || strings.Contains(settleBody, "private prompt") {
				t.Fatalf("settle leaked content: %s", settleBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_chat","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fakeStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"private prompt"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bodyBytes, &decoded); err != nil {
		t.Fatalf("decode response: %v body=%s", err, bodyBytes)
	}
	if decoded["object"] != "chat.completion" {
		t.Fatalf("bad chat envelope: %#v", decoded)
	}
	if !strings.Contains(string(bodyBytes), "Hello world") {
		t.Fatalf("missing output text: %s", bodyBytes)
	}
	deadline := time.Now().Add(time.Second)
	for settleBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(settleBody, `"route_type":"chat.completions"`) || !strings.Contains(settleBody, `"streamed":false`) {
		t.Fatalf("settle body missing chat metadata: %s", settleBody)
	}
}

func TestServeOneTrustedRouterRetriesFallbackCandidatesAndSettlesSelectedRoute(t *testing.T) {
	bearer := "test-user-bearer"
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			if strings.Contains(string(body), bearer) || strings.Contains(string(body), "private prompt") {
				t.Fatalf("authorize leaked sensitive material: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_auto","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[{"model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits"},{"model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, "private prompt") {
				t.Fatalf("settle leaked prompt: %s", settleBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_auto","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fallbackStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/auto","stream":false,"messages":[{"role":"user","content":"private prompt"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if len(streamer.attempts) != 2 {
		t.Fatalf("attempts = %#v, want two route candidates", streamer.attempts)
	}
	if streamer.attempts[0].Model != "anthropic/claude-3-5-sonnet" || streamer.attempts[1].Model != "openai/gpt-4o-mini" {
		t.Fatalf("bad fallback order: %#v", streamer.attempts)
	}
	if !strings.Contains(body, `"model":"openai/gpt-4o-mini"`) {
		t.Fatalf("response did not use selected fallback model: %s", body)
	}
	if !strings.Contains(settleBody, `"selected_model":"openai/gpt-4o-mini"`) ||
		!strings.Contains(settleBody, `"selected_endpoint":"openai/gpt-4o-mini@openai/prepaid"`) {
		t.Fatalf("settle did not bill selected fallback route: %s", settleBody)
	}
}

func TestServeOneTrustedRouterCustomModelPrependsHiddenPrompt(t *testing.T) {
	bearer := "test-user-bearer"
	const hiddenPrompt = "PRIVATE custom preamble"
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/resolve-custom-model":
			if strings.Contains(string(body), hiddenPrompt) || strings.Contains(string(body), "private user prompt") {
				t.Fatalf("resolve leaked prompt material: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1","route_type":"chat.completions","custom_model":{"id":"trustedrouter/user-8k3p2z","name":"Legal reviewer","base_model_id":"anthropic/claude-sonnet-4.6","hidden_prompt":"PRIVATE custom preamble","revision":3}}}`)
		case "/internal/gateway/authorize":
			if strings.Contains(string(body), hiddenPrompt) || strings.Contains(string(body), "private user prompt") {
				t.Fatalf("authorize leaked prompt material: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_custom","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-sonnet-4.6","endpoint_id":"anthropic/claude-sonnet-4.6@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","custom_model":{"id":"trustedrouter/user-8k3p2z","name":"Legal reviewer","base_model_id":"anthropic/claude-sonnet-4.6","hidden_prompt":"PRIVATE custom preamble","revision":3}}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, hiddenPrompt) || strings.Contains(settleBody, "private user prompt") {
				t.Fatalf("settle leaked prompt material: %s", settleBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_custom","cost_microdollars":12,"model":"anthropic/claude-sonnet-4.6","provider":"anthropic","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fakeStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/user-8k3p2z","stream":false,"messages":[{"role":"system","content":"caller system"},{"role":"user","content":"private user prompt"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"model":"trustedrouter/user-8k3p2z"`) {
		t.Fatalf("response did not preserve custom model id: %s", body)
	}
	if streamer.body == nil || !strings.HasPrefix(streamer.body.System, hiddenPrompt+"\n\ncaller system") {
		t.Fatalf("hidden prompt was not prepended before caller system: %#v", streamer.body)
	}
	deadline := time.Now().Add(time.Second)
	for settleBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(settleBody, `"selected_model":"anthropic/claude-sonnet-4.6"`) {
		t.Fatalf("settle did not bill base selected model: %s", settleBody)
	}
}

func TestResolveCustomModelForOrchestrationUsesBaseModelAndResponseOverride(t *testing.T) {
	bearer := "test-user-bearer"
	const hiddenPrompt = "PRIVATE orchestration preamble"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if r.URL.Path != "/internal/gateway/resolve-custom-model" {
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
		bodyText := string(body)
		if strings.Contains(bodyText, hiddenPrompt) || strings.Contains(bodyText, "private user prompt") {
			t.Fatalf("resolve leaked prompt material: %s", body)
		}
		if !strings.Contains(bodyText, `"model":"trustedrouter/user-socrates"`) {
			t.Fatalf("resolve did not identify custom model: %s", body)
		}
		_, _ = fmt.Fprint(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1","route_type":"chat.completions","custom_model":{"id":"trustedrouter/user-socrates","name":"Private Socrates","base_model_id":"trustedrouter/socrates-1.0","hidden_prompt":"PRIVATE orchestration preamble","revision":7}}}`)
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	req := &types.OpenAIChatRequest{
		Model: "trustedrouter/user-socrates",
		Messages: []types.OpenAIChatMessage{
			{Role: "user", Content: "private user prompt"},
		},
	}
	authz, err := maybeResolveCustomModelForOrchestration(context.Background(), req, trGateway, bearer, "chat.completions")
	if err != nil {
		t.Fatalf("resolve custom model: %v", err)
	}
	if authz == nil || authz.CustomModel == nil {
		t.Fatalf("missing custom model authz: %#v", authz)
	}
	if req.Model != "trustedrouter/socrates-1.0" {
		t.Fatalf("model = %q, want socrates base", req.Model)
	}
	if req.ResponseModel != "trustedrouter/user-socrates" {
		t.Fatalf("response model = %q", req.ResponseModel)
	}
	if len(req.Messages) < 2 || req.Messages[0].Role != "system" || req.Messages[0].Content != hiddenPrompt {
		t.Fatalf("hidden prompt was not prepended: %#v", req.Messages)
	}
}

func TestServeOneTrustedRouterFusionRunsPanelJudgeAndFinal(t *testing.T) {
	bearer := "test-user-bearer"
	privatePrompt := "private fusion prompt"
	var controlPlaneMu sync.Mutex
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(body), bearer) || strings.Contains(string(body), privatePrompt) {
			t.Fatalf("control-plane request leaked sensitive material: %s", body)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			controlPlaneMu.Lock()
			authorizeCalls = append(authorizeCalls, payload)
			authID := len(authorizeCalls)
			controlPlaneMu.Unlock()
			model := payload["model"].(string)
			endpoint := model + "@test/prepaid"
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", authID),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            endpoint,
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			controlPlaneMu.Lock()
			settleCalls = append(settleCalls, payload)
			settleID := len(settleCalls)
			controlPlaneMu.Unlock()
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", settleID),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
				"region":            "us-central1",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["google/gemini-3-flash-preview","moonshotai/kimi-k2.7-code"],"model":"z-ai/glm-5.2","max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"model":"trustedrouter/fusion"`) || !strings.Contains(body, "final answer from z-ai/glm-5.2") {
		t.Fatalf("fusion response did not use selectable judge/final model: %s", body)
	}
	var response map[string]any
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("decode fusion response: %v", err)
	}
	usage, ok := response["usage"].(map[string]any)
	if !ok {
		t.Fatalf("fusion response missing usage: %#v", response)
	}
	if usage["cost_microdollars"] != float64(4) {
		t.Fatalf("usage cost_microdollars = %#v, want total cost for four subcalls", usage["cost_microdollars"])
	}
	providerUsage, ok := usage["provider_usage"].(map[string]any)
	if !ok {
		t.Fatalf("usage missing provider_usage: %#v", usage)
	}
	if providerUsage["router"] != "trustedrouter/fusion" ||
		providerUsage["primitive"] != trustedRouterSynthModel ||
		providerUsage["selected_model"] != "z-ai/glm-5.2" ||
		providerUsage["panel_attempt_count"] != float64(2) ||
		providerUsage["judge_attempt_count"] != float64(1) ||
		providerUsage["final_attempt_count"] != float64(1) ||
		providerUsage["cost_microdollars"] != float64(4) {
		t.Fatalf("provider_usage summary = %#v", providerUsage)
	}
	panelUsage, ok := providerUsage["panel"].([]any)
	if !ok || len(panelUsage) != 2 {
		t.Fatalf("provider_usage panel = %#v", providerUsage["panel"])
	}
	firstPanelUsage := panelUsage[0].(map[string]any)
	if firstPanelUsage["route_type"] != "synth.panel" ||
		firstPanelUsage["model"] != "google/gemini-3-flash-preview" ||
		firstPanelUsage["cost_microdollars"] != float64(1) {
		t.Fatalf("bad provider_usage panel detail: %#v", firstPanelUsage)
	}
	for _, forbidden := range []string{"visible_answer", "raw_output", "thinking", "tool_calls", "aborted_thinking"} {
		if _, ok := firstPanelUsage[forbidden]; ok {
			t.Fatalf("provider_usage leaked %s: %#v", forbidden, firstPanelUsage)
		}
	}
	trusted, ok := response["trustedrouter"].(map[string]any)
	if !ok {
		t.Fatalf("fusion response missing trustedrouter details: %s", body)
	}
	synth, ok := trusted["synth"].(map[string]any)
	if !ok {
		t.Fatalf("fusion response missing trustedrouter.synth details: %#v", trusted)
	}
	if synth["cost_microdollars"] != float64(4) {
		t.Fatalf("synth cost_microdollars = %#v, want total cost for four subcalls", synth["cost_microdollars"])
	}
	panelDetails, ok := synth["panel"].([]any)
	if !ok || len(panelDetails) != 2 {
		t.Fatalf("fusion panel details = %#v, want two entries", synth["panel"])
	}
	firstPanel := panelDetails[0].(map[string]any)
	if firstPanel["model"] != "google/gemini-3-flash-preview" ||
		!strings.Contains(firstPanel["visible_answer"].(string), "analysis from google/gemini-3-flash-preview") {
		t.Fatalf("bad first panel detail: %#v", firstPanel)
	}
	if firstPanel["cost_microdollars"] != float64(1) {
		t.Fatalf("first panel cost_microdollars = %#v, want per-subcall cost", firstPanel["cost_microdollars"])
	}
	if strings.Contains(body, "<think>") || strings.Contains(body, "private fusion prompt") {
		t.Fatalf("fusion details leaked hidden thinking or original prompt: %s", body)
	}
	if len(authorizeCalls) != 4 {
		t.Fatalf("authorize calls = %d, want panel+panel+judge+final", len(authorizeCalls))
	}
	panelModels := map[string]bool{}
	for i := 0; i < 2; i++ {
		if authorizeCalls[i]["route_type"] != "fusion.panel" {
			t.Fatalf("authorize[%d] = %#v, want panel route", i, authorizeCalls[i])
		}
		panelModels[authorizeCalls[i]["model"].(string)] = true
	}
	for _, want := range []string{"google/gemini-3-flash-preview", "moonshotai/kimi-k2.7-code"} {
		if !panelModels[want] {
			t.Fatalf("panel authorize calls = %#v, missing %q", authorizeCalls[:2], want)
		}
	}
	if authorizeCalls[2]["model"] != "z-ai/glm-5.2" || authorizeCalls[2]["route_type"] != "fusion.judge" {
		t.Fatalf("authorize[2] = %#v, want judge", authorizeCalls[2])
	}
	if authorizeCalls[3]["model"] != "z-ai/glm-5.2" || authorizeCalls[3]["route_type"] != "fusion.final" {
		t.Fatalf("authorize[3] = %#v, want final", authorizeCalls[3])
	}
	if len(settleCalls) != 4 {
		t.Fatalf("settle calls = %d, want 4", len(settleCalls))
	}
	if len(streamer.calls) != 4 {
		t.Fatalf("provider calls = %#v, want 4", streamer.calls)
	}
	finalCall := streamer.calls[len(streamer.calls)-1]
	if !strings.Contains(finalCall.LastMessage, "Panel answers:") ||
		!strings.Contains(finalCall.LastMessage, "analysis from google/gemini-3-flash-preview") ||
		!strings.Contains(finalCall.LastMessage, "analysis from moonshotai/kimi-k2.7-code") ||
		!strings.Contains(finalCall.LastMessage, "Judge analysis JSON:") {
		t.Fatalf("final fusion prompt did not include panel evidence and judge analysis: %s", finalCall.LastMessage)
	}
}

func TestRunFusionPanelRunsMembersInParallel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       "auth_" + strings.ReplaceAll(model, "/", "_"),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     "gen_" + time.Now().Format("150405.000000000"),
				"cost_microdollars": 1,
				"provider":          "test",
				"region":            "us-central1",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{delay: 200 * time.Millisecond}
	req := &types.OpenAIChatRequest{
		Model:    "trustedrouter/synth",
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "compare"}},
	}
	config := fusionConfig{
		AnalysisModels:      []string{"model/a", "model/b", "model/c"},
		MaxCompletionTokens: 32,
	}

	started := time.Now()
	panel, err := runFusionPanel(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_parallel", "log_parallel")
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("runFusionPanel: %v", err)
	}
	if len(panel) != 3 {
		t.Fatalf("panel len = %d, want 3", len(panel))
	}
	for i, want := range []string{"model/a", "model/b", "model/c"} {
		if panel[i].Model != want {
			t.Fatalf("panel[%d].Model = %q, want %q; panel=%#v", i, panel[i].Model, want, panel)
		}
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("panel took %s; members appear to be serial instead of parallel", elapsed)
	}
}

func TestServeOneTrustedRouterSelectorReturnsSelectedPanelAnswerVerbatim(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()

	streamer := &fusionEchoLLM{textByModel: map[string]string{
		"model/a":        "first panel answer",
		"model/b":        "best panel answer",
		"model/selector": `{"selected_index":2,"rationale":"better answer"}`,
	}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/selector","stream":false,"messages":[{"role":"user","content":"choose the best"}],"tools":[{"type":"trustedrouter:selector","parameters":{"analysis_models":["model/a","model/b"],"selector_models":["model/selector"],"selector_prompt":"prefer answers with direct evidence","max_completion_tokens":64}}],"max_tokens":64}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	var response struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage         map[string]any            `json:"usage"`
		TrustedRouter map[string]map[string]any `json:"trustedrouter"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, bodyBytes)
	}
	if got := response.Choices[0].Message.Content; got != "best panel answer" {
		t.Fatalf("selector content = %q, want selected panel answer verbatim", got)
	}
	if response.Model != trustedRouterSelectorModel {
		t.Fatalf("model = %q, want %q", response.Model, trustedRouterSelectorModel)
	}
	if selector := response.TrustedRouter["selector"]; selector["mode"] != fusionModeSelector || int(selector["selected_index"].(float64)) != 2 {
		t.Fatalf("selector details = %#v", selector)
	}
	providerUsage, ok := response.Usage["provider_usage"].(map[string]any)
	if !ok {
		t.Fatalf("selector usage missing provider_usage: %#v", response.Usage)
	}
	if providerUsage["router"] != trustedRouterSelectorModel ||
		providerUsage["primitive"] != trustedRouterSelectorModel ||
		providerUsage["selected_model"] != "model/b" ||
		providerUsage["selector_attempt_count"] != float64(1) {
		t.Fatalf("selector provider_usage = %#v", providerUsage)
	}

	recorder.mu.Lock()
	authorizeCalls := append([]map[string]any{}, recorder.authorize...)
	settleCalls := append([]map[string]any{}, recorder.settle...)
	recorder.mu.Unlock()
	var authorizedModels []string
	for _, call := range authorizeCalls {
		if model, _ := call["model"].(string); model != "" {
			authorizedModels = append(authorizedModels, model)
		}
	}
	sort.Strings(authorizedModels)
	if got, want := strings.Join(authorizedModels, ","), "model/a,model/b,model/selector"; got != want {
		t.Fatalf("authorized models = %s, want %s", got, want)
	}
	if len(settleCalls) != 3 {
		t.Fatalf("settle calls = %d, want panel a + panel b + selector", len(settleCalls))
	}

	streamer.mu.Lock()
	calls := append([]fusionEchoCall{}, streamer.calls...)
	streamer.mu.Unlock()
	var selectorCall fusionEchoCall
	for _, call := range calls {
		if call.Model == "model/selector" {
			selectorCall = call
		}
	}
	if !strings.Contains(selectorCall.SystemMessage, "prefer answers with direct evidence") {
		t.Fatalf("selector prompt was not passed to selector system prompt: %q", selectorCall.SystemMessage)
	}
}

func TestServeOneTrustedRouterMapReduceRunsPartsInParallelAndUsesStagePrompts(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()

	streamer := &fusionEchoLLM{
		textByModel: map[string]string{
			"model/mapper":  `{"parts":[{"title":"Alpha","prompt":"Part Alpha"},{"title":"Beta","prompt":"Part Beta"},{"title":"Gamma","prompt":"Part Gamma"}]}`,
			"model/reducer": "combined final answer",
		},
		textByLastMessageContains: map[string]string{
			"Part Alpha": "alpha result",
			"Part Beta":  "beta result",
			"Part Gamma": "gamma result",
		},
		delayByModel: map[string]time.Duration{"model/parallel": 200 * time.Millisecond},
	}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/mapreduce","stream":false,"messages":[{"role":"user","content":"solve a multi-part problem"}],"tools":[{"type":"trustedrouter:mapreduce","parameters":{"mapper_models":["model/mapper"],"parallel_models":["model/parallel"],"reducer_models":["model/reducer"],"max_parts":3,"mapper_prompt":"split into exactly three parts","parallel_prompt":"answer with concise evidence","reducer_prompt":"merge without duplication","max_completion_tokens":64}}],"max_tokens":64}`)
	started := time.Now()
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	elapsed := time.Since(started)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("mapreduce took %s; parallel parts appear to be serial", elapsed)
	}
	var response struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage         map[string]any            `json:"usage"`
		TrustedRouter map[string]map[string]any `json:"trustedrouter"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, bodyBytes)
	}
	if got := response.Choices[0].Message.Content; got != "combined final answer" {
		t.Fatalf("mapreduce content = %q", got)
	}
	if response.Model != trustedRouterMapReduceModel {
		t.Fatalf("model = %q, want %q", response.Model, trustedRouterMapReduceModel)
	}
	if mapreduce := response.TrustedRouter["mapreduce"]; mapreduce["mode"] != fusionModeMapReduce {
		t.Fatalf("mapreduce details = %#v", mapreduce)
	}
	providerUsage, ok := response.Usage["provider_usage"].(map[string]any)
	if !ok {
		t.Fatalf("mapreduce usage missing provider_usage: %#v", response.Usage)
	}
	if providerUsage["router"] != trustedRouterMapReduceModel ||
		providerUsage["primitive"] != trustedRouterMapReduceModel ||
		providerUsage["selected_model"] != "model/reducer" ||
		providerUsage["mapper_attempt_count"] != float64(1) ||
		providerUsage["part_attempt_count"] != float64(3) ||
		providerUsage["reducer_attempt_count"] != float64(1) {
		t.Fatalf("mapreduce provider_usage = %#v", providerUsage)
	}

	recorder.mu.Lock()
	settleCalls := append([]map[string]any{}, recorder.settle...)
	recorder.mu.Unlock()
	if len(settleCalls) != 5 {
		t.Fatalf("settle calls = %d, want mapper + 3 parts + reducer", len(settleCalls))
	}

	streamer.mu.Lock()
	calls := append([]fusionEchoCall{}, streamer.calls...)
	streamer.mu.Unlock()
	var mapperSeen, reducerSeen bool
	var parallelSeen int
	for _, call := range calls {
		switch call.Model {
		case "model/mapper":
			mapperSeen = strings.Contains(call.SystemMessage, "split into exactly three parts")
		case "model/parallel":
			if strings.Contains(call.SystemMessage, "answer with concise evidence") {
				parallelSeen++
			}
		case "model/reducer":
			reducerSeen = strings.Contains(call.LastMessage, "merge without duplication") &&
				strings.Contains(call.LastMessage, "alpha result") &&
				strings.Contains(call.LastMessage, "beta result") &&
				strings.Contains(call.LastMessage, "gamma result")
		}
	}
	if !mapperSeen || parallelSeen != 3 || !reducerSeen {
		t.Fatalf("stage prompt/call coverage mapper=%v parallel=%d reducer=%v calls=%#v", mapperSeen, parallelSeen, reducerSeen, calls)
	}
}

func TestSelectorInvalidChoiceRefundsAndFallsBackToNextSelectorModel(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()

	streamer := &fusionEchoLLM{textByModel: map[string]string{
		"model/selector-bad":  `{"selected_index":9}`,
		"model/selector-good": `{"selected_index":1}`,
	}}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSelectorModel,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "choose"}},
	}
	panel := []fusionCallResult{{
		Model: "model/panel",
		Result: adapter.StreamResult{
			Text:         "panel answer",
			FinishReason: "end_turn",
		},
	}}
	selected, attempts, decision, err := runSelectorDecision(
		context.Background(),
		streamer,
		req,
		fusionConfig{SelectorModels: []string{"model/selector-bad", "model/selector-good"}},
		[]string{"model/selector-bad", "model/selector-good"},
		panel,
		trGateway,
		nil,
		"bearer",
		"req_selector_fallback",
		"log_selector_fallback",
	)
	if err != nil {
		t.Fatalf("runSelectorDecision: %v", err)
	}
	if selected.Result.Text != "panel answer" || decision.SelectedIndex != 1 || len(attempts) != 1 {
		t.Fatalf("selected=%#v attempts=%d decision=%#v", selected, len(attempts), decision)
	}
	recorder.mu.Lock()
	authorizeCalls := len(recorder.authorize)
	settleCalls := len(recorder.settle)
	refundCalls := len(recorder.refund)
	recorder.mu.Unlock()
	if authorizeCalls != 2 || refundCalls != 1 || settleCalls != 1 {
		t.Fatalf("authorize/refund/settle = %d/%d/%d, want 2/1/1", authorizeCalls, refundCalls, settleCalls)
	}
}

func TestMapReduceMapperRejectsTooManyPartsBeforeSettlement(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()

	var parts []string
	for i := 0; i < 9; i++ {
		parts = append(parts, fmt.Sprintf(`{"title":"Part %d","prompt":"Do part %d"}`, i+1, i+1))
	}
	streamer := &fusionEchoLLM{textByModel: map[string]string{
		"model/mapper": `{"parts":[` + strings.Join(parts, ",") + `]}`,
	}}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterMapReduceModel,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "split"}},
	}
	_, attempts, _, err := runMapReduceMapper(
		context.Background(),
		streamer,
		req,
		fusionConfig{MapperModels: []string{"model/mapper"}, MaxParts: maxMapReduceParts},
		trGateway,
		nil,
		"bearer",
		"req_mapreduce_too_many",
		"log_mapreduce_too_many",
	)
	if err == nil {
		t.Fatalf("runMapReduceMapper unexpectedly succeeded")
	}
	if len(attempts) != 0 {
		t.Fatalf("mapper attempts = %d, want 0 settled attempts for invalid plan", len(attempts))
	}
	recorder.mu.Lock()
	authorizeCalls := len(recorder.authorize)
	settleCalls := len(recorder.settle)
	refundCalls := len(recorder.refund)
	recorder.mu.Unlock()
	if authorizeCalls != 1 || refundCalls != 1 || settleCalls != 0 {
		t.Fatalf("authorize/refund/settle = %d/%d/%d, want 1/1/0", authorizeCalls, refundCalls, settleCalls)
	}
}

func TestServeOneTrustedRouterFusionStripsThinkFromFinalChatContent(t *testing.T) {
	bearer := "test-user-bearer"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       "auth_" + strings.ReplaceAll(model, "/", "_"),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     "gen_fusion_json",
				"cost_microdollars": 1,
				"provider":          "test",
				"region":            "us-central1",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{textByModel: map[string]string{
		"model/final": "<think>private</think>\n{\"ok\":true,\"answer\":\"ready\"}",
	}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/synth","stream":false,"messages":[{"role":"user","content":"Return JSON only."}],"tools":[{"type":"trustedrouter:synth","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge"],"final_models":["model/final"],"selection_strategy":"synthesize_non_refusals","max_completion_tokens":64}}],"max_tokens":64}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		TrustedRouter map[string]any `json:"trustedrouter"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, bodyBytes)
	}
	if len(response.Choices) != 1 {
		t.Fatalf("choices = %#v, want one", response.Choices)
	}
	content := response.Choices[0].Message.Content
	if !strings.HasPrefix(content, "{") {
		t.Fatalf("content = %q, want machine-parseable JSON at start", content)
	}
	if strings.Contains(strings.ToLower(content), "<think>") || strings.Contains(content, "private") {
		t.Fatalf("content leaked thinking: %q", content)
	}
	if response.TrustedRouter == nil || !strings.Contains(string(bodyBytes), `\u003cthink\u003eprivate\u003c/think\u003e`) {
		t.Fatalf("response did not preserve raw Synth details: %s", bodyBytes)
	}
}

func TestServeOneTrustedRouterFusionStreamsThinkingEvents(t *testing.T) {
	bearer := "test-user-bearer"
	var settleCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id": fmt.Sprintf("auth_fusion_stream_%s", strings.ReplaceAll(model, "/", "_")),
				"workspace_id":     "ws_1",
				"api_key_hash":     "key_1",
				"model":            model,
				"endpoint_id":      model + "@test/prepaid",
				"provider":         "test",
				"usage_type":       "Credits",
				"limit_usage_type": "Credits",
				"route_candidates": []any{},
			}})
		case "/internal/gateway/settle":
			settleCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_stream_%d", settleCalls),
				"cost_microdollars": 1,
				"provider":          "test",
				"region":            "us-central1",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{thinking: true}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/synth","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"compare options"}],"tools":[{"type":"trustedrouter:synth","parameters":{"analysis_models":["minimax/minimax-m3"],"judge_models":["moonshotai/kimi-k2.6"],"final_models":["z-ai/glm-5.2"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	for _, want := range []string{
		`"event":"panel.thinking_delta"`,
		`"event":"judge.thinking_delta"`,
		`"event":"final.thinking_delta"`,
		`"reasoning_content":"thinking from z-ai/glm-5.2"`,
		`"event":"final.done"`,
		`"cost_microdollars":3`,
		`"usage"`,
		"data: [DONE]\n\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %q: %s", want, body)
		}
	}
	if got, _ := fusionStreamVisibleAndReasoning(t, body); got != "final answer from z-ai/glm-5.2" {
		t.Fatalf("visible final stream content = %q", got)
	}
	if settleCalls != 3 {
		t.Fatalf("settle calls = %d, want panel+judge+final", settleCalls)
	}
}

func TestServeOneTrustedRouterFusionStreamingStripsLiteralThinkFromContent(t *testing.T) {
	bearer := "test-user-bearer"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       "auth_stream_" + strings.ReplaceAll(model, "/", "_"),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     "gen_fusion_stream_json",
				"cost_microdollars": 1,
				"provider":          "test",
				"region":            "us-central1",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{textByModel: map[string]string{
		"model/final": "<think>private</think>\n{\"ok\":true,\"answer\":\"ready\"}",
	}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/synth","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Return JSON only."}],"tools":[{"type":"trustedrouter:synth","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge"],"final_models":["model/final"],"selection_strategy":"synthesize_non_refusals","max_completion_tokens":64}}],"max_tokens":64}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}

	visible, reasoning := fusionStreamVisibleAndReasoning(t, body)
	if got := visible; got != `{"ok":true,"answer":"ready"}` {
		t.Fatalf("visible stream content = %q", got)
	}
	if got := reasoning; !strings.Contains(got, "private") {
		t.Fatalf("reasoning stream content = %q, want private", got)
	}
	if !strings.Contains(body, `\u003cthink\u003eprivate\u003c/think\u003e`) || !strings.Contains(body, `"event":"final.done"`) {
		t.Fatalf("stream did not preserve raw final details: %s", body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("stream missing DONE: %s", body)
	}
}

func fusionStreamVisibleAndReasoning(t *testing.T, body string) (string, string) {
	t.Helper()
	var visible strings.Builder
	var reasoning strings.Builder
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatalf("decode SSE JSON %q: %v", line, err)
		}
		if trusted, _ := event["trustedrouter"].(map[string]any); trusted != nil {
			if synth, _ := trusted["synth"].(map[string]any); synth != nil {
				if name, _ := synth["event"].(string); name == "final.text_delta" {
					text, _ := synth["text"].(string)
					if strings.Contains(strings.ToLower(text), "<think>") || strings.Contains(text, "private") {
						t.Fatalf("trustedrouter final text event leaked thinking: %q in %s", text, body)
					}
				}
			}
		}
		choices, _ := event["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if content, _ := delta["content"].(string); content != "" {
			if strings.Contains(strings.ToLower(content), "<think>") || strings.Contains(content, "private") {
				t.Fatalf("stream content leaked thinking: %q in %s", content, body)
			}
			visible.WriteString(content)
		}
		if thought, _ := delta["reasoning_content"].(string); thought != "" {
			reasoning.WriteString(thought)
		}
	}
	return visible.String(), reasoning.String()
}

func TestServeOneFusionCodeRoutesCodeKimiInPanelAndJudge(t *testing.T) {
	// End-to-end (mocked upstream + gateway, no real API calls): a
	// trustedrouter/fusion-code request uses the DEFAULT panel + judge, so the
	// kimi-k2.6 -> kimi-k2.7-code swap must show up in the authorize calls for
	// the panel and the judge, and the general Kimi must never be authorized.
	var controlPlaneMu sync.Mutex
	var authorizeCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			controlPlaneMu.Lock()
			authorizeCalls = append(authorizeCalls, payload)
			controlPlaneMu.Unlock()
			model, _ := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       "auth_" + model,
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     "gen",
				"cost_microdollars": 1,
				"model":             payload["selected_model"],
				"provider":          "test",
				"region":            "us-central1",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion-code","stream":false,"messages":[{"role":"user","content":"hi"}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody), requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var codeKimiPanel, codeKimiJudge bool
	for _, c := range authorizeCalls {
		model, _ := c["model"].(string)
		route, _ := c["route_type"].(string)
		if model == fusionGeneralKimi {
			t.Fatalf("fusion-code authorized the general Kimi %q (route %q); swap did not apply", model, route)
		}
		if model == fusionCodeKimi && route == "fusion.panel" {
			codeKimiPanel = true
		}
		if model == fusionCodeKimi && route == "fusion.judge" {
			codeKimiJudge = true
		}
	}
	if !codeKimiPanel || !codeKimiJudge {
		t.Fatalf("fusion-code must route %s in panel AND judge; authorize calls: %#v", fusionCodeKimi, authorizeCalls)
	}
}

func TestServeOneTrustedRouterFusionSynthesizesOnlyNonRefusals(t *testing.T) {
	bearer := "test-user-bearer"
	var controlPlaneMu sync.Mutex
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			controlPlaneMu.Lock()
			authorizeCalls = append(authorizeCalls, payload)
			authID := len(authorizeCalls)
			controlPlaneMu.Unlock()
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", authID),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			controlPlaneMu.Lock()
			settleCalls = append(settleCalls, payload)
			settleID := len(settleCalls)
			controlPlaneMu.Unlock()
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", settleID),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{refusalModels: map[string]bool{"model/refuses": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/refuses","model/answers"],"model":"model/final","type":"synthesize_non_refusals","max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "final answer from model/final") {
		t.Fatalf("fusion did not synthesize final answer: %s", body)
	}
	if len(authorizeCalls) != 4 || len(settleCalls) != 4 {
		t.Fatalf("calls authorize=%d settle=%d, want panel+panel+judge+final", len(authorizeCalls), len(settleCalls))
	}
	if len(streamer.calls) != 4 {
		t.Fatalf("provider calls = %#v, want 4", streamer.calls)
	}
	judgeCall := streamer.calls[2]
	finalCall := streamer.calls[3]
	for _, prompt := range []string{judgeCall.LastMessage, finalCall.LastMessage} {
		if strings.Contains(prompt, "model/refuses") || strings.Contains(prompt, "I'm sorry, but I can't help with that.") {
			t.Fatalf("synthesis prompt included refusal evidence: %s", prompt)
		}
		if !strings.Contains(prompt, "model/answers") || !strings.Contains(prompt, "analysis from model/answers") {
			t.Fatalf("synthesis prompt omitted non-refusal evidence: %s", prompt)
		}
	}
}

func TestServeOneTrustedRouterFusionFallsBackAcrossJudgeModels(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	var refundCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			settleCalls = append(settleCalls, payload)
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", len(settleCalls)),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		case "/internal/gateway/refund":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode refund payload: %v", err)
			}
			refundCalls = append(refundCalls, payload)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{
		textByModel:   map[string]string{"model/judge-empty": ""},
		refusalModels: map[string]bool{"model/judge-refuses": true},
	}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"model":"model/final","fallback_judges":["model/judge-empty","model/judge-refuses","model/judge-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "final answer from model/final") {
		t.Fatalf("fusion did not synthesize final answer: %s", body)
	}
	if len(authorizeCalls) != 5 {
		t.Fatalf("authorize calls = %d, want panel+3 judges+final", len(authorizeCalls))
	}
	if len(settleCalls) != 5 {
		t.Fatalf("settle calls = %d, want panel+empty judge+refusal judge+good judge+final", len(settleCalls))
	}
	if len(refundCalls) != 0 {
		t.Fatalf("refund calls = %d, want none because empty/refusal judges settled before model fallback", len(refundCalls))
	}
	wantRoutes := []string{"fusion.panel", "fusion.judge", "fusion.judge", "fusion.judge", "fusion.final"}
	for i, want := range wantRoutes {
		if got, _ := authorizeCalls[i]["route_type"].(string); got != want {
			t.Fatalf("authorize[%d].route_type = %q, want %q", i, got, want)
		}
	}
	if len(streamer.calls) != 5 {
		t.Fatalf("provider calls = %#v, want panel+empty judge+refusal judge+good judge+final", streamer.calls)
	}
	gotModels := []string{}
	for _, call := range streamer.calls {
		gotModels = append(gotModels, call.Model)
	}
	wantModels := []string{"model/panel", "model/judge-empty", "model/judge-refuses", "model/judge-good", "model/final"}
	if strings.Join(gotModels, ",") != strings.Join(wantModels, ",") {
		t.Fatalf("provider models = %#v, want %#v", gotModels, wantModels)
	}
	finalPrompt := streamer.calls[len(streamer.calls)-1].LastMessage
	if !strings.Contains(finalPrompt, "analysis from model/judge-good") {
		t.Fatalf("final prompt did not use successful judge analysis: %s", finalPrompt)
	}
	if strings.Contains(finalPrompt, "model/judge-empty") || strings.Contains(finalPrompt, "model/judge-refuses") || strings.Contains(finalPrompt, "I'm sorry, but I can't help with that.") {
		t.Fatalf("final prompt included rejected judge output: %s", finalPrompt)
	}
}

func TestServeOneTrustedRouterFusionDoesNotUseJudgeModelFallbackOnProviderError(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	var refundCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			settleCalls = append(settleCalls, payload)
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", len(settleCalls)),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		case "/internal/gateway/refund":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode refund payload: %v", err)
			}
			refundCalls = append(refundCalls, payload)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{failModels: map[string]bool{"model/judge-fails": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"model":"model/final","fallback_judges":["model/judge-fails","model/judge-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%s; provider failure must not consume fallback judge model", resp.StatusCode, body)
	}
	if len(authorizeCalls) != 2 {
		t.Fatalf("authorize calls = %d, want panel+failed judge only", len(authorizeCalls))
	}
	if len(settleCalls) != 1 {
		t.Fatalf("settle calls = %d, want only successful panel settled", len(settleCalls))
	}
	if len(refundCalls) != 1 {
		t.Fatalf("refund calls = %d, want failed judge hold refunded", len(refundCalls))
	}
	for _, call := range streamer.calls {
		if call.Model == "model/judge-good" || call.Model == "model/final" {
			t.Fatalf("provider fallback model was called after judge provider error: %#v", streamer.calls)
		}
	}
}

func TestServeOneTrustedRouterFusionRetriesSameModelProvidersBeforeModelFallbacks(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			provider := "test"
			candidates := []any{}
			switch model {
			case "model/judge-glm":
				provider = "badjudge"
				candidates = []any{
					map[string]any{"model": model, "endpoint_id": model + "@badjudge/prepaid", "provider": "badjudge", "usage_type": "Credits"},
					map[string]any{"model": model, "endpoint_id": model + "@goodjudge/prepaid", "provider": "goodjudge", "usage_type": "Credits"},
				}
			case "model/final-glm":
				provider = "badfinal"
				candidates = []any{
					map[string]any{"model": model, "endpoint_id": model + "@badfinal/prepaid", "provider": "badfinal", "usage_type": "Credits"},
					map[string]any{"model": model, "endpoint_id": model + "@goodfinal/prepaid", "provider": "goodfinal", "usage_type": "Credits"},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@" + provider + "/prepaid",
				"provider":               provider,
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       candidates,
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			settleCalls = append(settleCalls, payload)
			model, _ := payload["selected_model"].(string)
			provider, _ := payload["selected_provider"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", len(settleCalls)),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          provider,
			}})
		case "/internal/gateway/refund":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{failProviders: map[string]bool{"badjudge": true, "badfinal": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge-glm","model/judge-m3"],"final_models":["model/final-glm","model/final-m3"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "final answer from model/final-glm") {
		t.Fatalf("did not stay on the requested final model after provider fallback: %s", body)
	}
	for _, call := range authorizeCalls {
		model, _ := call["model"].(string)
		if model == "model/judge-m3" || model == "model/final-m3" {
			t.Fatalf("authorized model fallback even though same-model provider fallback succeeded: %#v", authorizeCalls)
		}
	}
	got := []string{}
	for _, call := range streamer.calls {
		got = append(got, call.Model+"@"+call.Provider)
	}
	wantContains := []string{
		"model/judge-glm@badjudge",
		"model/judge-glm@goodjudge",
		"model/final-glm@badfinal",
		"model/final-glm@goodfinal",
	}
	joined := strings.Join(got, ",")
	for _, want := range wantContains {
		if !strings.Contains(joined, want) {
			t.Fatalf("provider calls = %#v, missing %s", got, want)
		}
	}
	if len(settleCalls) == 0 || !strings.Contains(fmt.Sprint(settleCalls), "model/final-glm@goodfinal/prepaid") {
		t.Fatalf("settlement did not record selected same-model provider route: %#v", settleCalls)
	}
}

func TestServeOneTrustedRouterFusionJudgeRateLimitUsesFallbackJudgeImmediately(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			provider := "test"
			if model == "model/judge-429" {
				provider = "badjudge"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@" + provider + "/prepaid",
				"provider":               provider,
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			model, _ := payload["selected_model"].(string)
			provider, _ := payload["selected_provider"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     "gen_fusion",
				"cost_microdollars": 1,
				"model":             model,
				"provider":          provider,
			}})
		case "/internal/gateway/refund":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{failProviders: map[string]bool{"badjudge": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge-429","model/judge-good"],"final_models":["model/final"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(bodyBytes))
	}
	var badJudgeCalls, goodJudgeCalls int
	for _, call := range streamer.calls {
		switch {
		case call.Provider == "badjudge":
			badJudgeCalls++
		case call.Model == "model/judge-good":
			goodJudgeCalls++
		}
	}
	if badJudgeCalls != 1 || goodJudgeCalls != 1 {
		t.Fatalf("badjudge calls=%d good judge calls=%d all=%#v, want immediate one-shot 429 fallback", badJudgeCalls, goodJudgeCalls, streamer.calls)
	}
}

func TestServeOneTrustedRouterFusionFinalRateLimitUsesFallbackFinalImmediately(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			provider := "test"
			if model == "model/final-429" {
				provider = "badfinal"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@" + provider + "/prepaid",
				"provider":               provider,
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			model, _ := payload["selected_model"].(string)
			provider, _ := payload["selected_provider"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     "gen_fusion",
				"cost_microdollars": 1,
				"model":             model,
				"provider":          provider,
			}})
		case "/internal/gateway/refund":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{failProviders: map[string]bool{"badfinal": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge-good"],"final_models":["model/final-429","model/final-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "final answer from model/final-good") {
		t.Fatalf("body did not use fallback final: %s", body)
	}
	var badFinalCalls, goodFinalCalls int
	for _, call := range streamer.calls {
		switch {
		case call.Provider == "badfinal":
			badFinalCalls++
		case call.Model == "model/final-good":
			goodFinalCalls++
		}
	}
	if badFinalCalls != 1 || goodFinalCalls != 1 {
		t.Fatalf("badfinal calls=%d good final calls=%d all=%#v, want immediate one-shot 429 fallback", badFinalCalls, goodFinalCalls, streamer.calls)
	}
}

func TestServeOneTrustedRouterFusionFallsBackAcrossFinalModels(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	var refundCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			settleCalls = append(settleCalls, payload)
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", len(settleCalls)),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		case "/internal/gateway/refund":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode refund payload: %v", err)
			}
			refundCalls = append(refundCalls, payload)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{
		textByModel:   map[string]string{"model/final-empty": ""},
		refusalModels: map[string]bool{"model/final-refuses": true},
	}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge-good"],"final_models":["model/final-empty","model/final-refuses","model/final-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "final answer from model/final-good") {
		t.Fatalf("fusion did not use fallback final model: %s", body)
	}
	if strings.Contains(body, "model/final-refuses") {
		t.Fatalf("response leaked refused final model: %s", body)
	}
	if len(authorizeCalls) != 5 {
		t.Fatalf("authorize calls = %d, want panel+judge+3 finals", len(authorizeCalls))
	}
	if len(settleCalls) != 3 {
		t.Fatalf("settle calls = %d, want panel+judge+winning final", len(settleCalls))
	}
	if len(refundCalls) != 2 {
		t.Fatalf("refund calls = %d, want failed final+refused final refunds", len(refundCalls))
	}
	gotModels := []string{}
	for _, call := range streamer.calls {
		gotModels = append(gotModels, call.Model)
	}
	wantModels := []string{
		"model/panel",
		"model/judge-good",
		"model/final-empty",
		"model/final-refuses",
		"model/final-good",
	}
	if strings.Join(gotModels, ",") != strings.Join(wantModels, ",") {
		t.Fatalf("provider models = %#v, want %#v", gotModels, wantModels)
	}
}

func TestServeOneTrustedRouterFusionDoesNotUseFinalModelFallbackOnProviderError(t *testing.T) {
	bearer := "test-user-bearer"
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	var refundCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			settleCalls = append(settleCalls, payload)
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", len(settleCalls)),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		case "/internal/gateway/refund":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode refund payload: %v", err)
			}
			refundCalls = append(refundCalls, payload)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{failModels: map[string]bool{"model/final-fails": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge-good"],"final_models":["model/final-fails","model/final-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%s; provider failure must not consume fallback final model", resp.StatusCode, body)
	}
	if len(authorizeCalls) != 3 {
		t.Fatalf("authorize calls = %d, want panel+judge+failed final only", len(authorizeCalls))
	}
	if len(settleCalls) != 2 {
		t.Fatalf("settle calls = %d, want panel+judge only", len(settleCalls))
	}
	if len(refundCalls) != 1 {
		t.Fatalf("refund calls = %d, want failed final hold refunded", len(refundCalls))
	}
	for _, call := range streamer.calls {
		if call.Model == "model/final-good" {
			t.Fatalf("final fallback model was called after provider error: %#v", streamer.calls)
		}
	}
}

func TestServeOneTrustedRouterFusionContinuesAfterOnePanelFails(t *testing.T) {
	bearer := "test-user-bearer"
	var controlPlaneMu sync.Mutex
	var authorizeCalls []map[string]any
	var settleCalls []map[string]any
	var refundCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			controlPlaneMu.Lock()
			authorizeCalls = append(authorizeCalls, payload)
			authID := len(authorizeCalls)
			controlPlaneMu.Unlock()
			model := payload["model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", authID),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			controlPlaneMu.Lock()
			settleCalls = append(settleCalls, payload)
			settleID := len(settleCalls)
			controlPlaneMu.Unlock()
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", settleID),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		case "/internal/gateway/refund":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode refund payload: %v", err)
			}
			controlPlaneMu.Lock()
			refundCalls = append(refundCalls, payload)
			controlPlaneMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fusionEchoLLM{failModels: map[string]bool{"openai/gpt-5.5": true}}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["openai/gpt-5.5","moonshotai/kimi-k2.7-code"],"model":"z-ai/glm-5.2","max_completion_tokens":64}}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "final answer from z-ai/glm-5.2") {
		t.Fatalf("fusion did not continue to judge/final after failed panel: %s", body)
	}
	if len(refundCalls) != 1 {
		t.Fatalf("refund calls = %d, want failed panel refund", len(refundCalls))
	}
	if len(settleCalls) != 3 {
		t.Fatalf("settle calls = %d, want successful panel+judge+final", len(settleCalls))
	}
	if len(authorizeCalls) != 4 {
		t.Fatalf("authorize calls = %d, want failed panel+successful panel+judge+final", len(authorizeCalls))
	}
}

func TestServeOneTrustedRouterFusionRejectsUnsupportedExtensionToolNamespaces(t *testing.T) {
	bearer := "test-user-bearer"
	for _, toolType := range []string{"openrouter:fusion", "trustedrouter:exa"} {
		t.Run(toolType, func(t *testing.T) {
			var authorizeCalled bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authorizeCalled = true
				t.Fatalf("control plane should not be called for rejected tool namespace")
			}))
			defer server.Close()

			trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
			serverConn, client := net.Pipe()
			defer client.Close()
			go serveOne(context.Background(), serverConn, auth.New(nil), &panicStreamingLLM{t: t}, nil, nil, trGateway, nil)

			requestBody := []byte(fmt.Sprintf(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private prompt"}],"tools":[{"type":%q,"parameters":{"analysis_models":["google/gemini-3-flash-preview"]}}]}`, toolType))
			if _, err := fmt.Fprintf(
				client,
				"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				bearer,
				len(requestBody),
				requestBody,
			); err != nil {
				t.Fatalf("write request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			body := string(bodyBytes)
			if resp.StatusCode != 501 {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
			if !strings.Contains(body, "not_supported_in_alpha") || strings.Contains(body, "private prompt") {
				t.Fatalf("bad namespace rejection body: %s", body)
			}
			if authorizeCalled {
				t.Fatal("authorize was called")
			}
		})
	}
}

func TestFusionVisibleAnswerStripsThinkBlocks(t *testing.T) {
	got := fusionVisibleAnswer("prefix <think>private reasoning</think> visible <THINK>more</THINK> answer")
	if got != "prefix  visible  answer" {
		t.Fatalf("fusionVisibleAnswer = %q", got)
	}
	if got := fusionVisibleAnswer("<think>private only</think>"); got != "" {
		t.Fatalf("think-only output = %q, want empty", got)
	}
	if got := fusionVisibleAnswer("visible <think>unterminated"); got != "visible" {
		t.Fatalf("unterminated think output = %q, want visible", got)
	}
}

func TestFusionVisibleStreamFilterStripsThinkBlocksAcrossChunks(t *testing.T) {
	var content []string
	var thinking []string
	filter := newFusionVisibleStreamFilter(
		func(text string) { content = append(content, text) },
		func(text string) { thinking = append(thinking, text) },
	)
	for _, chunk := range []string{"<thi", "nk>pri", "vate</thi", "nk>\n{\"ok\":", "true}"} {
		filter.Write(chunk)
	}
	filter.Flush()
	if got := strings.Join(content, ""); got != `{"ok":true}` {
		t.Fatalf("content = %q, want JSON without thinking preface", got)
	}
	if got := strings.Join(thinking, ""); got != "private" {
		t.Fatalf("thinking = %q, want private", got)
	}
}

func TestFusionCallDetailsIncludesRawThinkingWhenProviderReturnsIt(t *testing.T) {
	detail := fusionCallDetails(fusionCallResult{
		Model: "z-ai/glm-5.2",
		Result: adapter.StreamResult{
			Text:         "visible answer",
			FinishReason: "stop",
			Thinking: []adapter.ThinkingBlock{{
				Text:      "raw thinking block",
				Signature: "sig_123",
			}},
		},
		RawText:      "<think>raw thinking block</think>\nvisible answer",
		InputTokens:  11,
		OutputTokens: 7,
		ElapsedMS:    1234,
	})
	if detail["visible_answer"] != "visible answer" {
		t.Fatalf("visible_answer = %#v", detail["visible_answer"])
	}
	if detail["elapsed_ms"] != int64(1234) {
		t.Fatalf("elapsed_ms = %#v, want 1234", detail["elapsed_ms"])
	}
	if raw := detail["raw_output"].(string); !strings.Contains(raw, "<think>raw thinking block</think>") {
		t.Fatalf("raw_output = %q, want raw think block", raw)
	}
	thinking, ok := detail["thinking"].([]map[string]any)
	if !ok || len(thinking) != 1 {
		t.Fatalf("thinking = %#v, want one raw thinking block", detail["thinking"])
	}
	if thinking[0]["text"] != "raw thinking block" || thinking[0]["signature"] != "sig_123" {
		t.Fatalf("thinking block = %#v", thinking[0])
	}
}

func TestFusionOverthinkingConfigRequiresSynthCode(t *testing.T) {
	if got := fusionOverthinkingConfig("z-ai/glm-5.2", "fusion.panel", true, false); got.enabled {
		t.Fatalf("plain trustedrouter/synth armed overthinking breaker: %#v", got)
	}
	if got := fusionOverthinkingConfig("z-ai/glm-5.2", "fusion.final", true, false); got.enabled {
		t.Fatalf("plain trustedrouter/synth armed final overthinking breaker: %#v", got)
	}
	if got := fusionOverthinkingConfig("z-ai/glm-5.2", "fusion.panel", true, true); !got.enabled || got.thresholdTokens != fusionPanelThinkingTokenBudget {
		t.Fatalf("synth-code panel breaker = %#v, want enabled panel budget", got)
	}
	if got := fusionOverthinkingConfig("z-ai/glm-5.2", "fusion.judge", true, true); got.enabled {
		t.Fatalf("judge should never arm overthinking breaker: %#v", got)
	}
}

func TestFusionCodePanelGLMOverthinkingRunsSameModelRescue(t *testing.T) {
	trGateway, recorder, closeServer := newFusionGatewayRecorder(t)
	defer closeServer()

	streamer := &fusionEchoLLM{
		overthinkModels:   map[string]bool{"z-ai/glm-5.2": true},
		rescueTextByModel: map[string]string{"z-ai/glm-5.2": "rescued panel step"},
	}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSynthCodeModel,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Implement the next step."}},
	}
	panel, err := runFusionPanel(context.Background(), streamer, req, fusionConfig{
		CodeModel:           true,
		AnalysisModels:      []string{"z-ai/glm-5.2"},
		MaxCompletionTokens: 64,
	}, trGateway, nil, "bearer", "req_overthink_panel", "log_overthink_panel")
	if err != nil {
		t.Fatalf("runFusionPanel: %v", err)
	}
	if len(panel) != 1 {
		t.Fatalf("panel length = %d, want 1", len(panel))
	}
	if got := strings.TrimSpace(panel[0].Result.Text); got != "rescued panel step" {
		t.Fatalf("panel answer = %q, want rescue result", got)
	}
	if panel[0].Rescue == nil {
		t.Fatalf("panel result missing overthinking rescue details: %#v", panel[0])
	}
	if panel[0].Rescue.ThinkingTokens <= fusionPanelThinkingTokenBudget {
		t.Fatalf("rescue thinking tokens = %d, want over budget", panel[0].Rescue.ThinkingTokens)
	}
	recorder.mu.Lock()
	authorizeCalls := append([]map[string]any{}, recorder.authorize...)
	settleCalls := append([]map[string]any{}, recorder.settle...)
	refundCalls := append([]map[string]any{}, recorder.refund...)
	recorder.mu.Unlock()
	if len(authorizeCalls) != 2 || len(refundCalls) != 1 || len(settleCalls) != 1 {
		t.Fatalf("authorize/refund/settle counts = %d/%d/%d, want 2/1/1", len(authorizeCalls), len(refundCalls), len(settleCalls))
	}
	for _, call := range authorizeCalls {
		if call["model"] != "z-ai/glm-5.2" {
			t.Fatalf("rescue changed model route: %#v", authorizeCalls)
		}
	}
	streamer.mu.Lock()
	calls := append([]fusionEchoCall{}, streamer.calls...)
	streamer.mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("provider calls = %#v, want original plus rescue", calls)
	}
	if !strings.Contains(calls[1].LastMessage, fusionOverthinkingRescueInstruction) ||
		!strings.Contains(calls[1].LastMessage, "deliberating") {
		t.Fatalf("rescue prompt did not include instruction and aborted reasoning: %q", calls[1].LastMessage)
	}
}

func TestFusionCodeFinalGLMOverthinkingRunsRescueBeforeModelFallback(t *testing.T) {
	trGateway, recorder, closeServer := newFusionGatewayRecorder(t)
	defer closeServer()

	streamer := &fusionEchoLLM{
		overthinkModels:   map[string]bool{"z-ai/glm-5.2": true},
		rescueTextByModel: map[string]string{"z-ai/glm-5.2": "rescued final answer"},
	}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSynthCodeModel,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Return the final answer."}},
	}
	final, attempts, err := runFusionFinal(
		context.Background(),
		streamer,
		req,
		fusionConfig{CodeModel: true, MaxCompletionTokens: 64},
		[]string{"z-ai/glm-5.2", "minimax/minimax-m3"},
		`{"final_guidance":"answer now"}`,
		[]fusionCallResult{{Model: "model/panel", Result: adapter.StreamResult{Text: "panel evidence"}}},
		trGateway,
		nil,
		"bearer",
		"req_overthink_final",
		"log_overthink_final",
		nil,
	)
	if err != nil {
		t.Fatalf("runFusionFinal: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "rescued final answer" {
		t.Fatalf("final answer = %q, want rescue result", got)
	}
	if final.Model != "z-ai/glm-5.2" {
		t.Fatalf("final model = %q, want same GLM model rescue before fallback", final.Model)
	}
	if len(attempts) != 1 || attempts[0].Rescue == nil {
		t.Fatalf("final attempts = %#v, want rescued first model only", attempts)
	}
	recorder.mu.Lock()
	authorizeCalls := append([]map[string]any{}, recorder.authorize...)
	settleCalls := append([]map[string]any{}, recorder.settle...)
	refundCalls := append([]map[string]any{}, recorder.refund...)
	recorder.mu.Unlock()
	if len(authorizeCalls) != 2 || len(refundCalls) != 1 || len(settleCalls) != 1 {
		t.Fatalf("authorize/refund/settle counts = %d/%d/%d, want 2/1/1", len(authorizeCalls), len(refundCalls), len(settleCalls))
	}
	for _, call := range authorizeCalls {
		if call["model"] != "z-ai/glm-5.2" {
			t.Fatalf("final rescue should not switch model before fallback: %#v", authorizeCalls)
		}
	}
}

func TestFusionToolCallsTextRendersNameAndArgs(t *testing.T) {
	if got := fusionToolCallsText(nil); got != "" {
		t.Fatalf("no tool calls = %q, want empty", got)
	}
	got := fusionToolCallsText([]types.ToolCall{
		{Name: "get_weather", Arguments: `{"city":"Paris"}`},
		{Name: "lookup", Arguments: ""},
	})
	want := `Proposed tool call(s): get_weather({"city":"Paris"}), lookup({})`
	if got != want {
		t.Fatalf("fusionToolCallsText = %q, want %q", got, want)
	}
}

func TestFusionPanelEvidenceSurfacesToolCalls(t *testing.T) {
	panel := []fusionCallResult{
		{Model: "m_tool", Result: adapter.StreamResult{
			Text:      "",
			ToolCalls: []types.ToolCall{{Name: "get_weather", Arguments: `{"city":"Paris"}`}},
		}},
		{Model: "m_text", Result: adapter.StreamResult{Text: "It is sunny."}},
	}
	got := fusionPanelEvidence(panel)
	// The actual tool call (name + args) must reach the judge/synthesizer, not a
	// content-free placeholder.
	if strings.Contains(got, "[panel member returned tool calls]") {
		t.Fatalf("evidence still uses the placeholder:\n%s", got)
	}
	if !strings.Contains(got, `get_weather({"city":"Paris"})`) {
		t.Fatalf("evidence missing the rendered tool call:\n%s", got)
	}
	if !strings.Contains(got, "It is sunny.") {
		t.Fatalf("evidence dropped the text answer:\n%s", got)
	}
}

func TestFusionPanelRequestPassesFunctionToolsStripsFusionTool(t *testing.T) {
	fnTool := map[string]any{"type": "function", "function": map[string]any{"name": "get_weather"}}
	for _, toolType := range []string{trustedRouterSynthTool, trustedRouterFusionTool} {
		t.Run(toolType, func(t *testing.T) {
			fusionTool := map[string]any{"type": toolType, "parameters": map[string]any{}}
			req := &types.OpenAIChatRequest{
				Model:    trustedRouterSynthModel,
				Messages: []types.OpenAIChatMessage{{Role: "user", Content: "weather in Paris?"}},
				Tools:    []any{fnTool, fusionTool},
			}
			out := fusionPanelRequest(req, "some/model", 0, 0, "")
			if len(out.Tools) != 1 {
				t.Fatalf("panel tools = %d, want 1 (function tool kept, synth config tool stripped)", len(out.Tools))
			}
			if m, _ := out.Tools[0].(map[string]any); m["type"] != "function" {
				t.Fatalf("panel tool type = %v, want function", m["type"])
			}
			if len(out.Messages) == 0 || out.Messages[0].Role != "system" {
				t.Fatalf("expected a leading system prompt")
			}
			if sys := types.ContentText(out.Messages[0].Content); !strings.Contains(sys, "emit the tool call directly") {
				t.Fatalf("panel system prompt is not tool-aware: %q", sys)
			}
		})
	}
}

func TestFusionPanelRequestNoToolsClearsToolChoice(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
	}
	out := fusionPanelRequest(req, "some/model", 0, 0, "")
	if len(out.Tools) != 0 {
		t.Fatalf("panel tools = %d, want 0", len(out.Tools))
	}
	if out.ToolChoice != nil {
		t.Fatalf("ToolChoice should be nil when no function tools are present")
	}
}

func TestRunAdvisorNoAdviceReturnsWorkerAnswer(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "what is 1+1?"}},
	}
	config := testAdvisorConfig(t)

	final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisor(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_advisor_simple", "log_advisor_simple", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runAdvisor: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "simple worker answer" {
		t.Fatalf("final text = %q", got)
	}
	if adviceCalls != 0 || budgetExhausted {
		t.Fatalf("adviceCalls=%d budgetExhausted=%t, want 0 false", adviceCalls, budgetExhausted)
	}
	if len(workers) != 1 || len(advisors) != 0 {
		t.Fatalf("workers=%d advisors=%d, want 1 0", len(workers), len(advisors))
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.authorize) != 1 || recorder.authorize[0]["route_type"] != "advisor.worker" {
		t.Fatalf("authorize calls = %#v, want one advisor.worker", recorder.authorize)
	}
}

func TestRunAdvisorAdviceOnceThenWorkerFinal(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{callAdviceFirst: true}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "review this risky migration"}},
	}
	config := testAdvisorConfig(t)

	final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisor(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_advisor_advice", "log_advisor_advice", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runAdvisor: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "worker final after advice" {
		t.Fatalf("final text = %q", got)
	}
	if adviceCalls != 1 || budgetExhausted {
		t.Fatalf("adviceCalls=%d budgetExhausted=%t, want 1 false", adviceCalls, budgetExhausted)
	}
	if len(workers) != 2 || len(advisors) != 1 {
		t.Fatalf("workers=%d advisors=%d, want 2 1", len(workers), len(advisors))
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	var routeTypes []string
	for _, payload := range recorder.authorize {
		routeTypes = append(routeTypes, fmt.Sprint(payload["route_type"]))
	}
	want := []string{"advisor.worker", "advisor.advisor", "advisor.worker"}
	if !reflect.DeepEqual(routeTypes, want) {
		t.Fatalf("route types = %#v, want %#v", routeTypes, want)
	}
}

func TestRunAdvisorAdviceRunsAdvisorsInParallel(t *testing.T) {
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{
		delayByModel: map[string]time.Duration{
			"advisor/slow-a": 90 * time.Millisecond,
			"advisor/slow-b": 90 * time.Millisecond,
		},
	}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterAdvisorModel,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "need advice"}},
	}
	config := testAdvisorConfig(t)
	config.AdvisorModels = []string{"advisor/slow-a", "advisor/slow-b"}

	started := time.Now()
	text, attempts := runAdvisorAdvice(context.Background(), streamer, req, config, req.Messages, trGateway, nil, "bearer", "req_advisor_parallel_advice", "log_advisor_parallel_advice", nil, nil, 0, nil)
	elapsed := time.Since(started)

	if elapsed >= 170*time.Millisecond {
		t.Fatalf("advisors appear serial, elapsed=%s", elapsed)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(attempts))
	}
	if !strings.Contains(text, "Advisor 1 (advisor/slow-a)") ||
		!strings.Contains(text, "answer from advisor/slow-a") ||
		!strings.Contains(text, "Advisor 2 (advisor/slow-b)") ||
		!strings.Contains(text, "answer from advisor/slow-b") {
		t.Fatalf("parallel advice text did not include both advisors:\n%s", text)
	}
}

func TestAdvisorProviderUsageReportsAdviceWithoutText(t *testing.T) {
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{callAdviceFirst: true}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "private risky migration prompt"}},
	}
	config := testAdvisorConfig(t)

	final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisor(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_advisor_provider_usage", "log_advisor_provider_usage", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runAdvisor: %v", err)
	}
	details := advisorResponseDetails(config, workers, advisors, trustedRouterSocrates10Model, final.Model, adviceCalls, budgetExhausted)
	providerUsage := advisorProviderUsage(details)
	if providerUsage["router"] != trustedRouterSocrates10Model ||
		providerUsage["primitive"] != trustedRouterAdvisorModel ||
		providerUsage["selected_model"] != "cerebras/gpt-oss-120b" ||
		providerUsage["worker_attempt_count"] != 2 ||
		providerUsage["advisor_attempt_count"] != 1 ||
		providerUsage["advisor_final_attempt_count"] != 0 ||
		providerUsage["advice_call_count"] != 1 ||
		providerUsage["cost_microdollars"] != 3 {
		t.Fatalf("providerUsage = %#v", providerUsage)
	}
	workersUsage, ok := providerUsage["worker_attempts"].([]map[string]any)
	if !ok || len(workersUsage) != 2 {
		t.Fatalf("worker_attempts = %#v", providerUsage["worker_attempts"])
	}
	if workersUsage[0]["route_type"] != "advisor.worker" || workersUsage[0]["model"] != "cerebras/gpt-oss-120b" {
		t.Fatalf("bad worker provider usage: %#v", workersUsage[0])
	}
	advisorsUsage, ok := providerUsage["advisor_attempts"].([]map[string]any)
	if !ok || len(advisorsUsage) != 1 {
		t.Fatalf("advisor_attempts = %#v", providerUsage["advisor_attempts"])
	}
	if advisorsUsage[0]["route_type"] != "advisor.advisor" || advisorsUsage[0]["model"] != "anthropic/claude-opus-4.8" {
		t.Fatalf("bad advisor provider usage: %#v", advisorsUsage[0])
	}
	encoded, err := json.Marshal(providerUsage)
	if err != nil {
		t.Fatalf("marshal providerUsage: %v", err)
	}
	for _, forbidden := range []string{
		"private risky migration prompt",
		"advisor says check rollback",
		"worker final after advice",
		`"visible_answer":`,
		`"raw_output":`,
		`"thinking":`,
		`"tool_calls":`,
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("provider_usage leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestServeOneOpenExploiterG1PreservesAliasAndReportsAdvisorUsage(t *testing.T) {
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{
		callAdviceForModels: map[string]bool{"z-ai/glm-5.2-fast": true},
	}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/openexploiter-g1","stream":false,"messages":[{"role":"user","content":"hard security task"}],"max_tokens":128}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	var response struct {
		Model  string         `json:"model"`
		Usage  map[string]any `json:"usage"`
		Router map[string]any `json:"trustedrouter"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, bodyBytes)
	}
	if response.Model != trustedRouterOpenExploiterG1Model {
		t.Fatalf("model = %q, want %q; body=%s", response.Model, trustedRouterOpenExploiterG1Model, bodyBytes)
	}
	details, ok := response.Router["advisor"].(map[string]any)
	if !ok {
		t.Fatalf("trustedrouter details = %#v, want advisor primitive", response.Router)
	}
	if details["router"] != trustedRouterOpenExploiterG1Model ||
		details["primitive"] != trustedRouterAdvisorModel ||
		details["selected_model"] != "z-ai/glm-5.2-fast" ||
		details["advice_call_count"] != float64(1) {
		t.Fatalf("advisor details = %#v", details)
	}
	providerUsage, ok := response.Usage["provider_usage"].(map[string]any)
	if !ok {
		t.Fatalf("usage provider_usage missing: %#v", response.Usage)
	}
	if providerUsage["router"] != trustedRouterOpenExploiterG1Model ||
		providerUsage["primitive"] != trustedRouterAdvisorModel ||
		providerUsage["selected_model"] != "z-ai/glm-5.2-fast" ||
		providerUsage["advice_call_count"] != float64(1) {
		t.Fatalf("provider_usage = %#v", providerUsage)
	}
	if got, ok := providerUsage["advisor_attempt_count"].(float64); !ok || got < 2 {
		t.Fatalf("advisor_attempt_count = %#v, want default G1 advisors reported", providerUsage["advisor_attempt_count"])
	}
	encoded := string(bodyBytes)
	for _, forbidden := range []string{`"socrates"`, "hard security task", "Advisor 1", "advisor says"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("response leaked or mislabeled %q: %s", forbidden, encoded)
		}
	}
}

func TestProviderUsageIncludesNestedOrchestrationWithoutText(t *testing.T) {
	nestedSynth := fusionResponseDetails(
		fusionConfig{Preset: "zeus-1.0", SelectionStrategy: "synthesize_non_refusals"},
		[]fusionCallResult{{
			Result:           adapter.StreamResult{Text: "nested panel answer", FinishReason: "stop"},
			Model:            "model/panel",
			RouteType:        "fusion.panel",
			InputTokens:      11,
			OutputTokens:     7,
			SettlementResult: &trustedrouter.SettleResult{GenerationID: "gen_panel", CostMicrodollars: 5},
		}},
		[]fusionCallResult{{
			Result:           adapter.StreamResult{Text: "nested judge answer", FinishReason: "stop"},
			Model:            "model/judge",
			RouteType:        "fusion.judge",
			InputTokens:      13,
			OutputTokens:     8,
			SettlementResult: &trustedrouter.SettleResult{GenerationID: "gen_judge", CostMicrodollars: 6},
		}},
		[]fusionCallResult{{
			Result:           adapter.StreamResult{Text: "nested final answer", FinishReason: "stop"},
			Model:            "model/final",
			RouteType:        "fusion.final",
			InputTokens:      17,
			OutputTokens:     9,
			SettlementResult: &trustedrouter.SettleResult{GenerationID: "gen_final", CostMicrodollars: 7},
		}},
		trustedRouterZeus10Model,
		"model/final",
	)
	nestedSelector := map[string]any{
		"router":         trustedRouterSelectorModel,
		"primitive":      trustedRouterSelectorModel,
		"selected_model": "model/selected",
		"selector_attempts": []map[string]any{{
			"route_type":        "fusion.selector",
			"model":             "model/selector",
			"generation_id":     "gen_selector",
			"input_tokens":      19,
			"output_tokens":     3,
			"cost_microdollars": 2,
		}},
		"cost_microdollars": 2,
	}
	nestedMapReduce := map[string]any{
		"router":         trustedRouterMapReduceModel,
		"primitive":      trustedRouterMapReduceModel,
		"selected_model": "model/reducer",
		"mapper_attempts": []map[string]any{{
			"route_type":        "fusion.mapreduce.mapper",
			"model":             "model/mapper",
			"generation_id":     "gen_mapper",
			"input_tokens":      5,
			"output_tokens":     4,
			"cost_microdollars": 1,
		}},
		"parts": []map[string]any{{
			"route_type":        "fusion.mapreduce.part",
			"model":             "model/part",
			"generation_id":     "gen_part",
			"input_tokens":      6,
			"output_tokens":     4,
			"cost_microdollars": 2,
		}},
		"reducer_attempts": []map[string]any{{
			"route_type":        "fusion.mapreduce.reducer",
			"model":             "model/reducer",
			"generation_id":     "gen_reducer",
			"input_tokens":      7,
			"output_tokens":     4,
			"cost_microdollars": 3,
		}},
		"cost_microdollars": 6,
	}
	details := advisorResponseDetails(
		testAdvisorConfig(t),
		nil,
		[]fusionCallResult{{
			Result:           adapter.StreamResult{Text: "advisor used nested synth", FinishReason: "stop"},
			Model:            trustedRouterZeus10Model,
			RouteType:        "advisor.advisor",
			InputTokens:      23,
			OutputTokens:     10,
			SettlementResult: &trustedrouter.SettleResult{GenerationID: "gen_advisor", CostMicrodollars: 18},
			Orchestration:    map[string]any{"synth": nestedSynth, "selector": nestedSelector, "mapreduce": nestedMapReduce},
		}},
		trustedRouterAristotle10Model,
		trustedRouterZeus10Model,
		1,
		false,
	)

	providerUsage := advisorProviderUsage(details)
	advisorsUsage, ok := providerUsage["advisor_attempts"].([]map[string]any)
	if !ok || len(advisorsUsage) != 1 {
		t.Fatalf("advisor_attempts = %#v", providerUsage["advisor_attempts"])
	}
	nested, ok := advisorsUsage[0]["orchestration"].(map[string]any)
	if !ok {
		t.Fatalf("nested orchestration missing: %#v", advisorsUsage[0])
	}
	synth, ok := nested["synth"].(map[string]any)
	if !ok {
		t.Fatalf("nested synth missing: %#v", nested)
	}
	if synth["panel_attempt_count"] != 1 || synth["judge_attempt_count"] != 1 || synth["final_attempt_count"] != 1 || synth["cost_microdollars"] != 18 {
		t.Fatalf("nested synth summary = %#v", synth)
	}
	selector, ok := nested["selector"].(map[string]any)
	if !ok {
		t.Fatalf("nested selector missing: %#v", nested)
	}
	if selector["selector_attempt_count"] != 1 || selector["cost_microdollars"] != 2 {
		t.Fatalf("nested selector summary = %#v", selector)
	}
	selectorAttempts, ok := selector["selector_attempts"].([]map[string]any)
	if !ok || len(selectorAttempts) != 1 || selectorAttempts[0]["route_type"] != "selector.decision" {
		t.Fatalf("nested selector attempts = %#v", selector["selector_attempts"])
	}
	mapreduce, ok := nested["mapreduce"].(map[string]any)
	if !ok {
		t.Fatalf("nested mapreduce missing: %#v", nested)
	}
	if mapreduce["mapper_attempt_count"] != 1 || mapreduce["part_attempt_count"] != 1 || mapreduce["reducer_attempt_count"] != 1 || mapreduce["cost_microdollars"] != 6 {
		t.Fatalf("nested mapreduce summary = %#v", mapreduce)
	}
	mapreduceReducers, ok := mapreduce["reducer_attempts"].([]map[string]any)
	if !ok || len(mapreduceReducers) != 1 || mapreduceReducers[0]["route_type"] != "mapreduce.reducer" {
		t.Fatalf("nested mapreduce reducer attempts = %#v", mapreduce["reducer_attempts"])
	}
	encoded, err := json.Marshal(providerUsage)
	if err != nil {
		t.Fatalf("marshal providerUsage: %v", err)
	}
	for _, forbidden := range []string{
		"nested panel answer",
		"nested judge answer",
		"nested final answer",
		"advisor used nested synth",
		`"visible_answer":`,
		`"raw_output":`,
		`"thinking":`,
		`"tool_calls":`,
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("provider_usage leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRunAdvisorWorkerFailureFallsBackToAdvisorFinal(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{failModels: map[string]bool{"cerebras/gpt-oss-120b": true}}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "solve the hard thing"}},
	}
	config := testAdvisorConfig(t)

	final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisor(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_advisor_worker_fails", "log_advisor_worker_fails", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runAdvisor: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "advisor final answer" {
		t.Fatalf("final text = %q", got)
	}
	if len(workers) != 0 || len(advisors) != 1 || adviceCalls != 0 || budgetExhausted {
		t.Fatalf("workers=%d advisors=%d adviceCalls=%d budgetExhausted=%t, want 0 1 0 false", len(workers), len(advisors), adviceCalls, budgetExhausted)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	var routeTypes []string
	for _, payload := range recorder.authorize {
		routeTypes = append(routeTypes, fmt.Sprint(payload["route_type"]))
	}
	want := []string{"advisor.worker", "advisor.advisor_final"}
	if !reflect.DeepEqual(routeTypes, want) {
		t.Fatalf("route types = %#v, want %#v", routeTypes, want)
	}
	if len(recorder.refund) != 1 || len(recorder.settle) != 1 {
		t.Fatalf("refund=%d settle=%d, want 1 1", len(recorder.refund), len(recorder.settle))
	}
}

func TestAdvisorStreamErrorIncludesProviderDiagnostics(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocratesProPlus10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard question"}},
	}
	baseErr := errors.New("llm/upstream: http 429: rate limited")
	err := newOrchestrationCallError(
		withInvokeAttemptError(baseErr, llm.InvokeOptions{
			Model:      "anthropic/claude-opus-4.8",
			Provider:   "anthropic",
			EndpointID: "anthropic/claude-opus-4.8@anthropic/prepaid",
		}),
		"advisor.advisor_final",
		req,
		&trustedrouter.Authorization{
			Model:      "anthropic/claude-opus-4.8",
			Provider:   "anthropic",
			EndpointID: "anthropic/claude-opus-4.8@anthropic/prepaid",
		},
		nil,
		nil,
	)
	event := advisorStreamErrorEvent(err, nil, nil)
	if event["event"] != "advisor.error" {
		t.Fatalf("event = %#v", event)
	}
	if event["stage"] != "advisor.advisor_final" {
		t.Fatalf("stage = %#v, event=%#v", event["stage"], event)
	}
	if event["attempted_model"] != "anthropic/claude-opus-4.8" {
		t.Fatalf("attempted_model = %#v, event=%#v", event["attempted_model"], event)
	}
	if event["endpoint"] != "anthropic/claude-opus-4.8@anthropic/prepaid" {
		t.Fatalf("endpoint = %#v, event=%#v", event["endpoint"], event)
	}
	if event["provider"] != "anthropic" {
		t.Fatalf("provider = %#v, event=%#v", event["provider"], event)
	}
	if event["provider_error_class"] != "rate_limited" {
		t.Fatalf("provider_error_class = %#v, event=%#v", event["provider_error_class"], event)
	}
	if got := fmt.Sprint(event["provider_error_detail"]); !strings.Contains(got, "http 429") {
		t.Fatalf("provider_error_detail = %q, event=%#v", got, event)
	}
	if event["input_tokens"] == nil || event["output_tokens"] == nil {
		t.Fatalf("token counts missing from event=%#v", event)
	}
	detail, ok := event["detail"].(map[string]any)
	if !ok {
		t.Fatalf("detail missing from event=%#v", event)
	}
	if detail["provider_error_class"] != "rate_limited" {
		t.Fatalf("detail provider error = %#v, detail=%#v", detail["provider_error_class"], detail)
	}
}

func TestRunAdvisorWorkerFallbackUsesDistinctIdempotencyKeys(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{failModels: map[string]bool{"cerebras/gpt-oss-120b": true}}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "reply pong"}},
	}
	config := testAdvisorConfig(t)
	config.WorkerModels = []string{"cerebras/gpt-oss-120b", "deepseek/deepseek-v4-flash"}

	final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisor(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_advisor_fallback", "log_advisor_fallback", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runAdvisor: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "answer from deepseek/deepseek-v4-flash" {
		t.Fatalf("final text = %q", got)
	}
	if len(workers) != 1 || len(advisors) != 0 || adviceCalls != 0 || budgetExhausted {
		t.Fatalf("workers=%d advisors=%d adviceCalls=%d budgetExhausted=%t, want 1 0 0 false", len(workers), len(advisors), adviceCalls, budgetExhausted)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.authorize) != 2 {
		t.Fatalf("authorize calls = %d, want 2: %#v", len(recorder.authorize), recorder.authorize)
	}
	firstKey := fmt.Sprint(recorder.authorize[0]["idempotency_key"])
	secondKey := fmt.Sprint(recorder.authorize[1]["idempotency_key"])
	if firstKey == "" || secondKey == "" || firstKey == secondKey {
		t.Fatalf("idempotency keys = %q, %q; want distinct non-empty keys", firstKey, secondKey)
	}
	if len(recorder.refund) != 1 {
		t.Fatalf("refund calls = %d, want 1: %#v", len(recorder.refund), recorder.refund)
	}
	if len(recorder.settle) != 1 {
		t.Fatalf("settle calls = %d, want 1: %#v", len(recorder.settle), recorder.settle)
	}
	if got := recorder.settle[0]["selected_model"]; got != "deepseek/deepseek-v4-flash" {
		t.Fatalf("settled model = %v, want deepseek/deepseek-v4-flash", got)
	}
}

func TestRunAdvisorAdviceBudgetExhaustedThenAnswer(t *testing.T) {
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &advisorScriptedLLM{callAdviceFirst: true, callAdviceAfterAdvisor: true}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard task"}},
	}
	config := testAdvisorConfig(t)

	final, _, _, adviceCalls, budgetExhausted, err := runAdvisor(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_advisor_budget", "log_advisor_budget", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runAdvisor: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "worker final after budget exhausted" {
		t.Fatalf("final text = %q", got)
	}
	if adviceCalls != 1 || !budgetExhausted {
		t.Fatalf("adviceCalls=%d budgetExhausted=%t, want 1 true", adviceCalls, budgetExhausted)
	}
}

func TestAdvisorComboPresetsConfigureWorkerAndAdvisorModels(t *testing.T) {
	tests := []struct {
		model    string
		workers  []string
		advisors []string
	}{
		{
			model:    trustedRouterAristotle10Model,
			workers:  []string{"deepseek/deepseek-v4-flash"},
			advisors: []string{trustedRouterZeus10Model},
		},
		{
			model:    trustedRouterPlato10Model,
			workers:  []string{"deepseek/deepseek-v4-flash"},
			advisors: []string{trustedRouterPlatoPro10Model},
		},
		{
			model:    trustedRouterPlatoPro10Model,
			workers:  []string{"z-ai/glm-5.2"},
			advisors: []string{trustedRouterPrometheus101MModel},
		},
		{
			model:    trustedRouterSocrates10Model,
			workers:  []string{"cerebras/gpt-oss-120b"},
			advisors: []string{trustedRouterSocratesPro10Model},
		},
		{
			model:    trustedRouterSocratesPro10Model,
			workers:  []string{"cerebras/zai-glm-4.7"},
			advisors: []string{trustedRouterSocratesProPlus10Model},
		},
		{
			model:    trustedRouterSocratesProPlus10Model,
			workers:  []string{"xiaomi/mimo-v2.5-pro-ultraspeed"},
			advisors: []string{trustedRouterZeus10Model},
		},
		{
			model:    trustedRouterSocrates11Model,
			workers:  []string{"xiaomi/mimo-v2.5-pro-ultraspeed"},
			advisors: []string{trustedRouterZeus10Model},
		},
		{
			model:    trustedRouterOpenExploiterA1Model,
			workers:  []string{trustedRouterOpenExploiterS1Model},
			advisors: []string{trustedRouterPrometheus10Model},
		},
		{
			model:    trustedRouterOpenExploiterFast1Model,
			workers:  []string{"xiaomi/mimo-v2.5-pro-ultraspeed"},
			advisors: []string{trustedRouterOpenExploiterA1Model},
		},
		{
			model:    trustedRouterOpenExploiterG1Model,
			workers:  []string{"z-ai/glm-5.2-fast", "z-ai/glm-5.2"},
			advisors: []string{fusionCodeKimi, trustedRouterPrometheus101MModel},
		},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			req := &types.OpenAIChatRequest{Model: tt.model}
			config, requested, err := advisorConfigForRequest(req)
			if err != nil {
				t.Fatalf("advisorConfigForRequest: %v", err)
			}
			if !requested {
				t.Fatalf("expected %s to request advisor orchestration", tt.model)
			}
			if err := normalizeAdvisorConfig(&config, req); err != nil {
				t.Fatalf("normalizeAdvisorConfig: %v", err)
			}
			if !reflect.DeepEqual(config.WorkerModels, tt.workers) {
				t.Fatalf("workers = %#v, want %#v", config.WorkerModels, tt.workers)
			}
			if !reflect.DeepEqual(config.AdvisorModels, tt.advisors) {
				t.Fatalf("advisors = %#v, want %#v", config.AdvisorModels, tt.advisors)
			}
		})
	}
}

func TestGenericAdvisorRequiresExplicitWorkerAndAdvisorModels(t *testing.T) {
	req := &types.OpenAIChatRequest{Model: trustedRouterAdvisorModel}
	config, requested, err := advisorConfigForRequest(req)
	if err != nil {
		t.Fatalf("advisorConfigForRequest: %v", err)
	}
	if !requested {
		t.Fatal("trustedrouter/advisor should request advisor orchestration")
	}
	err = validateGenericAdvisorConfig(config, req.Model)
	if err == nil {
		t.Fatal("validateGenericAdvisorConfig returned nil error")
	}
	var adapterErr *adapter.AdapterError
	if !asAdapterErr(err, &adapterErr) || adapterErr.Status != 400 || adapterErr.Context != "trustedrouter:advisor" {
		t.Fatalf("error = %#v, want 400 trustedrouter:advisor", err)
	}
}

func TestGenericAdvisorAcceptsDirectSDKToolConfig(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model: trustedRouterAdvisorModel,
		Tools: []any{
			map[string]any{
				"type": trustedRouterAdvisorTool,
				"parameters": map[string]any{
					"worker_models":  []any{"moonshotai/kimi-k2.7-code"},
					"advisor_models": []any{"z-ai/glm-5.2"},
				},
			},
		},
	}
	config, requested, err := advisorConfigForRequest(req)
	if err != nil {
		t.Fatalf("advisorConfigForRequest: %v", err)
	}
	if !requested {
		t.Fatal("trustedrouter/advisor should request advisor orchestration")
	}
	if err := validateGenericAdvisorConfig(config, req.Model); err != nil {
		t.Fatalf("validateGenericAdvisorConfig: %v", err)
	}
	if !reflect.DeepEqual(config.WorkerModels, []string{"moonshotai/kimi-k2.7-code"}) {
		t.Fatalf("worker models = %#v", config.WorkerModels)
	}
	if !reflect.DeepEqual(config.AdvisorModels, []string{"z-ai/glm-5.2"}) {
		t.Fatalf("advisor models = %#v", config.AdvisorModels)
	}
}

func TestAdvisorRejectsReservedToolCollision(t *testing.T) {
	err := rejectAdvisorToolCollision([]any{
		map[string]any{"type": "function", "function": map[string]any{"name": advisorAdviceToolName}},
	}, nil)
	if err == nil {
		t.Fatal("expected reserved tool collision error")
	}
	var aerr *adapter.AdapterError
	if !asAdapterErr(err, &aerr) || aerr.Status != 400 {
		t.Fatalf("error = %v, want 400 adapter error", err)
	}
}

func TestNormalizeAdvisorConfigDepthBounds(t *testing.T) {
	config := testAdvisorConfig(t)
	config.Depth = maxOrchestrationDepth + 1
	config.DepthSet = true
	err := normalizeAdvisorConfig(&config, &types.OpenAIChatRequest{})
	if err == nil {
		t.Fatal("expected depth bounds error")
	}
	var aerr *adapter.AdapterError
	if !asAdapterErr(err, &aerr) || aerr.Status != 400 {
		t.Fatalf("error = %v, want 400 adapter error", err)
	}
}

func TestAdvisorMaxAdviceCallsZeroStaysDisabled(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model: trustedRouterSocrates10Model,
		Tools: []any{map[string]any{
			"type": trustedRouterAdvisorTool,
			"parameters": map[string]any{
				"max_get_advice_calls": 0,
			},
		}},
	}
	config, requested, err := advisorConfigForRequest(req)
	if err != nil {
		t.Fatalf("advisorConfigForRequest: %v", err)
	}
	if !requested {
		t.Fatal("expected advisor request")
	}
	if err := normalizeAdvisorConfig(&config, req); err != nil {
		t.Fatalf("normalizeAdvisorConfig: %v", err)
	}
	if config.MaxAdviceCalls != 0 {
		t.Fatalf("MaxAdviceCalls = %d, want 0", config.MaxAdviceCalls)
	}
}

func TestAdvisorRejectsTooSmallMaxTokensBeforeAuthorize(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	lowMaxTokens := minAdvisorMaxTokens - 1
	req := &types.OpenAIChatRequest{
		Model:     trustedRouterSocrates10Model,
		Messages:  []types.OpenAIChatMessage{{Role: "user", Content: "reply pong"}},
		MaxTokens: &lowMaxTokens,
	}
	var out bytes.Buffer
	handled, err := maybeServeAdvisor(context.Background(), &out, &advisorScriptedLLM{}, req, trGateway, nil, "bearer", nil, "log_advisor_low_tokens")
	if !handled {
		t.Fatal("expected advisor request to be handled")
	}
	var aerr *adapter.AdapterError
	if !asAdapterErr(err, &aerr) || aerr.Status != 400 || aerr.Context != "max_tokens" {
		t.Fatalf("error = %v, want max_tokens 400", err)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.authorize) != 0 || len(recorder.settle) != 0 || len(recorder.refund) != 0 {
		t.Fatalf("gateway calls after invalid config: authorize=%#v settle=%#v refund=%#v", recorder.authorize, recorder.settle, recorder.refund)
	}
}

func TestAdvisorPromptSecretsRequiredInProductionGCP(t *testing.T) {
	t.Setenv("QUILL_GCP_PROJECT_ID", "trusted-router-prod")
	t.Setenv("TR_ALLOW_DEFAULT_SOCRATES_PROMPTS", "")
	t.Setenv("TR_REQUIRE_SOCRATES_PROMPTS", "")
	if !advisorPromptsRequired() {
		t.Fatalf("GCP runtime should require advisor prompt secrets")
	}

	t.Setenv("TR_ALLOW_DEFAULT_SOCRATES_PROMPTS", "1")
	if advisorPromptsRequired() {
		t.Fatalf("explicit local override should allow fallback prompts")
	}

	t.Setenv("QUILL_GCP_PROJECT_ID", "")
	t.Setenv("TR_REQUIRE_SOCRATES_PROMPTS", "1")
	if !advisorPromptsRequired() {
		t.Fatalf("explicit require flag should require advisor prompt secrets")
	}
}

func TestSelectFusionPanelResultFirstNonRefusal(t *testing.T) {
	panel := []fusionCallResult{
		{
			Model: "model_refusal",
			Result: adapter.StreamResult{
				Text:         "I'm sorry, but I can't help with that.",
				FinishReason: "stop",
			},
		},
		{
			Model: "model_answer",
			Result: adapter.StreamResult{
				Text:         "Here is a direct answer.",
				FinishReason: "stop",
			},
		},
	}
	selected, err := selectFusionPanelResult(panel, "first_non_refusal")
	if err != nil {
		t.Fatalf("selectFusionPanelResult: %v", err)
	}
	if selected.Model != "model_answer" {
		t.Fatalf("selected model = %q, want model_answer", selected.Model)
	}
}

func TestSelectFusionPanelResultSkipsEmptyPlaceholders(t *testing.T) {
	panel := []fusionCallResult{
		{
			Model: "model_empty",
			Result: adapter.StreamResult{
				Text:         "[panel member 1, model model_empty returned an empty answer; finish_reason=stop]",
				FinishReason: "empty",
			},
		},
		{
			Model: "model_answer",
			Result: adapter.StreamResult{
				Text:         "Here is a direct answer.",
				FinishReason: "stop",
			},
		},
	}
	selected, err := selectFusionPanelResult(panel, "first_non_refusal")
	if err != nil {
		t.Fatalf("selectFusionPanelResult: %v", err)
	}
	if selected.Model != "model_answer" {
		t.Fatalf("selected model = %q, want model_answer", selected.Model)
	}
}

func TestSelectFusionPanelResultFallsBackWhenAllRefuse(t *testing.T) {
	panel := []fusionCallResult{
		{
			Model: "model_refusal",
			Result: adapter.StreamResult{
				Text:         "I cannot provide that.",
				FinishReason: "stop",
			},
		},
	}
	selected, err := selectFusionPanelResult(panel, "first_non_refusal")
	if err != nil {
		t.Fatalf("selectFusionPanelResult: %v", err)
	}
	if selected.Model != "model_refusal" {
		t.Fatalf("selected model = %q, want model_refusal", selected.Model)
	}
}

func TestFusionPanelForSynthesisFiltersRefusalsAndPlaceholders(t *testing.T) {
	panel := []fusionCallResult{
		{
			Model: "model_refusal",
			Result: adapter.StreamResult{
				Text:         "I'm sorry, but I can't help with that.",
				FinishReason: "stop",
			},
		},
		{
			Model: "model_empty",
			Result: adapter.StreamResult{
				Text:         "[panel member 2, model model_empty returned an empty answer; finish_reason=stop]",
				FinishReason: "empty",
			},
		},
		{
			Model: "model_answer",
			Result: adapter.StreamResult{
				Text:         "Here is useful evidence.",
				FinishReason: "stop",
			},
		},
	}
	filtered, err := fusionPanelForSynthesis(panel, "synthesize_non_refusals")
	if err != nil {
		t.Fatalf("fusionPanelForSynthesis: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Model != "model_answer" {
		t.Fatalf("filtered panel = %#v, want only model_answer", filtered)
	}
}

func TestFusionPanelForSynthesisRejectsAllRefusals(t *testing.T) {
	panel := []fusionCallResult{
		{
			Model: "model_refusal",
			Result: adapter.StreamResult{
				Text:         "I cannot provide that.",
				FinishReason: "stop",
			},
		},
	}
	_, err := fusionPanelForSynthesis(panel, "synthesize_non_refusals")
	if err == nil {
		t.Fatal("fusionPanelForSynthesis returned nil error")
	}
	var adapterErr *adapter.AdapterError
	if !asAdapterErr(err, &adapterErr) || adapterErr.Status != 502 || !strings.Contains(adapterErr.Message, "no non-refusal") {
		t.Fatalf("error = %#v, want 502 no non-refusal", err)
	}
}

func TestFusionDefaultsUseOpenPanelExplicitJudgeAndFuserFallbacks(t *testing.T) {
	want := []string{
		"minimax/minimax-m3",
		"moonshotai/kimi-k2.6",
		"z-ai/glm-5.2",
		"google/gemma-4-31b-it",
		"deepseek/deepseek-v4-pro",
	}
	if !reflect.DeepEqual(fusionQualityPanel, want) {
		t.Fatalf("fusionQualityPanel = %#v, want %#v", fusionQualityPanel, want)
	}
	if defaultFusionSelectionStrategy != "synthesize_non_refusals" {
		t.Fatalf("defaultFusionSelectionStrategy = %q", defaultFusionSelectionStrategy)
	}
	if _, requested, err := fusionConfigForRequest(&types.OpenAIChatRequest{Model: trustedRouterSynthModel}); err != nil || !requested {
		t.Fatalf("synth must be a recognized synth request: requested=%v err=%v", requested, err)
	}
	finalModels, err := fusionFinalModels(fusionConfig{}, trustedRouterFusionModel, fusionQualityPanel[0])
	if err != nil {
		t.Fatalf("fusionFinalModels: %v", err)
	}
	judgeModels, err := fusionJudgeModels(fusionConfig{}, finalModels[0])
	if err != nil {
		t.Fatalf("fusionJudgeModels: %v", err)
	}
	if !reflect.DeepEqual(finalModels, []string{"z-ai/glm-5.2", "minimax/minimax-m3"}) {
		t.Fatalf("finalModels = %#v, want GLM 5.2 with M3 fallback", finalModels)
	}
	if !reflect.DeepEqual(judgeModels, []string{"moonshotai/kimi-k2.7-code", "minimax/minimax-m3"}) {
		t.Fatalf("judgeModels = %#v, want Kimi K2.7 Code with M3 fallback", judgeModels)
	}

	// trustedrouter/fusion-code is fusion with the code-tuned Kimi: it is a
	// recognized fusion request, and the swap still turns the general kimi-k2.6
	// panel model into kimi-k2.7-code — while leaving the already-code default
	// judge and the non-Kimi glm-5.2/m3 synthesizer untouched.
	for _, model := range []string{trustedRouterSynthCodeModel, trustedRouterFusionCodeModel} {
		if _, requested, err := fusionConfigForRequest(&types.OpenAIChatRequest{Model: model}); err != nil || !requested {
			t.Fatalf("%s must be a recognized synth request: requested=%v err=%v", model, requested, err)
		}
	}
	if got := applyFusionCodeSwap(fusionQualityPanel); got[1] != fusionCodeKimi {
		t.Fatalf("fusion-code panel swap = %#v, want %s at index 1", got, fusionCodeKimi)
	}
	if got := applyFusionCodeSwap(fusionDefaultJudgeModels); !reflect.DeepEqual(got, []string{fusionCodeKimi, "minimax/minimax-m3"}) {
		t.Fatalf("fusion-code judge swap = %#v, want %s with M3 fallback", got, fusionCodeKimi)
	}
	if got := applyFusionCodeSwap(fusionDefaultFinalModels); !reflect.DeepEqual(got, fusionDefaultFinalModels) {
		t.Fatalf("fusion-code swap must not touch the non-Kimi synthesizer: %#v", got)
	}
}

func TestGenericSynthRequiresExplicitPanelConfig(t *testing.T) {
	req := &types.OpenAIChatRequest{Model: trustedRouterSynthModel}
	config, requested, err := fusionConfigForRequest(req)
	if err != nil {
		t.Fatalf("fusionConfigForRequest: %v", err)
	}
	if !requested {
		t.Fatal("trustedrouter/synth should request fusion orchestration")
	}
	config.Mode = fusionModeForRequest(req.Model, config.Mode)
	err = validateGenericFusionConfig(config, req.Model)
	if err == nil {
		t.Fatal("validateGenericFusionConfig returned nil error")
	}
	var adapterErr *adapter.AdapterError
	if !asAdapterErr(err, &adapterErr) || adapterErr.Status != 400 || adapterErr.Context != "trustedrouter:synth" {
		t.Fatalf("error = %#v, want 400 trustedrouter:synth", err)
	}
}

func TestGenericSynthAcceptsDirectSDKToolConfig(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model: trustedRouterSynthModel,
		Tools: []any{
			map[string]any{
				"type": trustedRouterFusionTool,
				"parameters": map[string]any{
					"analysis_models": []any{"moonshotai/kimi-k2.7-code", "z-ai/glm-5.2"},
					"model":           "moonshotai/kimi-k2.7-code",
				},
			},
		},
	}
	config, requested, err := fusionConfigForRequest(req)
	if err != nil {
		t.Fatalf("fusionConfigForRequest: %v", err)
	}
	if !requested {
		t.Fatal("trustedrouter/synth should request fusion orchestration")
	}
	config.Mode = fusionModeForRequest(req.Model, config.Mode)
	if err := validateGenericFusionConfig(config, req.Model); err != nil {
		t.Fatalf("validateGenericFusionConfig: %v", err)
	}
	if !reflect.DeepEqual(config.AnalysisModels, []string{"moonshotai/kimi-k2.7-code", "z-ai/glm-5.2"}) {
		t.Fatalf("analysis models = %#v", config.AnalysisModels)
	}
	if config.JudgeModel != "moonshotai/kimi-k2.7-code" {
		t.Fatalf("judge model = %q", config.JudgeModel)
	}
}

func TestFusionJudgeModelsRejectsMoreThanEight(t *testing.T) {
	_, err := fusionJudgeModels(fusionConfig{
		JudgeModels: []string{
			"model/1",
			"model/2",
			"model/3",
			"model/4",
			"model/5",
			"model/6",
			"model/7",
			"model/8",
			"model/9",
		},
	}, "model/fallback")
	if err == nil {
		t.Fatal("fusionJudgeModels returned nil error")
	}
	var adapterErr *adapter.AdapterError
	if !asAdapterErr(err, &adapterErr) || adapterErr.Status != 400 || adapterErr.Context != "judge_models" {
		t.Fatalf("error = %#v, want 400 judge_models", err)
	}
}

func TestFusionFinalModelsRejectsMoreThanEight(t *testing.T) {
	_, err := fusionFinalModels(fusionConfig{
		FinalModels: []string{
			"model/1",
			"model/2",
			"model/3",
			"model/4",
			"model/5",
			"model/6",
			"model/7",
			"model/8",
			"model/9",
		},
	}, "trustedrouter/fusion", "model/fallback")
	if err == nil {
		t.Fatal("fusionFinalModels returned nil error")
	}
	var adapterErr *adapter.AdapterError
	if !asAdapterErr(err, &adapterErr) || adapterErr.Status != 400 || adapterErr.Context != "final_models" {
		t.Fatalf("error = %#v, want 400 final_models", err)
	}
}

func TestFusionFinalModelsPreservesLegacyModelField(t *testing.T) {
	models, err := fusionFinalModels(fusionConfig{JudgeModel: "~kimi/latest"}, "trustedrouter/fusion", "model/fallback")
	if err != nil {
		t.Fatalf("fusionFinalModels: %v", err)
	}
	if len(models) != 1 || models[0] != "moonshotai/kimi-k2.7-code" {
		t.Fatalf("models = %#v, want resolved kimi latest", models)
	}
}

func TestFusionJudgeResultRequiresText(t *testing.T) {
	if fusionJudgeResultUsable(fusionCallResult{Result: adapter.StreamResult{ToolCalls: []types.ToolCall{{ID: "call_1"}}}}) {
		t.Fatal("tool-only judge result was usable")
	}
	if !fusionJudgeResultUsable(fusionCallResult{Result: adapter.StreamResult{Text: `{"final_guidance":"use answer"}`}}) {
		t.Fatal("text judge result was unusable")
	}
}

func TestFusionFinalRequestTellsToolModelsToEmitToolCalls(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model: "trustedrouter/fusion",
		Messages: []types.OpenAIChatMessage{{
			Role:    "user",
			Content: "Use setup() first.",
		}},
		Tools: []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        "setup",
					"description": "Learn about the target.",
					"parameters":  map[string]any{"type": "object"},
				},
			},
			map[string]any{
				"type": trustedRouterFusionTool,
				"parameters": map[string]any{
					"analysis_models": []any{"google/gemini-3-flash-preview"},
				},
			},
		},
	}
	final := fusionFinalRequest(req, "anthropic/claude-opus-4.8", `{"final_guidance":"call setup"}`, nil, fusionConfig{})
	if len(final.Tools) != 1 {
		t.Fatalf("final tools = %#v, want only non-fusion tool", final.Tools)
	}
	last := final.Messages[len(final.Messages)-1]
	text := types.ContentText(last.Content)
	if !strings.Contains(text, "emit the tool call directly") || strings.Contains(text, "write the final answer") {
		t.Fatalf("bad tool final instruction: %s", text)
	}
}

func TestFusionFinalRequestIncludesCallerSynthesisPrompt(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model:    "trustedrouter/synth",
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Compare both options."}},
	}
	final := fusionFinalRequest(
		req,
		"z-ai/glm-5.2",
		`{"final_guidance":"prefer concise output"}`,
		[]fusionCallResult{{Model: "model/panel", Result: adapter.StreamResult{Text: "panel answer"}}},
		fusionConfig{
			PanelPrompt:        "Panel-only instruction.",
			SynthesisPrompt:    "Return exactly three bullets and include a recommendation.",
			BuiltInFinalPrompt: "Use panel evidence. Do not include chain-of-thought.",
		},
	)
	last := final.Messages[len(final.Messages)-1]
	text := types.ContentText(last.Content)
	if !strings.Contains(text, "Use panel evidence. Do not include chain-of-thought.") {
		t.Fatalf("final prompt omitted built-in synthesis prompt: %s", text)
	}
	if !strings.Contains(text, "Additional caller synthesis instructions:") ||
		!strings.Contains(text, "Return exactly three bullets and include a recommendation.") {
		t.Fatalf("final prompt omitted caller synthesis prompt: %s", text)
	}
	if strings.Contains(text, "Panel-only instruction.") {
		t.Fatalf("final prompt leaked caller panel prompt: %s", text)
	}
}

func TestFusionPanelRequestIncludesCallerPanelPrompt(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model:    "trustedrouter/synth",
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Analyze tradeoffs."}},
	}
	out := fusionPanelRequest(req, "some/model", 0, 0, "Use the customer's internal rubric.")
	if len(out.Messages) == 0 || out.Messages[0].Role != "system" {
		t.Fatalf("expected a leading system prompt")
	}
	system := types.ContentText(out.Messages[0].Content)
	if !strings.Contains(system, "Additional caller panel instructions:") ||
		!strings.Contains(system, "Use the customer's internal rubric.") {
		t.Fatalf("panel prompt omitted caller panel prompt: %s", system)
	}
	if len(out.Messages) < 2 || types.ContentText(out.Messages[1].Content) != "Analyze tradeoffs." {
		t.Fatalf("panel prompt should preserve original user message: %#v", out.Messages)
	}
}

func TestFusionSubcallsForceThroughputRouting(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model:    "trustedrouter/synth",
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Analyze tradeoffs."}},
		Provider: &types.ProviderRouting{
			Order:          types.StringList{"slow-provider"},
			Only:           types.StringList{"kimi", "fireworks"},
			Ignore:         types.StringList{"parasail"},
			DataCollection: "deny",
			Sort:           "price",
		},
	}
	panel := fusionPanelRequest(req, "moonshotai/kimi-k2.6", 0, 0, "")
	judge := fusionJudgeRequest(req, "moonshotai/kimi-k2.7-code", []fusionCallResult{
		{Model: "moonshotai/kimi-k2.6", Result: adapter.StreamResult{Text: "panel answer"}},
	}, 0)
	final := fusionFinalRequest(req, "z-ai/glm-5.2", `{"final_guidance":"answer"}`, []fusionCallResult{
		{Model: "moonshotai/kimi-k2.6", Result: adapter.StreamResult{Text: "panel answer"}},
	}, fusionConfig{})

	for name, out := range map[string]*types.OpenAIChatRequest{
		"panel": panel,
		"judge": judge,
		"final": final,
	} {
		if out.Provider == nil {
			t.Fatalf("%s provider routing missing", name)
		}
		if out.Provider.Sort != "throughput" {
			t.Fatalf("%s provider.sort = %#v, want throughput", name, out.Provider.Sort)
		}
		if len(out.Provider.Order) != 0 {
			t.Fatalf("%s provider.order = %#v, want cleared so sort=throughput can apply", name, out.Provider.Order)
		}
		if !reflect.DeepEqual([]string(out.Provider.Only), []string{"kimi", "fireworks"}) {
			t.Fatalf("%s provider.only = %#v", name, out.Provider.Only)
		}
		if !reflect.DeepEqual([]string(out.Provider.Ignore), []string{"parasail"}) {
			t.Fatalf("%s provider.ignore = %#v", name, out.Provider.Ignore)
		}
		if out.Provider.DataCollection != "deny" {
			t.Fatalf("%s provider.data_collection = %q", name, out.Provider.DataCollection)
		}
	}
	if req.Provider.Sort != "price" || !reflect.DeepEqual([]string(req.Provider.Order), []string{"slow-provider"}) {
		t.Fatalf("fusion subcall builder mutated caller provider routing: %#v", req.Provider)
	}
}

func TestFusionBuiltInPromptBundleSelectsSynthAndSynthCode(t *testing.T) {
	fusionPromptMu.Lock()
	old := fusionPromptCache
	fusionPromptMu.Unlock()
	defer func() {
		fusionPromptMu.Lock()
		fusionPromptCache = old
		fusionPromptMu.Unlock()
	}()

	configureFusionPrompts(&types.BootstrapData{
		SynthPanelPrompt:         "general panel prompt",
		SynthSynthesisPrompt:     "general final prompt",
		SynthCodePanelPrompt:     "code panel prompt",
		SynthCodeSynthesisPrompt: "code final prompt",
	})

	panel, final := fusionBuiltInPrompts(false)
	if panel != "general panel prompt" || final != "general final prompt" {
		t.Fatalf("general prompts = %q / %q", panel, final)
	}
	panel, final = fusionBuiltInPrompts(true)
	if panel != "code panel prompt" || final != "code final prompt" {
		t.Fatalf("code prompts = %q / %q", panel, final)
	}
}

func TestFusionBuiltInPromptBundleFallsBackFromCodeToGeneral(t *testing.T) {
	fusionPromptMu.Lock()
	old := fusionPromptCache
	fusionPromptMu.Unlock()
	defer func() {
		fusionPromptMu.Lock()
		fusionPromptCache = old
		fusionPromptMu.Unlock()
	}()

	configureFusionPrompts(&types.BootstrapData{
		SynthPanelPrompt:     "general panel prompt",
		SynthSynthesisPrompt: "general final prompt",
	})

	panel, final := fusionBuiltInPrompts(true)
	if panel != "general panel prompt" || final != "general final prompt" {
		t.Fatalf("code fallback prompts = %q / %q", panel, final)
	}
}

func TestParseFusionParametersAcceptsSynthesisPromptAliases(t *testing.T) {
	config, err := parseFusionParameters(map[string]any{
		"final_instructions": "Use JSON only.",
	})
	if err != nil {
		t.Fatalf("parseFusionParameters: %v", err)
	}
	if config.SynthesisPrompt != "Use JSON only." {
		t.Fatalf("SynthesisPrompt = %q, want alias value", config.SynthesisPrompt)
	}
}

func TestParseFusionParametersAcceptsPanelPrompt(t *testing.T) {
	config, err := parseFusionParameters(map[string]any{
		"panel_prompt": "Apply the agent context to every panel member.",
	})
	if err != nil {
		t.Fatalf("parseFusionParameters: %v", err)
	}
	if config.PanelPrompt != "Apply the agent context to every panel member." {
		t.Fatalf("PanelPrompt = %q, want panel_prompt value", config.PanelPrompt)
	}
}

func TestParseFusionParametersAcceptsFrontierPreset(t *testing.T) {
	config, err := parseFusionParameters(map[string]any{
		"preset": "frontier",
	})
	if err != nil {
		t.Fatalf("parseFusionParameters: %v", err)
	}
	if config.Preset != "frontier" {
		t.Fatalf("Preset = %q, want frontier", config.Preset)
	}
	if !reflect.DeepEqual(config.AnalysisModels, fusionFrontierPanel) {
		t.Fatalf("AnalysisModels = %#v, want frontier panel", config.AnalysisModels)
	}
}

func TestFusionNamedPresetModelsResolvePanels(t *testing.T) {
	tests := []struct {
		model  string
		preset string
		panel  []string
		code   bool
	}{
		{trustedRouterIrisModel, "budget", fusionBudgetPanel, false},
		{trustedRouterPrometheusModel, "quality", fusionQualityPanel, false},
		{trustedRouterZeusModel, "frontier", fusionFrontierPanel, false},
		{trustedRouterIris10Model, "budget", fusionBudgetPanel, false},
		{trustedRouterPrometheus10Model, "quality", fusionQualityPanel, false},
		{trustedRouterPrometheus101MModel, "quality-1m", fusionQuality1MPanel, false},
		{trustedRouterZeus10Model, "frontier", fusionFrontierPanel, false},
		{trustedRouterIrisCodeModel, "budget", fusionBudgetPanel, true},
		{trustedRouterPrometheusCodeModel, "quality", fusionQualityPanel, true},
		{trustedRouterZeusCodeModel, "frontier", fusionFrontierPanel, true},
		{trustedRouterIrisCode10Model, "budget", fusionBudgetPanel, true},
		{trustedRouterPrometheusCode10Model, "quality", fusionQualityPanel, true},
		{trustedRouterZeusCode10Model, "frontier", fusionFrontierPanel, true},
		{trustedRouterOpenExploiterS1Model, "openexploiter-s1", fusionOpenExploiterS1Panel, false},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if !isFusionModel(tt.model) {
				t.Fatalf("%s was not recognized as a synth model", tt.model)
			}
			if got := isFusionCodeModel(tt.model); got != tt.code {
				t.Fatalf("isFusionCodeModel(%q) = %v, want %v", tt.model, got, tt.code)
			}
			preset, panel, ok := fusionPresetPanelForModel(tt.model)
			if !ok {
				t.Fatalf("fusionPresetPanelForModel(%q) returned !ok", tt.model)
			}
			if preset != tt.preset {
				t.Fatalf("preset = %q, want %q", preset, tt.preset)
			}
			if !reflect.DeepEqual(panel, tt.panel) {
				t.Fatalf("panel = %#v, want %#v", panel, tt.panel)
			}
		})
	}
}

func TestFusionOpenExploiterS1PresetResolvesJudgeAndFinalModels(t *testing.T) {
	req := &types.OpenAIChatRequest{Model: trustedRouterOpenExploiterS1Model}
	config, requested, err := fusionConfigForRequest(req)
	if err != nil {
		t.Fatalf("fusionConfigForRequest: %v", err)
	}
	if !requested {
		t.Fatal("expected OpenExploiter-S1 to request synth orchestration")
	}
	preset, panel, ok := fusionPresetPanelForModel(req.Model)
	if !ok {
		t.Fatal("expected OpenExploiter-S1 panel preset")
	}
	config.Preset = preset
	config.AnalysisModels = panel
	finalModels, err := fusionFinalModels(config, req.Model, config.AnalysisModels[0])
	if err != nil {
		t.Fatalf("fusionFinalModels: %v", err)
	}
	judgeModels, err := fusionJudgeModels(config, req.Model)
	if err != nil {
		t.Fatalf("fusionJudgeModels: %v", err)
	}
	if !reflect.DeepEqual(config.AnalysisModels, []string{fusionCodeKimi, "z-ai/glm-5.2"}) {
		t.Fatalf("analysis models = %#v", config.AnalysisModels)
	}
	if !reflect.DeepEqual(judgeModels, []string{fusionCodeKimi}) {
		t.Fatalf("judge models = %#v", judgeModels)
	}
	if !reflect.DeepEqual(finalModels, []string{"z-ai/glm-5.2"}) {
		t.Fatalf("final models = %#v", finalModels)
	}
}

func TestParseFusionParametersRejectsInvalidSynthesisPrompt(t *testing.T) {
	if _, err := parseFusionParameters(map[string]any{
		"synthesis_prompt": 123,
	}); err == nil {
		t.Fatalf("parseFusionParameters accepted non-string synthesis_prompt")
	}
	if _, err := parseFusionParameters(map[string]any{
		"synthesis_prompt": strings.Repeat("x", maxFusionSynthesisPromptBytes+1),
	}); err == nil {
		t.Fatalf("parseFusionParameters accepted overlong synthesis_prompt")
	}
}

func TestParseFusionParametersRejectsInvalidPanelPrompt(t *testing.T) {
	if _, err := parseFusionParameters(map[string]any{
		"panel_prompt": 123,
	}); err == nil {
		t.Fatalf("parseFusionParameters accepted non-string panel_prompt")
	}
	if _, err := parseFusionParameters(map[string]any{
		"panel_prompt": strings.Repeat("x", maxFusionPanelPromptBytes+1),
	}); err == nil {
		t.Fatalf("parseFusionParameters accepted overlong panel_prompt")
	}
}

func TestServeOneResponsesNonStreamingFailsClosedWhenSettleFails(t *testing.T) {
	bearer := "test-user-bearer"
	var settleCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_resp","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleCalled = true
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":{"message":"settle unavailable"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"openai/gpt-4o-mini","input":"private response input","max_output_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !settleCalled {
		t.Fatal("expected settle to be attempted before response")
	}
	if strings.Contains(body, `"object":"response"`) || strings.Contains(body, "Hello world") || strings.Contains(body, "private response input") {
		t.Fatalf("failed settlement returned success or leaked content: %s", body)
	}
}

func TestServeOneResponsesStreamingUsesResponsesEvents(t *testing.T) {
	bearer := "test-bearer"
	digest := sha256.Sum256([]byte(bearer))
	reg := auth.New([]types.DeviceConfig{{
		KeyHash:  hex.EncodeToString(digest[:]),
		Owner:    "test",
		DeviceID: "device-1",
	}})
	server, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), server, reg, &fakeStreamingLLM{}, nil, nil, nil, nil)

	requestBody := []byte(`{"model":"claude-sonnet-4-6","input":"private response input","stream":true,"max_output_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	for _, eventName := range []string{
		"response.created",
		"response.in_progress",
		"response.output_item.added",
		"response.content_part.added",
		"response.output_text.delta",
		"response.output_text.done",
		"response.content_part.done",
		"response.output_item.done",
		"response.completed",
	} {
		if !strings.Contains(body, "event: "+eventName) {
			t.Fatalf("missing %s in stream: %s", eventName, body)
		}
	}
	if !strings.Contains(body, `"sequence_number":`) {
		t.Fatalf("missing response sequence numbers: %s", body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("missing done marker: %s", body)
	}
	if strings.Contains(body, "private response input") {
		t.Fatalf("response leaked input: %s", body)
	}
}

func TestServeOneResponsesRejectsUnsupportedTools(t *testing.T) {
	bearer := "test-bearer"
	digest := sha256.Sum256([]byte(bearer))
	reg := auth.New([]types.DeviceConfig{{
		KeyHash:  hex.EncodeToString(digest[:]),
		Owner:    "test",
		DeviceID: "device-1",
	}})
	server, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), server, reg, &fakeStreamingLLM{}, nil, nil, nil, nil)

	requestBody := []byte(`{"model":"claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search"}]}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 501 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if !strings.Contains(string(bodyBytes), "not_supported_in_alpha") {
		t.Fatalf("missing alpha error: %s", bodyBytes)
	}
}

func TestServeOneResponsesInputTokensCountsLocally(t *testing.T) {
	bearer := "test-bearer"
	digest := sha256.Sum256([]byte(bearer))
	reg := auth.New([]types.DeviceConfig{{
		KeyHash:  hex.EncodeToString(digest[:]),
		Owner:    "test",
		DeviceID: "device-1",
	}})
	server, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), server, reg, &panicStreamingLLM{t: t}, nil, nil, nil, nil)

	requestBody := []byte(`{"model":"claude-sonnet-4-6","input":"private response input","instructions":"brief"}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses/input_tokens HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"object":"response.input_tokens"`) || !strings.Contains(body, `"input_tokens":`) {
		t.Fatalf("bad input token response: %s", body)
	}
	if strings.Contains(body, "private response input") {
		t.Fatalf("input token response leaked input: %s", body)
	}
}

func TestServeOneResponsesInputTokensValidatesGatewayKeyWithoutContent(t *testing.T) {
	bearer := "test-user-bearer"
	var validateBody string
	var authorizeCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/validate":
			validateBody = string(body)
			if strings.Contains(validateBody, bearer) || strings.Contains(validateBody, "private response input") {
				t.Fatalf("validate leaked sensitive material: %s", validateBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1","route_type":"responses.input_tokens"}}`)
		case "/internal/gateway/authorize":
			authorizeCalled = true
			t.Fatalf("input token count should not reserve credits: %s", body)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), &panicStreamingLLM{t: t}, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"claude-sonnet-4-6","input":"private response input"}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses/input_tokens HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if !strings.Contains(validateBody, `"route_type":"responses.input_tokens"`) {
		t.Fatalf("validate did not include route type: %s", validateBody)
	}
	if authorizeCalled {
		t.Fatal("authorize was called")
	}
}

func TestServeOneResponsesStatefulEndpointsAreExplicitStubs(t *testing.T) {
	bearer := "test-bearer"
	digest := sha256.Sum256([]byte(bearer))
	reg := auth.New([]types.DeviceConfig{{
		KeyHash:  hex.EncodeToString(digest[:]),
		Owner:    "test",
		DeviceID: "device-1",
	}})
	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"retrieve", "GET", "/v1/responses/resp_123", ""},
		{"delete", "DELETE", "/v1/responses/resp_123", ""},
		{"cancel", "POST", "/v1/responses/resp_123/cancel", ""},
		{"compact", "POST", "/v1/responses/compact", `{"input":"private response input"}`},
		{"input_items", "GET", "/v1/responses/resp_123/input_items?limit=1", ""},
		{"conversations", "POST", "/v1/conversations", `{"metadata":{"prompt":"private response input"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			go serveOne(context.Background(), server, reg, &panicStreamingLLM{t: t}, nil, nil, nil, nil)

			_, err := fmt.Fprintf(
				client,
				"%s %s HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				tc.method,
				tc.path,
				bearer,
				len(tc.body),
				tc.body,
			)
			if err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			body := string(bodyBytes)
			if resp.StatusCode != 501 {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
			if !strings.Contains(body, `"code":"not_supported_in_alpha"`) {
				t.Fatalf("missing stable unsupported code: %s", body)
			}
			if strings.Contains(body, "private response input") {
				t.Fatalf("stub leaked request content: %s", body)
			}
		})
	}
}

func TestServeOneResponsesStatefulCreateFieldsFailBeforeProvider(t *testing.T) {
	bearer := "test-bearer"
	digest := sha256.Sum256([]byte(bearer))
	reg := auth.New([]types.DeviceConfig{{
		KeyHash:  hex.EncodeToString(digest[:]),
		Owner:    "test",
		DeviceID: "device-1",
	}})
	for _, requestBody := range [][]byte{
		[]byte(`{"model":"claude-sonnet-4-6","input":"private response input","store":true}`),
		[]byte(`{"model":"claude-sonnet-4-6","input":"private response input","background":true}`),
		[]byte(`{"model":"claude-sonnet-4-6","input":"private response input","previous_response_id":"resp_old"}`),
	} {
		server, client := net.Pipe()
		go serveOne(context.Background(), server, reg, &panicStreamingLLM{t: t}, nil, nil, nil, nil)
		_, err := fmt.Fprintf(
			client,
			"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			bearer,
			len(requestBody),
			requestBody,
		)
		if err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = client.Close()
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		body := string(bodyBytes)
		if resp.StatusCode != 501 {
			t.Fatalf("status = %d body=%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "not_supported_in_alpha") || strings.Contains(body, "private response input") {
			t.Fatalf("bad stateful field response: %s", body)
		}
	}
}

func TestParseRequestTargetRejectsInvalidNonce(t *testing.T) {
	_, _, err := parseRequestTarget("/attestation?nonce=not-hex")
	if err == nil {
		t.Fatal("expected invalid nonce error")
	}
}

func TestReadRequestRejectsOversizedBodyBeforeAllocation(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = fmt.Fprintf(
			client,
			"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: %d\r\n\r\n",
			maxRequestBodyBytes+1,
		)
	}()

	_, _, _, _, _, err := readRequest(server)
	if !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("err = %v, want errBodyTooLarge", err)
	}
}

func TestReadRequestAcceptsVisionPayloadAboveLegacyLimit(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	body := bytes.Repeat([]byte("x"), 5*1024*1024)
	go func() {
		defer client.Close()
		_, _ = fmt.Fprintf(
			client,
			"POST /v1/messages HTTP/1.1\r\nContent-Length: %d\r\n\r\n",
			len(body),
		)
		_, _ = client.Write(body)
	}()

	method, path, _, _, gotBody, err := readRequest(server)
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if method != "POST" || path != "/v1/messages" {
		t.Fatalf("method/path = %s %s, want POST /v1/messages", method, path)
	}
	if len(gotBody) != len(body) {
		t.Fatalf("body len = %d, want %d", len(gotBody), len(body))
	}
}

func TestReadRequestAcceptsAnthropicXAPIKey(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = fmt.Fprint(
			client,
			"POST /v1/messages HTTP/1.1\r\nx-api-key: tr-key-123\r\nContent-Length: 2\r\n\r\n{}",
		)
	}()

	_, _, bearer, _, body, err := readRequest(server)
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if bearer != "tr-key-123" {
		t.Fatalf("bearer = %q, want x-api-key value", bearer)
	}
	if string(body) != "{}" {
		t.Fatalf("body = %q, want {}", body)
	}
}

func TestServeOneMessagesNonStreamingReturnsEnvelopeAndSettles(t *testing.T) {
	bearer := "test-user-bearer"
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			if strings.Contains(string(body), bearer) || strings.Contains(string(body), "private prompt") {
				t.Fatalf("authorize leaked sensitive material: %s", body)
			}
			if !strings.Contains(string(body), `"route_type":"messages"`) {
				t.Fatalf("authorize missing messages route_type: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_msg","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-haiku-4.5","endpoint_id":"anthropic/claude-haiku-4.5@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[],"custom_model":{"id":"trustedrouter/user-msg123","name":"Messages model","base_model_id":"anthropic/claude-haiku-4.5","hidden_prompt":"PRIVATE messages preamble","revision":2}}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, "private prompt") || strings.Contains(settleBody, "Hello") {
				t.Fatalf("settle leaked content: %s", settleBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_msg","cost_microdollars":7,"model":"anthropic/claude-haiku-4.5","provider":"anthropic","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fakeStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/user-msg123","max_tokens":99,"system":[{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"private prompt","cache_control":{"type":"ephemeral"}}]}]}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bodyBytes, &decoded); err != nil {
		t.Fatalf("decode envelope: %v body=%s", err, bodyBytes)
	}
	if decoded["type"] != "message" || decoded["role"] != "assistant" || decoded["stop_reason"] != "end_turn" {
		t.Fatalf("bad messages envelope: %s", bodyBytes)
	}
	if !strings.Contains(string(bodyBytes), "Hello world") {
		t.Fatalf("missing output text: %s", bodyBytes)
	}
	if decoded["model"] != "trustedrouter/user-msg123" {
		t.Fatalf("message response model = %#v, want custom id", decoded["model"])
	}
	usage := decoded["usage"].(map[string]any)
	if usage["input_tokens"] != float64(2) || usage["output_tokens"] != float64(2) {
		t.Fatalf("envelope usage = %#v, want real upstream 2/2", usage)
	}

	// The native body must reach the provider verbatim: NativeContent set,
	// client max_tokens explicit, cache_control intact, raw system blocks.
	if streamer.body == nil || !streamer.body.NativeContent || !streamer.body.MaxTokensExplicit {
		t.Fatalf("provider body flags = %#v", streamer.body)
	}
	if streamer.body.MaxTokens != 99 {
		t.Fatalf("provider max_tokens = %d", streamer.body.MaxTokens)
	}
	if streamer.body.SystemRaw == nil {
		t.Fatalf("system blocks flattened — cache_control lost")
	}
	systemBlocks := streamer.body.SystemRaw.([]any)
	if got := systemBlocks[0].(map[string]any)["text"]; got != "PRIVATE messages preamble" {
		t.Fatalf("hidden preamble not prepended to native system blocks: %#v", systemBlocks)
	}
	if _, ok := systemBlocks[1].(map[string]any)["cache_control"]; !ok {
		t.Fatalf("caller system cache_control stripped: %#v", systemBlocks[1])
	}
	blocks := streamer.body.Messages[0].Content.([]any)
	if _, ok := blocks[0].(map[string]any)["cache_control"]; !ok {
		t.Fatalf("cache_control stripped: %#v", blocks[0])
	}

	deadline := time.Now().Add(time.Second)
	for settleBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(settleBody, `"route_type":"messages"`) ||
		!strings.Contains(settleBody, `"usage_estimated":false`) ||
		!strings.Contains(settleBody, `"actual_output_tokens":2`) {
		t.Fatalf("settle body missing messages metadata: %s", settleBody)
	}
}

func TestServeOneMessagesStreamingRelaysNativeSSE(t *testing.T) {
	bearer := "test-user-bearer"
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_msg_s","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-haiku-4.5","endpoint_id":"anthropic/claude-haiku-4.5@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_msg_s","cost_microdollars":7,"model":"anthropic/claude-haiku-4.5","provider":"anthropic","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"anthropic/claude-haiku-4.5","max_tokens":99,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content-type = %q", got)
	}
	stream := string(bodyBytes)
	// fakeStreamingLLM emits a native Anthropic stream → verbatim relay.
	for _, want := range []string{"event: message_start", `"text":"Hello"`, "event: message_delta", "event: message_stop"} {
		if !strings.Contains(stream, want) {
			t.Fatalf("stream missing %q: %s", want, stream)
		}
	}
	if strings.Contains(stream, "data: [DONE]") {
		t.Fatalf("OpenAI [DONE] sentinel leaked into a Messages stream: %s", stream)
	}

	deadline := time.Now().Add(time.Second)
	for settleBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(settleBody, `"route_type":"messages"`) || !strings.Contains(settleBody, `"streamed":true`) {
		t.Fatalf("settle body missing streamed messages metadata: %s", settleBody)
	}
}

func TestServeOneMessagesAcceptsLargeNativeVisionPayload(t *testing.T) {
	bearer := "test-user-bearer"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_msg","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-haiku-4.5","endpoint_id":"anthropic/claude-haiku-4.5@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_msg","cost_microdollars":7,"model":"anthropic/claude-haiku-4.5","provider":"anthropic","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	largeImageData := strings.Repeat("A", 5*1024*1024)
	requestPayload := map[string]any{
		"model":      "anthropic/claude-haiku-4.5",
		"max_tokens": 16,
		"messages": []map[string]any{{
			"role": "user",
			"content": []map[string]any{
				{"type": "text", "text": "describe the screenshot"},
				{
					"type": "image",
					"source": map[string]any{
						"type":       "base64",
						"media_type": "image/png",
						"data":       largeImageData,
					},
				},
			},
		}},
	}
	requestBody, err := json.Marshal(requestPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if len(requestBody) <= 4*1024*1024 {
		t.Fatalf("test payload len = %d, want above legacy 4MiB cap", len(requestBody))
	}

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fakeStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	writeDone := make(chan error, 1)
	go func() {
		_, err := fmt.Fprintf(
			client,
			"POST /v1/messages HTTP/1.1\r\nx-api-key: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n",
			bearer,
			len(requestBody),
		)
		if err == nil {
			_, err = client.Write(requestBody)
		}
		writeDone <- err
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write request: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out writing large vision request")
	}
	if streamer.body == nil || len(streamer.body.Messages) != 1 {
		t.Fatalf("streamer body missing messages: %#v", streamer.body)
	}
	blocks, ok := streamer.body.Messages[0].Content.([]any)
	if !ok || len(blocks) != 2 {
		t.Fatalf("content = %#v, want two native blocks", streamer.body.Messages[0].Content)
	}
	imageBlock, ok := blocks[1].(map[string]any)
	if !ok {
		t.Fatalf("image block = %#v", blocks[1])
	}
	source, ok := imageBlock["source"].(map[string]any)
	if !ok {
		t.Fatalf("image source = %#v", imageBlock["source"])
	}
	if got := source["data"]; got != largeImageData {
		t.Fatalf("large image data len = %d, want %d", len(fmt.Sprint(got)), len(largeImageData))
	}
}

type fakeStreamingLLM struct {
	model   string
	body    *types.AnthropicMessagesRequest
	options []llm.InvokeOptions
}

func (f *fakeStreamingLLM) InvokeStreaming(
	_ context.Context,
	req *types.OpenAIChatRequest,
	body *types.AnthropicMessagesRequest,
	out io.Writer,
	options ...llm.InvokeOptions,
) error {
	f.model = req.Model
	f.body = body
	f.options = options
	_, err := fmt.Fprint(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude","stop_reason":null,"usage":{"input_tokens":2,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}

type fusionEchoCall struct {
	Model         string
	Provider      string
	Endpoint      string
	LastMessage   string
	SystemMessage string
}

type fusionGatewayRecorder struct {
	mu        sync.Mutex
	authorize []map[string]any
	settle    []map[string]any
	refund    []map[string]any
}

func newFusionGatewayRecorder(t *testing.T) (*trustedrouter.Client, *fusionGatewayRecorder, func()) {
	t.Helper()
	recorder := &fusionGatewayRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode authorize payload: %v", err)
			}
			model, _ := payload["model"].(string)
			recorder.mu.Lock()
			recorder.authorize = append(recorder.authorize, payload)
			authID := len(recorder.authorize)
			recorder.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", authID),
				"workspace_id":           "ws_1",
				"api_key_hash":           "key_1",
				"model":                  model,
				"endpoint_id":            model + "@test/prepaid",
				"provider":               "test",
				"usage_type":             "Credits",
				"limit_usage_type":       "Credits",
				"route_candidates":       []any{},
				"broadcast_destinations": []any{},
			}})
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode settle payload: %v", err)
			}
			model, _ := payload["selected_model"].(string)
			recorder.mu.Lock()
			recorder.settle = append(recorder.settle, payload)
			settleID := len(recorder.settle)
			recorder.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", settleID),
				"cost_microdollars": 1,
				"model":             model,
				"provider":          "test",
			}})
		case "/internal/gateway/refund":
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode refund payload: %v", err)
			}
			recorder.mu.Lock()
			recorder.refund = append(recorder.refund, payload)
			recorder.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"refunded": true}})
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	return trustedrouter.New(server.URL, "internal-token", server.Client()), recorder, server.Close
}

type fusionEchoLLM struct {
	mu                        sync.Mutex
	calls                     []fusionEchoCall
	failModels                map[string]bool
	failProviders             map[string]bool
	refusalModels             map[string]bool
	textByModel               map[string]string
	textByLastMessageContains map[string]string
	rescueTextByModel         map[string]string
	overthinkModels           map[string]bool
	thinking                  bool
	delay                     time.Duration
	delayByModel              map[string]time.Duration
}

type advisorScriptedLLM struct {
	callAdviceFirst        bool
	callAdviceAfterAdvisor bool
	callAdviceForModels    map[string]bool
	failModels             map[string]bool
	delayByModel           map[string]time.Duration
}

func (s *advisorScriptedLLM) InvokeStreaming(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	if s.delayByModel != nil && s.delayByModel[req.Model] > 0 {
		select {
		case <-time.After(s.delayByModel[req.Model]):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.failModels != nil && s.failModels[req.Model] {
		return fmt.Errorf("scripted provider failure for %s", req.Model)
	}
	if s.callAdviceForModels != nil && s.callAdviceForModels[req.Model] {
		last := lastChatMessageText(req.Messages)
		if strings.Contains(last, "TrustedRouter advisor panel") || strings.Contains(last, "Advisor 1") || strings.Contains(last, "advisor says") {
			return writeAnthropicTextTestStream(out, req.Model, "worker final after advice from "+req.Model)
		}
		return writeAnthropicToolUseTestStream(out, advisorAdviceToolName)
	}
	switch req.Model {
	case "anthropic/claude-opus-4.8":
		if len(req.Messages) > 0 && strings.Contains(types.ContentText(req.Messages[0].Content), "worker model path failed") {
			return writeAnthropicTextTestStream(out, req.Model, "advisor final answer")
		}
		return writeAnthropicTextTestStream(out, req.Model, "advisor says check rollback and settlement")
	case "cerebras/gpt-oss-120b":
		last := lastChatMessageText(req.Messages)
		switch {
		case strings.Contains(last, "Advice budget exhausted"):
			return writeAnthropicTextTestStream(out, req.Model, "worker final after budget exhausted")
		case strings.Contains(last, "advisor says"):
			if s.callAdviceAfterAdvisor {
				return writeAnthropicToolUseTestStream(out, advisorAdviceToolName)
			}
			return writeAnthropicTextTestStream(out, req.Model, "worker final after advice")
		case s.callAdviceFirst:
			return writeAnthropicToolUseTestStream(out, advisorAdviceToolName)
		default:
			return writeAnthropicTextTestStream(out, req.Model, "simple worker answer")
		}
	default:
		return writeAnthropicTextTestStream(out, req.Model, "answer from "+req.Model)
	}
}

func testAdvisorConfig(t *testing.T) advisorConfig {
	t.Helper()
	config := advisorConfig{
		Enabled:              true,
		Depth:                defaultOrchestrationDepth,
		DepthSet:             true,
		WorkerModels:         []string{"cerebras/gpt-oss-120b"},
		AdvisorModels:        []string{"anthropic/claude-opus-4.8"},
		MaxAdviceCalls:       1,
		AdvisorMaxTokens:     1024,
		AdvisorTimeoutMS:     10000,
		BuiltInWorkerPrompt:  fallbackAdvisorWorkerPrompt,
		BuiltInAdvisorPrompt: fallbackAdvisorPrompt,
	}
	if err := normalizeAdvisorConfig(&config, &types.OpenAIChatRequest{}); err != nil {
		t.Fatalf("normalizeAdvisorConfig: %v", err)
	}
	return config
}

func writeAnthropicTextTestStream(out io.Writer, model string, text string) error {
	_, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"%s","stop_reason":null,"usage":{"input_tokens":3,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":4}}

event: message_stop
data: {"type":"message_stop"}

`, model, text)
	return err
}

func writeAnthropicToolUseTestStream(out io.Writer, name string) error {
	_, err := fmt.Fprintf(out, `event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_advisor","name":%q,"input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}

event: message_stop
data: {"type":"message_stop"}

`, name)
	return err
}

func (f *fusionEchoLLM) InvokeStreaming(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	options ...llm.InvokeOptions,
) error {
	option := llm.InvokeOptions{Model: req.Model}
	if len(options) > 0 {
		option = options[0]
	}
	delay := f.delay
	if f.delayByModel != nil && f.delayByModel[req.Model] > 0 {
		delay = f.delayByModel[req.Model]
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, fusionEchoCall{
		Model:         req.Model,
		Provider:      option.Provider,
		Endpoint:      option.EndpointID,
		LastMessage:   lastChatMessageText(req.Messages),
		SystemMessage: firstSystemMessageText(req.Messages),
	})
	f.mu.Unlock()
	if f.failProviders[option.Provider] {
		return errors.New("llm/upstream: http 429: rate limited")
	}
	if f.failModels[req.Model] {
		return errors.New("llm/upstream: http 502: provider error")
	}
	rescueRequested := strings.Contains(lastChatMessageText(req.Messages), fusionOverthinkingRescueInstruction)
	if f.overthinkModels[req.Model] && !rescueRequested {
		thinking := strings.Repeat("deliberating ", 1200)
		if _, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"%s","stop_reason":null,"usage":{"input_tokens":3,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":%q}}

`, req.Model, thinking); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return errors.New("test overthinking stream was not canceled")
		}
	}
	text := "analysis from " + req.Model
	if f.refusalModels[req.Model] {
		text = "I'm sorry, but I can't help with that."
	} else if len(req.Messages) > 0 &&
		strings.Contains(types.ContentText(req.Messages[len(req.Messages)-1].Content), "Panel answers:") &&
		strings.Contains(types.ContentText(req.Messages[len(req.Messages)-1].Content), "Judge analysis JSON:") {
		text = "final answer from " + req.Model
	}
	lastMessage := lastChatMessageText(req.Messages)
	for needle, override := range f.textByLastMessageContains {
		if strings.Contains(lastMessage, needle) {
			text = override
			break
		}
	}
	if override, ok := f.textByModel[req.Model]; ok {
		text = override
	}
	if rescueRequested {
		if override, ok := f.rescueTextByModel[req.Model]; ok {
			text = override
		}
	}
	thinkingEvents := ""
	if f.thinking {
		thinkingEvents = fmt.Sprintf(`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":%q}}

`, "thinking from "+req.Model)
	}
	_, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"%s","stop_reason":null,"usage":{"input_tokens":3,"output_tokens":0}}}

%s
event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":4}}

event: message_stop
data: {"type":"message_stop"}

`, req.Model, thinkingEvents, text)
	return err
}

func lastChatMessageText(messages []types.OpenAIChatMessage) string {
	if len(messages) == 0 {
		return ""
	}
	return types.ContentText(messages[len(messages)-1].Content)
}

func firstSystemMessageText(messages []types.OpenAIChatMessage) string {
	for _, message := range messages {
		if message.Role == "system" {
			return types.ContentText(message.Content)
		}
	}
	return ""
}

type fallbackAttempt struct {
	Model    string
	Provider string
	Endpoint string
}

type fallbackStreamingLLM struct {
	attempts []fallbackAttempt
}

func (f *fallbackStreamingLLM) InvokeStreaming(
	_ context.Context,
	req *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	options ...llm.InvokeOptions,
) error {
	option := llm.InvokeOptions{Model: req.Model}
	if len(options) > 0 {
		option = options[0]
	}
	f.attempts = append(f.attempts, fallbackAttempt{
		Model:    req.Model,
		Provider: option.Provider,
		Endpoint: option.EndpointID,
	})
	if len(f.attempts) == 1 {
		return errors.New("llm/upstream: http 429: rate limited")
	}
	_, err := fmt.Fprint(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude","stop_reason":null,"usage":{"input_tokens":2,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Fallback"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" success"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}

// TestServeOneRetriesLastCandidateOnTransientError covers the resilience fix: a
// single-candidate model (no fallover) that hits a transient upstream error (429)
// is RETRIED on the same provider instead of immediately 502-ing. This is what
// made slow reasoning models (gpt-5.x) intermittently 502 under load.
func TestServeOneRetriesLastCandidateOnTransientError(t *testing.T) {
	bearer := "test-user-bearer"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			// SINGLE route candidate -> nothing to fall over to.
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_auto","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-5.5","endpoint_id":"openai/gpt-5.5@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[{"model":"openai/gpt-5.5","endpoint_id":"openai/gpt-5.5@openai/prepaid","provider":"openai","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			_ = body
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_auto","cost_microdollars":12,"model":"openai/gpt-5.5","provider":"openai","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &fallbackStreamingLLM{} // 429 on first attempt, succeeds on the second
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/auto","stream":false,"messages":[{"role":"user","content":"hi"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(client, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", bearer, len(requestBody), requestBody)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s (transient 429 should have been retried, not 502)", resp.StatusCode, bodyBytes)
	}
	if len(streamer.attempts) != 2 {
		t.Fatalf("attempts = %d, want 2 (same candidate retried once)", len(streamer.attempts))
	}
	if streamer.attempts[0].Model != "openai/gpt-5.5" || streamer.attempts[1].Model != "openai/gpt-5.5" {
		t.Fatalf("expected both attempts on the same single candidate: %#v", streamer.attempts)
	}
}

type panicStreamingLLM struct {
	t *testing.T
}

func (p *panicStreamingLLM) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	_ io.Writer,
	_ ...llm.InvokeOptions,
) error {
	p.t.Helper()
	p.t.Fatal("provider should not be called")
	return nil
}

func TestServeOneTrustedRouterGatewayAuthorizesBYOKAndSettles(t *testing.T) {
	t.Setenv("CEREBRAS_TEST_KEY", "csk-live-from-env")
	bearer := "test-user-bearer"
	var authorizeBody string
	var settleBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-trustedrouter-internal-token") != "internal-token" {
			t.Fatalf("missing internal token")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			authorizeBody = string(body)
			if strings.Contains(authorizeBody, bearer) || strings.Contains(authorizeBody, "private prompt") {
				t.Fatalf("authorize leaked secret material: %s", authorizeBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"cerebras/llama3.1-8b","endpoint_id":"cerebras/llama3.1-8b@cerebras/byok","provider":"cerebras","usage_type":"BYOK","limit_usage_type":"BYOK","byok_secret_ref":"env://CEREBRAS_TEST_KEY","byok_cache_key":null,"byok_encrypted_secret":null,"route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, "Hello") || strings.Contains(settleBody, "private prompt") {
				t.Fatalf("settle leaked content: %s", settleBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	reg := auth.New(nil)
	streamer := &fakeStreamingLLM{}
	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	serverConn, client := net.Pipe()
	defer client.Close()

	go serveOne(context.Background(), serverConn, reg, streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"cerebras/llama3.1-8b","stream":true,"messages":[{"role":"user","content":"private prompt"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, bodyBytes)
	}
	_, _ = io.ReadAll(resp.Body)

	if !strings.Contains(authorizeBody, `"api_key_lookup_hash"`) {
		t.Fatalf("authorize did not use lookup hash: %s", authorizeBody)
	}
	if !strings.Contains(settleBody, `"selected_endpoint":"cerebras/llama3.1-8b@cerebras/byok"`) {
		t.Fatalf("settle did not include selected endpoint: %s", settleBody)
	}
	if len(streamer.options) != 1 || streamer.options[0].ProviderAPIKey != "csk-live-from-env" {
		t.Fatalf("provider key option = %#v", streamer.options)
	}
}

func TestServeOneTrustedRouterProviderErrorDoesNotReturnEmptyStream(t *testing.T) {
	bearer := "test-user-bearer"
	var refundBody string
	var settleCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_fail","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/refund":
			refundBody = string(body)
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		case "/internal/gateway/settle":
			settleCalled = true
			t.Fatalf("settle should not be called after provider failure: %s", body)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), &failingStreamingLLM{}, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"anthropic/claude-3-5-sonnet","stream":true,"messages":[{"role":"user","content":"private prompt"}],"max_tokens":32,"metadata":{"trustedrouter_synthetic":"true"}}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"type":"provider_error"`) ||
		!strings.Contains(body, `"source":"provider"`) ||
		!strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("stream did not expose stable provider error: %s", body)
	}
	if strings.Contains(body, "private prompt") {
		t.Fatalf("stream leaked prompt: %s", body)
	}
	deadline := time.Now().Add(time.Second)
	for refundBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if refundBody == "" {
		t.Fatal("expected provider failure to refund authorization")
	}
	if !strings.Contains(refundBody, `"metadata":{"trustedrouter_synthetic":"true"}`) {
		t.Fatalf("refund missing synthetic metadata: %s", refundBody)
	}
	if settleCalled {
		t.Fatal("settle was called after provider failure")
	}
}

func TestServeOneResponsesProviderErrorClosesPartialStream(t *testing.T) {
	bearer := "test-user-bearer"
	var refundBody string
	var settleCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_fail","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/refund":
			refundBody = string(body)
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		case "/internal/gateway/settle":
			settleCalled = true
			t.Fatalf("settle should not be called after provider failure: %s", body)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), &failingStreamingLLM{}, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"anthropic/claude-3-5-sonnet","input":"private response input","stream":true,"max_output_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "event: response.failed") ||
		!strings.Contains(body, `"type":"provider_error"`) ||
		!strings.Contains(body, `"source":"provider"`) ||
		!strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("responses stream did not close with stable failure: %s", body)
	}
	if strings.Contains(body, "private response input") {
		t.Fatalf("stream leaked input: %s", body)
	}
	deadline := time.Now().Add(time.Second)
	for refundBody == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if refundBody == "" {
		t.Fatal("expected provider failure to refund authorization")
	}
	if settleCalled {
		t.Fatal("settle was called after provider failure")
	}
}

func TestServeOneStreamsChunkedOpenAISSEFromInsideEnclave(t *testing.T) {
	bearer := "test-bearer"
	digest := sha256.Sum256([]byte(bearer))
	reg := auth.New([]types.DeviceConfig{{
		KeyHash:  hex.EncodeToString(digest[:]),
		Owner:    "test",
		DeviceID: "device-1",
	}})
	llm := &fakeStreamingLLM{}
	server, client := net.Pipe()
	defer client.Close()

	go serveOne(context.Background(), server, reg, llm, nil, nil, nil, nil)

	requestBody := []byte(`{"model":"claude-sonnet-4-6","stream":true,"messages":[{"role":"system","content":"private system"},{"role":"user","content":"private prompt"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer,
		len(requestBody),
		requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", got)
	}
	if got := resp.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("net/http should decode chunked transfer, got Transfer-Encoding header %q", got)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("missing OpenAI SSE done marker: %q", body)
	}
	if !strings.Contains(body, `"content":"Hello"`) || !strings.Contains(body, `"content":" world"`) {
		t.Fatalf("missing streamed content deltas: %q", body)
	}
	if strings.Contains(body, "private prompt") || strings.Contains(body, "private system") {
		t.Fatalf("response leaked prompt bytes: %q", body)
	}
	if llm.model != "claude-sonnet-4-6" {
		t.Fatalf("llm model = %q", llm.model)
	}
	if llm.body == nil || llm.body.System != "private system" || len(llm.body.Messages) != 1 {
		serialized, _ := json.Marshal(llm.body)
		t.Fatalf("bad transformed body: %s", serialized)
	}
}

type failingStreamingLLM struct{}

func (f *failingStreamingLLM) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	_ io.Writer,
	_ ...llm.InvokeOptions,
) error {
	return errors.New("provider exploded")
}
