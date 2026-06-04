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
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
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

func TestRetryableInvokeErrorFailsOverExceptOnBadRequests(t *testing.T) {
	// Retryable — fail over to the next authorized provider. Includes the
	// cases the previous allowlist silently missed: 404 (model not on this
	// provider's account, e.g. Cerebras + Llama), 401/403 (key unwired for
	// this provider, e.g. Together via the gateway), and connection-level /
	// timeout errors.
	retryable := []error{
		errors.New("llm/upstream: http 502: bad gateway"),
		errors.New("llm/upstream: http 503: service unavailable"),
		errors.New("llm/upstream: http 429: rate limited"),
		errors.New("llm/upstream: http 404: model not found"),
		errors.New("llm/upstream: http 401: unauthorized"),
		errors.New("llm/upstream: http 403: forbidden"),
		errors.New("llm/together: http client unavailable: dial tcp: connection refused"),
		errors.New("unexpected EOF"),
		errors.New("context deadline exceeded"),
	}
	for _, err := range retryable {
		if !retryableInvokeError(err) {
			t.Errorf("retryableInvokeError(%q) = false, want true (should fail over)", err)
		}
	}
	// Non-retryable — a malformed/oversized request every provider rejects the
	// same way, so failing over is pointless.
	for _, err := range []error{
		errors.New("llm/upstream: http 400: bad request"),
		errors.New("llm/upstream: http 422: unprocessable entity"),
	} {
		if retryableInvokeError(err) {
			t.Errorf("retryableInvokeError(%q) = true, want false (no failover)", err)
		}
	}
	if retryableInvokeError(nil) {
		t.Error("retryableInvokeError(nil) = true, want false")
	}
}

func TestNonRetryableUpstreamStatus(t *testing.T) {
	for _, s := range []int{400, 413, 422} {
		if !nonRetryableUpstreamStatus(s) {
			t.Errorf("nonRetryableUpstreamStatus(%d) = false, want true", s)
		}
	}
	for _, s := range []int{401, 403, 404, 408, 429, 500, 502, 503} {
		if nonRetryableUpstreamStatus(s) {
			t.Errorf("nonRetryableUpstreamStatus(%d) = true, want false (retryable)", s)
		}
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
			if strings.Contains(authorizeBody, bearer) || strings.Contains(authorizeBody, "private response input") {
				t.Fatalf("authorize leaked sensitive material: %s", authorizeBody)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_resp","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleBody = string(body)
			if strings.Contains(settleBody, "Hello") || strings.Contains(settleBody, "private response input") {
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

	requestBody := []byte(`{"model":"openai/gpt-4o-mini","input":"private response input","instructions":"be brief","max_output_tokens":32}`)
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
	if streamer.body == nil || streamer.body.System != "be brief" {
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

	requestBody := []byte(`{"model":"anthropic/claude-3-5-sonnet","stream":true,"messages":[{"role":"user","content":"private prompt"}],"max_tokens":32}`)
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
	if !strings.Contains(body, `"type":"provider_error"`) || !strings.Contains(body, "data: [DONE]\n\n") {
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
	if !strings.Contains(body, "event: response.failed") || !strings.Contains(body, `"type":"provider_error"`) || !strings.Contains(body, "data: [DONE]\n\n") {
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
