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
	"strings"
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

func TestServeOneTrustedRouterFusionRunsPanelJudgeAndFinal(t *testing.T) {
	bearer := "test-user-bearer"
	privatePrompt := "private fusion prompt"
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
			authorizeCalls = append(authorizeCalls, payload)
			model := payload["model"].(string)
			endpoint := model + "@test/prepaid"
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"authorization_id":       fmt.Sprintf("auth_fusion_%d", len(authorizeCalls)),
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
			settleCalls = append(settleCalls, payload)
			model, _ := payload["selected_model"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"settled":           true,
				"generation_id":     fmt.Sprintf("gen_fusion_%d", len(settleCalls)),
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
	if !strings.Contains(body, `"model":"z-ai/glm-5.2"`) || !strings.Contains(body, "final answer from z-ai/glm-5.2") {
		t.Fatalf("fusion response did not use selectable judge/final model: %s", body)
	}
	if len(authorizeCalls) != 4 {
		t.Fatalf("authorize calls = %d, want panel+panel+judge+final", len(authorizeCalls))
	}
	wantModels := []string{"google/gemini-3-flash-preview", "moonshotai/kimi-k2.7-code", "z-ai/glm-5.2", "z-ai/glm-5.2"}
	wantRoutes := []string{"fusion.panel", "fusion.panel", "fusion.judge", "fusion.final"}
	for i := range wantModels {
		if authorizeCalls[i]["model"] != wantModels[i] || authorizeCalls[i]["route_type"] != wantRoutes[i] {
			t.Fatalf("authorize[%d] = %#v, want model=%q route=%q", i, authorizeCalls[i], wantModels[i], wantRoutes[i])
		}
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

func TestServeOneFusionCodeRoutesCodeKimiInPanelAndJudge(t *testing.T) {
	// End-to-end (mocked upstream + gateway, no real API calls): a
	// trustedrouter/fusion-code request uses the DEFAULT panel + judge, so the
	// kimi-k2.6 -> kimi-k2.7-code swap must show up in the authorize calls for
	// the panel and the judge, and the general Kimi must never be authorized.
	var authorizeCalls []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			authorizeCalls = append(authorizeCalls, payload)
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
		failModels:    map[string]bool{"model/judge-fails": true},
		refusalModels: map[string]bool{"model/judge-refuses": true},
	}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"model":"model/final","fallback_judges":["model/judge-fails","model/judge-refuses","model/judge-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
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
	if len(settleCalls) != 4 {
		t.Fatalf("settle calls = %d, want panel+refusal judge+good judge+final", len(settleCalls))
	}
	if len(refundCalls) != 1 {
		t.Fatalf("refund calls = %d, want failed judge refund", len(refundCalls))
	}
	wantRoutes := []string{"fusion.panel", "fusion.judge", "fusion.judge", "fusion.judge", "fusion.final"}
	for i, want := range wantRoutes {
		if got, _ := authorizeCalls[i]["route_type"].(string); got != want {
			t.Fatalf("authorize[%d].route_type = %q, want %q", i, got, want)
		}
	}
	if len(streamer.calls) != 7 {
		t.Fatalf("provider calls = %#v, want 7 including upstream retries", streamer.calls)
	}
	gotModels := []string{}
	for _, call := range streamer.calls {
		gotModels = append(gotModels, call.Model)
	}
	wantModels := []string{"model/panel", "model/judge-fails", "model/judge-fails", "model/judge-fails", "model/judge-refuses", "model/judge-good", "model/final"}
	if strings.Join(gotModels, ",") != strings.Join(wantModels, ",") {
		t.Fatalf("provider models = %#v, want %#v", gotModels, wantModels)
	}
	finalPrompt := streamer.calls[len(streamer.calls)-1].LastMessage
	if !strings.Contains(finalPrompt, "analysis from model/judge-good") {
		t.Fatalf("final prompt did not use successful judge analysis: %s", finalPrompt)
	}
	if strings.Contains(finalPrompt, "model/judge-refuses") || strings.Contains(finalPrompt, "I'm sorry, but I can't help with that.") {
		t.Fatalf("final prompt included rejected judge output: %s", finalPrompt)
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
		failModels:    map[string]bool{"model/final-fails": true},
		refusalModels: map[string]bool{"model/final-refuses": true},
	}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"user","content":"private fusion prompt"}],"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["model/panel"],"judge_models":["model/judge-good"],"final_models":["model/final-fails","model/final-refuses","model/final-good"],"max_completion_tokens":64}}],"max_tokens":32}`)
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
		"model/final-fails",
		"model/final-refuses",
		"model/final-good",
	}
	if strings.Join(gotModels, ",") != strings.Join(wantModels, ",") {
		t.Fatalf("provider models = %#v, want %#v", gotModels, wantModels)
	}
}

func TestServeOneTrustedRouterFusionContinuesAfterOnePanelFails(t *testing.T) {
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
	fusionTool := map[string]any{"type": trustedRouterFusionTool, "parameters": map[string]any{}}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterFusionModel,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "weather in Paris?"}},
		Tools:    []any{fnTool, fusionTool},
	}
	out := fusionPanelRequest(req, "some/model", 0, 0)
	if len(out.Tools) != 1 {
		t.Fatalf("panel tools = %d, want 1 (function tool kept, fusion config tool stripped)", len(out.Tools))
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
}

func TestFusionPanelRequestNoToolsClearsToolChoice(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
	}
	out := fusionPanelRequest(req, "some/model", 0, 0)
	if len(out.Tools) != 0 {
		t.Fatalf("panel tools = %d, want 0", len(out.Tools))
	}
	if out.ToolChoice != nil {
		t.Fatalf("ToolChoice should be nil when no function tools are present")
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
	if !reflect.DeepEqual(judgeModels, []string{"moonshotai/kimi-k2.6", "minimax/minimax-m3"}) {
		t.Fatalf("judgeModels = %#v, want Kimi K2.6 with M3 fallback", judgeModels)
	}

	// trustedrouter/fusion-code is fusion with the code-tuned Kimi: it is a
	// recognized fusion request, and the swap turns the general kimi-k2.6 into
	// kimi-k2.7-code across the real default panel + judge — and ONLY the Kimi
	// (non-Kimi models like the glm-5.2/m3 synthesizer are left untouched).
	if _, requested, err := fusionConfigForRequest(&types.OpenAIChatRequest{Model: trustedRouterFusionCodeModel}); err != nil || !requested {
		t.Fatalf("fusion-code must be a recognized fusion request: requested=%v err=%v", requested, err)
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
	final := fusionFinalRequest(req, "anthropic/claude-opus-4.8", `{"final_guidance":"call setup"}`, nil)
	if len(final.Tools) != 1 {
		t.Fatalf("final tools = %#v, want only non-fusion tool", final.Tools)
	}
	last := final.Messages[len(final.Messages)-1]
	text := types.ContentText(last.Content)
	if !strings.Contains(text, "emit the tool call directly") || strings.Contains(text, "write the final answer") {
		t.Fatalf("bad tool final instruction: %s", text)
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
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_msg","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-haiku-4.5","endpoint_id":"anthropic/claude-haiku-4.5@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
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

	requestBody := []byte(`{"model":"anthropic/claude-haiku-4.5","max_tokens":99,"system":[{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"private prompt","cache_control":{"type":"ephemeral"}}]}]}`)
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
	Model       string
	Provider    string
	Endpoint    string
	LastMessage string
}

type fusionEchoLLM struct {
	calls         []fusionEchoCall
	failModels    map[string]bool
	refusalModels map[string]bool
}

func (f *fusionEchoLLM) InvokeStreaming(
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
	f.calls = append(f.calls, fusionEchoCall{
		Model:       req.Model,
		Provider:    option.Provider,
		Endpoint:    option.EndpointID,
		LastMessage: lastChatMessageText(req.Messages),
	})
	if f.failModels[req.Model] {
		return errors.New("llm/upstream: http 502: provider error")
	}
	text := "analysis from " + req.Model
	if f.refusalModels[req.Model] {
		text = "I'm sorry, but I can't help with that."
	} else if len(req.Messages) > 0 && strings.Contains(types.ContentText(req.Messages[len(req.Messages)-1].Content), "TrustedRouter Fusion panel answers and judge analysis follow") {
		text = "final answer from " + req.Model
	}
	_, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"%s","stop_reason":null,"usage":{"input_tokens":3,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":4}}

event: message_stop
data: {"type":"message_stop"}

`, req.Model, text)
	return err
}

func lastChatMessageText(messages []types.OpenAIChatMessage) string {
	if len(messages) == 0 {
		return ""
	}
	return types.ContentText(messages[len(messages)-1].Content)
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
