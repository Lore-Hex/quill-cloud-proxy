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
	if !strings.Contains(body, `"model":"z-ai/glm-5.2"`) || !strings.Contains(body, "final answer from z-ai/glm-5.2") {
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

func TestRunSocratesNoAdviceReturnsWorkerAnswer(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &socratesScriptedLLM{}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "what is 1+1?"}},
	}
	config := testSocratesConfig(t)

	final, workers, advisors, adviceCalls, budgetExhausted, err := runSocrates(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_socrates_simple", "log_socrates_simple", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runSocrates: %v", err)
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
	if len(recorder.authorize) != 1 || recorder.authorize[0]["route_type"] != "socrates.worker" {
		t.Fatalf("authorize calls = %#v, want one socrates.worker", recorder.authorize)
	}
}

func TestRunSocratesAdviceOnceThenWorkerFinal(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &socratesScriptedLLM{callAdviceFirst: true}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "review this risky migration"}},
	}
	config := testSocratesConfig(t)

	final, workers, advisors, adviceCalls, budgetExhausted, err := runSocrates(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_socrates_advice", "log_socrates_advice", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runSocrates: %v", err)
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
	want := []string{"socrates.worker", "socrates.advisor", "socrates.worker"}
	if !reflect.DeepEqual(routeTypes, want) {
		t.Fatalf("route types = %#v, want %#v", routeTypes, want)
	}
}

func TestRunSocratesWorkerFallbackUsesDistinctIdempotencyKeys(t *testing.T) {
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &socratesScriptedLLM{failModels: map[string]bool{"cerebras/gpt-oss-120b": true}}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "reply pong"}},
	}
	config := testSocratesConfig(t)
	config.WorkerModels = []string{"cerebras/gpt-oss-120b", "deepseek/deepseek-v4-flash"}

	final, workers, advisors, adviceCalls, budgetExhausted, err := runSocrates(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_socrates_fallback", "log_socrates_fallback", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runSocrates: %v", err)
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

func TestRunSocratesAdviceBudgetExhaustedThenAnswer(t *testing.T) {
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	streamer := &socratesScriptedLLM{callAdviceFirst: true, callAdviceAfterAdvisor: true}
	req := &types.OpenAIChatRequest{
		Model:    trustedRouterSocrates10Model,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard task"}},
	}
	config := testSocratesConfig(t)

	final, _, _, adviceCalls, budgetExhausted, err := runSocrates(context.Background(), streamer, req, config, trGateway, nil, "bearer", "req_socrates_budget", "log_socrates_budget", nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("runSocrates: %v", err)
	}
	if got := strings.TrimSpace(final.Result.Text); got != "worker final after budget exhausted" {
		t.Fatalf("final text = %q", got)
	}
	if adviceCalls != 1 || !budgetExhausted {
		t.Fatalf("adviceCalls=%d budgetExhausted=%t, want 1 true", adviceCalls, budgetExhausted)
	}
}

func TestSocratesRejectsReservedToolCollision(t *testing.T) {
	err := rejectSocratesToolCollision([]any{
		map[string]any{"type": "function", "function": map[string]any{"name": socratesAdviceToolName}},
	}, nil)
	if err == nil {
		t.Fatal("expected reserved tool collision error")
	}
	var aerr *adapter.AdapterError
	if !asAdapterErr(err, &aerr) || aerr.Status != 400 {
		t.Fatalf("error = %v, want 400 adapter error", err)
	}
}

func TestNormalizeSocratesConfigDepthBounds(t *testing.T) {
	config := testSocratesConfig(t)
	config.Depth = maxOrchestrationDepth + 1
	config.DepthSet = true
	err := normalizeSocratesConfig(&config, &types.OpenAIChatRequest{})
	if err == nil {
		t.Fatal("expected depth bounds error")
	}
	var aerr *adapter.AdapterError
	if !asAdapterErr(err, &aerr) || aerr.Status != 400 {
		t.Fatalf("error = %v, want 400 adapter error", err)
	}
}

func TestSocratesPromptSecretsRequiredInProductionGCP(t *testing.T) {
	t.Setenv("QUILL_GCP_PROJECT_ID", "trusted-router-prod")
	t.Setenv("TR_ALLOW_DEFAULT_SOCRATES_PROMPTS", "")
	t.Setenv("TR_REQUIRE_SOCRATES_PROMPTS", "")
	if !socratesPromptsRequired() {
		t.Fatalf("GCP runtime should require Socrates prompt secrets")
	}

	t.Setenv("TR_ALLOW_DEFAULT_SOCRATES_PROMPTS", "1")
	if socratesPromptsRequired() {
		t.Fatalf("explicit local override should allow fallback prompts")
	}

	t.Setenv("QUILL_GCP_PROJECT_ID", "")
	t.Setenv("TR_REQUIRE_SOCRATES_PROMPTS", "1")
	if !socratesPromptsRequired() {
		t.Fatalf("explicit require flag should require Socrates prompt secrets")
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
		{trustedRouterZeus10Model, "frontier", fusionFrontierPanel, false},
		{trustedRouterIrisCodeModel, "budget", fusionBudgetPanel, true},
		{trustedRouterPrometheusCodeModel, "quality", fusionQualityPanel, true},
		{trustedRouterZeusCodeModel, "frontier", fusionFrontierPanel, true},
		{trustedRouterIrisCode10Model, "budget", fusionBudgetPanel, true},
		{trustedRouterPrometheusCode10Model, "quality", fusionQualityPanel, true},
		{trustedRouterZeusCode10Model, "frontier", fusionFrontierPanel, true},
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
	Model       string
	Provider    string
	Endpoint    string
	LastMessage string
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
	mu                sync.Mutex
	calls             []fusionEchoCall
	failModels        map[string]bool
	failProviders     map[string]bool
	refusalModels     map[string]bool
	textByModel       map[string]string
	rescueTextByModel map[string]string
	overthinkModels   map[string]bool
	thinking          bool
	delay             time.Duration
}

type socratesScriptedLLM struct {
	callAdviceFirst        bool
	callAdviceAfterAdvisor bool
	failModels             map[string]bool
}

func (s *socratesScriptedLLM) InvokeStreaming(
	_ context.Context,
	req *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	if s.failModels != nil && s.failModels[req.Model] {
		return fmt.Errorf("scripted provider failure for %s", req.Model)
	}
	switch req.Model {
	case "anthropic/claude-opus-4.8":
		return writeAnthropicTextTestStream(out, req.Model, "advisor says check rollback and settlement")
	case "cerebras/gpt-oss-120b":
		last := lastChatMessageText(req.Messages)
		switch {
		case strings.Contains(last, "Advice budget exhausted"):
			return writeAnthropicTextTestStream(out, req.Model, "worker final after budget exhausted")
		case strings.Contains(last, "advisor says"):
			if s.callAdviceAfterAdvisor {
				return writeAnthropicToolUseTestStream(out, socratesAdviceToolName)
			}
			return writeAnthropicTextTestStream(out, req.Model, "worker final after advice")
		case s.callAdviceFirst:
			return writeAnthropicToolUseTestStream(out, socratesAdviceToolName)
		default:
			return writeAnthropicTextTestStream(out, req.Model, "simple worker answer")
		}
	default:
		return writeAnthropicTextTestStream(out, req.Model, "answer from "+req.Model)
	}
}

func testSocratesConfig(t *testing.T) socratesConfig {
	t.Helper()
	config := socratesConfig{
		Enabled:              true,
		Depth:                defaultOrchestrationDepth,
		DepthSet:             true,
		WorkerModels:         []string{"cerebras/gpt-oss-120b"},
		AdvisorModels:        []string{"anthropic/claude-opus-4.8"},
		MaxAdviceCalls:       1,
		AdvisorMaxTokens:     1024,
		AdvisorTimeoutMS:     10000,
		BuiltInWorkerPrompt:  fallbackSocratesWorkerPrompt,
		BuiltInAdvisorPrompt: fallbackSocratesAdvisorPrompt,
	}
	if err := normalizeSocratesConfig(&config, &types.OpenAIChatRequest{}); err != nil {
		t.Fatalf("normalizeSocratesConfig: %v", err)
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
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_socrates","name":%q,"input":{}}}

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
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, fusionEchoCall{
		Model:       req.Model,
		Provider:    option.Provider,
		Endpoint:    option.EndpointID,
		LastMessage: lastChatMessageText(req.Messages),
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
