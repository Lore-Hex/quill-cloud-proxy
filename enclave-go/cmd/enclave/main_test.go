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

func TestServeOneResponsesNonStreamingReturnsResponseAndSettles(t *testing.T) {
	bearer := "sk-tr-v1-user-secret"
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

func TestServeOneResponsesNonStreamingFailsClosedWhenSettleFails(t *testing.T) {
	bearer := "sk-tr-v1-user-secret"
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
		"response.output_item.added",
		"response.content_part.added",
		"response.output_text.delta",
		"response.output_text.done",
		"response.output_item.done",
		"response.completed",
	} {
		if !strings.Contains(body, "event: "+eventName) {
			t.Fatalf("missing %s in stream: %s", eventName, body)
		}
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

	_, _, _, _, err := readRequest(server)
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

func TestServeOneTrustedRouterGatewayAuthorizesBYOKAndSettles(t *testing.T) {
	t.Setenv("CEREBRAS_TEST_KEY", "csk-live-from-env")
	bearer := "sk-tr-v1-user-secret"
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
	bearer := "sk-tr-v1-user-secret"
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
	bearer := "sk-tr-v1-user-secret"
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
