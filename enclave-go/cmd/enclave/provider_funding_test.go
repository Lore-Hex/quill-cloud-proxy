package main

import (
	"bufio"
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

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// Venice's reply when TrustedRouter's Venice account ran dry (incident
// 2026-11-18). It reached customers verbatim for about five hours.
const veniceOutOfFundsBody = `{"error":{"message":"Insufficient USD or Diem balance to complete request. Visit https://venice.ai/settings/api to add credits."}}`

func veniceOutOfFunds(usageType string) error {
	return withInvokeAttemptError(
		fmt.Errorf("llm/venice: %w", &upstreamerror.Error{Status: 402, Body: veniceOutOfFundsBody}),
		llm.InvokeOptions{Model: "z-ai/glm-5-3-flash-uncensored", Provider: "venice", UsageType: usageType,
			EndpointID: "z-ai/glm-5-3-flash-uncensored@venice/" + strings.ToLower(map[string]string{"Credits": "prepaid", "BYOK": "byok"}[usageType])},
	)
}

func assertNoProviderTopUpText(t *testing.T, body string) {
	t.Helper()
	for _, leaked := range []string{"venice.ai", "add credits", "Insufficient", "Diem"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("customer-facing error carries the provider's top-up text %q: %s", leaked, body)
		}
	}
}

func TestPrepaidProviderOutOfFundsIsANeutralUnavailableError(t *testing.T) {
	err := veniceOutOfFunds("Credits")
	if !prepaidFundingFailure(err) {
		t.Fatal("prepaidFundingFailure = false for a prepaid Venice 402")
	}
	status, message := upstreamErrorResponse(err)
	if status != http.StatusServiceUnavailable || message != providerFundingUnavailableMessage {
		t.Fatalf("upstreamErrorResponse = %d %q", status, message)
	}
	status, body := providerErrorBody(err, &trustedrouter.Authorization{})
	encoded, _ := json.Marshal(body)
	if status != http.StatusServiceUnavailable || body["status"] != http.StatusServiceUnavailable {
		t.Fatalf("providerErrorBody status = %d body=%s", status, encoded)
	}
	if _, ok := body["metadata"]; ok {
		t.Fatalf("providerErrorBody kept provider metadata: %s", encoded)
	}
	assertNoProviderTopUpText(t, string(encoded))
	if got := failureReason(err); got != "provider_funding" {
		t.Fatalf("failureReason = %q, want provider_funding", got)
	}

	// The streaming terminal frame renders through the same body.
	var stream strings.Builder
	if writeErr := writeStreamingProviderError(&stream, "chat.completions", "chatcmpl-1", "m", err, false); writeErr != nil {
		t.Fatal(writeErr)
	}
	assertNoProviderTopUpText(t, stream.String())
}

func TestBYOKProviderOutOfFundsStaysTheCustomersOwnMessage(t *testing.T) {
	// A BYOK route runs on the customer's own Venice account: the top-up
	// message is about their account and theirs to read.
	err := veniceOutOfFunds("BYOK")
	if prepaidFundingFailure(err) {
		t.Fatal("prepaidFundingFailure = true for a BYOK route")
	}
	status, message := upstreamErrorResponse(err)
	if status != 402 || !strings.Contains(message, "add credits") {
		t.Fatalf("upstreamErrorResponse = %d %q", status, message)
	}
	if got := failureReason(err); got != "provider_error" {
		t.Fatalf("failureReason = %q, want provider_error", got)
	}
}

func TestOrdinaryProviderErrorsKeepTheirStatusAndMessage(t *testing.T) {
	err := withInvokeAttemptError(
		&upstreamerror.Error{Status: 400, Body: `{"error":{"message":"max_tokens is too large"}}`},
		llm.InvokeOptions{Provider: "venice", UsageType: "Credits"},
	)
	if prepaidFundingFailure(err) {
		t.Fatal("prepaidFundingFailure = true for a plain 400")
	}
	if status, message := upstreamErrorResponse(err); status != 400 || message != "max_tokens is too large" {
		t.Fatalf("upstreamErrorResponse = %d %q", status, message)
	}
}

type outOfFundsStreamingLLM struct {
	mu       sync.Mutex
	attempts []llm.InvokeOptions
}

func (f *outOfFundsStreamingLLM) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	_ io.Writer,
	options ...llm.InvokeOptions,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(options) > 0 {
		f.attempts = append(f.attempts, options[0])
	}
	return fmt.Errorf("llm/venice: %w", &upstreamerror.Error{Status: 402, Body: veniceOutOfFundsBody})
}

// End to end through serveOne: a Venice-only model whose one prepaid route is
// out of funds answers 503 with no Venice text, and the refund tells the
// control plane the provider account ran dry.
func TestServeOnePrepaidProviderOutOfFundsNeverReachesTheCustomer(t *testing.T) {
	var mu sync.Mutex
	var refund map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_venice","workspace_id":"ws_1","api_key_hash":"key_1","model":"z-ai/glm-5-3-flash-uncensored","endpoint_id":"z-ai/glm-5-3-flash-uncensored@venice/prepaid","provider":"venice","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[{"model":"z-ai/glm-5-3-flash-uncensored","endpoint_id":"z-ai/glm-5-3-flash-uncensored@venice/prepaid","provider":"venice","usage_type":"Credits"}]}}`)
		case "/internal/gateway/refund":
			mu.Lock()
			_ = json.Unmarshal(body, &refund)
			mu.Unlock()
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		default:
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	streamer := &outOfFundsStreamingLLM{}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"z-ai/glm-5-3-flash-uncensored","stream":false,"messages":[{"role":"user","content":"hi"}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-user-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody), requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	assertNoProviderTopUpText(t, body)
	if !strings.Contains(body, providerFundingUnavailableMessage) {
		t.Fatalf("body lacks the neutral message: %s", body)
	}
	if len(streamer.attempts) == 0 || streamer.attempts[0].UsageType != "Credits" {
		t.Fatalf("attempts = %#v", streamer.attempts)
	}
	mu.Lock()
	defer mu.Unlock()
	if refund == nil {
		t.Fatal("no refund reached the control plane")
	}
	encoded, _ := json.Marshal(refund)
	if !strings.Contains(string(encoded), `"provider_funding"`) {
		t.Fatalf("refund does not report provider_funding: %s", encoded)
	}
	assertNoProviderTopUpText(t, string(encoded))
}
