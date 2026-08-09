package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// The status code cannot answer the only question a retrying client needs
// answered: did a provider already run? A 502 from "could not reach the
// provider" and a 502 from "the generation succeeded, then settlement failed"
// look identical, and they call for opposite behaviour. x-should-retry is how
// the gateway says which one this is.

func headerOf(t *testing.T, raw []byte, name string) string {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("parse response: %v (raw=%q)", err, raw)
	}
	defer resp.Body.Close()
	return resp.Header.Get(name)
}

func TestWriteSpentErrorTellsClientsNotToRetry(t *testing.T) {
	var buf bytes.Buffer
	writeSpentError(&buf, 502, "settlement failed")
	if got := headerOf(t, buf.Bytes(), "x-should-retry"); got != "false" {
		t.Fatalf("x-should-retry = %q, want %q", got, "false")
	}
}

func TestWriteRetryableErrorTellsClientsToRetry(t *testing.T) {
	var buf bytes.Buffer
	writeRetryableError(&buf, 503, "model catalog unavailable")
	if got := headerOf(t, buf.Bytes(), "x-should-retry"); got != "true" {
		t.Fatalf("x-should-retry = %q, want %q", got, "true")
	}
}

func TestPlainWriteErrorStaysSilentSoClientsKeepTheirDefaults(t *testing.T) {
	// Emitting the header everywhere would mean guessing. Where the gateway
	// does not know whether a provider ran, it must say nothing and let the
	// SDK apply its own status heuristics.
	var buf bytes.Buffer
	writeError(&buf, 500, "something went wrong")
	if got := headerOf(t, buf.Bytes(), "x-should-retry"); got != "" {
		t.Fatalf("x-should-retry = %q, want it absent", got)
	}
}

// TestSettlementFailureAfterGenerationIsNotRetryable is the case this whole
// header exists for. The provider ran, we owe money for those tokens, and
// settlement then failed with a 502 — the exact status every TrustedRouter SDK
// treats as safe to move to another domain on. Re-sending regenerates and we
// pay twice.
func TestSettlementFailureAfterGenerationIsNotRetryable(t *testing.T) {
	bearer := "test-user-bearer"
	settleCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_chat","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleCalls++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"error":{"message":"settlement backend unavailable"}}`)
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

	requestBody := []byte(`{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"hello"}],"max_tokens":32}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer, len(requestBody), requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if settleCalls == 0 {
		t.Fatal("settlement was never attempted; this test is not exercising the post-generation path")
	}
	if streamer.body == nil {
		t.Fatal("the provider was never invoked; this test is not exercising the post-generation path")
	}
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := resp.Header.Get("x-should-retry"); got != "false" {
		t.Fatalf("x-should-retry = %q, want %q: a client will move this billed "+
			"request to another domain and pay for a second generation", got, "false")
	}
}
