package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/authcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestBillingBackoffHandler(t *testing.T) {
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "5000")
	t.Setenv("QUILL_KEEPALIVE", "off")
	var calls, validations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/gateway/authorize" {
			calls.Add(1)
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(402)
			_, _ = io.WriteString(w, `{"error":{"type":"insufficient_credits","message":"Insufficient credits: top up"}}`)
		} else {
			validations.Add(1)
			_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws-test","api_key_hash":"credential-test"}}`)
		}
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	body := `{"model":"test-model","messages":[{"role":"user","content":"private prompt"}]}`
	request := func(key, header, requestBody, path string) ([]byte, string) {
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", path, key, header, len(requestBody), requestBody)
		conn := newScriptedConn(raw, nil)
		logs := captureStderr(t, func() {
			serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
		})
		return append([]byte(nil), conn.writes.Bytes()...), logs
	}
	first, logs := request("private-key", "", body, "/v1/chat/completions")
	if !bytes.Contains(first, []byte("HTTP/1.1 402 ")) {
		t.Fatalf("expected 402: %s", first)
	}
	for _, event := range []string{"request_accept", "request_start", "request_end"} {
		if strings.Count(logs, "enclave."+event) != 1 {
			t.Fatalf("ordinary request missing %s: %s", event, logs)
		}
	}
	initialValidations := validations.Load()
	for range 8 {
		got, hitLogs := request("private-key", "", body, "/v1/chat/completions")
		if !bytes.Equal(got, first) {
			t.Fatalf("cached response bytes differ:\n got %q\nwant %q", got, first)
		}
		if strings.Contains(hitLogs, "enclave.request_") {
			t.Fatalf("suppressed request emitted per-request log: %s", hitLogs)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("authorize calls=%d, want 1", calls.Load())
	}
	if validations.Load() != initialValidations {
		t.Fatal("suppressed request performed identity lookup")
	}
	before := calls.Load()
	request("private-key", "Idempotency-Key: replay\r\n", body, "/v1/chat/completions")
	if calls.Load() != before+1 {
		t.Fatal("idempotency-key request did not reach authorize")
	}
	// The current chat adapter rejects the JSON field. Bypass preserves its
	// ordinary 400 instead of masking it with a cached 402.
	bodyKey := strings.TrimSuffix(body, "}") + `,"idempotency_key":"body-replay"}`
	bodyResponse, bodyLogs := request("private-key", "", bodyKey, "/v1/chat/completions")
	if !bytes.Contains(bodyResponse, []byte("HTTP/1.1 400 ")) || !strings.Contains(bodyLogs, "enclave.request_start") {
		t.Fatalf("body idempotency did not bypass cache: %s / %s", bodyResponse, bodyLogs)
	}

	before = calls.Load()
	request("different-private-key", "", body, "/v1/chat/completions")
	if calls.Load() != before+1 {
		t.Fatal("different credential did not reach authorize")
	}
	// Wait only in this integration test; cache boundary tests use a supplied clock.
	time.Sleep(5 * time.Second)
	before = calls.Load()
	_, logs = request("private-key", "", body, "/v1/chat/completions")
	if calls.Load() != before+1 {
		t.Fatal("expired window did not reach authorize")
	}
	if strings.Count(logs, `enclave.billing_402_backoff credential_id="credential-test" credential_fingerprint="`+trustedrouter.LookupHash("private-key")+`" suppressed=8 window_ms=5000`) != 1 {
		t.Fatalf("missing single window summary: %s", logs)
	}
	if strings.Contains(logs, "private-key") || strings.Contains(logs, "private prompt") {
		t.Fatalf("secret in logs: %s", logs)
	}
	_, logs = request("private-key", "", body, "/v1/chat/completions")
	if strings.Contains(logs, "billing_402_backoff") {
		t.Fatalf("duplicate summary: %s", logs)
	}
}

func TestBillingBackoffCredentialCacheUntouched(t *testing.T) {
	c := authcache.New(time.Minute, 2)
	err := &trustedrouter.ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402, Type: "insufficient_credits"}
	if c.Remember(trustedrouter.LookupHash("key"), err, time.Now()) || c.Len() != 0 {
		t.Fatal("billing denial entered credential cache")
	}
}

func TestBillingBackoffIdempotencyAndRoutes(t *testing.T) {
	for _, tc := range []struct {
		header, body string
		want         bool
	}{{"replay", `{}`, true}, {"", `{"idempotency_key":"key"}`, true}, {"", `{}`, false}, {"", `{`, true}} {
		if got := billingBackoffIdempotent(tc.header, []byte(tc.body)); got != tc.want {
			t.Fatalf("idempotency bypass=%v, want %v", got, tc.want)
		}
	}
	for _, route := range []string{"/health", "/attestation", "/v1/key", "/v1/models", "/v1/batches", "/v1/responses/input_tokens", "/unknown"} {
		if billingBackoffRoute("POST", route) || billingBackoffRoute("GET", route) {
			t.Fatalf("non-inference route cached: %s", route)
		}
	}
}

func TestBillingBackoffHandlerScope(t *testing.T) {
	for _, tc := range []struct {
		name, kind, ttl string
		status          int
	}{{"key-limit", "key_limit", "5000", 402}, {"budget", "budget_exceeded", "5000", 402}, {"disabled", "insufficient_credits", "0", 402}, {"invalid-key", "invalid_api_key", "5000", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QUILL_BILLING_402_BACKOFF_MS", tc.ttl)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/internal/gateway/authorize" {
					calls.Add(1)
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, `{"error":{"type":%q,"message":"denied"}}`, tc.kind)
				} else {
					_, _ = io.WriteString(w, `{"data":{}}`)
				}
			}))
			defer server.Close()
			gateway := trustedrouter.New(server.URL, "internal", server.Client())
			body := `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`
			for range 2 {
				raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer scope-key\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				conn := newScriptedConn(raw, nil)
				logs := captureStderr(t, func() {
					serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
				})
				if !strings.Contains(logs, "enclave.request_end") {
					t.Fatalf("ordinary request log suppressed: %s", logs)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("authorize calls=%d, want 2 for uncached %s", calls.Load(), tc.name)
			}
		})
	}
}

func TestBillingBackoffResponseRenderers(t *testing.T) {
	for _, route := range []string{"/v1/chat/completions", "/v1/messages", "/api/alpha/decide"} {
		for _, keepAlive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/keepalive=%v", route, keepAlive), func(t *testing.T) {
				denial := &trustedrouter.ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402, Type: "insufficient_credits", Message: "top up", RetryAfter: "12"}
				cache := trustedrouter.NewBillingBackoff(5*time.Second, 2)
				key := trustedrouter.NewBillingBackoffKey(trustedrouter.LookupHash("renderer-key"), "POST", route, nil)
				first := newScriptedConn("", nil)
				stats := &responseStatsConn{Conn: first}
				stats.BeginRequest(testRequestLogID)
				stats.SetResponseKeepAlive(keepAlive)
				stats.billingDenial = func(err error) { cache.Remember(key, "credential", testRequestLogID, false, err, time.Now()) }
				if route == "/v1/messages" {
					writeAnthropicGatewayAuthorizationError(stats, denial)
				} else if isDecidePath(route) {
					writeDecideFailure(stats, 402, "route-specific fallback", denial, false)
				} else {
					writeGatewayAuthorizationError(stats, denial)
				}
				rejection, hit := cache.Get(key, false, time.Now())
				if !hit {
					t.Fatal("renderer did not remember authorize denial")
				}
				second := newScriptedConn("", nil)
				replay := &responseStatsConn{Conn: second}
				replay.BeginRequest(rejection.RequestID)
				replay.SetResponseKeepAlive(keepAlive)
				writeBillingBackoff(replay, route, rejection)
				if !bytes.Equal(first.writes.Bytes(), second.writes.Bytes()) {
					t.Fatalf("response bytes differ:\n%s\n%s", first.writes.Bytes(), second.writes.Bytes())
				}
				status, n := replay.Snapshot()
				if status != 402 || n != second.writes.Len() || replay.ResponseReusable() != keepAlive {
					t.Fatalf("response accounting changed: status=%d bytes=%d reusable=%v", status, n, replay.ResponseReusable())
				}
			})
		}
	}
}
