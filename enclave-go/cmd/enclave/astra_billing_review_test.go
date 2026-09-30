package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/authcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// No listening sockets: the review sandbox does not permit loopback listeners.
type astraTransport func(*http.Request) (*http.Response, error)

func (f astraTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func astraResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": {"7"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func astraGateway(t *testing.T) *trustedrouter.Client {
	t.Helper()
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "5000")
	return trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/internal/gateway/authorize" {
			return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"top up"}}`), nil
		}
		return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
	})})
}

const astraChat = `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`

func astraRaw(route, body, headers string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer review-key\r\n%sContent-Length: %d\r\n\r\n%s", route, headers, len(body), body)
}

func astraRequest(t *testing.T, gateway *trustedrouter.Client, route, body, headers string) ([]byte, string) {
	t.Helper()
	conn := newScriptedConn(astraRaw(route, body, headers+"Connection: close\r\n"), nil)
	logs := captureStderr(t, func() {
		serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
	})
	return append([]byte(nil), conn.writes.Bytes()...), logs
}

func TestAstraBillingPreservesValidation(t *testing.T) {
	for _, route := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/embeddings", "/v1/images", "/api/alpha/decide"} {
		t.Run(route, func(t *testing.T) {
			gateway := astraGateway(t)
			cold, _ := astraRequest(t, gateway, route, `{"model":42}`, "")
			if parseHTTPStatus(cold) != 400 {
				t.Fatalf("baseline: %s", cold)
			}
			first, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
			if parseHTTPStatus(first) != 402 {
				t.Fatalf("seed: %s", first)
			}
			warm, _ := astraRequest(t, gateway, route, `{"model":42}`, "")
			if parseHTTPStatus(warm) != 400 {
				t.Fatalf("cached gate replaced ordinary 400 with %d", parseHTTPStatus(warm))
			}
		})
	}
}

func TestAstraBillingHonorsKnownRevocation(t *testing.T) {
	gateway := astraGateway(t)
	negative := authcache.New(time.Minute, 10)
	gateway.SetCredentialGuard(abuse.NewProtector(negative, nil))
	first, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
	if parseHTTPStatus(first) != 402 {
		t.Fatalf("seed: %s", first)
	}
	// A concurrent/idempotent/metadata request learned that the key was revoked.
	negative.Remember(trustedrouter.LookupHash("review-key"), &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key"}, time.Now())
	warm, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
	if parseHTTPStatus(warm) != 401 {
		t.Fatalf("known revoked key got %d, want 401", parseHTTPStatus(warm))
	}
	for _, event := range []string{"request_accept", "request_start", "request_end"} {
		if strings.Count(logs, "enclave."+event) != 1 {
			t.Fatalf("known rejection missing %s: %s", event, logs)
		}
	}
	key := trustedrouter.NewBillingBackoffKey(trustedrouter.LookupHash("review-key"), "POST", "/v1/chat/completions", []byte(astraChat))
	if _, hit := gateway.BillingBackoff().Get(key, false, time.Now()); hit {
		t.Fatal("known rejection retained billing entry")
	}
	bypass, _ := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "Idempotency-Key: check\r\n")
	if parseHTTPStatus(bypass) != 401 {
		t.Fatalf("baseline: %s", bypass)
	}
	warm, _ = astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
	if parseHTTPStatus(warm) != 401 {
		t.Fatalf("known revoked key got %d, want 401", parseHTTPStatus(warm))
	}
}

func TestAstraBillingSuppressesAllPerRequestLogs(t *testing.T) {
	gateway := astraGateway(t)
	astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
	_, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "User-Agent: "+strings.Repeat("x", 257)+"\r\n")
	if logs != "" {
		t.Fatalf("suppressed request logged: %s", logs)
	}
}

func TestAstraBillingKeepAliveLifecycle(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	gateway := astraGateway(t)
	// First denial installs the callback, hit must not install/retain it, next
	// idempotent request must remain ordinary, and final close must be honored.
	raw := astraRaw("/v1/chat/completions", astraChat, "") + astraRaw("/v1/chat/completions", astraChat, "") + astraRaw("/v1/chat/completions", astraChat, "Idempotency-Key: replay\r\nConnection: close\r\n")
	conn := newScriptedConn(raw, nil)
	logs := captureStderr(t, func() {
		serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
	})
	reader := bufio.NewReader(bytes.NewReader(conn.writes.Bytes()))
	var firstID string
	for i := 0; i < 3; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 402 || resp.Close != (i == 2) {
			t.Fatalf("response %d: status=%d close=%v", i, resp.StatusCode, resp.Close)
		}
		id := resp.Header.Get("x-request-id")
		if i == 0 {
			firstID = id
		} else if i == 1 && id != firstID {
			t.Fatal("cached ID changed")
		} else if i == 2 && id == firstID {
			t.Fatal("ordinary ID reused")
		}
	}
	for _, event := range []string{"request_accept", "request_start", "request_end"} {
		if strings.Count(logs, "enclave."+event) != 2 {
			t.Fatalf("lost/extra %s: %s", event, logs)
		}
	}
}

func TestAstraBillingBeginRequestClearsCallback(t *testing.T) {
	conn := &responseStatsConn{Conn: newScriptedConn("", nil)}
	conn.billingDenial = func(error) { t.Fatal("previous request's callback survived") }
	conn.BeginRequest("next")
	writeGatewayAuthorizationError(conn, &trustedrouter.ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402, Type: "insufficient_credits"})
}

func TestAstraBillingAllRouteWireParity(t *testing.T) {
	for route, body := range map[string]string{
		"/v1/chat/completions": astraChat,
		"/v1/responses":        `{"model":"test-model","input":"hi"}`,
		"/v1/messages":         `{"model":"test-model","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"/v1/embeddings":       `{"model":"test-model","input":"hi"}`,
		"/v1/images":           `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`,
		"/api/alpha/decide":    decideBody,
	} {
		t.Run(route, func(t *testing.T) {
			gateway := astraGateway(t)
			first, _ := astraRequest(t, gateway, route, body, "")
			second, logs := astraRequest(t, gateway, route, body, "")
			if parseHTTPStatus(first) != 402 || !bytes.Equal(first, second) || strings.Contains(logs, "enclave.request_") {
				t.Fatalf("wire mismatch or not suppressed:\n%s\n%s\n%s", first, second, logs)
			}
		})
	}
}

func TestAstraBillingAffordableRequestAfterExpensiveDenial(t *testing.T) {
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "5000")
	gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/internal/gateway/authorize" {
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				return nil, err
			}
			// Same balance throughout: the large reservation does not fit, the
			// small one does. Mirrors the router's reservation-based rejection.
			if request["max_output_tokens"].(float64) > 100 {
				return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"Insufficient credits"}}`), nil
			}
			return astraResponse(200, `{"data":{"authorization_id":"auth","model":"test-model","endpoint_id":"test","provider":"test","usage_type":"Credits"}}`), nil
		}
		return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
	})})
	small := strings.TrimSuffix(astraChat, "}") + `,"max_tokens":10}`
	large := strings.TrimSuffix(astraChat, "}") + `,"max_tokens":1000}`
	cold, _ := astraRequest(t, gateway, "/v1/chat/completions", small, "")
	if parseHTTPStatus(cold) != 200 {
		t.Fatalf("affordable baseline: %s", cold)
	}
	denied, _ := astraRequest(t, gateway, "/v1/chat/completions", large, "")
	if parseHTTPStatus(denied) != 402 {
		t.Fatalf("large baseline: %s", denied)
	}
	warm, _ := astraRequest(t, gateway, "/v1/chat/completions", small, "")
	if parseHTTPStatus(warm) != 200 {
		t.Fatalf("same affordable request now got %d, want 200", parseHTTPStatus(warm))
	}
}

func TestAstraBillingConcurrentMissesLogged(t *testing.T) {
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "5000")
	const n = 8
	entered, release := make(chan struct{}, n), make(chan struct{})
	gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/internal/gateway/authorize" {
			entered <- struct{}{}
			<-release
			return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"top up"}}`), nil
		}
		return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
	})})
	logs := captureStderr(t, func() {
		var wg sync.WaitGroup
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn := newScriptedConn(astraRaw("/v1/chat/completions", astraChat, "Connection: close\r\n"), nil)
				serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
			}()
		}
		for range n {
			<-entered
		}
		close(release)
		wg.Wait()
		conn := newScriptedConn(astraRaw("/v1/chat/completions", astraChat, "Connection: close\r\n"), nil)
		serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
	})
	for _, event := range []string{"request_accept", "request_start", "request_end"} {
		if strings.Count(logs, "enclave."+event) != n {
			t.Fatalf("lost real log or logged hit: %s", logs)
		}
	}
}

func TestAstraBillingConfidentialValidationPrecedesHit(t *testing.T) {
	gateway := astraGateway(t)
	astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
	got, logs := astraRequest(t, gateway, "/v1/images", `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`, "Host: api.confidential.trustedrouter.com\r\n")
	if parseHTTPStatus(got) != 400 || !strings.Contains(string(got), "confidential_route_unsupported") || !strings.Contains(logs, "enclave.request_end") {
		t.Fatalf("confidential validation masked: %s / %s", got, logs)
	}
}

func TestAstraBillingDifferentBodiesEachAuthorize(t *testing.T) {
	t.Setenv("QUILL_BILLING_402_BACKOFF_MS", "5000")
	calls := 0
	gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/internal/gateway/authorize" {
			calls++
			return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"top up"}}`), nil
		}
		return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
	})})
	for _, body := range []string{astraChat, strings.Replace(astraChat, "hello", "different", 1)} {
		before := calls
		first, _ := astraRequest(t, gateway, "/v1/chat/completions", body, "")
		if calls != before+1 || parseHTTPStatus(first) != 402 {
			t.Fatalf("different body authorize calls=%d, want %d; response=%s", calls, before+1, first)
		}
		again, logs := astraRequest(t, gateway, "/v1/chat/completions", body, "")
		if calls != before+1 || !bytes.Equal(first, again) || logs != "" {
			t.Fatalf("identical body was not silently reused: calls=%d logs=%s", calls, logs)
		}
	}
}
