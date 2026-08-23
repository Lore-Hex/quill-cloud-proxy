package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAuthorizeRetryStaysOnAuthorityThatReceivedFirstAttempt(t *testing.T) {
	const (
		primaryHost  = "127.0.0.1:18081"
		fallbackHost = "127.0.0.1:18082"
	)
	primaryAttempts, fallbackAttempts, fallbackAuthorizeAttempts := 0, 0, 0
	response := func(request *http.Request, status int, body string) *http.Response {
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}
	}
	client := New(
		"http://"+primaryHost+",http://"+fallbackHost,
		"internal",
		&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Host {
			case primaryHost:
				primaryAttempts++
				if primaryAttempts == 1 {
					return nil, &dialFailure{err: errors.New("primary unavailable")}
				}
				return response(request, http.StatusOK, `{"data":{"authorization_id":"auth_wrong_authority"}}`), nil
			case fallbackHost:
				fallbackAttempts++
				switch request.URL.Path {
				case "/internal/gateway/authorize":
					fallbackAuthorizeAttempts++
					if fallbackAuthorizeAttempts == 1 {
						return response(request, http.StatusServiceUnavailable, `{"error":{"message":"retry here","type":"service_unavailable"}}`), nil
					}
					return response(request, http.StatusOK, `{"data":{"authorization_id":"auth_fallback"}}`), nil
				case "/internal/gateway/settle":
					return response(request, http.StatusOK, `{"data":{"generation_id":"gen_fallback","settled":true}}`), nil
				case "/internal/gateway/refund":
					return response(request, http.StatusOK, `{"data":{"settled":true}}`), nil
				default:
					t.Fatalf("unexpected fallback path %q", request.URL.Path)
					return nil, errors.New("unexpected fallback path")
				}
			default:
				t.Fatalf("unexpected host %q", request.URL.Host)
				return nil, errors.New("unexpected host")
			}
		})},
	)
	client.authorizeRetry = retryPolicy{
		attempts: 3,
		sleep:    func(context.Context, time.Duration) error { return nil },
	}

	authorization, err := client.Authorize(
		t.Context(),
		"sk-test",
		&qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"},
	)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authorization.AuthorizationID != "auth_fallback" {
		t.Fatalf("authorization id = %q, want fallback authority result", authorization.AuthorizationID)
	}
	settled, err := client.Settle(t.Context(), authorization, Usage{InputTokens: 1, OutputTokens: 1})
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if settled.GenerationID != "gen_fallback" {
		t.Fatalf("generation id = %q, want fallback authority result", settled.GenerationID)
	}
	if err := client.Refund(t.Context(), authorization, 502, "provider_error", 0.01, nil); err != nil {
		t.Fatalf("Refund: %v", err)
	}
	if primaryAttempts != 1 {
		t.Fatalf("primary attempts = %d, want 1; retry/finalization must not move after fallback responded", primaryAttempts)
	}
	if fallbackAuthorizeAttempts != 2 || fallbackAttempts != 4 {
		t.Fatalf("fallback attempts = %d (%d authorize), want 4 (2 authorize)", fallbackAttempts, fallbackAuthorizeAttempts)
	}
}

func TestAuthorizeRetriesTransientControlPlaneFailureWithStableIdempotencyKey(t *testing.T) {
	var attempts int
	var idempotencyKeys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		idempotencyKeys = append(idempotencyKeys, fmt.Sprint(payload["idempotency_key"]))
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"message":"transient database contention","type":"service_unavailable"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_retry","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"endpoint_1","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	client.authorizeRetry = retryPolicy{
		attempts: 3,
		sleep:    func(context.Context, time.Duration) error { return nil },
	}
	auth, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{
		Model:    "openai/gpt-4o-mini",
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "private input"}},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.AuthorizationID != "auth_retry" || attempts != 2 {
		t.Fatalf("authorization = %#v, attempts = %d", auth, attempts)
	}
	if len(idempotencyKeys) != 2 || idempotencyKeys[0] == "" || idempotencyKeys[0] != idempotencyKeys[1] {
		t.Fatalf("idempotency keys = %#v, want one stable non-empty key", idempotencyKeys)
	}
}

func TestAuthorizeDoesNotRetryRateLimit(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"message":"daily spend limit exceeded","type":"key_window_limit_exceeded"}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	client.authorizeRetry = retryPolicy{
		attempts: 3,
		sleep:    func(context.Context, time.Duration) error { return nil },
	}
	_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"})
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("err = %#v, want 429 ControlPlaneError", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestAuthorizeTransientRetryIsBounded(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":{"message":"still contended","type":"service_unavailable"}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	client.authorizeRetry = retryPolicy{
		attempts: 3,
		sleep:    func(context.Context, time.Duration) error { return nil },
	}
	_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"})
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %#v, want final 503 ControlPlaneError", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestAuthorizeEmbeddingsRetriesWithCallerIdempotencyKey(t *testing.T) {
	attempts := 0
	var idempotencyKeys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if payload["route_type"] != "embeddings" {
			t.Fatalf("route_type = %v, want embeddings", payload["route_type"])
		}
		idempotencyKeys = append(idempotencyKeys, fmt.Sprint(payload["idempotency_key"]))
		if attempts == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = io.WriteString(w, `{"error":{"message":"gateway timeout","type":"service_unavailable"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_embedding","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/text-embedding-3-small","endpoint_id":"endpoint_1","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	client.authorizeRetry = retryPolicy{
		attempts: 3,
		sleep:    func(context.Context, time.Duration) error { return nil },
	}
	auth, err := client.AuthorizeEmbeddings(t.Context(), "sk-test", &qtypes.EmbeddingRequest{
		Model:          "openai/text-embedding-3-small",
		Input:          "private embedding input",
		IdempotencyKey: "caller-idem",
	}, 6)
	if err != nil {
		t.Fatalf("AuthorizeEmbeddings: %v", err)
	}
	if auth.AuthorizationID != "auth_embedding" || attempts != 2 {
		t.Fatalf("authorization = %#v, attempts = %d", auth, attempts)
	}
	if len(idempotencyKeys) != 2 || idempotencyKeys[0] != "caller-idem" || idempotencyKeys[1] != "caller-idem" {
		t.Fatalf("idempotency keys = %#v, want caller-idem twice", idempotencyKeys)
	}
}

func TestAuthorizeRetryBudgetReturnsOriginalControlPlaneError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":{"message":"database contention","type":"service_unavailable"}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	client.authorizeRetry = retryPolicy{
		attempts:    3,
		maxDelay:    time.Second,
		totalBudget: 10 * time.Millisecond,
		sleep: func(ctx context.Context, _ time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"})
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %#v, want original 503 ControlPlaneError", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 before retry budget expired", attempts)
	}
}

func TestAuthorizeRetryDelayIsExponentialBoundedAndHonorsRetryAfter(t *testing.T) {
	policy := retryPolicy{baseDelay: 500 * time.Millisecond, maxDelay: 4 * time.Second}
	first := authorizationRetryDelay(1, policy, time.Second)
	second := authorizationRetryDelay(2, policy, time.Second)
	late := authorizationRetryDelay(20, policy, time.Second)
	if first != time.Second {
		t.Fatalf("first delay = %v, want Retry-After floor of 1s", first)
	}
	if second < time.Second || second > 2*time.Second {
		t.Fatalf("second delay = %v, want [1s, 2s]", second)
	}
	if late < time.Second || late > 4*time.Second {
		t.Fatalf("late delay = %v, want [1s, 4s]", late)
	}
}
