package trustedrouter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type settlementTransport func(*http.Request) (*http.Response, error)

func (f settlementTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func settlementResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"settled":true,"cost_microdollars":7,"generation_id":"gen_once"}}`))}
}

func TestSettleRecoversLostAcknowledgementWithoutChangingAuthorityOrBody(t *testing.T) {
	for _, failure := range []error{syscall.ECONNRESET, syscall.EPIPE, io.EOF, io.ErrUnexpectedEOF} {
		t.Run(failure.Error(), func(t *testing.T) {
			var bodies []string
			commits := make(map[string]bool)
			client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "trustedrouter.com" || r.URL.Path != "/internal/gateway/settle" {
					t.Fatalf("wrong endpoint: %s", r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, string(body))
				commits[string(body)] = true
				if len(bodies) == 1 {
					return nil, failure
				}
				return settlementResponse(200), nil
			})})
			result, err := client.Settle(context.Background(), &Authorization{AuthorizationID: "auth_once", Model: "model"}, Usage{RequestID: "request_once", InputTokens: 3, OutputTokens: 4})
			if err != nil || result == nil || result.GenerationID != "gen_once" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if len(bodies) != 2 || bodies[0] != bodies[1] || len(commits) != 1 {
				t.Fatalf("attempts=%d distinct commits=%d", len(bodies), len(commits))
			}
		})
	}
}

func TestSettleRetryNeverMovesToAnotherBillingDatabase(t *testing.T) {
	var hosts []string
	client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Host)
		if len(hosts) == 1 {
			return nil, syscall.ECONNRESET
		}
		return nil, &dialFailure{err: errors.New("connection refused")}
	})})
	client.baseURLs = []string{"https://trustedrouter.com", "https://other-billing.example"}
	auth := &Authorization{AuthorizationID: "auth_once"}
	auth.pinControlPlaneEndpoint(0)
	_, err := client.Settle(context.Background(), auth, Usage{})
	if err == nil || len(hosts) != 2 {
		t.Fatalf("hosts=%v err=%v", hosts, err)
	}
	for _, host := range hosts {
		if host != "trustedrouter.com" {
			t.Fatalf("cross-authority retry: %v", hosts)
		}
	}
}

func TestSettleRetryIsBoundedAndDoesNotRetryPermanentErrors(t *testing.T) {
	for _, tc := range []struct {
		name             string
		failure          error
		status, attempts int
	}{
		{"reset", syscall.ECONNRESET, 0, 3},
		{"cancelled", context.Canceled, 0, 1},
		{"deadline", context.DeadlineExceeded, 0, 1},
		{"unknown", errors.New("invalid certificate"), 0, 1},
		{"bad request", nil, 400, 1},
		{"forbidden", nil, 403, 1},
		{"conflict", nil, 409, 1},
		{"unavailable remains with durable retry queue", nil, 503, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(*http.Request) (*http.Response, error) {
				attempts++
				if tc.failure != nil {
					return nil, tc.failure
				}
				return settlementResponse(tc.status), nil
			})})
			_, err := client.Settle(context.Background(), &Authorization{AuthorizationID: "auth_once"}, Usage{})
			if err == nil || attempts != tc.attempts {
				t.Fatalf("attempts=%d err=%v", attempts, err)
			}
		})
	}
}

func TestSettleDoesNotReplayAnUnpinnedMultiAuthorityFailure(t *testing.T) {
	var attempts int
	client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(*http.Request) (*http.Response, error) {
		attempts++
		return nil, syscall.ECONNRESET
	})})
	client.baseURLs = append(client.baseURLs, "https://other-billing.example")
	_, err := client.Settle(context.Background(), &Authorization{AuthorizationID: "auth_once"}, Usage{})
	if err == nil || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestSettleRetryHonorsCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	attempts := 0
	client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(r *http.Request) (*http.Response, error) {
		attempts++
		<-r.Context().Done()
		return nil, fmt.Errorf("transport: %w", r.Context().Err())
	})})
	started := time.Now()
	_, err := client.Settle(ctx, &Authorization{AuthorizationID: "auth_once"}, Usage{})
	if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 || time.Since(started) > time.Second {
		t.Fatalf("attempts=%d elapsed=%v err=%v", attempts, time.Since(started), err)
	}
}

func TestSettleRetriesAfterServerCommitsAndClosesConnection(t *testing.T) {
	var requests, commits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if requests.Add(1) == 1 {
			commits.Add(1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, `{"data":{"already_settled":true,"settled":true,"finalization_outcome":"settled","generation_id":"gen_once","cost_microdollars":7}}`)
	}))
	t.Cleanup(server.Close)
	result, err := New(server.URL, "internal", server.Client()).Settle(context.Background(), &Authorization{AuthorizationID: "auth_once"}, Usage{})
	if err != nil || result == nil || !result.AlreadySettled || result.CostMicrodollars != 7 || requests.Load() != 2 || commits.Load() != 1 {
		t.Fatalf("result=%+v err=%v requests=%d commits=%d", result, err, requests.Load(), commits.Load())
	}
}

func TestSettleHasItsOwnTotalBudget(t *testing.T) {
	client := New("https://trustedrouter.com", "internal", &http.Client{Transport: settlementTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > settlementRetryBudget || time.Until(deadline) <= 0 {
			t.Fatalf("missing or unbounded settlement deadline: %v %v", deadline, ok)
		}
		return settlementResponse(200), nil
	})})
	if _, err := client.Settle(context.Background(), &Authorization{AuthorizationID: "auth_once"}, Usage{}); err != nil {
		t.Fatal(err)
	}
}
