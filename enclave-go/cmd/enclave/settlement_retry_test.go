package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// settleArrivals is a control plane that records when each settle arrives.
func settleArrivals(t *testing.T) (*trustedrouter.Client, <-chan time.Time) {
	t.Helper()
	arrivals := make(chan time.Time, 8)
	gateway := trustedrouter.New("http://127.0.0.1:18080", "internal-test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/internal/gateway/settle" {
			return nil, errors.New("unexpected path: " + r.URL.Path)
		}
		arrivals <- time.Now()
		return &http.Response{
			StatusCode: 200, Header: make(http.Header), Request: r,
			Body: io.NopCloser(strings.NewReader(`{"data":{"cost_microdollars":15,"disposition":"finalized"}}`)),
		}, nil
	})})
	return gateway, arrivals
}

func TestSettlementRetryQueueHoldsAbandonedSettlePastRouterBudget(t *testing.T) {
	t.Setenv("QUILL_SETTLEMENT_RETRY_QUEUE_SIZE", "")
	q := newSettlementRetryQueueFromEnv()
	// quill-router: _BILLING_PATH_SPANNER_BUDGET_SECONDS (20 s) bounds a settle,
	// and _ROLLBACK_FLOOR_SECONDS (2 s) bounds its rollback after that budget.
	routerSettleBound := 20*time.Second + 2*time.Second
	if q.abandonedDelay != abandonedSettleRetryDelay || q.abandonedDelay <= routerSettleBound {
		t.Fatalf("abandoned delay = %s, want %s > router bound %s", q.abandonedDelay, abandonedSettleRetryDelay, routerSettleBound)
	}
}

func TestSettlementRetryAfterAbandonedSettleWaitsForDelay(t *testing.T) {
	for name, cause := range map[string]error{
		"deadline": context.DeadlineExceeded,
		"canceled": context.Canceled,
		"wrapped":  fmt.Errorf("settle: %w", context.DeadlineExceeded),
	} {
		t.Run(name, func(t *testing.T) {
			gateway, arrivals := settleArrivals(t)
			const delay = 150 * time.Millisecond
			q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1, abandonedDelay: delay}
			q.Start(t.Context())
			enqueued := time.Now()
			if !q.Enqueue(settlementRetryJob{
				trGateway: gateway, authorization: &trustedrouter.Authorization{AuthorizationID: "auth_abandoned"},
				requestLogID: "abandoned", cause: cause,
			}) {
				t.Fatal("abandoned settle retry was not accepted")
			}
			if len(q.jobs) != 0 || q.deferred.Load() != 1 {
				t.Fatalf("queued=%d deferred=%d, want the retry held off the queue", len(q.jobs), q.deferred.Load())
			}
			select {
			case arrived := <-arrivals:
				if waited := arrived.Sub(enqueued); waited < delay {
					t.Fatalf("retry sent after %s, before the %s delay", waited, delay)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("deferred retry was never sent")
			}
			deadline := time.Now().Add(time.Second)
			for q.deferred.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if q.deferred.Load() != 0 {
				t.Fatalf("deferred=%d after delivery", q.deferred.Load())
			}
		})
	}
}

func TestSettlementRetryAfterRealErrorKeepsImmediateTiming(t *testing.T) {
	for name, cause := range map[string]error{
		"5xx":        &trustedrouter.ControlPlaneError{Path: "/internal/gateway/settle", StatusCode: http.StatusServiceUnavailable},
		"reset":      fmt.Errorf("post: %w", syscall.ECONNRESET),
		"eof":        io.ErrUnexpectedEOF,
		"rejected":   &trustedrouter.ControlPlaneError{Path: "/internal/gateway/settle", StatusCode: http.StatusBadRequest},
		"unreported": nil,
	} {
		t.Run(name, func(t *testing.T) {
			gateway, arrivals := settleArrivals(t)
			q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1, abandonedDelay: time.Hour}
			if !q.Enqueue(settlementRetryJob{
				trGateway: gateway, authorization: &trustedrouter.Authorization{AuthorizationID: "auth_error"},
				requestLogID: "error", cause: cause,
			}) {
				t.Fatal("retry was not accepted")
			}
			if len(q.jobs) != 1 || q.deferred.Load() != 0 {
				t.Fatalf("queued=%d deferred=%d, want an immediate retry", len(q.jobs), q.deferred.Load())
			}
			job := <-q.jobs
			if !job.notBefore.IsZero() || job.cause != nil {
				t.Fatalf("job kept notBefore=%s cause=%v", job.notBefore, job.cause)
			}
			started := time.Now()
			q.process(t.Context(), job)
			select {
			case arrived := <-arrivals:
				if waited := arrived.Sub(started); waited > time.Second {
					t.Fatalf("error-caused retry waited %s", waited)
				}
			default:
				t.Fatal("error-caused retry was not sent")
			}
		})
	}
}

func TestSettlementRetryDeferOnlyAppliesToFirstAttempt(t *testing.T) {
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 3, abandonedDelay: time.Hour}
	// A worker re-enqueue after a failed retry has used its own 28 s budget,
	// longer than the router's, so nothing can still be running.
	if !q.Enqueue(settlementRetryJob{attempt: 2, requestLogID: "second", cause: context.DeadlineExceeded}) {
		t.Fatal("second attempt was not accepted")
	}
	if len(q.jobs) != 1 || q.deferred.Load() != 0 {
		t.Fatalf("queued=%d deferred=%d, want the backoff schedule unchanged", len(q.jobs), q.deferred.Load())
	}
}

func TestSettlementRetryDeferOverflowQueuesImmediately(t *testing.T) {
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1), maxAttempts: 1, abandonedDelay: time.Hour}
	for i := range 2 {
		if !q.Enqueue(settlementRetryJob{requestLogID: fmt.Sprint("abandoned-", i), cause: context.DeadlineExceeded}) {
			t.Fatalf("retry %d was not accepted", i)
		}
	}
	// Never drop a retry for lack of timer room: a duplicate settle is safe for
	// billing because the router keeps the first writer.
	if q.deferred.Load() != 1 || len(q.jobs) != 1 {
		t.Fatalf("deferred=%d queued=%d, want one held and one queued", q.deferred.Load(), len(q.jobs))
	}
}

// The production defect: the Stage D wait expired while the router was still
// running the original settle, and a zero-delay retry raced it. The final frame
// must still go out at the wait with the estimated cost, and the retry must not
// reach the router until the original has ended and the delay has passed.
func TestServeStreamingStageDSettleTimeoutRetryWaitsForOriginalSettle(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "50")
	const routerRuns = 300 * time.Millisecond
	const delay = 400 * time.Millisecond
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1, abandonedDelay: delay}
	q.Start(t.Context())
	original := settlementRetries
	settlementRetries = q
	t.Cleanup(func() { settlementRetries = original })

	var mu sync.Mutex
	var originalEnded time.Time
	var settles atomic.Int32
	retried := make(chan time.Time, 1)
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.Path == trustedrouter.HeartbeatPath:
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
		case request.URL.Path == "/internal/gateway/settle":
			if settles.Add(1) == 1 {
				// The router keeps running a settle after the enclave stops waiting.
				started := time.Now()
				time.AfterFunc(routerRuns, func() {
					mu.Lock()
					originalEnded = started.Add(routerRuns)
					mu.Unlock()
				})
				<-request.Context().Done()
				return nil, request.Context().Err()
			}
			retried <- time.Now()
			return &http.Response{StatusCode: 200, Header: make(http.Header), Request: request,
				Body: io.NopCloser(strings.NewReader(`{"data":{"cost_microdollars":15,"disposition":"finalized"}}`))}, nil
		case strings.HasSuffix(request.URL.Path, "/disposition"):
			return &http.Response{StatusCode: 404, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	// A priced Credits authorization, so the terminal frame can report the
	// locally estimated cost when the settle has not answered in time.
	authorization := stageDStreamingAuthorization()
	authorization.CandidateCostReporting = true
	authorization.Provider, authorization.UsageType = "anthropic", "Credits"
	authorization.CandidatePrices[0].PriceHistoryVersion = 1
	authorization.CandidatePrices[0].RequestFeeMicro = 7
	var out bytes.Buffer
	streamStarted := time.Now()
	serveStreaming(t.Context(), &out, provider,
		&types.OpenAIChatRequest{Model: "model", Stream: true, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, authorization, nil,
		time.Now(), nil, "chat.completions", "stage-d-timeout-retry", "model")
	streamEnded := time.Now()

	body := out.String()
	if !strings.Contains(body, "data: [DONE]") || !strings.Contains(body, `"cost_microdollars":8,`) {
		t.Fatalf("terminal frame missing [DONE] or the estimated cost; body=%s", body)
	}
	if took := streamEnded.Sub(streamStarted); took >= routerRuns {
		t.Fatalf("stream took %s; the final frame waited past the Stage D deadline", took)
	}
	if settles.Load() != 1 || q.deferred.Load() != 1 {
		t.Fatalf("settles=%d deferred=%d at stream end, want the retry held", settles.Load(), q.deferred.Load())
	}
	select {
	case arrived := <-retried:
		mu.Lock()
		ended := originalEnded
		mu.Unlock()
		if ended.IsZero() || arrived.Before(ended) {
			t.Fatalf("retry arrived at %s while the original settle ran until %s", arrived, ended)
		}
		if waited := arrived.Sub(streamEnded); waited < delay-100*time.Millisecond {
			t.Fatalf("retry arrived %s after the stream, before the %s delay", waited, delay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deferred retry was never sent")
	}
	if settles.Load() != 2 {
		t.Fatalf("settles=%d, want the original and one retry", settles.Load())
	}
}

// A real error is not a settle the router may still be running: its retry
// keeps the zero first-attempt delay even with Stage D deferral configured.
func TestServeStreamingStageDSettleErrorRetriesImmediately(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1, abandonedDelay: time.Hour}
	original := settlementRetries
	settlementRetries = q
	t.Cleanup(func() { settlementRetries = original })

	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case trustedrouter.HeartbeatPath:
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
		case "/internal/gateway/settle":
			return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Request: request,
				Body: io.NopCloser(strings.NewReader(`{"error":{"message":"fixture rejected settlement"}}`))}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	var out bytes.Buffer
	serveStreaming(t.Context(), &out, provider,
		&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
		time.Now(), nil, "chat.completions", "stage-d-error-retry", "model")
	if len(q.jobs) != 1 || q.deferred.Load() != 0 {
		t.Fatalf("queued=%d deferred=%d, want an immediate retry", len(q.jobs), q.deferred.Load())
	}
}
