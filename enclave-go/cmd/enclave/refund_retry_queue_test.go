package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Refund retries live in a queue of their own. These tests pin what that buys:
// a refund is never sent ahead of a settle that is waiting, a refund the queue
// cannot take is dropped without touching a settle, and a refund's backoff
// never holds the worker.

// terminalLog is a control plane that records, in order, each settle and
// refund it receives. refundStatus fails every refund with that status.
type terminalLog struct {
	mu           sync.Mutex
	calls        []string
	refundStatus int
}

func (l *terminalLog) gateway(t *testing.T) *trustedrouter.Client {
	t.Helper()
	return trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			id, _ := body["authorization_id"].(string)
			respond := func(status int, payload string) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
			}
			l.mu.Lock()
			defer l.mu.Unlock()
			switch r.URL.Path {
			case "/internal/gateway/settle":
				l.calls = append(l.calls, "settle:"+id)
				return respond(200, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":12}}`)
			case "/internal/gateway/refund":
				l.calls = append(l.calls, "refund:"+id)
				if l.refundStatus != 0 {
					return respond(l.refundStatus, `{"error":{"message":"refused","type":"test"}}`)
				}
				return respond(200, `{"data":{"refunded":true}}`)
			}
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
			return respond(500, `{}`)
		}),
	})
}

func (l *terminalLog) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

func (l *terminalLog) setRefundStatus(status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refundStatus = status
}

// The private fields stand in for what a retry job must never put in a log.
func retryTestAuthorization(id string) *trustedrouter.Authorization {
	return &trustedrouter.Authorization{AuthorizationID: id, Model: "m", EndpointID: "e@openai/prepaid", WorkspaceID: "ws_private", APIKeyHash: "key_private"}
}

func settleRetryJob(gateway *trustedrouter.Client, id string) settlementRetryJob {
	return settlementRetryJob{
		cause: errors.New("settle was not acknowledged"), trGateway: gateway, authorization: retryTestAuthorization(id),
		usage: trustedrouter.Usage{RequestID: "req_" + id, InputTokens: 1, OutputTokens: 1, User: "user_private"},
	}
}

func refundRetryJob(gateway *trustedrouter.Client, id string) settlementRetryJob {
	return settlementRetryJob{
		cause: errors.New("refund was not acknowledged"), trGateway: gateway, authorization: retryTestAuthorization(id),
		kind: "refund", refundStatus: 502, refundType: "provider_error", refundElapsed: 0.1,
	}
}

// drainRetryQueue runs the queue's own worker until it is idle.
func drainRetryQueue(t *testing.T, queue *settlementRetryQueue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	queue.Start(ctx)
	if err := queue.WaitForIdle(ctx); err != nil {
		t.Fatalf("the queue did not drain: %v", err)
	}
}

// Refunds queued first are still sent last. The worker's select is random when
// both queues are ready, so this repeats until a wrong order would have shown.
func TestRetryWorkerSendsEveryQueuedSettleBeforeARefund(t *testing.T) {
	for round := 0; round < 40; round++ {
		log := &terminalLog{}
		gateway := log.gateway(t)
		queue := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), refunds: make(chan settlementRetryJob, 4), maxAttempts: 1}
		for _, id := range []string{"r1", "r2"} {
			if !queue.Enqueue(refundRetryJob(gateway, id)) {
				t.Fatalf("refund %s was not queued", id)
			}
		}
		for _, id := range []string{"s1", "s2", "s3"} {
			if !queue.Enqueue(settleRetryJob(gateway, id)) {
				t.Fatalf("settle %s was not queued", id)
			}
		}
		drainRetryQueue(t, queue)
		got := log.seen()
		if want := "[settle:s1 settle:s2 settle:s3 refund:r1 refund:r2]"; fmt.Sprint(got) != want {
			t.Fatalf("round %d: sent %v, want %s", round, got, want)
		}
	}
}

// A refund the refund queue cannot take is dropped, counted and logged. It
// evicts nothing: every settle and the refund already queued are delivered.
func TestRefundQueueOverflowDropsTheRefundAndNothingElse(t *testing.T) {
	log := &terminalLog{}
	gateway := log.gateway(t)
	queue := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 2), refunds: make(chan settlementRetryJob, 1), maxAttempts: 1}
	for _, id := range []string{"s1", "s2"} {
		if !queue.Enqueue(settleRetryJob(gateway, id)) {
			t.Fatalf("settle %s was not queued", id)
		}
	}
	var kept []bool
	stderr := captureStderr(t, func() {
		for _, id := range []string{"r1", "r2", "r3"} {
			kept = append(kept, queue.Enqueue(refundRetryJob(gateway, id)))
		}
	})
	if fmt.Sprint(kept) != "[true false false]" {
		t.Fatalf("refunds kept = %v, want only the first", kept)
	}
	if dropped := queue.refundsDropped.Load(); dropped != 2 {
		t.Fatalf("refunds dropped = %d, want 2", dropped)
	}
	if len(queue.jobs) != 2 || len(queue.refunds) != 1 {
		t.Fatalf("queued settles = %d refunds = %d, want 2 and 1", len(queue.jobs), len(queue.refunds))
	}
	if count := strings.Count(stderr, "enclave.refund_retry_drop "); count != 2 || !strings.Contains(stderr, `reason="refund_queue_full"`) {
		t.Fatalf("drop log lines = %d, stderr: %s", count, stderr)
	}
	// The drop is reported by request and authorization, never by customer.
	for _, private := range []string{"ws_private", "key_private", "user_private"} {
		if strings.Contains(stderr, private) {
			t.Fatalf("the log names a customer identifier %q: %s", private, stderr)
		}
	}
	drainRetryQueue(t, queue)
	if got, want := fmt.Sprint(log.seen()), "[settle:s1 settle:s2 refund:r1]"; got != want {
		t.Fatalf("sent %s, want %s", got, want)
	}
}

// A queue built without refund capacity keeps no refund retry and loses no
// settle to one.
func TestQueueWithoutRefundCapacityKeepsNoRefundRetry(t *testing.T) {
	log := &terminalLog{}
	gateway := log.gateway(t)
	queue := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1), maxAttempts: 1}
	if !queue.Enqueue(settleRetryJob(gateway, "s1")) {
		t.Fatal("the settle was not queued")
	}
	if queue.Enqueue(refundRetryJob(gateway, "r1")) {
		t.Fatal("a refund retry was kept by a queue with no room for refunds")
	}
	drainRetryQueue(t, queue)
	if got, want := fmt.Sprint(log.seen()), "[settle:s1]"; got != want {
		t.Fatalf("sent %s, want %s", got, want)
	}
}

// A refund that fails again waits out its backoff on a timer. The worker is
// free at once, so a settle queued meanwhile is not kept waiting for it.
func TestRefundBackoffNeverHoldsTheWorker(t *testing.T) {
	log := &terminalLog{refundStatus: 503}
	gateway := log.gateway(t)
	queue := &settlementRetryQueue{
		jobs: make(chan settlementRetryJob, 2), refunds: make(chan settlementRetryJob, 2),
		maxAttempts: 3, baseDelay: time.Hour, maxDelay: time.Hour,
	}
	started := time.Now()

	// First attempt fails. With an hour of backoff the worker must not sleep.
	if !queue.Enqueue(refundRetryJob(gateway, "r1")) {
		t.Fatal("the refund was not queued")
	}
	queue.process(context.Background(), <-queue.refunds)
	if held := queue.deferredRefunds.Load(); held != 1 || len(queue.refunds) != 0 {
		t.Fatalf("held refunds = %d queued refunds = %d, want the retry held on a timer", held, len(queue.refunds))
	}
	if queue.deferred.Load() != 0 {
		t.Fatal("a held refund used the settles' allowance")
	}

	// A settle queued now is sent straight away.
	if !queue.Enqueue(settleRetryJob(gateway, "s1")) {
		t.Fatal("the settle was not queued")
	}
	queue.process(context.Background(), <-queue.jobs)

	// Shutdown releases the held refund; its next attempt does not sleep either.
	log.setRefundStatus(0)
	queue.ReleaseDeferred()
	var retry settlementRetryJob
	select {
	case retry = <-queue.refunds:
	case <-time.After(10 * time.Second):
		t.Fatal("the held refund was not released")
	}
	if retry.attempt != 2 {
		t.Fatalf("released refund attempt = %d, want 2", retry.attempt)
	}
	queue.process(context.Background(), retry)

	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Fatalf("took %s: the worker waited out a refund backoff", elapsed)
	}
	if got, want := fmt.Sprint(log.seen()), "[refund:r1 settle:s1 refund:r1]"; got != want {
		t.Fatalf("sent %s, want %s", got, want)
	}
}

// A refund the queue gives up on is parked in the outbox only while the outbox
// has spare room. Once it does not, refunds are refused there and settles are
// still accepted.
func TestParkedRefundTakesOnlySpareOutboxRoom(t *testing.T) {
	log := &terminalLog{}
	gateway := log.gateway(t)
	// Never started: nothing drains the outbox, as when its store is down.
	writer := settleoutbox.NewWriter(newOutboxTestStore(), nil, nil)
	queue := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1), refunds: make(chan settlementRetryJob, 1), maxAttempts: 1}
	queue.SetOutbox(writer)

	// Park settles until a refund is refused.
	refused := false
	for i := 0; i < 20000 && !refused; i++ {
		before := writer.Pending()
		queue.park(refundRetryJob(gateway, fmt.Sprintf("r%d", i)), "retry_exhausted")
		if writer.Pending() == before {
			refused = true
			break
		}
		queue.park(settleRetryJob(gateway, fmt.Sprintf("s%d", i)), "retry_exhausted")
	}
	if !refused {
		t.Fatal("the outbox never refused a refund: refunds can fill it")
	}
	parked := writer.Pending()
	if parked == 0 {
		t.Fatal("the outbox refused a refund while empty")
	}
	// A settle still finds room where the refund did not, and keeps finding it.
	for i := 0; i < 10; i++ {
		queue.park(settleRetryJob(gateway, fmt.Sprintf("late%d", i)), "retry_exhausted")
	}
	if got := writer.Pending(); got != parked+10 {
		t.Fatalf("outbox entries = %d, want the 10 settles added to %d", got, parked)
	}
	before := writer.Pending()
	queue.park(refundRetryJob(gateway, "late-refund"), "retry_exhausted")
	if writer.Pending() != before {
		t.Fatal("a refund was parked in the room kept for settles")
	}
}
