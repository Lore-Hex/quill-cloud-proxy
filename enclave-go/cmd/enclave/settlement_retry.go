package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	defaultSettlementRetryQueueSize = 1024
	defaultSettlementRetryAttempts  = 6
	defaultSettlementRetryBaseDelay = 500 * time.Millisecond
	defaultSettlementRetryMaxDelay  = 15 * time.Second
	// abandonedSettleRetryDelay holds back the first retry of a settle or
	// refund the enclave stopped waiting for (its context deadline passed or
	// was cancelled). The router keeps running that request after the enclave
	// disconnects. A retry sent meanwhile races the original for the same
	// reservation and authorization rows; on 2026-10-22 such a duplicate
	// pushed an original settle into the router's durable fallback and a 503
	// after 20 s.
	//
	// quill-router's billing-path Spanner budget is 20 s
	// (_BILLING_PATH_SPANNER_BUDGET_SECONDS, routes/internal/gateway.py), but
	// it starts when the sync handler enters its worker thread, so threadpool
	// queueing before that is not bounded by it. The router's own comment
	// there budgets the settle at 25 s from the enclave's side, matching this
	// client's 25 s response-header timeout. The hold is measured from
	// enqueue, which is at least settleBeforeTerminal (2 s) after the send on
	// the terminal paths, so the retry reaches the router about 25-27 s after
	// the original was sent: at or past that 25 s envelope. A context
	// cancelled before the send (request cancellation at shutdown) sends
	// nothing, and the hold then only delays the retry. Retries after a real
	// error (5xx, connection reset, rejection) keep their existing timing:
	// that request has already ended.
	abandonedSettleRetryDelay = 23 * time.Second
)

var settlementRetries = newSettlementRetryQueueFromEnv()

type settlementRetryJob struct {
	reportedCost   *int
	trGateway      *trustedrouter.Client
	authorization  *trustedrouter.Authorization
	usage          trustedrouter.Usage
	requestLogID   string
	clientContext  *types.ClientContext
	attempt        int
	enqueuedAt     time.Time
	kind           string
	refundStatus   int
	refundType     string
	refundElapsed  float64
	refundMetadata map[string]any
	// cause is the error that failed the request-path attempt. Enqueue reads
	// it once to decide whether the original may still be running at the
	// router, then drops it.
	cause     error
	notBefore time.Time
	// frozen is the exact control-plane request every attempt of this retry
	// sends, built once from the compacted job (freezeSettlementRetry). nil
	// with frozenSet is a refund without an authorization: nothing to send.
	// frozenErr is why it could not be built; each attempt reports it.
	frozen    *trustedrouter.FrozenTerminal
	frozenErr error
	frozenSet bool
}

type settlementRetryQueue struct {
	startOnce   sync.Once
	idleChecks  chan chan bool
	jobs        chan settlementRetryJob
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	// abandonedDelay is abandonedSettleRetryDelay in production. Zero sends
	// every first retry immediately.
	abandonedDelay time.Duration
	// deferred counts retries held back until the abandoned original has
	// ended. They wait on timers, not in jobs, so they never delay the
	// retries queued behind them.
	deferred atomic.Int64
	// release is closed by ReleaseDeferred at shutdown; held retries then
	// enqueue at once instead of waiting out their hold.
	releaseMu sync.Mutex
	release   chan struct{}
	released  bool
	// outbox, when set, parks the frozen terminal of every job this queue
	// would otherwise lose: retries exhausted, a drop when the queue is
	// full or disabled, and jobs still queued when the shutdown flush ends.
	// nil until SetOutbox; nil means the loss stays a log line, as before.
	outbox atomic.Pointer[settleoutbox.Writer]
}

// SetOutbox attaches the durable settle outbox. Call it before serving
// starts; nothing is enqueued before then.
func (q *settlementRetryQueue) SetOutbox(outbox *settleoutbox.Writer) {
	if q == nil {
		return
	}
	q.outbox.Store(outbox)
}

// park hands a job the queue is giving up on to the outbox. It never blocks:
// the outbox queues the write. A job with nothing to send (a refund without
// an authorization) or whose terminal could not be frozen is not parked.
func (q *settlementRetryQueue) park(job settlementRetryJob, reason string) {
	if q == nil {
		return
	}
	outbox := q.outbox.Load()
	if outbox == nil {
		return
	}
	job = compactSettlementRetryJob(job)
	if job.attempt <= 0 {
		job.attempt = 1
	}
	switch {
	case job.frozenErr != nil:
		fmt.Fprintf(os.Stderr,
			"enclave.settle_outbox_skip request_log_id=%q auth_id=%q reason=%q cause=%q\n",
			job.requestLogID, authorizationID(job.authorization), reason, errorClass(job.frozenErr))
		return
	case job.frozen == nil:
		return
	}
	kind := job.kind
	if kind == "" {
		kind = settleoutbox.KindSettle
	}
	accepted := outbox.Offer(settleoutbox.Entry{Terminal: *job.frozen, Reason: reason, Attempts: job.attempt})
	fmt.Fprintf(os.Stderr,
		"enclave.settle_outbox_parked request_log_id=%q request_id=%q auth_id=%q kind=%q reason=%q attempts=%d accepted=%t\n",
		job.requestLogID, job.usage.RequestID, authorizationID(job.authorization), kind, reason, job.attempt, accepted)
}

func newSettlementRetryQueueFromEnv() *settlementRetryQueue {
	size := envInt("QUILL_SETTLEMENT_RETRY_QUEUE_SIZE", defaultSettlementRetryQueueSize)
	if size <= 0 {
		return &settlementRetryQueue{}
	}
	maxAttempts := envInt("QUILL_SETTLEMENT_RETRY_ATTEMPTS", defaultSettlementRetryAttempts)
	if maxAttempts <= 0 {
		maxAttempts = defaultSettlementRetryAttempts
	}
	baseDelay := envDurationMS("QUILL_SETTLEMENT_RETRY_BASE_DELAY_MS", defaultSettlementRetryBaseDelay)
	maxDelay := envDurationMS("QUILL_SETTLEMENT_RETRY_MAX_DELAY_MS", defaultSettlementRetryMaxDelay)
	if maxDelay < baseDelay {
		maxDelay = baseDelay
	}
	return &settlementRetryQueue{
		jobs:           make(chan settlementRetryJob, size),
		maxAttempts:    maxAttempts,
		baseDelay:      baseDelay,
		maxDelay:       maxDelay,
		abandonedDelay: abandonedSettleRetryDelay,
	}
}

func (q *settlementRetryQueue) Enabled() bool {
	return q != nil && q.jobs != nil
}

func (q *settlementRetryQueue) Start(ctx context.Context) {
	if !q.Enabled() {
		return
	}
	q.startOnce.Do(func() {
		q.idleChecks = make(chan chan bool)
		go q.run(ctx)
	})
}

// Call only after request handlers have drained. The worker acknowledges
// between attempts, so an in-flight settlement is never mistaken for an empty
// queue. Retries stay bounded by the caller's shutdown deadline.
func (q *settlementRetryQueue) WaitForIdle(ctx context.Context) error {
	if !q.Enabled() {
		return nil
	}
	for {
		check := make(chan bool, 1)
		select {
		case q.idleChecks <- check:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case idle := <-check:
			if idle {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Flush is the shutdown drain: it releases held retries, which would
// otherwise outlive the process, and waits until the queue is idle or ctx
// ends. Call it only after request handlers have drained.
func (q *settlementRetryQueue) Flush(ctx context.Context) {
	if !q.Enabled() {
		return
	}
	q.ReleaseDeferred()
	if err := q.WaitForIdle(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "enclave.shutdown_settlement_pending queued=%d err=%q\n", len(q.jobs), err.Error())
		// The process is about to exit with these still queued. Park what
		// is in the queue; the worker may post one of them meanwhile, which
		// is a duplicate the router keeps the first writer of.
		for parked := 0; ; parked++ {
			select {
			case job := <-q.jobs:
				q.park(job, "shutdown")
				continue
			default:
			}
			if parked > 0 {
				fmt.Fprintf(os.Stderr, "enclave.shutdown_settlement_parked count=%d\n", parked)
			}
			break
		}
	}
	if deferred := q.deferred.Load(); deferred > 0 {
		// Released held retries that still had not reached the queue.
		fmt.Fprintf(os.Stderr, "enclave.shutdown_settlement_deferred count=%d\n", deferred)
	}
}

func (q *settlementRetryQueue) Enqueue(job settlementRetryJob) bool {
	if !q.Enabled() {
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_drop request_log_id=%q request_id=%q auth_id=%q reason=%q\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			"queue_disabled",
		)
		q.park(job, "queue_disabled")
		return false
	}
	if job.attempt <= 0 {
		job.attempt = 1
	}
	if job.attempt == 1 && job.notBefore.IsZero() && q.abandonedDelay > 0 && stageDTimeout(job.cause) {
		job.notBefore = time.Now().Add(q.abandonedDelay)
	}
	job = compactSettlementRetryJob(job)
	if job.enqueuedAt.IsZero() {
		job.enqueuedAt = time.Now()
	}
	if q.deferUntilDue(job) {
		return true
	}
	select {
	case q.jobs <- job:
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_enqueue request_log_id=%q request_id=%q auth_id=%q attempt=%d queued=%d capacity=%d\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			job.attempt,
			len(q.jobs),
			cap(q.jobs),
		)
		return true
	default:
	}

	select {
	case dropped := <-q.jobs:
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_drop_oldest request_log_id=%q request_id=%q auth_id=%q dropped_attempt=%d queued=%d capacity=%d\n",
			dropped.requestLogID,
			dropped.usage.RequestID,
			authorizationID(dropped.authorization),
			dropped.attempt,
			len(q.jobs),
			cap(q.jobs),
		)
		q.park(dropped, "evicted")
	default:
	}

	select {
	case q.jobs <- job:
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_enqueue request_log_id=%q request_id=%q auth_id=%q attempt=%d queued=%d capacity=%d after_drop=true\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			job.attempt,
			len(q.jobs),
			cap(q.jobs),
		)
		return true
	default:
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_drop request_log_id=%q request_id=%q auth_id=%q reason=%q queued=%d capacity=%d\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			"queue_full",
			len(q.jobs),
			cap(q.jobs),
		)
		q.park(job, "queue_full")
		return false
	}
}

// releaseSignal returns the channel ReleaseDeferred closes, and whether it
// already has.
func (q *settlementRetryQueue) releaseSignal() (<-chan struct{}, bool) {
	q.releaseMu.Lock()
	defer q.releaseMu.Unlock()
	if q.release == nil {
		q.release = make(chan struct{})
	}
	return q.release, q.released
}

// ReleaseDeferred enqueues every held retry now, and stops holding new ones.
// Call it at shutdown before WaitForIdle: the process exits before a hold
// would end, and a duplicate settle is safe for billing because the router
// keeps the first writer, while a dropped one is not.
func (q *settlementRetryQueue) ReleaseDeferred() {
	if !q.Enabled() {
		return
	}
	q.releaseMu.Lock()
	defer q.releaseMu.Unlock()
	if q.release == nil {
		q.release = make(chan struct{})
	}
	if !q.released {
		q.released = true
		close(q.release)
	}
}

// deferUntilDue parks a job whose notBefore is in the future and enqueues it
// when due or when ReleaseDeferred is called. If as many jobs are parked as
// the queue holds, or the queue is releasing, the job is queued now instead,
// which is the behaviour before deferral existed: a duplicate settle is safe
// for billing because the router keeps the first writer.
func (q *settlementRetryQueue) deferUntilDue(job settlementRetryJob) bool {
	wait := time.Until(job.notBefore)
	if wait <= 0 {
		return false
	}
	release, released := q.releaseSignal()
	if released {
		return false
	}
	if q.deferred.Add(1) > int64(cap(q.jobs)) {
		q.deferred.Add(-1)
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_defer_full request_log_id=%q request_id=%q auth_id=%q capacity=%d\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			cap(q.jobs),
		)
		return false
	}
	fmt.Fprintf(os.Stderr,
		"enclave.settlement_retry_deferred request_log_id=%q request_id=%q auth_id=%q attempt=%d delay_ms=%d\n",
		job.requestLogID,
		job.usage.RequestID,
		authorizationID(job.authorization),
		job.attempt,
		wait.Milliseconds(),
	)
	go func() {
		// Decrement only after Enqueue, so WaitForIdle cannot report idle
		// while a released job is between the hold and the queue.
		defer q.deferred.Add(-1)
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-release:
		}
		job.notBefore = time.Time{}
		q.Enqueue(job)
	}()
	return true
}

func (q *settlementRetryQueue) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-q.jobs:
			q.process(ctx, job)
		case check := <-q.idleChecks:
			// deferred first: a held job is pushed before its counter drops, so a
			// zero count means every released job is already in q.jobs, which
			// only this goroutine drains. The reverse order can miss one in flight.
			check <- q.deferred.Load() == 0 && len(q.jobs) == 0
		}
	}
}

func (q *settlementRetryQueue) process(ctx context.Context, job settlementRetryJob) {
	job = compactSettlementRetryJob(job)
	if job.attempt <= 0 {
		job.attempt = 1
	}
	delay := q.delay(job.attempt)
	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	// The frozen request already carries the request's audit id and client
	// context, so a retried settle names the same gateway_request_id the
	// first attempt did although the worker runs on the queue's own context.
	var result *trustedrouter.SettleResult
	var err error
	switch {
	case job.frozenErr != nil:
		err = job.frozenErr
	case job.frozen == nil:
		result = &trustedrouter.SettleResult{}
	default:
		result, err = job.trGateway.PostFrozenTerminal(ctx, *job.frozen)
	}
	if err == nil {
		if job.kind != "refund" && job.reportedCost != nil && result.HasCost() && *job.reportedCost != result.CostMicrodollars {
			logUsageCostMismatch(job.authorization, job.usage, *job.reportedCost, result.CostMicrodollars)
		}
		if job.kind == "refund" && stageDDispositionLost(result) {
			fmt.Fprintf(os.Stderr, "enclave.stage_d_refund_lost request_log_id=%q auth_id=%q disposition=%q\n", job.requestLogID, authorizationID(job.authorization), result.Disposition)
			return
		}
		if job.kind != "refund" && stageDDispositionLost(result) {
			logStageDSettleLost(job.authorization, result, "retry")
			return
		}
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_success request_log_id=%q request_id=%q auth_id=%q attempt=%d age_ms=%d\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			job.attempt,
			time.Since(job.enqueuedAt).Milliseconds(),
		)
		return
	}

	fmt.Fprintf(os.Stderr,
		"enclave.settlement_retry_failed request_log_id=%q request_id=%q auth_id=%q attempt=%d err=%q\n",
		job.requestLogID,
		job.usage.RequestID,
		authorizationID(job.authorization),
		job.attempt,
		errorClass(err),
	)
	if job.attempt >= q.maxAttempts {
		fmt.Fprintf(os.Stderr,
			"enclave.settlement_retry_give_up request_log_id=%q request_id=%q auth_id=%q attempts=%d age_ms=%d\n",
			job.requestLogID,
			job.usage.RequestID,
			authorizationID(job.authorization),
			job.attempt,
			time.Since(job.enqueuedAt).Milliseconds(),
		)
		q.park(job, "retry_exhausted")
		return
	}
	job.attempt++
	_ = q.Enqueue(job)
}

// compactSettlementRetryJob keeps the durable billing identity and measured
// usage while dropping prompt-adjacent data and provider secrets. A control-
// plane outage may fill this queue, so a count bound alone is not sufficient.
func compactSettlementRetryJob(job settlementRetryJob) settlementRetryJob {
	if job.reportedCost != nil {
		cost := *job.reportedCost
		job.reportedCost = &cost
	}
	if job.clientContext != nil {
		// Detach from the request's value so the queued job never aliases
		// memory the request goroutine may still touch.
		copy := *job.clientContext
		job.clientContext = &copy
	}
	if auth := job.authorization; auth != nil {
		job.authorization = &trustedrouter.Authorization{
			AuthorizationID:         auth.AuthorizationID,
			Model:                   auth.Model,
			EndpointID:              auth.EndpointID,
			RouteType:               auth.RouteType,
			ControlPlaneEndpoint:    auth.ControlPlaneEndpoint,
			ControlPlaneEndpointSet: auth.ControlPlaneEndpointSet,
		}
	}
	job.usage.User = ""
	job.usage.SessionID = ""
	job.usage.Trace = nil
	job.usage.Metadata = nil
	job.usage.App = ""
	job.usage.HTTPReferer = ""
	job.usage.AppCategories = nil
	job.refundMetadata = nil
	job.cause = nil
	if !job.frozenSet {
		job.frozen, job.frozenErr = freezeSettlementRetry(job)
		job.frozenSet = true
	}
	return job
}

// freezeSettlementRetry builds the request a compacted job retries: the
// settle or refund the request path would send for the job's compacted
// authorization and usage, on a context carrying only its audit id and client
// context. Compaction has already dropped the user, session, trace, metadata,
// refund metadata and the authorization's async and shadow state, so none of
// it reaches the frozen bytes.
func freezeSettlementRetry(job settlementRetryJob) (*trustedrouter.FrozenTerminal, error) {
	ctx := trustedrouter.WithRequestLogID(context.Background(), job.requestLogID)
	ctx = trustedrouter.WithClientContext(ctx, job.clientContext)
	if job.kind == "refund" {
		return job.trGateway.FreezeRefund(ctx, job.authorization, job.refundStatus, job.refundType, job.refundElapsed, job.refundMetadata)
	}
	return job.trGateway.FreezeSettle(ctx, job.authorization, job.usage)
}

func (q *settlementRetryQueue) delay(attempt int) time.Duration {
	if attempt <= 1 {
		return 0
	}
	delay := q.baseDelay
	for i := 2; i < attempt; i++ {
		delay *= 2
		if delay >= q.maxDelay {
			return q.maxDelay
		}
	}
	return delay
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envDurationMS(name string, fallback time.Duration) time.Duration {
	value := envInt(name, int(fallback/time.Millisecond))
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func authorizationID(authorization *trustedrouter.Authorization) string {
	if authorization == nil {
		return ""
	}
	return authorization.AuthorizationID
}
