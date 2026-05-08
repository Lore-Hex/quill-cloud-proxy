package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	defaultSettlementRetryQueueSize = 1024
	defaultSettlementRetryAttempts  = 6
	defaultSettlementRetryBaseDelay = 500 * time.Millisecond
	defaultSettlementRetryMaxDelay  = 15 * time.Second
)

type settlementRetryJob struct {
	trGateway     *trustedrouter.Client
	authorization *trustedrouter.Authorization
	secretCache   *byokcache.Cache
	usage         trustedrouter.Usage
	req           *types.OpenAIChatRequest
	originalInput any
	output        string
	requestLogID  string
	attempt       int
	enqueuedAt    time.Time
}

type settlementRetryQueue struct {
	jobs        chan settlementRetryJob
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
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
		jobs:        make(chan settlementRetryJob, size),
		maxAttempts: maxAttempts,
		baseDelay:   baseDelay,
		maxDelay:    maxDelay,
	}
}

func (q *settlementRetryQueue) Enabled() bool {
	return q != nil && q.jobs != nil
}

func (q *settlementRetryQueue) Start(ctx context.Context) {
	if !q.Enabled() {
		return
	}
	go q.run(ctx)
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
		return false
	}
	if job.attempt <= 0 {
		job.attempt = 1
	}
	if job.enqueuedAt.IsZero() {
		job.enqueuedAt = time.Now()
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
		return false
	}
}

func (q *settlementRetryQueue) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-q.jobs:
			q.process(ctx, job)
		}
	}
}

func (q *settlementRetryQueue) process(ctx context.Context, job settlementRetryJob) {
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

	_, err := settleAndBroadcast(
		ctx,
		job.trGateway,
		job.authorization,
		job.secretCache,
		job.usage,
		job.req,
		job.originalInput,
		job.output,
	)
	if err == nil {
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
		return
	}
	job.attempt++
	_ = q.Enqueue(job)
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
