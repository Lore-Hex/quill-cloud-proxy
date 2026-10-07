package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type providerInvocationContextKey struct{}

var errEmptyUpstreamResponse = errors.New("empty upstream response")

type providerInvocation struct {
	reader        *io.PipeReader
	selectedRoute *selectedRouteTracker
	done          chan struct{}
	cancel        context.CancelFunc
	joinOnce      sync.Once
}

func startProviderInvocation(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	invokeOptions []llm.InvokeOptions,
	trEnabled bool,
	authorization *trustedrouter.Authorization,
	requestLogID string,
) *providerInvocation {
	providerCtx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	done := make(chan struct{})
	providerReq := *req
	go func() {
		defer close(done)
		invokeProviderStream(providerCtx, br, &providerReq, anthropicReq, pw, invokeOptions, trEnabled, authorization, selectedRoute, requestLogID, true, true)
	}()
	return &providerInvocation{reader: pr, selectedRoute: selectedRoute, done: done, cancel: cancel}
}

func (i *providerInvocation) abort(err error) {
	if i == nil {
		return
	}
	i.cancel()
	_ = i.reader.CloseWithError(err)
}

// join waits for the provider's final timing/shadow updates, logging, and pipe
// close, which can follow the final response frame. On success this can delay
// handler return and connection reuse, but not delivery of the response.
// Call abort before join to interrupt context-aware reads and blocked writes.
func (i *providerInvocation) join() {
	if i == nil {
		return
	}
	i.joinOnce.Do(func() {
		// A Client can ignore cancellation (including in an upstream read), so cap
		// cleanup rather than hanging the handler forever on a broken provider.
		// The cap applies once per invocation, including repeated cleanup calls.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-i.done:
		case <-timer.C:
		}
	})
}

func withProviderInvocation(ctx context.Context, invocation *providerInvocation) context.Context {
	if invocation == nil {
		return ctx
	}
	return context.WithValue(ctx, providerInvocationContextKey{}, invocation)
}

func providerInvocationFromContext(ctx context.Context) *providerInvocation {
	if ctx == nil {
		return nil
	}
	invocation, _ := ctx.Value(providerInvocationContextKey{}).(*providerInvocation)
	return invocation
}

func invokeProviderStream(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	pw *io.PipeWriter,
	invokeOptions []llm.InvokeOptions,
	trEnabled bool,
	authorization *trustedrouter.Authorization,
	selectedRoute *selectedRouteTracker,
	requestLogID string,
	useLongLastCandidateBudget bool,
	allowTransientRetries bool,
) {
	options := invokeOptions
	if len(options) == 0 {
		options = []llm.InvokeOptions{{Model: req.Model}}
	}
	overallStart := time.Now()
	phases := requesttiming.FromContext(ctx)
	requestID := authorizationRequestID(authorization)
	var lastErr error
	finishFailure := func(err error) {
		selectedRoute.SetFailure(err)
		_ = pw.CloseWithError(err)
	}
	var winningProvider, winningModel, winningEndpoint string
	var winningBytes int
	var winningTTFBms, winningTotalMs int64
	for i, option := range options {
		if err := ctx.Err(); err != nil {
			finishFailure(err)
			return
		}
		if option.Model == "" {
			option.Model = req.Model
		}
		selectedRoute.RecordCandidateAttempt(option)
		req.Model = option.Model
		if err := adapter.RejectUnsupportedN(req); err != nil {
			lastErr = withInvokeAttemptError(err, option)
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
				requestLogID, requestID, i+1, i, time.Since(overallStart).Milliseconds(), errorClass(err),
			)
			finishFailure(lastErr)
			return
		}
		// The TTFB budget exists to fall over to the next candidate fast; the LAST
		// candidate has nothing to fall over to, so give it a longer budget for slow
		// reasoning first bytes.
		isLast := i == len(options)-1
		budget := firstByteBudget
		if isLast && useLongLastCandidateBudget {
			budget = finalCandidateFirstByteBudget
		}

		var err error
		var candidateWriter *routeSelectingWriter
		var attemptDuration time.Duration
		var ttfbMs int64
		for tryN := 0; ; tryN++ {
			// A failed attested candidate must not lend its verification tier to a
			// later plain-TLS fallback that actually serves the response.
			ctx = llm.WithUpstreamVerification(ctx, "", time.Time{}, time.Time{})
			attemptCtx, cancelAttempt := context.WithCancel(ctx)
			var ttfbFired atomic.Bool
			ttfbTimer := time.AfterFunc(budget, func() {
				ttfbFired.Store(true)
				cancelAttempt()
			})
			attemptStart := time.Now()
			var ttfb time.Duration
			var ttfbCaptured bool
			candidateWriter = &routeSelectingWriter{
				w:         pw,
				streaming: req.Stream,
				tracker:   selectedRoute,
				option:    option,
				phases:    phases,
				onFirstByte: func() {
					ttfb = time.Since(attemptStart)
					ttfbCaptured = true
					ttfbTimer.Stop()
				},
			}
			if x := shadowobserve.FromContext(ctx); x != nil {
				model := option.UpstreamModel
				if model == "" {
					model = option.Model
				}
				x.ProviderStart(shadowobserve.Route{Endpoint: option.EndpointID, Provider: option.Provider, Model: model}, i == 0 && tryN == 0)
				candidateWriter.shadow = x
				candidateWriter.content = &shadowobserve.ContentStream{}
			}
			candidateWriter.invocation = phases.InvokeStart()
			redactedCtx, redactError := upstreamerror.WithCredentialRedaction(attemptCtx, option.ProviderAPIKey)
			err = redactError(br.InvokeStreaming(redactedCtx, req, anthropicReq, candidateWriter, option))
			phases.InvokeComplete(candidateWriter.invocation)
			if candidateWriter.shadow != nil {
				candidateWriter.shadow.ProviderEnd(err == nil)
			}
			if err == nil && candidateWriter.BytesWritten() == 0 {
				// A write attempt selects the route (and lets the caller commit the
				// response head) before the underlying writer reports its byte count.
				// Preserve that commitment separately while converting a zero-byte
				// clean completion into a retryable upstream failure.
				err = errEmptyUpstreamResponse
			}
			attemptDuration = time.Since(attemptStart)
			ttfbTimer.Stop()
			cancelAttempt()
			if ttfbFired.Load() && err != nil {
				err = fmt.Errorf("llm/upstream: time-to-first-byte exceeded %s: %w", budget, err)
			}

			ttfbMs = int64(-1)
			if ttfbCaptured {
				ttfbMs = ttfb.Milliseconds()
			}
			outcome := "ok"
			errStr := ""
			if err != nil {
				outcome = "fail"
				errStr = errorClass(err)
			}
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_attempt request_log_id=%q request_id=%q attempt=%d/%d try=%d model=%q provider=%q endpoint=%q outcome=%s ttfb_ms=%d total_ms=%d bytes=%d err=%q\n",
				requestLogID,
				requestID,
				i+1, len(options), tryN,
				option.Model, option.Provider, option.EndpointID,
				outcome,
				ttfbMs,
				attemptDuration.Milliseconds(),
				candidateWriter.BytesWritten(),
				errStr,
			)
			// Retry the same provider on a transient pre-output failure only when
			// explicitly allowed. Orchestration calls disable this so 429/5xx moves
			// immediately to the next route/model instead of waiting on same-provider
			// backoff.
			if err == nil || candidateWriter.ResponseCommitted() || !allowTransientRetries || !isLast || !useLongLastCandidateBudget ||
				tryN >= maxTransientUpstreamRetries || !isTransientUpstreamError(err) {
				break
			}
			retryStart := phases.Now()
			retryErr := sleepBeforeTransientRetry(ctx, transientUpstreamBackoff(tryN))
			phases.RetryWaitDone(retryStart)
			if retryErr != nil {
				// Use the same failure/logging/billing path as an invocation that
				// returns context cancellation, without starting another attempt.
				err = retryErr
				break
			}
		}

		if err == nil {
			if candidateWriter.BytesWritten() == 0 {
				selectedRoute.Select(option)
			}
			winningProvider, winningModel, winningEndpoint = option.Provider, option.Model, option.EndpointID
			winningBytes = candidateWriter.BytesWritten()
			winningTTFBms = ttfbMs
			winningTotalMs = attemptDuration.Milliseconds()
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_complete request_log_id=%q request_id=%q outcome=ok provider_used=%q model=%q endpoint=%q attempts=%d fallbacks=%d ttfb_ms=%d upstream_ms=%d total_ms=%d bytes=%d\n",
				requestLogID,
				requestID,
				winningProvider, winningModel, winningEndpoint,
				i+1, i,
				winningTTFBms,
				winningTotalMs,
				time.Since(overallStart).Milliseconds(),
				winningBytes,
			)
			_ = pw.Close()
			return
		}
		attemptErr := withInvokeAttemptError(err, option)
		lastErr = preferredProviderError(lastErr, attemptErr)
		if !trEnabled || candidateWriter.ResponseCommitted() || i == len(options)-1 || !retryableInvokeError(err) {
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
				requestLogID, requestID, i+1, i, time.Since(overallStart).Milliseconds(), errorClass(err),
			)
			// Once accepted, a failure belongs to the selected stream, not an earlier route.
			if candidateWriter.ResponseCommitted() {
				lastErr = attemptErr
			}
			finishFailure(lastErr)
			return
		}
	}
	if lastErr != nil {
		fmt.Fprintf(os.Stderr,
			"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
			requestLogID, requestID, len(options), len(options)-1, time.Since(overallStart).Milliseconds(), errorClass(lastErr),
		)
		finishFailure(lastErr)
		return
	}
	selectedRoute.SignalReadyWithoutSelection()
	_ = pw.Close()
}

// Prefer the first parsed client error (4xx except 408/429); otherwise retain the last error.
func preferredProviderError(previous, current error) error {
	informative := func(err error) bool {
		d := upstreamerror.Parse(err)
		return d.Status >= 400 && d.Status < 500 && d.Status != 408 && d.Status != 429 && d.Parsed
	}
	if informative(previous) {
		return previous
	}
	return current
}

type invokeAttemptError struct {
	err    error
	option llm.InvokeOptions
}

func (e *invokeAttemptError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *invokeAttemptError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func withInvokeAttemptError(err error, option llm.InvokeOptions) error {
	if err == nil {
		return nil
	}
	var existing *invokeAttemptError
	if errors.As(err, &existing) {
		return err
	}
	return &invokeAttemptError{err: err, option: option}
}

func invokeAttemptOption(err error) (llm.InvokeOptions, bool) {
	var attemptErr *invokeAttemptError
	if errors.As(err, &attemptErr) && attemptErr != nil {
		return attemptErr.option, true
	}
	return llm.InvokeOptions{}, false
}

func authorizationRequestID(authorization *trustedrouter.Authorization) string {
	if authorization == nil {
		return "anon"
	}
	if id := authorization.AuthorizationID; id != "" {
		return id
	}
	return "anon"
}

func errorClass(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "time-to-first-byte exceeded"):
		return "ttfb_exceeded"
	case strings.Contains(msg, "context canceled"):
		return "ctx_canceled"
	case strings.Contains(msg, "context deadline exceeded"):
		return "ctx_deadline"
	case strings.Contains(strings.ToLower(msg), "http 5"):
		return "upstream_5xx"
	case strings.Contains(strings.ToLower(msg), "http 429"), strings.Contains(strings.ToLower(msg), "rate limit"):
		return "rate_limited"
	case strings.Contains(strings.ToLower(msg), "http 4"):
		return "upstream_4xx"
	}
	// Anything else used to be logged as the first 80 characters of the
	// message. An error's text is whatever its author put there -- a vendor's
	// rejection quoting the prompt, a decoder quoting the literal it choked on
	// -- and this enclave does not write prompts to a log. So the fallback is a
	// fixed word for the transport conditions worth telling apart, and
	// otherwise the error's Go TYPES, which say where it came from and hold
	// nothing anyone typed.
	lower := strings.ToLower(msg)
	for _, known := range transportErrorClasses {
		if strings.Contains(lower, known.marker) {
			return known.class
		}
	}
	return "other:" + errorTypeChain(err)
}

// transportErrorClasses maps a marker in an error's text to the FIXED word
// logged for it. What is logged is always a string from this table, never text
// from the error, so matching on a marker is safe whatever else the message
// holds. Ordered: the first match wins. The gateway's own conditions come
// first and keep the exact values they have always been logged under, because
// alerts and a test match on them.
var transportErrorClasses = []struct{ marker, class string }{
	{"empty upstream response", "empty upstream response"},
	{"first-byte budget exceeded", "user_model_first_byte_timeout"},
	{"thinking budget exceeded", "thinking_budget_exceeded"},
	{"attestation verification required", "attestation_required"},
	{"cert fingerprint mismatch", "cert_fingerprint_mismatch"},
	{"peer pid mismatch", "sidecar_pid_mismatch"},
	{"unexpected eof", "unexpected_eof"},
	{"connection reset", "conn_reset"},
	{"connection refused", "conn_refused"},
	{"broken pipe", "broken_pipe"},
	{"i/o timeout", "io_timeout"},
	{"no such host", "dns_no_such_host"},
	{"certificate", "tls_certificate"},
	{"handshake", "tls_handshake"},
	{"goaway", "http2_goaway"},
	{"stream error", "http2_stream_error"},
	{"eof", "eof"},
}

// errorTypeChain names the Go type at each level of err's Unwrap chain, e.g.
// "*url.Error>*net.OpError>*os.SyscallError". Types only, at most four deep.
func errorTypeChain(err error) string {
	var names []string
	for depth := 0; err != nil && depth < 4; depth++ {
		if _, marker := err.(*settlementAttemptedError); !marker {
			names = append(names, fmt.Sprintf("%T", err))
		}
		err = errors.Unwrap(err)
	}
	return strings.Join(names, ">")
}

type selectedRouteTracker struct {
	failure  error
	mu       sync.Mutex
	once     sync.Once
	ready    chan struct{}
	model    string
	endpoint string
	provider string
	attempts int
	selected bool
	routes   []routeAttempt
}

type routeAttempt struct {
	model    string
	endpoint string
	provider string
}

func newSelectedRouteTracker() *selectedRouteTracker {
	return &selectedRouteTracker{ready: make(chan struct{})}
}

func (t *selectedRouteTracker) Select(option llm.InvokeOptions) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.selected = true
	if t.model == "" && option.Model != "" {
		t.model = option.Model
	}
	if t.endpoint == "" && option.EndpointID != "" {
		t.endpoint = option.EndpointID
	}
	if t.provider == "" && option.Provider != "" {
		t.provider = option.Provider
	}
	t.mu.Unlock()
	t.once.Do(func() {
		close(t.ready)
	})
}

func (t *selectedRouteTracker) Failure() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failure
}

func (t *selectedRouteTracker) SetFailure(err error) {
	t.mu.Lock()
	t.failure = err
	t.mu.Unlock()
	t.SignalReadyWithoutSelection()
}

// Serialize the success head with a provider failure already available before it.
func (t *selectedRouteTracker) WriteStreamHead(w io.Writer) (error, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failure != nil {
		return t.failure, nil
	}
	return nil, writeResponseHead(w, 200, "text/event-stream")
}

func (t *selectedRouteTracker) HasSelection() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selected
}

func (t *selectedRouteTracker) SignalReadyWithoutSelection() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		close(t.ready)
	})
}

func (t *selectedRouteTracker) RecordCandidateAttempt(option llm.InvokeOptions) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.attempts++
	t.routes = append(t.routes, routeAttempt{
		model:    option.Model,
		endpoint: option.EndpointID,
		provider: option.Provider,
	})
	t.mu.Unlock()
}

func (t *selectedRouteTracker) AttemptedRoutes() []routeAttempt {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]routeAttempt(nil), t.routes...)
}

func (t *selectedRouteTracker) Ready() <-chan struct{} {
	if t == nil {
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	return t.ready
}

func (t *selectedRouteTracker) Model(fallback string, authorization *trustedrouter.Authorization) string {
	if t != nil {
		t.mu.Lock()
		model := t.model
		t.mu.Unlock()
		if model != "" {
			return model
		}
	}
	if fallback != "" {
		return fallback
	}
	if authorization != nil {
		return authorization.Model
	}
	return ""
}

func (t *selectedRouteTracker) Endpoint(fallback string, authorization *trustedrouter.Authorization) string {
	if t != nil {
		t.mu.Lock()
		endpoint := t.endpoint
		t.mu.Unlock()
		if endpoint != "" {
			return endpoint
		}
	}
	if fallback != "" {
		return fallback
	}
	if authorization != nil {
		return authorization.EndpointID
	}
	return ""
}

func (t *selectedRouteTracker) Provider(fallback string, authorization *trustedrouter.Authorization) string {
	if t != nil {
		t.mu.Lock()
		provider := t.provider
		t.mu.Unlock()
		if provider != "" {
			return provider
		}
	}
	if fallback != "" {
		return fallback
	}
	if authorization != nil {
		return authorization.Provider
	}
	return ""
}

func (t *selectedRouteTracker) AttemptCount() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attempts
}

func (t *selectedRouteTracker) FallbackCount() int {
	attempts := t.AttemptCount()
	if attempts <= 1 {
		return 0
	}
	return attempts - 1
}

var firstByteBudget = func() time.Duration {
	return parseFirstByteBudget(os.Getenv("QUILL_FIRST_BYTE_TIMEOUT_SECONDS"))
}()

func parseFirstByteBudget(raw string) time.Duration {
	if raw == "" {
		return 20 * time.Second
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 20 * time.Second
}

// finalCandidateFirstByteBudget is the time-to-first-byte budget for the LAST/only
// candidate. The standard 20s budget exists to fall over to another candidate fast;
// on the last candidate there is NOTHING to fall over to, so this is not a
// fallover trigger but a HANG DETECTOR — it should sit on a "the upstream is
// genuinely dead" timescale (minutes), not a "switch providers" one (seconds).
//
// The enclave is a raw-TLS server whose request ctx is context.Background() (no
// deadline, no client-disconnect cancellation), so this budget is the only bound
// on how long we wait for the first byte. gpt-5.x / o-series reasoning models
// reason SILENTLY before emitting anything: observed production first-byte times
// for openai/gpt-5.5 are 60-87s on success, and under concurrent load one run
// took >120s and got cancelled -> user-facing 502. The previous 120s cap was
// still inside the legitimate-reasoning band. 300s clears the worst observed
// first byte (~87s) by >3x while still catching a truly hung upstream. Tunable
// via QUILL_FINAL_FIRST_BYTE_TIMEOUT_SECONDS.
var finalCandidateFirstByteBudget = func() time.Duration {
	if n, err := strconv.Atoi(os.Getenv("QUILL_FINAL_FIRST_BYTE_TIMEOUT_SECONDS")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 300 * time.Second
}()

// maxTransientUpstreamRetries bounds same-candidate retries on transient pre-output
// errors (rate limit / 5xx / dropped connection). Retrying is only ever done before
// the first output byte, so it never duplicates output or double-bills.
const maxTransientUpstreamRetries = 2

var sleepBeforeTransientRetry = func(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func transientUpstreamBackoff(tryN int) time.Duration {
	switch {
	case tryN <= 0:
		return 1 * time.Second
	case tryN == 1:
		return 2 * time.Second
	default:
		return 4 * time.Second
	}
}

// isTransientUpstreamError reports whether a pre-output failure is worth retrying
// on the SAME provider (rate limit, 5xx, dropped connection). 4xx (malformed),
// client cancellation, and ttfb timeouts are not retried here.
func isTransientUpstreamError(err error) bool {
	if errors.Is(err, errEmptyUpstreamResponse) {
		return true
	}
	switch errorClass(err) {
	case "upstream_5xx", "rate_limited":
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection refused")
}

type routeSelectingWriter struct {
	streaming   bool
	shadow      *shadowobserve.Execution
	content     *shadowobserve.ContentStream
	w           io.Writer
	tracker     *selectedRouteTracker
	option      llm.InvokeOptions
	bytes       int
	committed   bool
	onFirstByte func()
	phases      *requesttiming.Timer
	invocation  *requesttiming.Invocation
	firstByte   sync.Once
}

func (w *routeSelectingWriter) selectRoute() {
	// Acceptance ends the fallback budget. streamhttp independently bounds
	// silence before and between raw body bytes for the selected provider.
	w.phases.FirstByte(w.invocation)
	w.committed = true
	if w.onFirstByte != nil {
		w.firstByte.Do(w.onFirstByte)
	}
	w.tracker.Select(w.option)
}

func (w *routeSelectingWriter) UpstreamOpened() bool {
	if w.streaming {
		w.selectRoute()
	}
	return w.streaming
}

func (w *routeSelectingWriter) Write(p []byte) (int, error) {
	if w.shadow != nil && w.content.Feed(p) {
		w.shadow.Content(false)
	}
	if len(p) > 0 {
		w.selectRoute()
	}
	n, err := w.w.Write(p)
	w.bytes += n
	return n, err
}

func (w *routeSelectingWriter) ResponseCommitted() bool {
	return w != nil && w.committed
}

func (w *routeSelectingWriter) BytesWritten() int {
	if w == nil {
		return 0
	}
	return w.bytes
}

// retryableInvokeError reports whether a failed provider attempt should fall
// over to the next authorized candidate. invokeProviderStream consults it ONLY
// before upstream acceptance (or the first write for buffered calls), so fallback never
// duplicates output or double-bills (a rejected attempt streams nothing and
// bills nothing).
//
// We fail over on ANY pre-output error, INCLUDING 4xx. In a large multi-
// provider catalog the dominant failure mode is "this provider doesn't serve
// this model on our account" — surfaced inconsistently as 400 "invalid model",
// 404 "model not found", or 401/403 (key/account not entitled) — and another
// authorized candidate very often DOES serve it. Declining to fail over on 4xx
// (the prior behavior) returned a user-facing 502 whenever the top-ranked
// provider merely lacked the model. The only cost of retrying a genuinely
// malformed request is that it's tried across candidates before returning its
// error — rare, and 4xx responses are cheap. (Output already streamed, client
// cancellation, and TTFB-budget cancellation are handled by the caller's
// response-commitment / context checks, not here.)
func retryableInvokeError(err error) bool {
	var aerr *adapter.AdapterError
	if asAdapterErr(err, &aerr) {
		return false
	}
	if isClientInputError(err) {
		return false
	}
	return err != nil
}

func writeStreamingProviderError(w io.Writer, routeType, requestID, model string, err error, hideDetails bool) error {
	return writeStreamingProviderErrorWithSettlement(w, routeType, requestID, model, err, hideDetails, nil)
}

// A known settlement/refund outcome belongs before the failure sentinel too.
// The caller supplies it only for a negotiated authorization.
func writeStreamingProviderErrorWithSettlement(w io.Writer, routeType, requestID, model string, err error, hideDetails bool, settlement *trustedrouter.SettleResult) error {
	if settlement != nil && (routeType == "responses" || routeType == "chat.completions") {
		metadata := map[string]any{}
		if settlement.HasCost() {
			usage := map[string]any{}
			annotateUsageCost(usage, settlement)
			metadata["usage"] = usage
		}
		if settlement.TrustedRouterSettlement != nil {
			metadata["trusted_router_settlement"] = settlement.TrustedRouterSettlement
		}
		if len(metadata) > 0 {
			prefix := ""
			if routeType == "responses" {
				metadata["type"] = "trusted_router.settlement"
				prefix = "event: trusted_router.settlement\n"
			} else {
				metadata["id"], metadata["object"], metadata["model"], metadata["choices"], metadata["created"] = requestID, "chat.completion.chunk", model, []any{}, time.Now().Unix()
			}
			encoded, marshalErr := json.Marshal(metadata)
			if marshalErr != nil {
				return marshalErr
			}
			if _, writeErr := fmt.Fprintf(w, "%sdata: %s\n\n", prefix, encoded); writeErr != nil {
				return writeErr
			}
		}
	}
	_, errBody := providerErrorBody(err, &trustedrouter.Authorization{HidePublicMetadata: hideDetails})
	if routeType == "messages" {
		if errBody["type"] == "provider_error" {
			errBody["type"] = "api_error"
		}
		encoded, marshalErr := json.Marshal(map[string]any{"type": "error", "error": errBody})
		if marshalErr != nil {
			return marshalErr
		}
		_, writeErr := fmt.Fprintf(w, "event: error\ndata: %s\n\n", encoded)
		return writeErr
	}
	if routeType == "responses" {
		payload := map[string]any{
			"type": "response.failed",
			"response": map[string]any{
				"id":         requestID,
				"object":     "response",
				"created_at": time.Now().Unix(),
				"model":      model,
				"status":     "failed",
				"error":      errBody,
			},
		}
		encoded, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := fmt.Fprintf(w, "event: response.failed\ndata: %s\n\n", encoded); writeErr != nil {
			return writeErr
		}
		_, writeErr := io.WriteString(w, "data: [DONE]\n\n")
		return writeErr
	}
	payload := map[string]any{
		"id": requestID, "object": "chat.completion.chunk", "model": model, "created": time.Now().Unix(),
		"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "error"}},
		"error":   errBody,
	}
	encoded, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return marshalErr
	}
	if _, writeErr := fmt.Fprintf(w, "data: %s\n\n", encoded); writeErr != nil {
		return writeErr
	}
	_, writeErr := io.WriteString(w, "data: [DONE]\n\n")
	return writeErr
}

func asAdapterErr(err error, target **adapter.AdapterError) bool {
	for cur := err; cur != nil; {
		if e, ok := cur.(*adapter.AdapterError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := cur.(unwrapper)
		if !ok {
			break
		}
		cur = u.Unwrap()
	}
	return false
}
