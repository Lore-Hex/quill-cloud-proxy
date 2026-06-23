package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

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
) {
	options := invokeOptions
	if len(options) == 0 {
		options = []llm.InvokeOptions{{Model: req.Model}}
	}
	overallStart := time.Now()
	requestID := authorizationRequestID(authorization)
	var lastErr error
	var winningProvider, winningModel, winningEndpoint string
	var winningBytes int
	var winningTTFBms, winningTotalMs int64
	for i, option := range options {
		if option.Model == "" {
			option.Model = req.Model
		}
		req.Model = option.Model
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
			attemptCtx, cancelAttempt := context.WithCancel(ctx)
			var ttfbFired bool
			ttfbTimer := time.AfterFunc(budget, func() {
				ttfbFired = true
				cancelAttempt()
			})
			attemptStart := time.Now()
			var ttfb time.Duration
			var ttfbCaptured bool
			candidateWriter = &routeSelectingWriter{
				w:       pw,
				tracker: selectedRoute,
				option:  option,
				onFirstByte: func() {
					ttfb = time.Since(attemptStart)
					ttfbCaptured = true
					ttfbTimer.Stop()
				},
			}
			err = br.InvokeStreaming(attemptCtx, req, anthropicReq, candidateWriter, option)
			attemptDuration = time.Since(attemptStart)
			ttfbTimer.Stop()
			cancelAttempt()
			if ttfbFired && err != nil {
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
			// Retry the same provider on a transient pre-output failure, but only on
			// the LAST candidate — earlier candidates fall over to the next one
			// instead. Safe: no bytes written yet, so no duplicate output / billing.
			if err == nil || candidateWriter.BytesWritten() > 0 || !isLast || !useLongLastCandidateBudget ||
				tryN >= maxTransientUpstreamRetries || !isTransientUpstreamError(err) {
				break
			}
			time.Sleep(transientUpstreamBackoff(tryN))
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
		lastErr = err
		if !trEnabled || candidateWriter.BytesWritten() > 0 || i == len(options)-1 || !retryableInvokeError(err) {
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
				requestLogID, requestID, i+1, i, time.Since(overallStart).Milliseconds(), errorClass(err),
			)
			if trEnabled {
				_ = pw.CloseWithError(err)
				return
			}
			emitErrorAsAnthropicSSE(pw, err)
			_ = pw.Close()
			return
		}
	}
	if lastErr != nil {
		fmt.Fprintf(os.Stderr,
			"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
			requestLogID, requestID, len(options), len(options)-1, time.Since(overallStart).Milliseconds(), errorClass(lastErr),
		)
		_ = pw.CloseWithError(lastErr)
		return
	}
	_ = pw.Close()
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
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return strings.ReplaceAll(msg, "\n", " ")
}

type selectedRouteTracker struct {
	mu       sync.Mutex
	once     sync.Once
	ready    chan struct{}
	model    string
	endpoint string
}

func newSelectedRouteTracker() *selectedRouteTracker {
	return &selectedRouteTracker{ready: make(chan struct{})}
}

func (t *selectedRouteTracker) Select(option llm.InvokeOptions) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.model == "" && option.Model != "" {
		t.model = option.Model
	}
	if t.endpoint == "" && option.EndpointID != "" {
		t.endpoint = option.EndpointID
	}
	t.mu.Unlock()
	t.once.Do(func() {
		close(t.ready)
	})
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
	w           io.Writer
	tracker     *selectedRouteTracker
	option      llm.InvokeOptions
	bytes       int
	onFirstByte func()
	firstByte   sync.Once
}

func (w *routeSelectingWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.tracker.Select(w.option)
		if w.onFirstByte != nil {
			w.firstByte.Do(w.onFirstByte)
		}
	}
	n, err := w.w.Write(p)
	w.bytes += n
	return n, err
}

func (w *routeSelectingWriter) BytesWritten() int {
	if w == nil {
		return 0
	}
	return w.bytes
}

// retryableInvokeError reports whether a failed provider attempt should fall
// over to the next authorized candidate. invokeProviderStream consults it ONLY
// before the first output byte is written, so trying the next provider never
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
// bytes-written / context checks, not here.)
func retryableInvokeError(err error) bool {
	return err != nil
}

func writeStreamingProviderError(w io.Writer, routeType, requestID, model string) error {
	errBody := map[string]any{
		"message": "provider error",
		"type":    "provider_error",
		"source":  "provider",
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
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: response.failed\ndata: %s\n\n", encoded); err != nil {
			return err
		}
		_, err = io.WriteString(w, "data: [DONE]\n\n")
		return err
	}
	payload := map[string]any{"error": errBody}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", encoded); err != nil {
		return err
	}
	_, err = io.WriteString(w, "data: [DONE]\n\n")
	return err
}

func emitErrorAsAnthropicSSE(w io.Writer, err error) {
	code, msg := classifyUpstreamError(err)
	text := fmt.Sprintf("[upstream: %s: %s]", code, msg)

	delta := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	deltaJSON, _ := json.Marshal(delta)
	fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaJSON)

	stopDelta := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn"},
	}
	stopJSON, _ := json.Marshal(stopDelta)
	fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", stopJSON)
	fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
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
