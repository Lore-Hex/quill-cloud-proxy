package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		var ttfbFired bool
		ttfbTimer := time.AfterFunc(firstByteBudget, func() {
			ttfbFired = true
			cancelAttempt()
		})
		attemptStart := time.Now()
		var ttfb time.Duration
		var ttfbCaptured bool
		candidateWriter := &routeSelectingWriter{
			w:       pw,
			tracker: selectedRoute,
			option:  option,
			onFirstByte: func() {
				ttfb = time.Since(attemptStart)
				ttfbCaptured = true
				ttfbTimer.Stop()
			},
		}
		err := br.InvokeStreaming(attemptCtx, req, anthropicReq, candidateWriter, option)
		attemptDuration := time.Since(attemptStart)
		ttfbTimer.Stop()
		cancelAttempt()
		if ttfbFired && err != nil {
			err = fmt.Errorf("llm/upstream: time-to-first-byte exceeded %s: %w", firstByteBudget, err)
		}

		ttfbMs := int64(-1)
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
			"enclave.invoke_attempt request_log_id=%q request_id=%q attempt=%d/%d model=%q provider=%q endpoint=%q outcome=%s ttfb_ms=%d total_ms=%d bytes=%d err=%q\n",
			requestLogID,
			requestID,
			i+1, len(options),
			option.Model, option.Provider, option.EndpointID,
			outcome,
			ttfbMs,
			attemptDuration.Milliseconds(),
			candidateWriter.BytesWritten(),
			errStr,
		)

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
	raw := os.Getenv("QUILL_FIRST_BYTE_TIMEOUT_SECONDS")
	if raw == "" {
		return 8 * time.Second
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 8 * time.Second
}()

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
// over to the next authorized candidate. The default is to FAIL OVER: when no
// output bytes have been written yet, a different provider is almost always
// worth trying. We decline ONLY for errors a different provider cannot fix — a
// malformed or oversized *request* (HTTP 400/413/422), which every provider
// rejects identically. Everything else routes to the next candidate: upstream
// 5xx, 429, 408, 404 (model absent on this provider), 401/403 (bad or missing
// key for this provider), and all transport / timeout / cancellation errors.
//
// This replaced an allowlist of error-string substrings that recognized only
// 5xx / 429 / timeouts and SILENTLY declined to fail over on anything else — so
// a provider that 404'd (model not on that account), 401'd (key unwired), or
// failed at the connection level returned a user-facing 502 even when healthy
// authorized providers were available to try.
func retryableInvokeError(err error) bool {
	if err == nil {
		return false
	}
	if status, ok := llm.HTTPStatusFromError(err); ok {
		return !nonRetryableUpstreamStatus(status)
	}
	// Non-typed errors are transport / timeout / cancellation failures — fail
	// over. As a guard for any non-typed upstream error string, still decline
	// on an explicit client-request rejection.
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "http 400") || strings.Contains(message, "status 400") ||
		strings.Contains(message, "http 422") || strings.Contains(message, "status 422") {
		return false
	}
	return true
}

// nonRetryableUpstreamStatus is true for upstream statuses that signal a bad
// request every provider would reject the same way, so failing over is
// pointless. Everything else (incl. 401/403/404/408/429 and all 5xx) is
// retryable.
func nonRetryableUpstreamStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func writeStreamingProviderError(w io.Writer, routeType, requestID, model string) error {
	errBody := map[string]any{
		"message": "provider error",
		"type":    "provider_error",
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
