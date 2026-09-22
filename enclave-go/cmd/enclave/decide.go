package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const decideRouteType = "decide"

// A native model that fails verification gets one more attempt. Both attempts
// spent tokens and both are billed; a third is not worth the latency.
const nativeDecisionAttempts = 2

// decideFinalizeTimeout bounds a settle or refund made after the request's own
// context may already be gone.
const decideFinalizeTimeout = 10 * time.Second

// hostedTemplateTokenAllowance is room for whatever fixed prompt a hosted
// decision model wraps around the request before counting its input.
const hostedTemplateTokenAllowance = 4096

// finalizeContext is for the hosted SETTLE that closes an authorization. It
// keeps the request's values and drops its cancellation: a draining gateway
// cancels in-flight requests, and the vendor has already been paid by then.
// (Refunds need no such care at the call site: the control-plane client sends
// every refund on a context of its own.)
func finalizeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), decideFinalizeTimeout)
}

// controlPlaneErrorClass describes a settle/refund/authorize failure for a log
// without ever returning the error's own text.
func controlPlaneErrorClass(err error) string {
	var controlErr *trustedrouter.ControlPlaneError
	switch {
	case errors.As(err, &controlErr) && controlErr.StatusCode > 0:
		return fmt.Sprintf("control_plane_%d", controlErr.StatusCode)
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	}
	return "control_plane_unreachable"
}

// errNoGeneration says a native attempt ended without a generation to judge
// (see generationRecorder.complete). That is the PROVIDER failing, not the
// model answering badly, and it is treated as such: refunded, and tried again.
var errNoGeneration = errors.New("decide: the provider produced no complete generation")

// generationRecorder watches ONE native attempt's provider stream for the two
// facts the shared collector throws away: whether the stream reached its
// terminal `message_stop`, and whether it carried an `error` event. The
// collector starts from finish_reason "stop" and has no case for `error`, so a
// stream that simply ends -- a provider dying mid-answer -- comes back looking
// like a finished generation and is SETTLED: the caller pays for a failure.
//
// It reads SSE `event:` lines only. Model text cannot forge one: it travels
// inside a JSON string on a `data:` line, where a newline is the two characters
// `\n`. One recorder serves one attempt. The provider loop commits to a host
// at its first byte and never moves to another after that, so within an attempt
// only one host ever writes here.
type generationRecorder struct {
	// The provider goroutine writes while the settle hook reads, and may still
	// be writing when it does: the collector returns at `message_stop`, not at
	// the end of the stream.
	mu       sync.Mutex
	line     []byte // the current line, up to eventLinePrefix bytes of it
	overflow bool   // the current line is longer than that
	sawStop  bool
	sawError bool
	sawDelta bool // a content delta arrived: the generation wrote something
}

const eventLinePrefix = 64

func (g *generationRecorder) Write(p []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sawStop {
		// The generation is complete. Whatever follows -- a late error event, a
		// client error -- changes nothing the caller was owed, and must not make
		// billing depend on whether it arrived before or after the hook looked.
		return
	}
	for _, c := range p {
		if c != '\n' {
			if len(g.line) < eventLinePrefix {
				g.line = append(g.line, c)
			} else {
				g.overflow = true
			}
			continue
		}
		if !g.overflow {
			switch strings.TrimRight(string(g.line), "\r ") {
			case "event: message_stop":
				g.sawStop = true
				return
			case "event: error":
				g.sawError = true
			case "event: content_block_delta":
				g.sawDelta = true
			}
		}
		g.line, g.overflow = g.line[:0], false
	}
}

// complete is the validate-before-settle hook. A model that ran to a finish
// and answered in the wrong form is NOT rejected here: that attempt is billed,
// as documented. What is rejected -- and so refunded, and tried again -- is a
// provider that did not finish: no terminal event, an error event, or a finish
// with nothing written at all (a filtered or errored completion that a stream
// translator closed with a synthetic stop).
//
// The converse is deliberate too. A provider client that returns an error
// AFTER its stream reached `message_stop` -- the HTTP body ending badly once
// everything has arrived -- delivered a complete generation. The answer is
// used and billed once; the late error changes nothing the caller was owed.
func (g *generationRecorder) complete(result adapter.StreamResult) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.sawStop || g.sawError || strings.TrimSpace(result.Text) == "" {
		return errNoGeneration
	}
	return nil
}

// finishedGeneration reports whether the provider's stream carried a whole
// generation -- content, no error, its terminal event -- whether or not anyone
// then managed to read it. A stop with nothing before it is not one.
func (g *generationRecorder) finishedGeneration() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sawStop && g.sawDelta && !g.sawError
}

// recordingClient is the model client for one native attempt, with its output
// passed by the recorder. Only InvokeStreaming is forwarded, which is all the
// provider loop calls.
type recordingClient struct {
	inner    llm.Client
	recorder *generationRecorder
}

func (r recordingClient) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, anthropicReq *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	return r.inner.InvokeStreaming(ctx, req, anthropicReq, recordedWriter{out, r.recorder}, options...)
}

type recordedWriter struct {
	out      io.Writer
	recorder *generationRecorder
}

func (w recordedWriter) Write(p []byte) (int, error) {
	w.recorder.Write(p)
	return w.out.Write(p)
}

// nativeFailureStatus maps a failed native attempt to the caller's status. Only
// the CONTROL PLANE may speak to the caller in 4xx: its 401/402/429 are about
// the caller's own key and credits. A provider's 401 or 403 is about OUR key,
// and relaying it would tell the caller their credentials are bad. The shared
// classifier reads "http 401" out of any error text, so it is not used here.
func nativeFailureStatus(err error) int {
	var controlErr *trustedrouter.ControlPlaneError
	if errors.As(err, &controlErr) && controlErr.StatusCode > 0 {
		return controlErr.StatusCode
	}
	return 502
}

// writeDecideFailure writes a failure that may have come from the control
// plane, keeping what the control plane said about WHEN to come back: a 429
// for a per-key window carries the seconds until it resets, and an agent that
// is not told backs off blindly. spent adds x-should-retry: false.
func writeDecideFailure(conn io.Writer, status int, message string, err error, spent bool) {
	headers := retryHeadersFromControlPlaneError(err)
	if spent {
		if headers == nil {
			headers = map[string]string{}
		}
		headers[shouldRetryHeader] = "false"
	}
	writeErrorWithSourceHeaders(conn, status, message, "router", headers)
}

type decideRequest struct {
	Model     string                     `json:"model"`
	State     json.RawMessage            `json:"state"`
	Questions map[string]decide.Question `json:"questions"`
	Stream    bool                       `json:"stream,omitempty"`
	// Native models only. Reasoning turns thinking ON for a harder decision;
	// the output contract is unchanged. Provider replaces the tuned host pin.
	Reasoning       any                    `json:"reasoning,omitempty"`
	ReasoningEffort string                 `json:"reasoning_effort,omitempty"`
	MaxTokens       *int                   `json:"max_tokens,omitempty"`
	Provider        *types.ProviderRouting `json:"provider,omitempty"`
	User            string                 `json:"user,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	Metadata        map[string]any         `json:"metadata,omitempty"`
	Trace           map[string]any         `json:"trace,omitempty"`
	Tags            *types.RequestTags     `json:"tags,omitempty"`

	// askedNoul names the questions the caller spelled "noul". Questions holds
	// them as "boolean"; the answers go back in the caller's spelling.
	askedNoul map[string]bool
}

type decideUsage struct {
	InputTokens  int `json:"inputTokens"`
	OutputTokens int `json:"outputTokens"`
}

type decideResponse struct {
	Model         string                   `json:"model"`
	Answers       map[string]decide.Answer `json:"answers"`
	Usage         decideUsage              `json:"usage"`
	TrustedRouter map[string]any           `json:"trustedrouter"`
}

// isDecidePath reports whether path is the decide route. Its name is
// POST /api/alpha/decide: "alpha" because the contract may still change, and
// "decide" because that is what it does. Everything else is an alias, so that
// an existing client -- of this gateway's first path, or of another gateway's
// path for the same {model, state, questions} contract -- is a base-URL change
// away:
//
//	/api/decide            the name, for when it leaves alpha
//	/v1/decide             where this route was first published
//	/v1/evaluate           Vercel AI Gateway and the AI SDK
//	/api/alpha/decisions   OpenRouter's Decisions API, in alpha
//	/api/decisions         the same, for when it leaves alpha
//
// A client of the last two asks its yes/no questions as "noul" (TypeSafe's
// word); see decide.CanonicalQuestions for how that is accepted and answered.
func isDecidePath(path string) bool {
	switch path {
	case "/api/alpha/decide", "/api/decide", "/v1/decide", "/v1/evaluate", "/api/alpha/decisions", "/api/decisions":
		return true
	}
	return false
}

// serveDecide handles POST /api/alpha/decide and its aliases (isDecidePath): shared
// state plus typed questions in, typed answers with probabilities out.
// Non-streaming.
// The state is sent ONLY to the upstream model, never to the control plane or
// a log. Whichever backend answers, the result passes decide.Verify before a
// byte reaches the caller.
func serveDecide(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	rawBody []byte,
	trGateway *trustedrouter.Client,
	trEnabled bool,
	bearer string,
	secretCache *byokcache.Cache,
	idempotencyKey string,
	attribution requestAttributionHeaders,
	requestLogID string,
) {
	var req decideRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		if message, ok := tagValidationMessage(err); ok {
			writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
			return
		}
		writeOpenAIError(conn, 400, "invalid JSON", "invalid_request_error", "bad_request", "")
		return
	}
	if req.Model == "" {
		writeOpenAIError(conn, 400, "model is required", "invalid_request_error", "bad_request", "model")
		return
	}
	if req.Stream {
		writeOpenAIError(conn, 400, "decision models do not stream", "invalid_request_error", "bad_request", "stream")
		return
	}
	// "noul" is a spelling, not a type: everything below sees "boolean", and
	// the answers are re-spelled for the questions that asked with it.
	req.Questions, req.askedNoul = decide.CanonicalQuestions(req.Questions)
	specs, err := decide.Parse(req.Questions)
	if err == nil {
		_, err = decide.StateText(req.State)
	}
	if err != nil {
		var invalid *decide.Error
		if errors.As(err, &invalid) {
			writeOpenAIError(conn, 400, invalid.Message, "invalid_request_error", "bad_request", invalid.Param)
			return
		}
		writeOpenAIError(conn, 400, "invalid request", "invalid_request_error", "bad_request", "")
		return
	}
	if req.SessionID == "" {
		req.SessionID = attribution.SessionID
	}
	chatAttribution := &types.OpenAIChatRequest{
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
		Tags: types.CloneRequestTags(req.Tags), App: attribution.App, HTTPReferer: attribution.HTTPReferer,
		AppCategories: append([]string(nil), attribution.AppCategories...),
	}
	if err := validateOrObserveRequestMetadata(chatAttribution, requestLogID); err != nil {
		if message, ok := tagValidationMessage(err); ok {
			writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
			return
		}
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "invalid_request_metadata", "")
		return
	}
	if decide.HostedModels[req.Model] {
		// A hosted decision model has no thinking to turn on and no token
		// budget, and its hosts are the vendor and its relay in that order.
		// Saying so beats silently ignoring the parameter. "Set" means a value
		// that asks for something: null, "" and stream:false are how clients
		// spell "unset", and rejecting them would break every SDK that always
		// serializes its defaults. A fixed order keeps the message stable when
		// more than one is set.
		// reasoning:false and reasoning_effort:"none" ask for what a hosted
		// model already does, so they are unset too; a malformed value still
		// counts as set and is refused here rather than silently dropped.
		effort, reasoningErr := decide.RequestedReasoning(req.Reasoning, req.ReasoningEffort)
		var malformed *decide.Error
		if errors.As(reasoningErr, &malformed) {
			// Name the field that is wrong, as a native model would: the
			// caller's typo is the same typo on any model.
			writeOpenAIError(conn, 400, malformed.Message, "invalid_request_error", "bad_request", malformed.Param)
			return
		}
		asksToReason := effort != ""
		for _, param := range []struct {
			name string
			set  bool
		}{
			{"reasoning", asksToReason && req.Reasoning != nil}, {"reasoning_effort", asksToReason && req.ReasoningEffort != ""},
			{"max_tokens", req.MaxTokens != nil}, {"provider", req.Provider != nil},
		} {
			if param.set {
				writeOpenAIError(conn, 400, param.name+" is not supported by hosted decision model "+req.Model, "invalid_request_error", "bad_request", param.name)
				return
			}
		}
		serveHostedDecide(ctx, conn, br, &req, specs, chatAttribution, trGateway, trEnabled, bearer, secretCache, idempotencyKey)
		return
	}
	// Every other id is a chat model driven as a decision function: a tuned
	// configuration when there is one, the assume-nothing generic one when not.
	native, tuned := decide.NativeModels[req.Model]
	if !tuned {
		native = decide.GenericNativeModel
	}
	serveNativeDecide(ctx, conn, br, &req, specs, native, chatAttribution, trGateway, trEnabled, bearer, secretCache, idempotencyKey, requestLogID)
}

func serveHostedDecide(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *decideRequest,
	specs []decide.Spec,
	attribution *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	trEnabled bool,
	bearer string,
	secretCache *byokcache.Cache,
	idempotencyKey string,
) {
	requestStarted := time.Now()
	publicModel := req.Model
	questionBytes, _ := json.Marshal(req.Questions)
	inputTokens := types.EstimateEmbeddingInputTokens([]string{string(req.State), string(questionBytes)})

	var authorization *trustedrouter.Authorization
	var invokeOptions []llm.InvokeOptions
	if trEnabled {
		authReq := &types.EmbeddingRequest{
			Model: req.Model, User: attribution.User, SessionID: attribution.SessionID,
			Metadata: attribution.Metadata, Trace: attribution.Trace, Tags: types.CloneRequestTags(attribution.Tags),
			IdempotencyKey: idempotencyKey, App: attribution.App, HTTPReferer: attribution.HTTPReferer,
			AppCategories: attribution.AppCategories,
		}
		var err error
		authorization, err = trGateway.AuthorizeEmbeddingsWithRoute(ctx, bearer, authReq, inputTokens, decideRouteType)
		if err != nil {
			writeDecideFailure(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"), err, false)
			return
		}
	}
	refund := func(status int, errorType string) {
		if !trEnabled {
			return
		}
		// The client sends every refund on a context of its own.
		if err := trGateway.Refund(ctx, authorization, status, errorType, time.Since(requestStarted).Seconds(), nil); err != nil {
			fmt.Fprintf(os.Stderr, "enclave.decide_refund_failed model=%q error_class=%q\n", req.Model, controlPlaneErrorClass(err))
		}
	}
	if trEnabled {
		var err error
		invokeOptions, err = invokeOptionsForAuthorization(ctx, secretCache, authorization)
		if err != nil {
			refund(502, "byok_secret_error")
			writeError(conn, 502, "provider key unavailable")
			return
		}
	}
	decider, ok := br.(llm.DecideClient)
	if !ok {
		refund(501, "decide_unsupported")
		writeError(conn, 501, "decision models are not supported by this gateway build")
		return
	}
	// A hosted decision model can have more than one host (the vendor's own
	// API first, a relay second). Walk the authorized candidates in order, the
	// same way chat does: nothing has been written to the caller yet, so moving
	// to the next host on ANY upstream failure can neither duplicate output nor
	// double-bill. Settlement names whichever host actually served.
	candidates := invokeOptions
	if len(candidates) == 0 {
		candidates = []llm.InvokeOptions{{}}
	}
	wire := &llm.DecideRequest{Model: req.Model, State: req.State, Questions: req.Questions}
	var upstream *llm.DecideResponse
	var served llm.InvokeOptions
	var err error
	// refusedAsInvalid: did EVERY host that answered refuse the request itself
	// (400, 413, 422)? Then it is the caller's request that is wrong -- too
	// long for the model, say -- and a 502 would tell them to retry something
	// that can never work. One host failing any other way leaves it unknown.
	refusedAsInvalid := true
	attemptCount := 0
	for index, candidate := range candidates {
		attemptCount++
		upstream, err = decider.InvokeDecide(ctx, wire, candidate)
		if err == nil {
			served = candidate
			break
		}
		if status, _ := llm.DecideErrorStatus(err); status != 400 && status != 413 && status != 422 {
			refusedAsInvalid = false
		}
		// The class, never err. InvokeDecide's errors hold no upstream text by
		// construction, and DecideErrorClass returns "unknown" for anything
		// else rather than its message.
		fmt.Fprintf(os.Stderr, "enclave.decide_host_failed model=%q provider=%q attempt=%d of=%d error_class=%q\n",
			publicModel, candidate.Provider, index+1, len(candidates), llm.DecideErrorClass(err))
		if ctx.Err() != nil {
			// Hosts that were never asked cannot be said to have refused it.
			// When this WAS the last host, every one of them has spoken, and a
			// cancellation arriving with its answer changes nothing.
			if index < len(candidates)-1 {
				refusedAsInvalid = false
			}
			break
		}
	}
	if err != nil {
		refundStatus := 502
		if status, hasStatus := llm.DecideErrorStatus(err); hasStatus {
			refundStatus = status
		}
		if refusedAsInvalid {
			refund(refundStatus, "provider_rejected_request")
			writeOpenAIError(conn, 400, "the decision model rejected this request as invalid; it may exceed the model's input limit", "invalid_request_error", "provider_rejected_request", "")
			return
		}
		refund(refundStatus, "provider_error")
		writeProviderError(conn, 502, "provider error")
		return
	}
	// Second pass: the hosted model is a third party. Its answers are checked
	// against the request exactly as a native model's are.
	answers, err := decide.Verify(specs, upstream.Answers)
	if err != nil {
		refund(502, "decide_verification_failed")
		// The violation KIND only: the reason names the caller's own questions
		// and options, and request content never reaches a log.
		fmt.Fprintf(os.Stderr, "enclave.decide_verification_failed model=%q backend=hosted provider=%q kind=%q\n",
			publicModel, served.Provider, decide.ViolationKind(err))
		// The caller is refunded, but the vendor ran and was paid, and asking
		// again buys the same answer: do not retry.
		writeSpentProviderError(conn, 502, "decision model returned an invalid answer")
		return
	}
	billedInput := upstream.InputTokens
	if billedInput <= 0 {
		billedInput = inputTokens
	}
	// The count is the vendor's word and is what the caller pays for, so it is
	// held to what this request could possibly have cost: a token is at least
	// one byte of input, plus the vendor's own fixed template. A response
	// claiming more (a bug, or 9223372036854775807) is billed at the ceiling
	// and says so in the log.
	if ceiling := len(req.State) + len(questionBytes) + hostedTemplateTokenAllowance; billedInput > ceiling {
		fmt.Fprintf(os.Stderr, "enclave.decide_usage_clamped model=%q provider=%q reported_input_tokens=%d ceiling=%d\n",
			publicModel, served.Provider, billedInput, ceiling)
		billedInput = ceiling
	}
	var settlement *trustedrouter.SettleResult
	if trEnabled {
		servedEndpoint := served.EndpointID
		if servedEndpoint == "" {
			servedEndpoint = authorization.EndpointID
		}
		usage := trustedrouter.Usage{
			RequestID: newRequestID(), InputTokens: billedInput, OutputTokens: 0, // output is not metered
			ElapsedSeconds: maxDurationSeconds(time.Since(requestStarted), 0.001), UsageEstimated: upstream.InputTokens <= 0,
			FinishReason: "stop", RouteType: decideRouteType, SelectedModel: publicModel, SelectedEndpoint: servedEndpoint,
			User: attribution.User, SessionID: attribution.SessionID, Trace: attribution.Trace, Metadata: attribution.Metadata,
			App: attribution.App, HTTPReferer: attribution.HTTPReferer, AppCategories: append([]string(nil), attribution.AppCategories...),
		}
		settleCtx, cancelSettle := finalizeContext(ctx)
		settlement, err = trGateway.Settle(settleCtx, authorization, usage)
		cancelSettle()
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclave.decide_settle_failed model=%q error_class=%q\n", publicModel, controlPlaneErrorClass(err))
			writeDecideFailure(conn, 502, "settlement failed", err, true)
			return
		}
	}
	fallbackCount := attemptCount - 1
	writeDecideResponse(ctx, conn, decideResponse{Model: publicModel, Answers: decide.InAskedSpelling(answers, req.askedNoul), Usage: decideUsage{InputTokens: billedInput, OutputTokens: upstream.OutputTokens}}, settlement, authorization, decideRoutingMetadata{
		Served: served, CandidateCount: len(candidates), AttemptCount: attemptCount, FallbackCount: &fallbackCount,
	})
}

func serveNativeDecide(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *decideRequest,
	specs []decide.Spec,
	native decide.NativeModel,
	attribution *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	trEnabled bool,
	bearer string,
	secretCache *byokcache.Cache,
	idempotencyKey string,
	requestLogID string,
) {
	// Validate the caller's options BEFORE anything else, so a bad request is
	// a 400 no matter how this gateway is deployed.
	chatReq, err := nativeDecideChatRequest(req, specs, native, attribution)
	if err != nil {
		var invalid *decide.Error
		if errors.As(err, &invalid) {
			writeOpenAIError(conn, 400, invalid.Message, "invalid_request_error", "bad_request", invalid.Param)
			return
		}
		writeOpenAIError(conn, 400, "invalid request", "invalid_request_error", "bad_request", "")
		return
	}
	if !trEnabled {
		writeError(conn, 501, "native decision models require the control plane")
		return
	}
	usage := decideUsage{}
	upstreamAttempts, fallbackAttempts := 0, 0
	var lastSettlement *trustedrouter.SettleResult
	var lastAuthorization *trustedrouter.Authorization
	// spent: did a provider already produce a complete result for this
	// request? That is what x-should-retry: false means (see writeSpentError):
	// re-sending would generate, and pay for, that result again. It is true
	// once an attempt has returned a result, and when an attempt fails AT
	// settlement, which only happens after one. It is not inferred from
	// anything else. Token counts were wrong (an attempt can settle with
	// input_tokens 0, all cache reads); so were text deltas (a filtered
	// completion has none) and bytes written (a keepalive before any
	// generation is bytes). A provider that fails mid-stream produced no
	// result, is refunded, and retrying it is exactly right.
	spent := false
	for attempt := 1; attempt <= nativeDecisionAttempts; attempt++ {
		attemptReq := *chatReq
		// Each attempt is its own billed generation, so each needs its own key.
		attemptKey := idempotencyKey
		if attemptKey != "" && attempt > 1 {
			attemptKey = fmt.Sprintf("%s:decide-retry-%d", idempotencyKey, attempt)
		}
		attemptReq.IdempotencyKey = attemptKey
		recorder := &generationRecorder{}
		call, err := runFusionCallValidated(ctx, recordingClient{br, recorder}, &attemptReq, trGateway, secretCache, bearer, decideRouteType, attemptKey, requestLogID, nil, false, recorder.complete, true)
		// Use the shared chat route tracker's counts, including refunded calls;
		// decision iterations themselves are not upstream attempts or fallbacks.
		upstreamAttempts += call.AttemptCount
		fallbackAttempts += call.FallbackCount
		if err != nil {
			var afterResult *settlementAttemptedError
			var verdict *trustedrouter.ControlPlaneError
			atSettlement := errors.As(err, &afterResult)
			// A PROVIDER failing -- an error mid-stream, a stream that just
			// ends, a finish with nothing written -- has been refunded by the
			// shared call and nothing has reached the caller, so it gets the
			// other attempt, which may land on a host that is up. (Failures
			// before a host's first byte already failed over inside the call.)
			// A control-plane verdict is different: no credit, a key limit, a
			// failed settlement. Asking again changes nothing, so it is
			// surfaced.
			// One thin case sits between "finished" and "failed": the transport
			// dies after the provider's `event: message_stop` line and before
			// the collector has the event's data. The collector reports a
			// transport error and drops the text, so the attempt is refunded and
			// the other one runs like any provider failure -- but a generation
			// WAS finished and paid for, so if this request ends in failure the
			// client is told not to regenerate it.
			spent = spent || recorder.finishedGeneration()
			if !atSettlement && !errors.As(err, &verdict) && attempt < nativeDecisionAttempts {
				fmt.Fprintf(os.Stderr, "enclave.decide_no_generation model=%q attempt=%d error_class=%q\n", req.Model, attempt, errorClass(err))
				continue
			}
			spent = spent || atSettlement
			writeDecideFailure(conn, nativeFailureStatus(err), messageFromControlPlaneError(err, "provider error"), err, spent)
			return
		}
		spent = true
		usage.InputTokens += call.InputTokens
		usage.OutputTokens += call.OutputTokens
		lastSettlement = call.SettlementResult
		lastAuthorization = call.Authorization
		answers, err := decide.ExtractNative(specs, call.Result.Text)
		if err == nil {
			// Second pass, identical to the hosted path.
			answers, err = decide.Verify(specs, answers)
		}
		if err == nil {
			writeDecideResponse(ctx, conn, decideResponse{Model: req.Model, Answers: decide.InAskedSpelling(answers, req.askedNoul), Usage: usage}, lastSettlement, lastAuthorization, decideRoutingMetadata{
				Served:         llm.InvokeOptions{Model: call.Model, Provider: call.Provider, EndpointID: call.Endpoint},
				CandidateCount: routeCandidateCount(call.Authorization, nil), AttemptCount: upstreamAttempts, FallbackCount: &fallbackAttempts,
			})
			return
		}
		fmt.Fprintf(os.Stderr, "enclave.decide_verification_failed model=%q backend=native attempt=%d kind=%q\n",
			req.Model, attempt, decide.ViolationKind(err))
	}
	writeSpentError(conn, 502, "decision model returned an invalid answer")
}

func nativeDecideChatRequest(req *decideRequest, specs []decide.Spec, native decide.NativeModel, attribution *types.OpenAIChatRequest) (*types.OpenAIChatRequest, error) {
	chatReq, err := decide.NativeChatRequest(req.Model, req.State, specs, native, decide.NativeOptions{
		Reasoning: req.Reasoning, ReasoningEffort: req.ReasoningEffort, MaxTokens: req.MaxTokens, Provider: req.Provider,
	})
	if err != nil {
		return nil, err
	}
	chatReq.User = attribution.User
	chatReq.SessionID = attribution.SessionID
	chatReq.Trace = attribution.Trace
	chatReq.Metadata = attribution.Metadata
	chatReq.Tags = types.CloneRequestTags(attribution.Tags)
	chatReq.App = attribution.App
	chatReq.HTTPReferer = attribution.HTTPReferer
	chatReq.AppCategories = append([]string(nil), attribution.AppCategories...)
	return chatReq, nil
}

func writeDecideResponse(ctx context.Context, conn io.Writer, resp decideResponse, settlement *trustedrouter.SettleResult, authorization *trustedrouter.Authorization, routing decideRoutingMetadata) {
	if routing.Served.Model == "" {
		routing.Served.Model = resp.Model
	}
	resp.TrustedRouter = decideTrustedRouterRouting(authorization, settlement, routing)
	out, err := json.Marshal(resp)
	if err == nil {
		out, err = annotateBatchSettlementOnlyUsage(ctx, out, settlement, authorization)
	}
	if err != nil {
		writeSpentError(conn, 500, "decision encoding error")
		return
	}
	writeJSONResponse(conn, 200, out)
}
