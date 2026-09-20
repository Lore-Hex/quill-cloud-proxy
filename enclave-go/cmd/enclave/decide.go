package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

// finalizeContext is for the settle or refund that closes an authorization. It
// keeps the request's values and drops its cancellation: a draining gateway
// cancels in-flight requests, and a refund sent on a cancelled context is a
// refund that never leaves, stranding the hold until the control plane reaps
// it. Same shape as the image route's refund.
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
}

type decideUsage struct {
	InputTokens  int `json:"inputTokens"`
	OutputTokens int `json:"outputTokens"`
}

type decideResponse struct {
	Model   string                   `json:"model"`
	Answers map[string]decide.Answer `json:"answers"`
	Usage   decideUsage              `json:"usage"`
}

// serveDecide handles POST /v1/decide (alias /v1/evaluate): shared state plus
// typed questions in, typed answers with probabilities out. Non-streaming.
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
		for _, param := range []struct {
			name string
			set  bool
		}{
			{"reasoning", req.Reasoning != nil}, {"reasoning_effort", req.ReasoningEffort != ""},
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
			writeError(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"))
			return
		}
		invokeOptions, err = invokeOptionsForAuthorization(ctx, secretCache, authorization)
		if err != nil {
			refundCtx, cancel := finalizeContext(ctx)
			_ = trGateway.Refund(refundCtx, authorization, 502, "byok_secret_error", time.Since(requestStarted).Seconds(), nil)
			cancel()
			writeError(conn, 502, "provider key unavailable")
			return
		}
	}
	refund := func(status int, errorType string) {
		if !trEnabled {
			return
		}
		refundCtx, cancel := finalizeContext(ctx)
		defer cancel()
		if err := trGateway.Refund(refundCtx, authorization, status, errorType, time.Since(requestStarted).Seconds(), nil); err != nil {
			fmt.Fprintf(os.Stderr, "enclave.decide_refund_failed model=%q error_class=%q\n", req.Model, controlPlaneErrorClass(err))
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
	for index, candidate := range candidates {
		upstream, err = decider.InvokeDecide(ctx, wire, candidate)
		if err == nil {
			served = candidate
			break
		}
		// The class, never err. InvokeDecide's errors hold no upstream text by
		// construction, and DecideErrorClass returns "unknown" for anything
		// else rather than its message.
		fmt.Fprintf(os.Stderr, "enclave.decide_host_failed model=%q provider=%q attempt=%d of=%d error_class=%q\n",
			publicModel, candidate.Provider, index+1, len(candidates), llm.DecideErrorClass(err))
		if ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		refundStatus := 502
		if status, hasStatus := llm.DecideErrorStatus(err); hasStatus {
			refundStatus = status
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
		writeProviderError(conn, 502, "decision model returned an invalid answer")
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
			writeSpentError(conn, 502, "settlement failed")
			return
		}
	}
	writeDecideResponse(ctx, conn, decideResponse{Model: publicModel, Answers: answers, Usage: decideUsage{InputTokens: billedInput, OutputTokens: upstream.OutputTokens}}, settlement, authorization)
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
	var lastSettlement *trustedrouter.SettleResult
	var lastAuthorization *trustedrouter.Authorization
	// spent: has any provider run for this request? It decides whether a
	// failure tells the client not to retry. Token counts cannot answer that:
	// an attempt can settle with input_tokens 0 (everything read from cache),
	// and an attempt whose SETTLEMENT failed ran a provider and returned no
	// usage at all. So it is tracked directly: an attempt that settled, or a
	// provider that was seen producing output.
	spent := false
	for attempt := 1; attempt <= nativeDecisionAttempts; attempt++ {
		attemptReq := *chatReq
		// Each attempt is its own billed generation, so each needs its own key.
		attemptKey := idempotencyKey
		if attemptKey != "" && attempt > 1 {
			attemptKey = fmt.Sprintf("%s:decide-retry-%d", idempotencyKey, attempt)
		}
		attemptReq.IdempotencyKey = attemptKey
		sawOutput := func(adapter.StreamDelta) { spent = true }
		call, err := runFusionCallObserved(ctx, br, &attemptReq, trGateway, secretCache, bearer, decideRouteType, attemptKey, requestLogID, nil, false, sawOutput, false)
		if err != nil {
			// Authorization or provider failure: runFusionCall has already
			// refunded. Nothing about a retry would differ, so surface it.
			status, message := nativeFailureStatus(err), messageFromControlPlaneError(err, "provider error")
			if spent {
				writeSpentError(conn, status, message)
				return
			}
			writeError(conn, status, message)
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
			writeDecideResponse(ctx, conn, decideResponse{Model: req.Model, Answers: answers, Usage: usage}, lastSettlement, lastAuthorization)
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

func writeDecideResponse(ctx context.Context, conn io.Writer, resp decideResponse, settlement *trustedrouter.SettleResult, authorization *trustedrouter.Authorization) {
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
