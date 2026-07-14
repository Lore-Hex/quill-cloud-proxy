package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// serveEmbeddings handles POST /v1/embeddings. Non-streaming: authorize
// (metadata-only) → dispatch to the per-provider embeddings client → settle
// on INPUT tokens (output=0) → return the OpenAI embeddings envelope. The
// caller's input text is sent ONLY to the upstream provider and never to the
// control plane or any log.
func serveEmbeddings(
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
	requestStarted := time.Now()

	var req types.EmbeddingRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		if message, ok := tagValidationMessage(err); ok {
			writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
			return
		}
		writeOpenAIError(conn, 400, "invalid JSON", "invalid_request_error", "bad_request", "")
		return
	}
	req.IdempotencyKey = idempotencyKey
	if req.SessionID == "" {
		req.SessionID = attribution.SessionID
	}
	req.App = attribution.App
	req.HTTPReferer = attribution.HTTPReferer
	req.AppCategories = append([]string(nil), attribution.AppCategories...)
	chatAttribution := &types.OpenAIChatRequest{
		User:          req.User,
		SessionID:     req.SessionID,
		Trace:         req.Trace,
		Tags:          types.CloneRequestTags(req.Tags),
		App:           req.App,
		HTTPReferer:   req.HTTPReferer,
		AppCategories: req.AppCategories,
	}
	if err := validateOrObserveRequestMetadata(chatAttribution, requestLogID); err != nil {
		if message, ok := tagValidationMessage(err); ok {
			writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
			return
		}
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "invalid_request_metadata", "")
		return
	}
	req.User = chatAttribution.User
	req.SessionID = chatAttribution.SessionID
	req.Trace = chatAttribution.Trace
	req.Tags = types.CloneRequestTags(chatAttribution.Tags)
	req.App = chatAttribution.App
	req.HTTPReferer = chatAttribution.HTTPReferer
	req.AppCategories = append([]string(nil), chatAttribution.AppCategories...)
	if req.Model == "" {
		writeOpenAIError(conn, 400, "model is required", "invalid_request_error", "bad_request", "model")
		return
	}
	inputs := req.Inputs()
	if len(inputs) == 0 {
		writeOpenAIError(conn, 400, "input must be a non-empty string or array of strings", "invalid_request_error", "bad_request", "input")
		return
	}
	inputTokens := types.EstimateEmbeddingInputTokens(inputs)

	var authorization *trustedrouter.Authorization
	var invokeOptions []llm.InvokeOptions
	if trEnabled {
		var err error
		authorization, err = trGateway.AuthorizeEmbeddings(ctx, bearer, &req, inputTokens)
		if err != nil {
			writeError(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"))
			return
		}
		invokeOptions, err = invokeOptionsForAuthorization(ctx, secretCache, authorization)
		if err != nil {
			_ = trGateway.Refund(ctx, authorization, 502, "byok_secret_error", time.Since(requestStarted).Seconds(), nil)
			writeError(conn, 502, "BYOK provider key unavailable")
			return
		}
		if len(invokeOptions) > 0 && invokeOptions[0].Model != "" {
			req.Model = invokeOptions[0].Model
		} else {
			req.Model = authorization.Model
		}
	}

	embedder, ok := br.(llm.EmbeddingClient)
	if !ok {
		if trEnabled {
			_ = trGateway.Refund(ctx, authorization, 501, "embeddings_unsupported", time.Since(requestStarted).Seconds(), nil)
		}
		writeError(conn, 501, "embeddings not supported by this gateway build")
		return
	}

	resp, err := embedder.InvokeEmbedding(ctx, &req, invokeOptions...)
	if err != nil {
		// Classify for billing (real upstream status when present); the
		// client always sees 502 to avoid leaking upstream specifics, same
		// as the chat path. Detail goes to stderr only (no input text).
		refundStatus := 502
		if status, hasStatus := llm.HTTPStatusFromError(err); hasStatus {
			refundStatus = status
		}
		if trEnabled {
			_ = trGateway.Refund(ctx, authorization, refundStatus, "provider_error", time.Since(requestStarted).Seconds(), nil)
		}
		fmt.Fprintf(os.Stderr, "enclave.embeddings_failed model=%q err=%v\n", req.Model, err)
		writeProviderError(conn, 502, "provider error")
		return
	}
	// Always echo the public model id, never the upstream-native one.
	resp.Model = req.Model

	if trEnabled {
		billedInput := resp.Usage.PromptTokens
		if billedInput <= 0 {
			billedInput = inputTokens
		}
		usage := trustedrouter.Usage{
			RequestID:        newRequestID(),
			InputTokens:      billedInput,
			OutputTokens:     0, // embeddings have no completion phase
			ElapsedSeconds:   maxDurationSeconds(time.Since(requestStarted), 0.001),
			UsageEstimated:   true,
			FinishReason:     "stop",
			Streamed:         false,
			RouteType:        "embeddings",
			SelectedModel:    req.Model,
			SelectedEndpoint: authorization.EndpointID,
			User:             req.User,
			SessionID:        req.SessionID,
			Trace:            req.Trace,
			Metadata:         req.Metadata,
			App:              req.App,
			HTTPReferer:      req.HTTPReferer,
			AppCategories:    append([]string(nil), req.AppCategories...),
		}
		if _, err := trGateway.Settle(ctx, authorization, usage); err != nil {
			fmt.Fprintf(os.Stderr, "enclave.embeddings_settle_failed model=%q err=%v\n", req.Model, err)
			writeError(conn, 502, "settlement failed")
			return
		}
	}

	out, err := json.Marshal(resp)
	if err != nil {
		writeError(conn, 500, "embeddings encoding error")
		return
	}
	writeJSONResponse(conn, 200, out)
}
