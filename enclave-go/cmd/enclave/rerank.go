package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var rerankEnabled bool

func configureRerank() { rerankEnabled = os.Getenv("TR_RERANK_ENABLED") == "true" }

func serveRerank(ctx context.Context, conn io.Writer, br llm.Client, rawBody []byte, trGateway *trustedrouter.Client, trEnabled bool, bearer, idempotencyKey string, attribution requestAttributionHeaders, requestLogID string) {
	requestStarted := time.Now()
	req, err := types.ParseRerankRequest(rawBody)
	if err != nil {
		var validation *types.RerankValidationError
		if errors.As(err, &validation) {
			writeOpenAIError(conn, 400, validation.Message, "invalid_request_error", "bad_request", validation.Param)
			return
		}
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

	if p := req.Provider; p != nil {
		for _, mode := range []string{p.Usage, p.UsageType, p.Billing} {
			if mode != "" && !strings.EqualFold(mode, "credits") && !strings.EqualFold(mode, "prepaid") {
				writeOpenAIError(conn, 400, "rerank requires Credits", "invalid_request_error", "bad_request", "provider")
				return
			}
		}
	}
	reranker, ok := br.(llm.RerankClient)
	if !ok {
		writeError(conn, 501, "rerank not supported by this gateway build")
		return
	}
	if !trEnabled {
		writeError(conn, 503, "rerank authorization unavailable")
		return
	}
	inputTokens := types.EstimateRerankInputTokens(req.Query, req.Documents)
	var authorization *trustedrouter.Authorization
	defer func() { refundUnclosedHold(ctx, trGateway, authorization, "rerank", requestStarted, nil) }()
	authorization, err = trGateway.AuthorizeEmbeddingsWithRouteSync(ctx, bearer, &req.EmbeddingRequest, inputTokens, "rerank")
	if err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	option, err := rerankAuthorizedOption(authorization)
	if err != nil {
		status := 400
		if errors.Is(err, llm.ErrRerankUnsupported) {
			status = 501
		}
		refundHold(ctx, trGateway, authorization, status, "rerank_route_unsupported", time.Since(requestStarted).Seconds(), nil)
		if status == 501 {
			writeError(conn, 501, "rerank not supported by this provider")
			return
		}
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "bad_request", "provider")
		return
	}
	phases := requesttiming.FromContext(ctx)
	invocation := phases.InvokeStart()
	authorization.RecordShadowInvocation(option.EndpointID, option.Provider)
	resp, err := reranker.InvokeRerank(ctx, req, option)
	phases.InvokeComplete(invocation)
	if err == nil && resp == nil {
		err = errors.New("invalid rerank provider response")
	}
	var results []types.RerankResult
	if err == nil {
		results, err = types.PublicRerankResults(req, resp.Results)
	}
	if err == nil && ((resp.InputTokens != nil && *resp.InputTokens < 0) || (resp.SearchUnits != nil && *resp.SearchUnits < 0)) {
		err = errors.New("invalid rerank usage")
	}
	if err != nil {
		status := 502
		if upstream, ok := llm.HTTPStatusFromError(err); ok {
			status = upstream
		}
		if errors.Is(err, llm.ErrRerankInputLimit) {
			status = 413
		}
		if errors.Is(err, llm.ErrRerankUnsupported) {
			status = 501
		}
		refundHold(ctx, trGateway, authorization, status, "provider_error", time.Since(requestStarted).Seconds(), nil)
		fmt.Fprintf(os.Stderr, "enclave.rerank_failed request_log_id=%q upstream_status=%d documents=%d error_class=provider_error\n", requestLogID, status, len(req.Documents))
		if errors.Is(err, llm.ErrRerankInputLimit) {
			writeOpenAIError(conn, 400, llm.ErrRerankInputLimit.Error(), "invalid_request_error", "rerank_input_too_long", "documents")
			return
		}
		if errors.Is(err, llm.ErrRerankUnsupported) {
			writeError(conn, 501, "rerank not supported by this provider")
			return
		}
		writeProviderError(conn, 502, "provider error")
		return
	}
	billedInput, estimated := inputTokens, true
	if resp.InputTokens != nil {
		billedInput, estimated = *resp.InputTokens, false
	}
	requestID := newRequestID()
	usage := trustedrouter.Usage{
		RequestID: requestID, InputTokens: billedInput, OutputTokens: 0,
		ElapsedSeconds: maxDurationSeconds(time.Since(requestStarted), 0.001), UsageEstimated: estimated,
		FinishReason: "stop", Streamed: false, RouteType: "rerank", SelectedModel: option.Model, SelectedEndpoint: option.EndpointID,
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
		App: req.App, HTTPReferer: req.HTTPReferer, AppCategories: append([]string(nil), req.AppCategories...),
	}
	settlement, err := trGateway.Settle(ctx, authorization, usage)
	if err != nil {
		refundHold(ctx, trGateway, authorization, 502, "settlement_failed", time.Since(requestStarted).Seconds(), nil)
		fmt.Fprintf(os.Stderr, "enclave.rerank_settle_failed request_log_id=%q error_class=settlement\n", requestLogID)
		writeSpentError(conn, 502, "settlement failed")
		return
	}
	responseUsage := map[string]any{"total_tokens": billedInput}
	if resp.SearchUnits != nil {
		responseUsage["search_units"] = *resp.SearchUnits
	}
	annotateUsageCost(responseUsage, settlement)
	out, err := json.Marshal(map[string]any{"id": requestID, "model": req.Model, "provider": option.Provider, "results": results, "usage": responseUsage})
	if err != nil {
		writeSpentError(conn, 500, "rerank encoding error")
		return
	}
	writeJSONResponse(conn, 200, out)
}

// Rerank selects only the first authorized candidate and never resolves keys.
func rerankAuthorizedOption(a *trustedrouter.Authorization) (llm.InvokeOptions, error) {
	invalid := errors.New("rerank requires a prepaid Voyage or Cohere route")
	if a == nil || !strings.EqualFold(a.UsageType, "Credits") || a.BYOKSecretRef != "" || a.BYOKEncryptedSecret != nil || a.BYOKCacheKey != "" || a.BYOKProvider != "" {
		return llm.InvokeOptions{}, invalid
	}
	candidate := trustedrouter.RouteCandidate{Model: a.Model, UpstreamModel: a.UpstreamModel, Provider: a.Provider, EndpointID: a.EndpointID, UsageType: a.UsageType}
	if len(a.RouteCandidates) > 0 {
		candidate = a.RouteCandidates[0]
	}
	if candidate.Model == "" {
		candidate.Model = a.Model
	}
	if candidate.Provider == "" {
		candidate.Provider = a.Provider
	}
	if candidate.EndpointID == "" {
		candidate.EndpointID = a.EndpointID
	}
	if candidate.UpstreamModel == "" {
		candidate.UpstreamModel = a.UpstreamModel
	}
	if candidate.UsageType == "" {
		candidate.UsageType = a.UsageType
	}
	if !strings.EqualFold(candidate.UsageType, "Credits") || candidate.BYOKSecretRef != "" || candidate.BYOKEncryptedSecret != nil || candidate.BYOKCacheKey != "" || candidate.BYOKProvider != "" {
		return llm.InvokeOptions{}, invalid
	}
	if candidate.Provider != "voyage" && candidate.Provider != "cohere" {
		return llm.InvokeOptions{}, llm.ErrRerankUnsupported
	}
	if candidate.UpstreamModel == "" || candidate.EndpointID == "" || candidate.Model == "" {
		return llm.InvokeOptions{}, invalid
	}
	return llm.InvokeOptions{Model: candidate.Model, UpstreamModel: candidate.UpstreamModel, Provider: candidate.Provider, EndpointID: candidate.EndpointID, UsageType: "Credits"}, nil
}
