package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const parasailLiberty20BillingProfile = "parasail-liberty-2.0"
const parasailLiberty20TopLevelRoute = "partner.parasail.liberty-2.0.top_level"
const parasailLiberty20TopLevelIdempotencyPrefix = "partner-top:parasail-liberty-2.0:"
const parasailLiberty20InternalRoutePrefix = "partner.parasail.liberty-2.0.internal."
const parasailLiberty20IdempotencyPrefix = "partner:parasail-liberty-2.0:"

func partnerInternalBillingRoute(req *types.OpenAIChatRequest, logicalRoute string) string {
	if req == nil || req.InternalBillingProfile != parasailLiberty20BillingProfile {
		return logicalRoute
	}
	return parasailLiberty20InternalRoutePrefix + strings.TrimPrefix(logicalRoute, ".")
}

func partnerInternalIdempotencyKey(req *types.OpenAIChatRequest, key string) string {
	if req == nil || req.InternalBillingProfile != parasailLiberty20BillingProfile {
		return key
	}
	return parasailLiberty20IdempotencyPrefix + key
}

func authorizePartnerTopLevel(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	trGateway *trustedrouter.Client,
	bearer string,
	requestID string,
) (*trustedrouter.Authorization, error) {
	if config.BillingProfile != parasailLiberty20BillingProfile {
		return nil, nil
	}
	topReq := cloneChatRequest(req)
	topReq.Model = parasailLiberty20Model
	topReq.Models = nil
	topReq.InternalBillingProfile = ""
	idempotencyKey := strings.TrimSpace(req.IdempotencyKey)
	if idempotencyKey == "" {
		idempotencyKey = requestID
	}
	topReq.IdempotencyKey = parasailLiberty20TopLevelIdempotencyPrefix + idempotencyKey
	return trGateway.AuthorizeWithRoute(
		ctx,
		bearer,
		topReq,
		parasailLiberty20TopLevelRoute,
	)
}

func refundPartnerTopLevel(
	ctx context.Context,
	trGateway *trustedrouter.Client,
	auth *trustedrouter.Authorization,
	err error,
	started time.Time,
	metadata map[string]any,
) {
	if auth == nil {
		return
	}
	status := statusFromControlPlaneError(err)
	if status < 400 {
		status = 502
	}
	_ = trGateway.Refund(
		ctx,
		auth,
		status,
		"partner_orchestration_error",
		maxDurationSeconds(time.Since(started), 0.001),
		metadata,
	)
}

func settlePartnerTopLevel(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	auth *trustedrouter.Authorization,
	final fusionCallResult,
	requestID string,
	started time.Time,
	originalInput any,
) (*trustedrouter.SettleResult, error) {
	if auth == nil {
		return nil, nil
	}
	inputTokens := trustedrouter.EstimateInputTokens(req)
	if inputTokens < 1 {
		inputTokens = 1
	}
	outputTokens := final.OutputTokens
	if outputTokens < 1 {
		outputTokens = trustedrouter.EstimateOutputTokens(
			adapter.ResponsesOutputForUsage(final.Result),
		)
	}
	if outputTokens < 1 {
		outputTokens = 1
	}
	reasoningTokens := 0
	if final.Result.Usage != nil {
		reasoningTokens = final.Result.Usage.ReasoningTokens
	}
	usage := trustedrouter.Usage{
		RequestID:        requestID,
		InputTokens:      inputTokens,
		OutputTokens:     outputTokens,
		ElapsedSeconds:   maxDurationSeconds(time.Since(started), 0.001),
		UsageEstimated:   final.UsageEstimated,
		ReasoningTokens:  reasoningTokens,
		FinishReason:     final.Result.FinishReason,
		Streamed:         req.Stream,
		RouteType:        parasailLiberty20TopLevelRoute,
		SelectedModel:    auth.Model,
		SelectedEndpoint: auth.EndpointID,
		User:             req.User,
		SessionID:        req.SessionID,
		Trace:            req.Trace,
		Metadata:         req.Metadata,
	}
	applyUsageAttribution(&usage, req)
	var output string
	if strings.TrimSpace(final.Result.Text) != "" {
		output = final.Result.Text
	}
	result, err := settleAndBroadcast(
		ctx,
		trGateway,
		auth,
		secretCache,
		usage,
		req,
		originalInput,
		output,
	)
	if err != nil {
		return nil, fmt.Errorf("partner top-level settlement: %w", err)
	}
	return result, nil
}

func partnerChargedCost(
	settlement *trustedrouter.SettleResult,
	groups ...[]fusionCallResult,
) int {
	if settlement != nil {
		return settlement.CostMicrodollars
	}
	return advisorTotalCostMicrodollars(groups...)
}

func partnerPublicUsageTotals(
	req *types.OpenAIChatRequest,
	final fusionCallResult,
	settlement *trustedrouter.SettleResult,
	fallbackInput int,
	fallbackOutput int,
) (int, int) {
	if settlement == nil {
		return fallbackInput, fallbackOutput
	}
	inputTokens := trustedrouter.EstimateInputTokens(req)
	if inputTokens < 1 {
		inputTokens = 1
	}
	outputTokens := final.OutputTokens
	if outputTokens < 1 {
		outputTokens = trustedrouter.EstimateOutputTokens(
			adapter.ResponsesOutputForUsage(final.Result),
		)
	}
	if outputTokens < 1 {
		outputTokens = 1
	}
	return inputTokens, outputTokens
}

func applyPartnerSettlementDetails(
	details map[string]any,
	settlement *trustedrouter.SettleResult,
) {
	if settlement == nil {
		return
	}
	details["cost_microdollars"] = settlement.CostMicrodollars
	details["billing_provider"] = "parasail"
	details["pricing"] = map[string]any{
		"input_microdollars_per_million_tokens":  2_000_000,
		"output_microdollars_per_million_tokens": 20_000_000,
	}
}
