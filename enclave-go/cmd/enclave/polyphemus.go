package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const polyphemusModel = "trustedrouter/polyphemus-1.0"
const polyphemusSelectRoute = "responses.polyphemus.select"

type modelSelector interface {
	Select(context.Context, string, float64, string) (*llm.ModelSelection, error)
}

var enclaveModelSelector modelSelector

func configureModelSelector(key string) {
	enclaveModelSelector = nil
	if selector, err := llm.NewTelluvianSelector(key, llm.NewProviderHTTPClient()); err == nil {
		enclaveModelSelector = selector
	}
}

type polyphemusGateway interface {
	PublicModels(context.Context) ([]byte, error)
	AuthorizeWithRoute(context.Context, string, *types.OpenAIChatRequest, string) (*trustedrouter.Authorization, error)
	Settle(context.Context, *trustedrouter.Authorization, trustedrouter.Usage) (*trustedrouter.SettleResult, error)
	Refund(context.Context, *trustedrouter.Authorization, int, string, float64, map[string]any) error
}

type polyphemusReceipt struct {
	CostMicrodollars int
	ElapsedMS        int64
	SelectedModel    string
	GenerationID     string
	SelectorCalls    int
	FallbackReason   string
	InputTokens      int
	SessionSupplied  bool
}

type polyphemusContextKey struct{}

func polyphemusReceiptFromContext(ctx context.Context) *polyphemusReceipt {
	receipt, _ := ctx.Value(polyphemusContextKey{}).(*polyphemusReceipt)
	return receipt
}

func polyphemusError(status int, message string) *adapter.AdapterError {
	return &adapter.AdapterError{Status: status, Message: message, Context: "polyphemus"}
}

// All customers share the operator's Telluvian key. Scope conversation IDs to
// the caller's API key without exposing either value upstream. UUIDv8 carries
// the domain-separated HMAC; no per-instance session state is needed.
func polyphemusSelectorSessionID(bearer, sessionID string) string {
	if bearer == "" || sessionID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(bearer))
	_, _ = mac.Write([]byte("trustedrouter/telluvian/session/v1\x00" + sessionID))
	id := mac.Sum(nil)[:16]
	id[6] = (id[6] & 0x0f) | 0x80
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func validatePolyphemus(req *types.OpenAIChatRequest, routeType string) *adapter.AdapterError {
	if routeType != "responses" || req.Response == nil {
		return polyphemusError(400, "Polyphemus requires POST /v1/responses")
	}
	if len(req.Models) > 0 || req.Response.WebSearch != nil || len(req.Plugins) > 0 || req.ImageGeneration {
		return polyphemusError(400, "Polyphemus supports text and function tools, not model fallback arrays or hosted tools")
	}
	if req.Depth != nil && (*req.Depth < 0 || *req.Depth > maxOrchestrationDepth) {
		return polyphemusError(400, "depth must be between 0 and 4")
	}
	if p := req.Provider; p != nil {
		privacy := strings.ToLower(strings.TrimSpace(p.MinPrivacy))
		if (privacy != "" && privacy != "any" && privacy != "standard") || (p.ZDR != nil && *p.ZDR) || strings.EqualFold(p.DataCollection, "deny") {
			return polyphemusError(400, "Polyphemus sends context to Telluvian and does not support no-store, ZDR, or confidential requests")
		}
		for _, mode := range []string{p.Usage, p.UsageType, p.Billing} {
			if mode != "" && !strings.EqualFold(mode, "credits") && !strings.EqualFold(mode, "prepaid") {
				return polyphemusError(400, "Polyphemus requires Credits, not BYOK")
			}
		}
	}
	for _, message := range req.Messages {
		if message.Content == nil {
			continue
		}
		if _, ok := message.Content.(string); ok {
			continue
		}
		encoded, err := json.Marshal(message.Content)
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err != nil || json.Unmarshal(encoded, &parts) != nil || parts == nil {
			return polyphemusError(400, "Polyphemus currently supports text input only")
		}
		for _, part := range parts {
			if part.Type != "text" {
				return polyphemusError(400, "Polyphemus currently supports text input only")
			}
		}
	}
	return nil
}

// Only an exact, unique, currently published concrete chat model is eligible.
// Upstream names cannot introduce a new URL, alias, provider, or recursion.
func resolveSelectedModel(body []byte, recommendation string) (string, error) {
	var catalog struct {
		Data []struct {
			ID string `json:"id"`
			TR struct {
				Chat      bool  `json:"supports_chat"`
				Credits   bool  `json:"prepaid_available"`
				Responses *bool `json:"supports_responses"`
			} `json:"trustedrouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return "", polyphemusError(503, "Model catalog unavailable")
	}
	matches := make(map[string]bool)
	for _, model := range catalog.Data {
		if !model.TR.Chat || !model.TR.Credits || (model.TR.Responses != nil && !*model.TR.Responses) || strings.HasPrefix(model.ID, "trustedrouter/") || isOrchestrationModel(model.ID) {
			continue
		}
		_, suffix, _ := strings.Cut(model.ID, "/")
		if model.ID == recommendation || (!strings.Contains(recommendation, "/") && suffix == recommendation) {
			matches[model.ID] = true
		}
	}
	if len(matches) != 1 {
		return "", polyphemusError(502, "Telluvian recommended an unavailable or ambiguous model")
	}
	for model := range matches {
		return model, nil
	}
	return "", polyphemusError(502, "No eligible model selected")
}

// Admission and finalization are the same durable operations used by every
// generation. The selector never runs on a replayed admission, since its own
// API has no idempotency guarantee. Do not retry ambiguous selector failures.
func preparePolyphemus(ctx context.Context, req *types.OpenAIChatRequest, gateway polyphemusGateway, selector modelSelector, bearer, requestLogID string) (context.Context, error) {
	if err := validatePolyphemus(req, "responses"); err != nil {
		return ctx, err
	}
	payload, err := json.Marshal(struct {
		Messages []types.OpenAIChatMessage `json:"messages"`
		Tools    []any                     `json:"tools,omitempty"`
	}{req.Messages, req.Tools})
	if err != nil || len(payload) > 1<<20 {
		return ctx, polyphemusError(400, "Polyphemus selection context exceeds 1 MiB")
	}
	catalog, err := gateway.PublicModels(ctx)
	if err != nil {
		return ctx, polyphemusError(503, "Model catalog unavailable")
	}
	rootID := strings.TrimSpace(req.IdempotencyKey)
	if rootID == "" {
		rootID = newResponseID()
	}
	selectReq := cloneChatRequest(req)
	rootDigest := sha256.Sum256([]byte(rootID))
	stageKey := hex.EncodeToString(rootDigest[:])
	selectReq.IdempotencyKey = "polyphemus-select:" + stageKey
	canonical, err := json.Marshal(req)
	if err != nil {
		return ctx, polyphemusError(400, "Invalid Polyphemus request")
	}
	mac := hmac.New(sha256.New, []byte(bearer))
	_, _ = mac.Write(canonical)
	selectReq.RequestFingerprint = hex.EncodeToString(mac.Sum(nil))
	if selectReq.Provider == nil {
		selectReq.Provider = &types.ProviderRouting{}
	}
	selectReq.Provider.Usage = "credits"
	// Meter only the exact context sent to Model Select, including tools. Its
	// API reports no usage, so use the shared estimate and label it explicitly.
	// The authorization estimate adds message overhead and safely covers this
	// smaller settlement count. No prompt is sent to the control plane.
	selectorInputTokens := types.ContentTokenEstimate(string(payload))
	selectReq.Messages = []types.OpenAIChatMessage{{Role: "user", Content: string(payload)}}
	selectReq.Tools = nil
	one := 1
	selectReq.MaxTokens, selectReq.MaxCompletionTokens, selectReq.MaxOutputTokens = &one, nil, nil
	selectReq.InferenceReceipt = types.InferenceReceiptRequest{}
	selectReq.RequestedParameters = nil
	auth, err := gateway.AuthorizeWithRoute(ctx, bearer, selectReq, polyphemusSelectRoute)
	if err != nil {
		return ctx, err
	}
	if auth.IdempotentReplay {
		return ctx, polyphemusError(409, "Polyphemus request already admitted; use a new idempotency key for a new request")
	}
	if auth.Model != polyphemusModel || auth.Provider != "telluvian" || !strings.EqualFold(auth.UsageType, "credits") {
		_ = gateway.Refund(ctx, auth, 502, "routing_integrity_error", 0, req.Metadata)
		return ctx, polyphemusError(502, "Polyphemus selection routing integrity check failed")
	}
	selectorSessionID := polyphemusSelectorSessionID(bearer, req.SessionID)
	started := time.Now()
	// Provider failures may fall back; admission/privacy/billing failures never do.
	fallback := func(reason string, calls int) (context.Context, error) {
		finalCtx, cancel := finalizeContext(ctx)
		defer cancel()
		elapsed := time.Since(started)
		if err := gateway.Refund(finalCtx, auth, 502, reason, elapsed.Seconds(), req.Metadata); err != nil {
			if live, ok := gateway.(*trustedrouter.Client); ok {
				settlementRetries.Enqueue(settlementRetryJob{trGateway: live, authorization: auth, kind: "refund", refundStatus: 502, refundType: reason, refundElapsed: elapsed.Seconds(), refundMetadata: req.Metadata, requestLogID: requestLogID, clientContext: trustedrouter.ClientContextFromContext(ctx)})
			}
			return ctx, polyphemusError(502, "Model selection refund pending; do not replay this request")
		}
		if err := ctx.Err(); err != nil {
			return ctx, polyphemusError(499, "Request cancelled before fallback")
		}
		receipt := &polyphemusReceipt{ElapsedMS: elapsed.Milliseconds(), SelectedModel: "trustedrouter/auto", SelectorCalls: calls, FallbackReason: reason, SessionSupplied: calls > 0 && selectorSessionID != ""}
		fmt.Fprintf(os.Stderr, "enclave.polyphemus.fallback request_log_id=%q reason=%q\n", requestLogID, reason)
		return continuePolyphemus(ctx, req, receipt, stageKey, selectReq.RequestFingerprint), nil
	}
	if selector == nil {
		return fallback("model_selector_unavailable", 0)
	}
	selection, err := selector.Select(ctx, string(payload), .9, selectorSessionID)
	selectorElapsedMS := time.Since(started).Milliseconds()
	if err != nil || selection == nil {
		return fallback("model_selection_failed", 1)
	}
	model, err := resolveSelectedModel(catalog, selection.Model)
	if err != nil {
		return fallback("invalid_model_selection", 1)
	}
	usage := trustedrouter.Usage{
		InputTokens: selectorInputTokens, UsageEstimated: true,
		RequestID: rootID, SelectedModel: polyphemusModel, SelectedEndpoint: auth.EndpointID,
		RouteType: polyphemusSelectRoute, FinishReason: "stop", ElapsedSeconds: time.Since(started).Seconds(),
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
	}
	applyUsageAttribution(&usage, req)
	finalCtx, cancel := finalizeContext(ctx)
	settlement, err := gateway.Settle(finalCtx, auth, usage)
	cancel()
	if err != nil {
		if live, ok := gateway.(*trustedrouter.Client); ok {
			settlementRetries.Enqueue(settlementRetryJob{trGateway: live, authorization: auth, usage: usage, requestLogID: requestLogID, clientContext: trustedrouter.ClientContextFromContext(ctx)})
		}
		return ctx, polyphemusError(502, "Model selection settlement pending; do not replay this request")
	}
	if settlement == nil || settlement.CostMicrodollars < 1 || stageDDispositionLost(settlement) {
		return ctx, polyphemusError(502, "Model selection settlement did not complete")
	}
	receipt := &polyphemusReceipt{CostMicrodollars: settlement.CostMicrodollars, ElapsedMS: selectorElapsedMS, SelectedModel: model, GenerationID: settlement.GenerationID, SelectorCalls: 1, InputTokens: selectorInputTokens, SessionSupplied: selectorSessionID != ""}
	// Preserve caller reasoning if specified; otherwise apply the recommendation.
	if req.Reasoning == nil && req.ReasoningEffort == "" {
		req.ReasoningEffort = selection.Reasoning.Effort
	}
	fmt.Fprintf(os.Stderr, "enclave.polyphemus.selection_done request_log_id=%q selected_model=%q selector_elapsed_ms=%d selector_cost_microdollars=%d\n", requestLogID, model, receipt.ElapsedMS, receipt.CostMicrodollars)
	return continuePolyphemus(ctx, req, receipt, stageKey, selectReq.RequestFingerprint), nil
}

func continuePolyphemus(ctx context.Context, req *types.OpenAIChatRequest, receipt *polyphemusReceipt, stageKey, fingerprint string) context.Context {
	req.Model = receipt.SelectedModel
	req.ResponseModel = polyphemusModel
	if req.Provider == nil {
		req.Provider = &types.ProviderRouting{}
	}
	req.Provider.Usage = "credits"
	req.IdempotencyKey = "polyphemus-generation:" + stageKey
	req.RequestFingerprint = fingerprint
	return context.WithValue(ctx, polyphemusContextKey{}, receipt)
}

func annotatePolyphemusUsage(ctx context.Context, usage map[string]any) {
	receipt := polyphemusReceiptFromContext(ctx)
	if receipt == nil || usage == nil {
		return
	}
	providerUsage, _ := usage["provider_usage"].(map[string]any)
	if providerUsage == nil {
		providerUsage = map[string]any{}
	}
	providerUsage["router"] = "polyphemus"
	providerUsage["selector_provider"] = "telluvian"
	providerUsage["selector_calls"] = receipt.SelectorCalls
	providerUsage["selector_session_supplied"] = receipt.SessionSupplied
	providerUsage["selector_cost_microdollars"] = receipt.CostMicrodollars
	providerUsage["selector_input_tokens"] = receipt.InputTokens
	providerUsage["selector_usage_estimated"] = true
	providerUsage["selector_token_basis"] = "serialized_context_utf8_bytes_div_4"
	providerUsage["selector_upstream_cost_known"] = false
	providerUsage["selector_elapsed_ms"] = receipt.ElapsedMS
	if receipt.FallbackReason != "" {
		providerUsage["selector_fallback_model"] = receipt.SelectedModel
		providerUsage["selector_fallback_reason"] = receipt.FallbackReason
	} else {
		providerUsage["selected_model"] = receipt.SelectedModel
		providerUsage["selector_generation_id"] = receipt.GenerationID
	}
	if cost, exists := usage["cost_microdollars"]; exists {
		generationCost := providerUsageInt(cost)
		providerUsage["generation_cost_microdollars"] = generationCost
		usage["cost_microdollars"] = generationCost + receipt.CostMicrodollars
		usage["total_cost_microdollars"] = generationCost + receipt.CostMicrodollars
		providerUsage["cost_microdollars"] = generationCost + receipt.CostMicrodollars
		providerUsage["total_cost_microdollars"] = generationCost + receipt.CostMicrodollars
	}
	usage["provider_usage"] = providerUsage
}

func annotatePolyphemusResponse(ctx context.Context, body []byte) ([]byte, error) {
	if polyphemusReceiptFromContext(ctx) == nil {
		return body, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	payload["model"] = polyphemusModel
	usage, _ := payload["usage"].(map[string]any)
	annotatePolyphemusUsage(ctx, usage)
	if usage != nil {
		payload["trustedrouter"] = mergeTrustedRouterRouting(payload["trustedrouter"], usage["provider_usage"].(map[string]any))
	}
	return json.Marshal(payload)
}
