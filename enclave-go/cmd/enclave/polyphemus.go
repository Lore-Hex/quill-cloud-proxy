package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/polyclass"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const polyphemusModel = adapter.PolyphemusModel
const polyphemusSelectRoute = "responses.polyphemus.select"

// Polyphemus picks between two models with a local classifier: the measured
// /polyphemus-classifier helper (NVIDIA's prompt task-and-complexity
// classifier) reads the latest user turn inside this gateway. No prompt text
// leaves the gateway to choose a model.
//
// The strong model handles code, prompts that need expert domain knowledge,
// and every request that carries tools; the cheap model handles the rest.
// Confidential requests use a pair that only runs on confidential endpoints.
const (
	polyphemusStrongModel             = "anthropic/claude-opus-5.5"
	polyphemusCheapModel              = "deepseek/deepseek-v4.1-flash-1017"
	polyphemusConfidentialStrongModel = "moonshotai/kimi-k3.1-pro"
	polyphemusConfidentialCheapModel  = "deepseek/deepseek-v4.1-flash-1017"
	// domain_knowledge is 0 (none) to 1 (expert). Technical prompts score
	// about 0.95 or more and everyday ones about 0.3 to 0.5.
	polyphemusExpertDomain = 0.8
)

type promptClassifier interface {
	Classify(context.Context, string) (polyclass.Result, error)
}

var enclaveModelSelector promptClassifier

// configureModelSelector starts loading the classifier at boot so the first
// Polyphemus request does not wait for the weights.
func configureModelSelector() {
	client := polyclass.New()
	client.Warm()
	enclaveModelSelector = client
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
	// Classifier labels and the tier they chose. Labels describe the prompt's
	// kind, never its content, and go only to the caller's own response.
	Task            string
	DomainKnowledge float64
	Tier            string
	Confidential    bool
	// Pinned means an earlier turn of this conversation chose the model, so
	// the classifier was not run and no selector fee applies.
	Pinned bool
}

type polyphemusContextKey struct{}

func polyphemusReceiptFromContext(ctx context.Context) *polyphemusReceipt {
	receipt, _ := ctx.Value(polyphemusContextKey{}).(*polyphemusReceipt)
	return receipt
}

func polyphemusError(status int, message string) *adapter.AdapterError {
	return &adapter.AdapterError{Status: status, Message: message, Context: "polyphemus"}
}

// Polyphemus may pick a different model on every turn, but a tool-using
// conversation cannot change models midway: tool call ids, thought signatures
// and context windows are model specific. The enclave keeps no conversation
// state, so the chosen model rides in the call_id of every function call
// Polyphemus returns, and clients echo call_ids back on the next turn:
// "pm1" + 2 hex digits (length of the encoded model) + base64url(model) + "_" +
// the upstream id. The charset fits every provider's id pattern. The prefix is
// removed before the history reaches the model. A forged pin can only name a
// model the caller could request directly, and still passes the catalog check.
const polyphemusPinPrefix = "pm1"

func polyphemusPinCallID(model, id string) string {
	if model == "" || id == "" {
		return id
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(model))
	if len(encoded) > 0xff {
		return id
	}
	return fmt.Sprintf("%s%02x%s_%s", polyphemusPinPrefix, len(encoded), encoded, id)
}

func polyphemusUnpinCallID(id string) (model, upstream string, ok bool) {
	rest, found := strings.CutPrefix(id, polyphemusPinPrefix)
	if !found || len(rest) < 2 {
		return "", id, false
	}
	n, err := strconv.ParseUint(rest[:2], 16, 8)
	if err != nil || len(rest) < 2+int(n)+2 || rest[2+int(n)] != '_' {
		return "", id, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rest[2 : 2+int(n)])
	if err != nil || len(decoded) == 0 {
		return "", id, false
	}
	return string(decoded), rest[3+int(n):], true
}

// unpinPolyphemusHistory restores upstream tool call ids in place and returns
// the model pinned by the latest assistant tool call, if any.
func unpinPolyphemusHistory(messages []types.OpenAIChatMessage) string {
	pinned := ""
	for i := range messages {
		for j := range messages[i].ToolCalls {
			if model, upstream, ok := polyphemusUnpinCallID(messages[i].ToolCalls[j].ID); ok {
				messages[i].ToolCalls[j].ID = upstream
				pinned = model
			}
		}
		if _, upstream, ok := polyphemusUnpinCallID(messages[i].ToolCallID); ok {
			messages[i].ToolCallID = upstream
		}
	}
	return pinned
}

// polyphemusToolCallStamp returns the call_id rewrite for this response, or nil
// when there is nothing to pin (not Polyphemus, or the auto fallback).
func polyphemusToolCallStamp(ctx context.Context) func(string) string {
	receipt := polyphemusReceiptFromContext(ctx)
	if receipt == nil || receipt.FallbackReason != "" || receipt.SelectedModel == "" {
		return nil
	}
	model := receipt.SelectedModel
	return func(id string) string { return polyphemusPinCallID(model, id) }
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
		for _, mode := range []string{p.Usage, p.UsageType, p.Billing} {
			if mode != "" && !strings.EqualFold(mode, "credits") && !strings.EqualFold(mode, "prepaid") {
				return polyphemusError(400, "Polyphemus requires Credits, not BYOK")
			}
		}
	}
	for _, message := range req.Messages {
		if _, err := polyphemusMessageText(message.Content); err != nil {
			return err
		}
	}
	return nil
}

// polyphemusMessageText joins a message's text parts. Any non-text part is
// refused: the classifier and the routing rule only understand text.
func polyphemusMessageText(content any) (string, *adapter.AdapterError) {
	switch value := content.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	}
	encoded, err := json.Marshal(content)
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err != nil || json.Unmarshal(encoded, &parts) != nil || parts == nil {
		return "", polyphemusError(400, "Polyphemus currently supports text input only")
	}
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part.Type != "text" {
			return "", polyphemusError(400, "Polyphemus currently supports text input only")
		}
		texts = append(texts, part.Text)
	}
	return strings.Join(texts, "\n"), nil
}

// polyphemusSelectionText is the latest user turn whose first MaxTextBytes
// contain text: exactly what the classifier sees.
func polyphemusSelectionText(messages []types.OpenAIChatMessage) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role != "user" {
			continue
		}
		if text, err := polyphemusMessageText(messages[i].Content); err == nil {
			if text = polyclass.Truncate(text); strings.TrimSpace(text) != "" {
				return text
			}
		}
	}
	return ""
}

// Privacy tiers, numbered as in the control plane's catalog
// (trustedrouter.privacy_tier on /v1/models).
const (
	privacyTierNoStore       = 1
	privacyTierZeroRetention = 2
	privacyTierConfidential  = 3
	privacyTierTrusted       = 4
)

// polyphemusRequiredTier is the lowest privacy tier the caller accepts, by
// the control plane's own names for provider.min_privacy.
func polyphemusRequiredTier(ctx context.Context, req *types.OpenAIChatRequest) int {
	tier := 0
	if trustedrouter.ConfidentialOnly(ctx) {
		tier = privacyTierConfidential
	}
	p := req.Provider
	if p == nil {
		return tier
	}
	named := 0
	switch strings.ToLower(strings.TrimSpace(p.MinPrivacy)) {
	case "no_store", "no-store", "nostore":
		named = privacyTierNoStore
	case "zdr", "zero_retention", "zero-retention":
		named = privacyTierZeroRetention
	case "confidential", "e2e", "e2ee", "max", "maximum":
		named = privacyTierConfidential
	case "trusted":
		named = privacyTierTrusted
	}
	if p.ZDR != nil && *p.ZDR {
		named = max(named, privacyTierZeroRetention)
	}
	if strings.EqualFold(p.DataCollection, "deny") {
		named = max(named, privacyTierNoStore)
	}
	return max(tier, named)
}

// polyphemusConfidential reports whether the caller requires confidential
// routing.
func polyphemusConfidential(ctx context.Context, req *types.OpenAIChatRequest) bool {
	return polyphemusRequiredTier(ctx, req) >= privacyTierConfidential
}

// choosePolyphemusModel is the whole routing rule.
func choosePolyphemusModel(result polyclass.Result, hasTools, confidential bool) (model, tier string) {
	strong := hasTools || result.Task == "Code Generation" || result.DomainKnowledge >= polyphemusExpertDomain
	switch {
	case strong && confidential:
		return polyphemusConfidentialStrongModel, "strong"
	case strong:
		return polyphemusStrongModel, "strong"
	case confidential:
		return polyphemusConfidentialCheapModel, "cheap"
	default:
		return polyphemusCheapModel, "cheap"
	}
}

// resolveSelectedModel requires the exact id to be a unique, currently
// published, credit-billed concrete chat model that serves Responses and
// offers an endpoint at or above the caller's privacy tier. Checking before
// settlement keeps the selector fee off requests the model cannot serve.
func resolveSelectedModel(body []byte, model string, requiredTier int) error {
	var catalog struct {
		Data []struct {
			ID string `json:"id"`
			TR struct {
				Chat        bool  `json:"supports_chat"`
				Credits     bool  `json:"prepaid_available"`
				Responses   *bool `json:"supports_responses"`
				PrivacyTier int   `json:"privacy_tier"`
			} `json:"trustedrouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return polyphemusError(503, "Model catalog unavailable")
	}
	matches := 0
	for _, row := range catalog.Data {
		if row.ID != model {
			continue
		}
		if !row.TR.Chat || !row.TR.Credits || (row.TR.Responses != nil && !*row.TR.Responses) || row.TR.PrivacyTier < requiredTier || strings.HasPrefix(row.ID, "trustedrouter/") || isOrchestrationModel(row.ID) {
			return polyphemusError(502, "Selected model is not available")
		}
		matches++
	}
	if matches != 1 {
		return polyphemusError(502, "Selected model is not available")
	}
	return nil
}

// Admission and finalization are the same durable operations used by every
// generation. The selector never runs on a replayed admission.
func preparePolyphemus(ctx context.Context, req *types.OpenAIChatRequest, gateway polyphemusGateway, classifier promptClassifier, bearer, requestLogID string) (context.Context, error) {
	if err := validatePolyphemus(req, "responses"); err != nil {
		return ctx, err
	}
	pinnedModel := unpinPolyphemusHistory(req.Messages)
	catalog, err := gateway.PublicModels(ctx)
	if err != nil {
		return ctx, polyphemusError(503, "Model catalog unavailable")
	}
	rootID := strings.TrimSpace(req.IdempotencyKey)
	if rootID == "" {
		rootID = newResponseID()
	}
	selectReq := cloneChatRequest(req)
	selectReq.Polyphemus = nil
	rootDigest := sha256.Sum256([]byte(rootID))
	stageKey := hex.EncodeToString(rootDigest[:])
	selectReq.IdempotencyKey = "polyphemus-select:" + stageKey
	canonical, err := json.Marshal(req)
	if err != nil {
		return ctx, polyphemusError(400, "Invalid Polyphemus request")
	}
	mac := hmac.New(sha256.New, []byte(bearer))
	_, _ = mac.Write(canonical)
	if req.Polyphemus != nil {
		// The field is never serialized, so the canonical JSON above omits it;
		// bind it here. The options are accepted for compatibility and ignored.
		options, _ := json.Marshal(struct {
			XPerf    any    `json:"x_perf,omitempty"`
			ModelZoo string `json:"model_zoo,omitempty"`
		}{req.Polyphemus.XPerf, req.Polyphemus.ModelZoo})
		_, _ = mac.Write([]byte("\x00polyphemus\x00"))
		_, _ = mac.Write(options)
	}
	selectReq.RequestFingerprint = hex.EncodeToString(mac.Sum(nil))
	if selectReq.Provider == nil {
		selectReq.Provider = &types.ProviderRouting{}
	}
	selectReq.Provider.Usage = "credits"
	requiredTier := polyphemusRequiredTier(ctx, req)
	confidential := requiredTier >= privacyTierConfidential
	if pinnedModel != "" {
		if err := resolveSelectedModel(catalog, pinnedModel, requiredTier); err == nil {
			fmt.Fprintf(os.Stderr, "enclave.polyphemus.pinned request_log_id=%q selected_model=%q\n", requestLogID, pinnedModel)
			return continuePolyphemus(ctx, req, &polyphemusReceipt{SelectedModel: pinnedModel, Pinned: true, Confidential: confidential}, stageKey, selectReq.RequestFingerprint), nil
		}
		// The pinned model left the catalog; choose again.
		fmt.Fprintf(os.Stderr, "enclave.polyphemus.pin_unavailable request_log_id=%q\n", requestLogID)
	}
	if len(req.Tools) > 0 {
		// Tools always mean the strong model, so the classifier could not
		// change the choice: skip it and its fee.
		model, tier := choosePolyphemusModel(polyclass.Result{}, true, confidential)
		if err := resolveSelectedModel(catalog, model, requiredTier); err != nil {
			fmt.Fprintf(os.Stderr, "enclave.polyphemus.unresolved_selection request_log_id=%q selected_model=%q\n", requestLogID, model)
			receipt := &polyphemusReceipt{SelectedModel: "trustedrouter/auto", FallbackReason: "invalid_model_selection", Confidential: confidential}
			return continuePolyphemus(ctx, req, receipt, stageKey, selectReq.RequestFingerprint), nil
		}
		fmt.Fprintf(os.Stderr, "enclave.polyphemus.selection_done request_log_id=%q selected_model=%q tier=%q selector_calls=0\n", requestLogID, model, tier)
		return continuePolyphemus(ctx, req, &polyphemusReceipt{SelectedModel: model, Tier: tier, Confidential: confidential}, stageKey, selectReq.RequestFingerprint), nil
	}
	// Meter exactly the text the classifier reads, with the shared estimate.
	// No prompt is sent to the control plane: admission sees only its size.
	selectionText := polyphemusSelectionText(req.Messages)
	if selectionText == "" {
		return ctx, polyphemusError(400, "Polyphemus needs a user message with text")
	}
	selectorInputTokens := types.ContentTokenEstimate(selectionText)
	selectReq.Messages = []types.OpenAIChatMessage{{Role: "user", Content: selectionText}}
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
	// "telluvian" is the selector's former provider slug, accepted until the
	// control plane's catalog moves it to "trustedrouter".
	if auth.Model != polyphemusModel || (auth.Provider != "trustedrouter" && auth.Provider != "telluvian") || !strings.EqualFold(auth.UsageType, "credits") {
		_ = gateway.Refund(ctx, auth, 502, "routing_integrity_error", 0, req.Metadata)
		return ctx, polyphemusError(502, "Polyphemus selection routing integrity check failed")
	}
	started := time.Now()
	// Classifier failures fall back; admission/privacy/billing failures never do.
	fallback := func(reason string, calls int) (context.Context, error) {
		finalCtx, cancel := finalizeContext(ctx)
		defer cancel()
		elapsed := time.Since(started)
		if err := gateway.Refund(finalCtx, auth, 502, reason, elapsed.Seconds(), req.Metadata); err != nil {
			if live, ok := gateway.(*trustedrouter.Client); ok {
				settlementRetries.Enqueue(settlementRetryJob{trGateway: live, authorization: auth, kind: "refund", refundStatus: 502, refundType: reason, refundElapsed: elapsed.Seconds(), refundMetadata: req.Metadata, requestLogID: requestLogID, clientContext: trustedrouter.ClientContextFromContext(ctx), cause: err})
			}
			return ctx, polyphemusError(502, "Model selection refund pending; do not replay this request")
		}
		if err := ctx.Err(); err != nil {
			return ctx, polyphemusError(499, "Request cancelled before fallback")
		}
		receipt := &polyphemusReceipt{ElapsedMS: elapsed.Milliseconds(), SelectedModel: "trustedrouter/auto", SelectorCalls: calls, FallbackReason: reason, Confidential: confidential}
		fmt.Fprintf(os.Stderr, "enclave.polyphemus.fallback request_log_id=%q reason=%q\n", requestLogID, reason)
		return continuePolyphemus(ctx, req, receipt, stageKey, selectReq.RequestFingerprint), nil
	}
	if classifier == nil {
		return fallback("model_selector_unavailable", 0)
	}
	result, err := classifier.Classify(ctx, selectionText)
	selectorElapsedMS := time.Since(started).Milliseconds()
	if err != nil {
		return fallback("model_selection_failed", 1)
	}
	model, tier := choosePolyphemusModel(result, false, confidential)
	if err := resolveSelectedModel(catalog, model, requiredTier); err != nil {
		fmt.Fprintf(os.Stderr, "enclave.polyphemus.unresolved_selection request_log_id=%q selected_model=%q\n", requestLogID, model)
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
			settlementRetries.Enqueue(settlementRetryJob{trGateway: live, authorization: auth, usage: usage, requestLogID: requestLogID, clientContext: trustedrouter.ClientContextFromContext(ctx), cause: err})
		}
		return ctx, polyphemusError(502, "Model selection settlement pending; do not replay this request")
	}
	if settlement == nil || settlement.CostMicrodollars < 1 || stageDDispositionLost(settlement) {
		return ctx, polyphemusError(502, "Model selection settlement did not complete")
	}
	receipt := &polyphemusReceipt{
		CostMicrodollars: settlement.CostMicrodollars, ElapsedMS: selectorElapsedMS, SelectedModel: model,
		GenerationID: settlement.GenerationID, SelectorCalls: 1, InputTokens: selectorInputTokens,
		Task: result.Task, DomainKnowledge: result.DomainKnowledge, Tier: tier, Confidential: confidential,
	}
	fmt.Fprintf(os.Stderr, "enclave.polyphemus.selection_done request_log_id=%q selected_model=%q tier=%q selector_elapsed_ms=%d selector_cost_microdollars=%d\n", requestLogID, model, tier, receipt.ElapsedMS, receipt.CostMicrodollars)
	return continuePolyphemus(ctx, req, receipt, stageKey, selectReq.RequestFingerprint), nil
}

func continuePolyphemus(ctx context.Context, req *types.OpenAIChatRequest, receipt *polyphemusReceipt, stageKey, fingerprint string) context.Context {
	req.Polyphemus = nil // never forwarded to the chosen model
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
	providerUsage["selector_provider"] = "trustedrouter"
	providerUsage["selector_runs_in_gateway"] = true
	providerUsage["selector_calls"] = receipt.SelectorCalls
	providerUsage["selector_pinned"] = receipt.Pinned
	providerUsage["selector_confidential"] = receipt.Confidential
	providerUsage["selector_cost_microdollars"] = receipt.CostMicrodollars
	providerUsage["selector_input_tokens"] = receipt.InputTokens
	providerUsage["selector_usage_estimated"] = true
	providerUsage["selector_token_basis"] = "classified_text_utf8_bytes_div_4"
	providerUsage["selector_elapsed_ms"] = receipt.ElapsedMS
	if receipt.Tier != "" {
		providerUsage["selector_tier"] = receipt.Tier
	}
	if receipt.Task != "" {
		providerUsage["selector_task"] = receipt.Task
		providerUsage["selector_domain_knowledge"] = receipt.DomainKnowledge
	}
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
