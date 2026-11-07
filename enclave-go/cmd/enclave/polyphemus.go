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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const polyphemusModel = adapter.PolyphemusModel

// polyphemusXPerf is the default for Telluvian's quality bar when the caller
// sends no polyphemus.x_perf: pick the cheapest model at or above this
// level, where 1.0 is Telluvian's fixed reference (openai/gpt-6-astra's published level;
// see telluvian.ai/docs/model-zoo). The probe may still choose a cheaper model when it
// predicts comparable success on the request. At 0.9 it chose deepseek-v4-flash
// (published 0.36) for every SimpleQA-Verified question tried and missed all four.
const polyphemusXPerf = 1.0
const polyphemusSelectRoute = "responses.polyphemus.select"

type modelSelector interface {
	Select(context.Context, string, llm.SelectionControls, string) (*llm.ModelSelection, error)
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
	// Pinned means an earlier turn of this conversation chose the model, so
	// Telluvian was not called and no selector fee applies.
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

// Telluvian may pick a different model on every turn, but a tool-using
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
// On failure it also returns a diagnosis safe to log.
func resolveSelectedModel(body []byte, recommendation string) (string, string, error) {
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
		return "", "", polyphemusError(503, "Model catalog unavailable")
	}
	matchesFor := func(name string, eligibleOnly bool) map[string]bool {
		matches := make(map[string]bool)
		for _, model := range catalog.Data {
			if eligibleOnly && (!model.TR.Chat || !model.TR.Credits || (model.TR.Responses != nil && !*model.TR.Responses) || strings.HasPrefix(model.ID, "trustedrouter/") || isOrchestrationModel(model.ID)) {
				continue
			}
			_, suffix, _ := strings.Cut(model.ID, "/")
			if model.ID == name || (!strings.Contains(name, "/") && suffix == name) {
				matches[model.ID] = true
			}
		}
		return matches
	}
	// Telluvian writes Anthropic versions the way Anthropic's API does
	// (claude-opus-5-5, claude-haiku-4-5-20251001); the catalog's credit-billed
	// ids use dots (claude-opus-5.5). The dashed ids that do appear in the
	// catalog are BYOK-only. Each fallback runs only when the name before it
	// matched no eligible model, and the result must still be unique.
	candidates := telluvianModelNames(recommendation)
	var matches map[string]bool
	for _, name := range candidates {
		if matches = matchesFor(name, true); len(matches) > 0 {
			break
		}
	}
	if len(matches) != 1 {
		// The recommendation is third-party text that may echo the prompt, so
		// only catalog ids, which are public, reach the diagnosis.
		diagnosis := "no_catalog_match"
		if len(matches) > 1 {
			diagnosis = "ambiguous"
		} else {
			for _, name := range candidates {
				if known := matchesFor(name, false); len(known) == 1 {
					for id := range known {
						diagnosis = "ineligible:" + id
					}
					break
				}
			}
		}
		return "", diagnosis, polyphemusError(502, "Telluvian recommended an unavailable or ambiguous model")
	}
	for model := range matches {
		return model, "", nil
	}
	return "", "no_catalog_match", polyphemusError(502, "No eligible model selected")
}

var (
	modelDateSuffix   = regexp.MustCompile(`-20[0-9]{6}$`)
	dashedVersionPair = regexp.MustCompile(`-([0-9]+)-([0-9])($|-)`)
)

// telluvianModelNames lists the names to try for a recommendation, in order:
// as given; with dashed major-minor versions dotted (claude-opus-4-5 →
// claude-opus-4.5); then, for Claude only, also without a -YYYYMMDD snapshot
// date, since the catalog's Claude ids are usually undated. Other vendors'
// snapshot dates name distinct models, so they are kept.
func telluvianModelNames(name string) []string {
	names := []string{name}
	add := func(candidate string) {
		if candidate != names[len(names)-1] {
			names = append(names, candidate)
		}
	}
	dotted := name
	// Repeat: a match consumes the dash it ends on, so adjacent pairs need another pass.
	for next := dashedVersionPair.ReplaceAllString(dotted, "-$1.$2$3"); next != dotted; next = dashedVersionPair.ReplaceAllString(dotted, "-$1.$2$3") {
		dotted = next
	}
	add(dotted)
	stem := name
	if _, rest, ok := strings.Cut(name, "/"); ok {
		stem = rest
	}
	if strings.HasPrefix(stem, "claude-") {
		add(modelDateSuffix.ReplaceAllString(dotted, ""))
	}
	return names
}

// Admission and finalization are the same durable operations used by every
// generation. The selector never runs on a replayed admission, since its own
// API has no idempotency guarantee. Do not retry ambiguous selector failures.
func preparePolyphemus(ctx context.Context, req *types.OpenAIChatRequest, gateway polyphemusGateway, selector modelSelector, bearer, requestLogID string) (context.Context, error) {
	if err := validatePolyphemus(req, "responses"); err != nil {
		return ctx, err
	}
	pinnedModel := unpinPolyphemusHistory(req.Messages)
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
	selectReq.Polyphemus = nil // selector controls go to Telluvian, not to admission
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
		// The field is never serialized, so the canonical JSON above omits it; bind it here.
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
	if pinnedModel != "" {
		model, _, err := resolveSelectedModel(catalog, pinnedModel)
		if err == nil && model == pinnedModel {
			fmt.Fprintf(os.Stderr, "enclave.polyphemus.pinned request_log_id=%q selected_model=%q\n", requestLogID, model)
			return continuePolyphemus(ctx, req, &polyphemusReceipt{SelectedModel: model, Pinned: true}, stageKey, selectReq.RequestFingerprint), nil
		}
		// The pinned model left the catalog; let Telluvian choose again.
		fmt.Fprintf(os.Stderr, "enclave.polyphemus.pin_unavailable request_log_id=%q\n", requestLogID)
	}
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
				settlementRetries.Enqueue(settlementRetryJob{trGateway: live, authorization: auth, kind: "refund", refundStatus: 502, refundType: reason, refundElapsed: elapsed.Seconds(), refundMetadata: req.Metadata, requestLogID: requestLogID, clientContext: trustedrouter.ClientContextFromContext(ctx), cause: err})
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
	selection, err := selector.Select(ctx, string(payload), polyphemusSelectionControls(req), selectorSessionID)
	selectorElapsedMS := time.Since(started).Milliseconds()
	if err != nil || selection == nil {
		return fallback("model_selection_failed", 1)
	}
	model, diagnosis, err := resolveSelectedModel(catalog, selection.Model)
	if err != nil {
		// An empty diagnosis is our own unreadable catalog, not Telluvian's pick.
		if diagnosis != "" {
			fmt.Fprintf(os.Stderr, "enclave.polyphemus.unresolved_selection request_log_id=%q diagnosis=%q\n", requestLogID, diagnosis)
		}
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
	receipt := &polyphemusReceipt{CostMicrodollars: settlement.CostMicrodollars, ElapsedMS: selectorElapsedMS, SelectedModel: model, GenerationID: settlement.GenerationID, SelectorCalls: 1, InputTokens: selectorInputTokens, SessionSupplied: selectorSessionID != ""}
	// Preserve caller reasoning if specified; otherwise apply the
	// recommendation, clamped to the efforts the chosen model accepts.
	if req.Reasoning == nil && req.ReasoningEffort == "" {
		req.ReasoningEffort = polyphemusSupportedEffort(catalog, model, selection.Reasoning.Effort)
	}
	fmt.Fprintf(os.Stderr, "enclave.polyphemus.selection_done request_log_id=%q selected_model=%q selector_elapsed_ms=%d selector_cost_microdollars=%d\n", requestLogID, model, receipt.ElapsedMS, receipt.CostMicrodollars)
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
	providerUsage["selector_provider"] = "telluvian"
	providerUsage["selector_calls"] = receipt.SelectorCalls
	providerUsage["selector_session_supplied"] = receipt.SessionSupplied
	providerUsage["selector_pinned"] = receipt.Pinned
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

// polyphemusSelectionControls applies the caller's polyphemus options over the
// defaults. The responses adapter has already validated them.
func polyphemusSelectionControls(req *types.OpenAIChatRequest) llm.SelectionControls {
	controls := llm.SelectionControls{XPerf: polyphemusXPerf}
	if options := req.Polyphemus; options != nil {
		if options.XPerf != nil {
			controls.XPerf = options.XPerf
		}
		controls.ModelZoo = options.ModelZoo
	}
	return controls
}

// polyphemusEffortOrder ranks reasoning efforts from least to most thinking.
var polyphemusEffortOrder = []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"}

// polyphemusSupportedEffort maps Telluvian's recommended effort onto one the
// selected model accepts, per the catalog's trustedrouter.capabilities.
// reasoning_effort: the strongest supported effort at or below the
// recommendation, else the weakest above it. A model declaring no efforts
// gets none. An unknown or malformed declaration, one with no effort we can
// rank, or a recommendation we cannot rank passes through unchanged.
func polyphemusSupportedEffort(body []byte, model, effort string) string {
	effort = strings.ToLower(strings.TrimSpace(effort))
	if effort == "" {
		return ""
	}
	want := slices.Index(polyphemusEffortOrder, effort)
	if want < 0 {
		return effort
	}
	// Decode only the selected row's declaration, so another model's
	// malformed capabilities cannot disable the clamp.
	var catalog struct {
		Data []struct {
			ID string `json:"id"`
			TR struct {
				Capabilities json.RawMessage `json:"capabilities"`
			} `json:"trustedrouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return effort
	}
	var supported *[]string
	for _, row := range catalog.Data {
		if row.ID != model {
			continue
		}
		var capabilities struct {
			ReasoningEffort *[]string `json:"reasoning_effort"`
		}
		if err := json.Unmarshal(row.TR.Capabilities, &capabilities); err != nil {
			return effort
		}
		supported = capabilities.ReasoningEffort
		break
	}
	if supported == nil {
		return effort
	}
	if len(*supported) == 0 {
		return ""
	}
	below, above := "", ""
	for i, candidate := range polyphemusEffortOrder {
		if !slices.ContainsFunc(*supported, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), candidate) }) {
			continue
		}
		if i <= want {
			below = candidate
		} else if above == "" {
			above = candidate
		}
	}
	switch {
	case below != "":
		return below
	case above != "":
		return above
	default:
		return effort // nothing declared that we can rank
	}
}
