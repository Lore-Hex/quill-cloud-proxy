package speculation

import "strings"

// Reason is the closed local eligibility/miss taxonomy. ProtocolError and the
// authenticated denial Verdict taxonomy retain their separate frozen meanings.
type Reason string

const (
	ReasonEligible       Reason = "eligible"
	ReasonGrant          Reason = "grant_missing"
	ReasonShadow         Reason = "shadow_grant"
	ReasonClock          Reason = "clock_invalid"
	ReasonDeadline       Reason = "start_deadline"
	ReasonBinding        Reason = "binding_mismatch"
	ReasonOwner          Reason = "owner_boot"
	ReasonTrust          Reason = "local_trust" // Verified boot trust only; §2 inputs have separate reasons below.
	ReasonPilot          Reason = "not_pilot_workspace"
	ReasonPaid           Reason = "paid_provenance_missing"
	ReasonKeyEligible    Reason = "key_ineligible"
	ReasonPolicy         Reason = "policy_stale"
	ReasonStageD         Reason = "stage_d_unavailable"
	ReasonHealthMissing  Reason = "health_missing"
	ReasonHealth         Reason = "health_unhealthy"
	ReasonWorkspaceLatch Reason = "workspace_latched"
	ReasonKeyLatch       Reason = "key_latched"
	ReasonWorkspaceEpoch Reason = "workspace_epoch"
	ReasonKeyEpoch       Reason = "key_epoch"
	ReasonRoute          Reason = "route_uncertified"
	ReasonChat           Reason = "not_streaming_chat"
	ReasonCredits        Reason = "credits_not_explicit" // #nosec G101 -- eligibility reason, not a credential.
	ReasonTier           Reason = "service_tier"
	ReasonProvenance     Reason = "idempotency_provenance_missing"
	ReasonIdempotency    Reason = "caller_idempotency"
	ReasonReceipts       Reason = "inference_receipts"
	ReasonTools          Reason = "tools"
	ReasonReasoning      Reason = "reasoning"
	ReasonMedia          Reason = "media"
	ReasonBYOK           Reason = "byok"
	ReasonCustomModel    Reason = "custom_model"
	ReasonOrchestration  Reason = "orchestration"
	ReasonConfidential   Reason = "confidential_host"
	ReasonExtraCost      Reason = "extra_reservation_cost"
	ReasonResponseModel  Reason = "response_model_rewriting"
	ReasonPreferences    Reason = "provider_preferences"
	ReasonExternalPrompt Reason = "external_prompt"
	ReasonCacheWrite     Reason = "prompt_cache_write"
	ReasonAttribution    Reason = "unsupported_attribution"
	ReasonField          Reason = "unsupported_field"
	ReasonPayload        Reason = "invalid_payload"
	ReasonOutputCap      Reason = "explicit_output_cap"
	ReasonBoundMethod    Reason = "unsupported_token_bound"
	ReasonInputBound     Reason = "input_bound"
	ReasonCost           Reason = "cost_ceiling"
)

// CallerIdempotency preserves ingress presence (including empty values) before
// an internal key is generated. No key value is stored. A zero value is unknown.
type CallerIdempotency struct{ captured, header, body bool }

func CaptureCallerIdempotency(headerPresent bool, originalBody map[string]any) CallerIdempotency {
	_, bodyPresent := originalBody["idempotency_key"]
	return CallerIdempotency{true, headerPresent, bodyPresent}
}

// ParsedRequest retains every parsed public field, including unknown ones, so
// the narrow adapter cannot silently discard unsupported behavior. Body uses
// the protocol JSON domain (integers int/int64, arrays []any, objects maps).
// Internal fields are trusted parsing/routing facts, never public overrides.
// ConfidentialOnly includes the ingress host restriction, not just body policy.
type ParsedRequest struct {
	Body                 map[string]any
	RouteType            string
	CallerIdempotency    CallerIdempotency
	InferenceReceipts    bool
	BYOK                 bool
	CustomModel          bool
	Orchestration        bool
	ConfidentialOnly     bool
	ExtraReservationCost int64
	ResponseModel        string
}

// LocalContext must be captured before ordinary authorize. Bindings are the
// current trusted VerifyGrant context, including the complete route and latest
// generation; never copy them from the candidate grant. Certificate membership
// independently allowlists the exact endpoint/model/adapter. No permit or money
// is consumed here: an eligible snapshot is not a physical-send authorization.
type LocalContext struct {
	Bindings          map[string]any
	Certificates      []AdapterCertificate
	RequestPolicyHash string
	OwnerBootID       string
	OwnerBootCount    int
	PilotAllowed      bool
	PaidProvenance    bool
	// KeyEligible requires active/unexpired route authorization, resolved ownership,
	// no spend limits, and no delegated/browser/partner/BYOK credentials.
	KeyEligible                bool
	BootVerified               bool
	PolicyFresh, StageDEnabled bool
}

type Decision struct {
	Eligible bool   `json:"eligible"`
	Reason   Reason `json:"reason"`
}

type EligibilitySnapshot struct {
	Dispatch              Decision `json:"dispatch"`
	Shadow                Decision `json:"shadow"`
	ShadowDispatchAllowed bool     `json:"shadow_dispatch_allowed"`
}

// EvaluateEligibility evaluates the same predicates for real and shadow grants.
// ShadowDispatchAllowed is always false, even when Shadow.Eligible is true.
func EvaluateEligibility(g ReceivedGrant, local LocalContext, req ParsedRequest, health LocalHealth, now Monotonic) EligibilitySnapshot {
	r := eligibilityReason(g, local, req, health, now)
	shadow := Decision{r == ReasonEligible, r}
	if r == ReasonEligible && g.grant.Shadow() {
		r = ReasonShadow
	}
	return EligibilitySnapshot{Decision{r == ReasonEligible, r}, shadow, false}
}

func eligibilityReason(g ReceivedGrant, local LocalContext, req ParsedRequest, health LocalHealth, now Monotonic) Reason {
	c, err := g.grant.Claims()
	if err != nil {
		return ReasonGrant
	}
	if !g.live(now) {
		return ReasonDeadline
	}
	if r := healthReason(c, health); r != ReasonEligible {
		return r
	}
	for _, f := range strings.Fields(bindings) {
		if !equal(c[f], local.Bindings[f]) {
			return ReasonBinding
		}
	}
	if !equal(c["route"], local.Bindings["route"]) {
		return ReasonBinding
	}
	if local.OwnerBootCount != 1 || local.OwnerBootID != c["boot_id"] {
		return ReasonOwner
	}
	if !local.PilotAllowed {
		return ReasonPilot
	}
	if !local.PaidProvenance {
		return ReasonPaid
	}
	if !local.KeyEligible {
		return ReasonKeyEligible
	}
	if !local.BootVerified {
		return ReasonTrust
	}
	if !local.PolicyFresh || local.RequestPolicyHash != c["route"].(map[string]any)["routing_policy_hash"] {
		return ReasonPolicy
	}
	if !local.StageDEnabled {
		return ReasonStageD
	}
	_, r := PreparePayload(g.grant, local.Certificates, req)
	return r
}

func requestReason(req ParsedRequest) Reason {
	b := req.Body
	if req.RouteType != "chat.completions" || b["stream"] != true {
		return ReasonChat
	}
	if !req.CallerIdempotency.captured {
		return ReasonProvenance
	}
	_, bodyKey := b["idempotency_key"]
	if req.CallerIdempotency.header || req.CallerIdempotency.body || bodyKey {
		return ReasonIdempotency
	}
	if req.InferenceReceipts || hasAny(b, "inference_receipt inference_receipts") {
		return ReasonReceipts
	}
	if hasAny(b, "tools tool_choice functions function_call plugins max_tool_calls web_search_options parallel_tool_calls") {
		return ReasonTools
	}
	if hasAny(b, "reasoning reasoning_effort thinking") {
		return ReasonReasoning
	}
	if hasAny(b, "audio modalities image video") {
		return ReasonMedia
	}
	if req.BYOK {
		return ReasonBYOK
	}
	if req.CustomModel {
		return ReasonCustomModel
	}
	if req.Orchestration || hasAny(b, "models fusion decide advisor subagent batch depth") {
		return ReasonOrchestration
	}
	if req.ConfidentialOnly {
		return ReasonConfidential
	}
	if req.ExtraReservationCost != 0 {
		return ReasonExtraCost
	}
	if req.ResponseModel != "" {
		return ReasonResponseModel
	}
	if hasAny(b, "prompt_url external_prompt") {
		return ReasonExternalPrompt
	}
	if hasAny(b, "prompt_cache_key prompt_cache_options") {
		return ReasonCacheWrite
	}
	if hasAny(b, "user session_id trace metadata tags app http_referer app_categories request_fingerprint") {
		return ReasonAttribution
	}
	if tier, exists := b["service_tier"]; exists && tier != "" && tier != "default" {
		return ReasonTier
	}
	p, ok := b["provider"].(map[string]any)
	usage, _ := p["usage"].(string)
	if !ok || !strings.EqualFold(strings.TrimSpace(usage), "credits") {
		return ReasonCredits
	}
	for k := range p {
		if !member(k, "usage order only ignore allow_fallbacks require_parameters data_collection") {
			return ReasonPreferences
		}
	}
	return ReasonEligible
}

func hasAny(b map[string]any, fields string) bool {
	for _, k := range strings.Fields(fields) {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}
