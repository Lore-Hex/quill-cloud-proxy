package speculation

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// ConservativeUTF8Bytes is implemented locally: one token per serialized UTF-8
// byte, plus a certified upper bound for model framing. It is only valid for an
// independently audited endpoint/model whose tokenization satisfies that bound.
// Merely speaking Chat or declaring a method in a grant is not certification.
const ConservativeUTF8Bytes = "conservative-utf8-bytes-v1"

// AdapterCertificate is trusted local allowlist evidence, never caller input.
// Route must equal the complete signed route (including method ID and prices).
// BoundAlgorithm selects executable code; the signed input_bound_method must
// also name a supported certification method. FramingTokens covers ALL implicit model
// framing/system additions; explicit system additions are serialized below.
// VendorPricesBounded certifies all reachable price tiers, no cache discount,
// and no unrepresented fees. SingleAttempt includes transport/SDK retries.
type AdapterCertificate struct {
	Route               map[string]any
	BoundAlgorithm      string
	FramingKnown        bool
	FramingTokens       int64
	SystemPrefix        []string
	HardOutputCap       bool
	SingleAttempt       bool
	NoHiddenTools       bool
	NoHiddenReasoning   bool
	VendorPricesBounded bool
}

// PreparedPayload owns the final bytes. E4 and E12 must use this same seam and
// E12 must send these bytes without adapter rewriting. Callers own the returned
// slice; no input aliases it. BMicro is vendor liability, not a customer charge.
type PreparedPayload struct {
	Bytes              []byte
	SHA256             string
	InputBound, BMicro int64
}

// PreparePayload does no I/O, tokenization callbacks, clock reads or mutation.
// It can prepare shadow payloads, but confers no dispatch authority.
func PreparePayload(g VerifiedGrant, certificates []AdapterCertificate, req ParsedRequest) (PreparedPayload, Reason) {
	c, err := g.Claims()
	if err != nil {
		return PreparedPayload{}, ReasonGrant
	}
	if r := requestReason(req); r != ReasonEligible {
		return PreparedPayload{}, r
	}
	route := c["route"].(map[string]any)
	if len(certificates) != 1 || !equal(certificates[0].Route, route) || req.Body["model"] != route["upstream_model"] {
		return PreparedPayload{}, ReasonRoute
	}
	cert := certificates[0]
	if !cert.HardOutputCap || !cert.SingleAttempt || !cert.NoHiddenTools || !cert.NoHiddenReasoning || !cert.VendorPricesBounded {
		return PreparedPayload{}, ReasonRoute
	}
	if cert.BoundAlgorithm != ConservativeUTF8Bytes || !supportedBoundMethod(route["input_bound_method"]) || !cert.FramingKnown || cert.FramingTokens < 0 {
		return PreparedPayload{}, ReasonBoundMethod
	}
	cap, ok := explicitCap(req.Body["max_tokens"])
	if !ok || cap > number(route, "output_limit") {
		return PreparedPayload{}, ReasonOutputCap
	}
	wire, r := serializeChat(req.Body, cert.SystemPrefix, cap)
	if r != ReasonEligible {
		return PreparedPayload{}, r
	}
	// Bound before addition, so even a corrupt local certificate cannot wrap.
	if cert.FramingTokens > 8192 || len(wire) > 8192-int(cert.FramingTokens) {
		return PreparedPayload{}, ReasonInputBound
	}
	bound := int64(len(wire)) + cert.FramingTokens
	if bound > number(route, "input_bound") {
		return PreparedPayload{}, ReasonInputBound
	}
	b, err := CostCeiling(bound, route["input_rate_micro_per_m"], cap, route["output_rate_micro_per_m"], route["maximum_request_fees_micro"])
	if err != nil || b <= 0 || b > number(c, "per_request_ceiling_micro") || b > 10000 {
		return PreparedPayload{}, ReasonCost
	}
	return PreparedPayload{wire, digest(wire), bound, b}, ReasonEligible
}

func explicitCap(v any) (int64, bool) {
	var n int64
	switch v := v.(type) {
	case int:
		n = int64(v)
	case int64:
		n = v
	default:
		return 0, false
	}
	return n, n > 0 && n <= 512
}

func serializeChat(body map[string]any, prefix []string, cap int64) ([]byte, Reason) {
	wire := make(map[string]any, len(body))
	for k, v := range body {
		switch k {
		case "provider": // Control-plane policy, bound separately by its hash.
		case "model", "stream", "service_tier", "temperature", "top_p", "stop", "seed", "frequency_penalty", "presence_penalty", "logit_bias", "logprobs", "top_logprobs", "stream_options":
			wire[k] = v
		case "messages", "max_tokens": // Constructed below, never defaulted.
		default:
			return nil, ReasonField
		}
	}
	model, ok := body["model"].(string)
	if !ok || model == "" || strings.HasPrefix(model, "trustedrouter/") {
		return nil, ReasonCustomModel
	}
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) == 0 {
		return nil, ReasonPayload
	}
	out := make([]any, 0, len(messages)+len(prefix))
	for _, text := range prefix {
		if !utf8.ValidString(text) {
			return nil, ReasonPayload
		}
		out = append(out, map[string]any{"role": "system", "content": text})
	}
	for _, value := range messages {
		msg, ok := value.(map[string]any)
		if !ok {
			return nil, ReasonPayload
		}
		if hasAny(msg, "tool_calls tool_call_id function_call") || msg["role"] == "tool" || msg["role"] == "function" {
			return nil, ReasonTools
		}
		if hasAny(msg, "reasoning reasoning_content") {
			return nil, ReasonReasoning
		}
		content, ok := msg["content"].(string)
		if !ok {
			return nil, ReasonMedia
		}
		role, ok := msg["role"].(string)
		if !ok || !member(role, "system user assistant developer") || !utf8.ValidString(content) {
			return nil, ReasonPayload
		}
		if len(msg) != 2 {
			return nil, ReasonField
		}
		out = append(out, map[string]any{"role": role, "content": content})
	}
	wire["messages"], wire["max_tokens"] = out, cap
	b, err := json.Marshal(wire)
	if err != nil {
		return nil, ReasonPayload
	}
	return b, ReasonEligible
}

// The frozen fixture method is an explicit alias for this conservative bound,
// usable only with independent local certificate evidence, like the real method.
// This does not install fixture keys or certify a production endpoint.
func supportedBoundMethod(method any) bool {
	return method == ConservativeUTF8Bytes || method == "certified-fixture-bound-v1"
}
