package speculation

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

func TestPreparedFixtureWire(t *testing.T) {
	c := eligibleCase(t)
	h := newHarness(t)
	got, r := PreparePayload(c.grant.grant, c.local.Certificates, c.req)
	descriptor, _ := h.descriptor.Claims()
	if r != ReasonEligible || !bytes.Equal(got.Bytes, h.wire) || got.SHA256 != descriptor["request_sha256"] {
		t.Fatalf("fixture wire %s %s %+v", got.Bytes, r, got)
	}
	if got.InputBound != int64(len(h.wire))+32 || got.BMicro != 580 {
		t.Fatal(got)
	}
	// Returned bytes have no input alias and do not live in a package cache.
	got.Bytes[0] = 'x'
	again, r := PreparePayload(c.grant.grant, c.local.Certificates, c.req)
	if r != ReasonEligible || !bytes.Equal(again.Bytes, h.wire) {
		t.Fatal("mutable output alias")
	}
}
func TestPayloadMisses(t *testing.T) {
	cases := []struct {
		name   string
		reason Reason
		edit   func(*eligibilityCase)
	}{
		{"zero_grant", ReasonGrant, func(c *eligibilityCase) { c.grant.grant = VerifiedGrant{} }},
		{"cap_missing", ReasonOutputCap, func(c *eligibilityCase) { delete(c.req.Body, "max_tokens") }},
		{"cap_zero", ReasonOutputCap, func(c *eligibilityCase) { c.req.Body["max_tokens"] = int64(0) }},
		{"cap_negative", ReasonOutputCap, func(c *eligibilityCase) { c.req.Body["max_tokens"] = int64(-1) }},
		{"cap_513", ReasonOutputCap, func(c *eligibilityCase) { c.req.Body["max_tokens"] = int64(513) }},
		{"cap_float", ReasonOutputCap, func(c *eligibilityCase) { c.req.Body["max_tokens"] = 512.0 }},
		{"chars4", ReasonBoundMethod, func(c *eligibilityCase) { c.local.Certificates[0].BoundAlgorithm = "chars/4" }},
		{"unknown_tokenizer", ReasonBoundMethod, func(c *eligibilityCase) { c.local.Certificates[0].BoundAlgorithm = "tokenizer-unknown" }},
		{"framing_missing", ReasonBoundMethod, func(c *eligibilityCase) { c.local.Certificates[0].FramingKnown = false }},
		{"framing_negative", ReasonBoundMethod, func(c *eligibilityCase) { c.local.Certificates[0].FramingTokens = -1 }},
		{"framing_overflow", ReasonInputBound, func(c *eligibilityCase) { c.local.Certificates[0].FramingTokens = math.MaxInt64 }},
		{"oversized_input", ReasonInputBound, func(c *eligibilityCase) { m(c.req.Body["messages"].([]any)[0])["content"] = strings.Repeat("a", 8192) }},
		{"uncapped_adapter", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates[0].HardOutputCap = false }},
		{"retries", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates[0].SingleAttempt = false }},
		{"hidden_tools", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates[0].NoHiddenTools = false }},
		{"hidden_reasoning", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates[0].NoHiddenReasoning = false }},
		{"price_evidence", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates[0].VendorPricesBounded = false }},
		{"certificate_route", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates[0].Route = nil }},
		{"unknown_field", ReasonField, func(c *eligibilityCase) { c.req.Body["future_field"] = true }},
		{"missing_messages", ReasonPayload, func(c *eligibilityCase) { delete(c.req.Body, "messages") }},
		{"empty_messages", ReasonPayload, func(c *eligibilityCase) { c.req.Body["messages"] = []any{} }},
		{"malformed_message", ReasonPayload, func(c *eligibilityCase) { c.req.Body["messages"] = []any{true} }},
		{"message_tools", ReasonTools, func(c *eligibilityCase) { m(c.req.Body["messages"].([]any)[0])["tool_calls"] = []any{} }},
		{"message_reasoning", ReasonReasoning, func(c *eligibilityCase) { m(c.req.Body["messages"].([]any)[0])["reasoning_content"] = "x" }},
		{"multimodal", ReasonMedia, func(c *eligibilityCase) {
			m(c.req.Body["messages"].([]any)[0])["content"] = []any{map[string]any{"type": "text", "text": "x"}}
		}},
		{"role", ReasonPayload, func(c *eligibilityCase) { m(c.req.Body["messages"].([]any)[0])["role"] = "unknown" }},
		{"utf8", ReasonPayload, func(c *eligibilityCase) { m(c.req.Body["messages"].([]any)[0])["content"] = string([]byte{255}) }},
		{"message_field", ReasonField, func(c *eligibilityCase) { m(c.req.Body["messages"].([]any)[0])["name"] = "x" }},
		{"system_utf8", ReasonPayload, func(c *eligibilityCase) { c.local.Certificates[0].SystemPrefix = []string{string([]byte{255})} }},
		{"marshal", ReasonPayload, func(c *eligibilityCase) { c.req.Body["temperature"] = math.NaN() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := eligibleCase(t)
			tc.edit(&c)
			got, r := PreparePayload(c.grant.grant, c.local.Certificates, c.req)
			if r != tc.reason || len(got.Bytes) != 0 {
				t.Fatalf("want %s got %s %+v", tc.reason, r, got)
			}
		})
	}
}
func TestPayloadFramingSystemAndExactBounds(t *testing.T) {
	c := eligibleCase(t)
	c.local.Certificates[0].SystemPrefix = []string{"system addition"}
	c.req.Body["max_tokens"] = 512
	p, r := PreparePayload(c.grant.grant, c.local.Certificates, c.req)
	if r != ReasonEligible || !bytes.Contains(p.Bytes, []byte("system addition")) || p.InputBound != int64(len(p.Bytes))+32 {
		t.Fatal(p, r)
	}
	c.local.Certificates[0].FramingTokens = 8192 - int64(len(p.Bytes))
	p, r = PreparePayload(c.grant.grant, c.local.Certificates, c.req)
	if r != ReasonEligible || p.InputBound != 8192 || p.BMicro != 4608 {
		t.Fatal(p, r)
	}
	c.local.Certificates[0].FramingTokens++
	if _, r = PreparePayload(c.grant.grant, c.local.Certificates, c.req); r != ReasonInputBound {
		t.Fatal(r)
	}
}
func TestPayloadSignedBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		want Reason
	}{
		{"unsupported_method", func(c map[string]any) { m(c["route"])["input_bound_method"] = "chars/4" }, ReasonBoundMethod},
		{"unknown_method", func(c map[string]any) { m(c["route"])["input_bound_method"] = "unknown-tokenizer" }, ReasonBoundMethod},
		{"conservative_method", func(c map[string]any) { m(c["route"])["input_bound_method"] = ConservativeUTF8Bytes }, ReasonEligible},
		{"signed_output", func(c map[string]any) { m(c["route"])["output_limit"] = int64(256) }, ReasonOutputCap},
		{"signed_input", func(c map[string]any) { m(c["route"])["input_bound"] = int64(1) }, ReasonInputBound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			claims, _ := h.real.Claims()
			tc.edit(claims)
			context := m(h.bundle["context"])
			context["route"] = claims["route"]
			g, e := VerifyGrant(signedEligibilityToken(t, h, claims, RealTyp), h.keys, context, 1700000000, false)
			if e != nil {
				t.Fatal(e)
			}
			c := eligibleCase(t)
			c.local.Certificates[0].Route = m(claims["route"])
			if _, r := PreparePayload(g, c.local.Certificates, c.req); r != tc.want {
				t.Fatal(r)
			}
		})
	}
	// Zero-priced actual input can have B=0 even though the signed maximum
	// input has a positive cost. It must miss, never create a zero-cost permit.
	h := newHarness(t)
	claims, _ := h.real.Claims()
	route := m(claims["route"])
	route["input_rate_micro_per_m"], route["output_rate_micro_per_m"] = int64(0), int64(0)
	route["maximum_request_fees_micro"] = int64(0)
	// Defensive impossible-after-verification branch; no production constructor
	// permits this value, but keep the payload boundary closed on corrupt state.
	raw, _ := json.Marshal(claims)
	g := h.real
	g.payload = string(raw)
	c := eligibleCase(t)
	c.local.Certificates[0].Route = route
	if _, r := PreparePayload(g, c.local.Certificates, c.req); r != ReasonCost {
		t.Fatal(r)
	}
}
func TestSerializerRejectsInternalAlias(t *testing.T) {
	for _, v := range []any{"trustedrouter/auto", "", 42} {
		body := map[string]any{"model": v}
		if _, r := serializeChat(body, nil, 512); r != ReasonCustomModel {
			t.Fatal(r)
		}
	}
}
func TestSerializerDeterminismProperty(t *testing.T) {
	c := eligibleCase(t)
	property := func(text string, seed int64) bool {
		// quick generates valid Unicode; JSON escaping and multibyte input are
		// covered independently of ASCII-only protocol claims.
		body := map[string]any{"model": "fixture-text", "stream": true, "max_tokens": int64(512), "messages": []any{map[string]any{"role": "user", "content": text}}, "provider": map[string]any{"usage": "Credits"}, "temperature": 0.25, "logit_bias": map[string]any{"2": -1, "1": 1}}
		before, _ := json.Marshal(body)
		keys := make([]string, 0, len(body))
		for k := range body {
			keys = append(keys, k)
		}
		rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- reproducible property-test permutations.
		rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		reordered := map[string]any{}
		for _, k := range keys {
			reordered[k] = body[k]
		}
		req := c.req
		req.Body = body
		p, r := PreparePayload(c.grant.grant, c.local.Certificates, req)
		req.Body = reordered
		q, s := PreparePayload(c.grant.grant, c.local.Certificates, req)
		after, _ := json.Marshal(body)
		return r == ReasonEligible && s == r && reflect.DeepEqual(p, q) && bytes.Equal(before, after) && p.SHA256 == digest(p.Bytes) && p.InputBound == int64(len(p.Bytes))+32
	}
	random := rand.New(rand.NewSource(73)) // #nosec G404 -- reproducible property-test seed.
	if err := quick.Check(property, &quick.Config{MaxCount: 500, Rand: random}); err != nil {
		t.Fatal(err)
	}
}
