// Package speculation implements the frozen v1 speculation wire contract.
// It is pure: verification creates no dispatch, billing, output or storage authority.
package speculation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

const (
	RealTyp             = "speculation-eligibility+jws"
	ShadowTyp           = "speculation-eligibility-shadow+jws"
	DescriptorTyp       = "speculation-descriptor+jws"
	Margin        int64 = 2
)

// TrustedKey is supplied by authenticated local configuration, never by a token.
type TrustedKey struct {
	Kid             string `json:"kid"`
	Purpose         string `json:"purpose"`
	PublicKeyB64URL any    `json:"public_key_b64url"`
	Iss             string `json:"iss"`
	Aud             string `json:"aud"`
	Environment     string `json:"environment"`
	Plane           string `json:"plane"`
}

// VerifiedGrant retains immutable received bytes; obtain it through VerifyGrant.
type VerifiedGrant struct {
	compact       string
	payload       string
	shadow        bool
	startDeadline int64
}

func (g VerifiedGrant) Compact() string      { return g.compact }
func (g VerifiedGrant) Shadow() bool         { return g.shadow }
func (g VerifiedGrant) StartDeadline() int64 { return g.startDeadline }
func (g VerifiedGrant) Claims() (claims map[string]any, err error) {
	defer refusal(&err)
	return claimsObject(g.payload), nil
}

// VerifiedDescriptor binds a single invocation to a permit in a verified grant.
type VerifiedDescriptor struct {
	compact string
	payload string
}

func (d VerifiedDescriptor) Compact() string { return d.compact }
func (d VerifiedDescriptor) Claims() (claims map[string]any, err error) {
	defer refusal(&err)
	return claimsObject(d.payload), nil
}
func claimsObject(payload string) map[string]any {
	v := parseJSON([]byte(payload))
	m, ok := v.(map[string]any)
	require(ok, "input")
	return m
}

// SHA256 hashes exact bytes without reserialization.
func SHA256(raw any) (value string, err error) {
	defer refusal(&err)
	b, ok := raw.([]byte)
	require(ok, "input")
	return digest(b), nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func verifySignature(key TrustedKey, signature, message []byte) (err error) {
	// A configured key's encoding failure is signature, not wire base64.
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(ProtocolError); ok {
				err = ProtocolError("signature")
			} else {
				panic(r)
			}
		}
	}()
	public := b64decode(key.PublicKeyB64URL)
	require(len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize, "signature")
	require(ed25519.Verify(public, message, signature), "signature")
	return nil
}
func verify(token any, keys []TrustedKey, typ, purpose string) (map[string]any, TrustedKey, []byte) {
	s, ok := token.(string)
	require(ok && utf8.RuneCountInString(s) <= 65536 && strings.Count(s, ".") == 2, "compact")
	parts := strings.Split(s, ".")
	hb := b64decode(parts[0])
	h := object(parseJSON(hb), "alg kid typ", "", "")
	require(bytes.Equal(hb, canonical(h)), "canonical_header")
	require(h["alg"] == "EdDSA", "algorithm")
	require(h["typ"] == typ, "type")
	matches := []TrustedKey{}
	for _, k := range keys {
		if k.Kid == h["kid"] {
			matches = append(matches, k)
		}
	}
	require(len(matches) == 1, "key")
	key := matches[0]
	require(key.Purpose == purpose, "purpose")
	payload := b64decode(parts[1])
	byteRule(payload)
	signature := b64decode(parts[2])
	if e := verifySignature(key, signature, []byte(parts[0]+"."+parts[1])); e != nil {
		panic(e)
	}
	v := parseJSON(payload)
	claims, ok := v.(map[string]any)
	require(ok, "fields")
	return claims, key, payload
}

const grantStrings = "iss aud environment plane workspace_id key_id lookup_digest boot_id stable_slot_id region grant_id"
const grantIntegers = "v generation workspace_epoch key_epoch image_policy_version tier paid_headroom_micro iat exp start_before key_expires_at trust_fresh_until per_request_ceiling_micro"
const routeStrings = "endpoint_id provider upstream_model region routing_policy_hash catalog_hash privacy input_bound_method"
const routeIntegers = "adapter_capability_version input_bound output_limit input_rate_micro_per_m output_rate_micro_per_m maximum_request_fees_micro price_expires_at"
const bindings = "workspace_id key_id lookup_digest boot_id stable_slot_id region generation workspace_epoch key_epoch image_policy_version"

func routeSchema(v any) map[string]any {
	m := object(v, routeStrings, routeIntegers, "stage_d")
	_, ok := m["stage_d"].(bool)
	require(ok, "stage_d")
	return m
}
func grantSchema(c map[string]any) {
	object(c, grantStrings, grantIntegers, "history route permits")
	routeSchema(c["route"])
	object(c["history"], "", "clean_since count last_success_at sequence window_start", "")
	p, ok := c["permits"].([]any)
	require(ok && len(p) > 0, "permits")
	for _, v := range p {
		object(v, "", "ordinal b_micro", "")
	}
}
func number(m map[string]any, k string) int64 { return integer(m[k]) }

// VerifyGrant verifies eligibility at physical start against current trusted
// bindings, the complete approved route and tier_ceiling_micro in context.
func VerifyGrant(token any, keys []TrustedKey, context map[string]any, now any, shadow bool) (grant VerifiedGrant, err error) {
	defer refusal(&err)
	clock := integer(now)
	typ, purpose := RealTyp, "grant"
	if shadow {
		typ, purpose = ShadowTyp, "shadow-grant"
	}
	c, key, payload := verify(token, keys, typ, purpose)
	grantSchema(c)
	checkCanonical(c, payload)
	require(c["v"] == int64(1), "version")
	for _, pin := range []struct{ name, value string }{{"iss", key.Iss}, {"aud", key.Aud}, {"environment", key.Environment}, {"plane", key.Plane}} {
		require(equal(c[pin.name], pin.value), "identity")
	}
	hashValue(c["lookup_digest"])
	for _, f := range strings.Fields(bindings) {
		v, ok := context[f]
		require(ok && equal(c[f], v), "binding")
	}
	route := c["route"].(map[string]any)
	for _, f := range []string{"routing_policy_hash", "catalog_hash"} {
		hashValue(route[f])
	}
	require(route["stage_d"] == true, "stage_d")
	routeSchema(context["route"])
	require(equal(route, context["route"]), "route")
	require(equal(route["region"], c["region"]), "route")
	require(number(route, "input_bound") > 0 && number(route, "input_bound") <= 8192 && number(route, "output_limit") > 0 && number(route, "output_limit") <= 512, "token_bound")
	require(number(route, "adapter_capability_version") > 0, "adapter")
	require(c["tier"] == int64(2) || c["tier"] == int64(3), "tier")
	require(number(c, "paid_headroom_micro") >= 5000000, "paid_headroom")
	history := c["history"].(map[string]any)
	issued := number(c, "iat")
	require(number(history, "count") >= 20 && number(history, "sequence") >= number(history, "count"), "history_count")
	window, last, clean := number(history, "window_start"), number(history, "last_success_at"), number(history, "clean_since")
	require(issued-600 <= window && window <= last && last <= issued && last >= issued-30 && clean <= issued-900, "history_time")
	require(number(c, "exp")-issued > 0 && number(c, "exp")-issued <= 30 && issued < number(c, "start_before"), "lifetime")
	deadline := min(number(c, "start_before"), number(c, "exp")-Margin, number(c, "key_expires_at")-Margin, number(route, "price_expires_at")-Margin, number(c, "trust_fresh_until")-Margin)
	require(issued <= clock && clock < deadline, "start_window")
	ceiling := number(c, "per_request_ceiling_micro")
	require(ceiling > 0 && ceiling <= 10000, "ceiling")
	b, e := CostCeiling(route["input_bound"], route["input_rate_micro_per_m"], route["output_limit"], route["output_rate_micro_per_m"], route["maximum_request_fees_micro"])
	if e != nil {
		panic(e)
	}
	require(b > 0 && b <= ceiling, "cost")
	permits := c["permits"].([]any)
	seen := map[int64]bool{}
	var total int64
	for _, v := range permits {
		p := v.(map[string]any)
		ordinal := number(p, "ordinal")
		require(!seen[ordinal], "ordinal")
		seen[ordinal] = true
		amount := number(p, "b_micro")
		require(b <= amount && amount <= ceiling, "permit_cost")
		total += amount
	}
	tier, ok := context["tier_ceiling_micro"]
	require(ok, "tier_ceiling")
	allowance, e := WorkspaceAllowance(tier, c["paid_headroom_micro"])
	if e != nil {
		panic(e)
	}
	require(total <= allowance, "allowance")
	return VerifiedGrant{token.(string), string(payload), shadow, deadline}, nil
}

const descriptorStrings = "grant_id grant_sha256 execution_id invocation_nonce request_sha256 routing_policy_hash endpoint_id workspace_id key_id boot_id"
const descriptorIntegers = "v ordinal b_micro workspace_epoch key_epoch"

// VerifyDescriptor binds exact request bytes, execution and nonce. It does not
// recheck start time: a descriptor may complete ordinary authorization later.
func VerifyDescriptor(token any, keys []TrustedKey, grant VerifiedGrant, requestBytes []byte, executionID, invocationNonce any) (descriptor VerifiedDescriptor, err error) {
	defer refusal(&err)
	require(!grant.shadow, "dry_run_cannot_dispatch")
	c, key, payload := verify(token, keys, DescriptorTyp, "descriptor")
	object(c, descriptorStrings, descriptorIntegers, "")
	checkCanonical(c, payload)
	require(c["v"] == int64(1), "version")
	for _, f := range []string{"grant_sha256", "request_sha256", "routing_policy_hash"} {
		hashValue(c[f])
	}
	g := claimsObject(grant.payload)
	require(equal(key.Kid, g["boot_id"]), "descriptor_boot")
	for _, f := range strings.Fields("grant_id workspace_id key_id boot_id workspace_epoch key_epoch") {
		require(equal(c[f], g[f]), "descriptor_binding")
	}
	require(c["grant_sha256"] == digest([]byte(grant.compact)), "grant_hash")
	require(c["request_sha256"] == digest(requestBytes), "request_hash")
	require(equal(c["execution_id"], executionID) && equal(c["invocation_nonce"], invocationNonce), "invocation")
	route, ok := g["route"].(map[string]any)
	require(ok, "input")
	for _, f := range []string{"endpoint_id", "routing_policy_hash"} {
		require(equal(c[f], route[f]), "descriptor_route")
	}
	permits, ok := g["permits"].([]any)
	require(ok, "input")
	found := false
	for _, v := range permits {
		p, ok := v.(map[string]any)
		require(ok, "input")
		if equal(p["ordinal"], c["ordinal"]) && equal(p["b_micro"], c["b_micro"]) {
			found = true
		}
	}
	require(found, "descriptor_permit")
	return VerifiedDescriptor{token.(string), string(payload)}, nil
}

// VerifyAcceptance requires an authenticated response and independently durable
// ordinary authorization. An accepted marker does not open the Stage D gate.
func VerifyAcceptance(response map[string]any, descriptor VerifiedDescriptor, authorization map[string]any) (verdict string, err error) {
	defer refusal(&err)
	require(equal(response["authorization"], authorization), "authorization")
	d := claimsObject(descriptor.payload)
	for _, f := range []string{"invocation_nonce", "workspace_id", "key_id"} {
		require(equal(authorization[f], d[f]), "authorization")
	}
	stringValue(authorization["authorization_id"])
	require(authorization["billing_mode"] == "ordinary", "authorization")
	v, present := response["speculation_accepted"]
	if !present {
		return "ordinary", nil
	}
	marker := object(v, "descriptor_sha256 invocation_nonce authorization_id endpoint_id routing_policy_hash", "v", "")
	require(marker["v"] == int64(1) || equal(marker["v"], int64(1)), "version")
	hashValue(marker["descriptor_sha256"])
	hashValue(marker["routing_policy_hash"])
	require(marker["descriptor_sha256"] == digest([]byte(descriptor.compact)), "descriptor_hash")
	for _, f := range []string{"invocation_nonce", "endpoint_id", "routing_policy_hash"} {
		require(equal(marker[f], d[f]), "marker_binding")
	}
	for _, f := range strings.Fields("authorization_id invocation_nonce endpoint_id routing_policy_hash workspace_id key_id") {
		expected, ok := marker[f]
		if !ok {
			expected = d[f]
		}
		require(equal(authorization[f], expected), "authorization")
	}
	require(authorization["billing_mode"] == "ordinary" && authorization["stage_d"] == true, "authorization")
	return "accepted", nil
}

// RenewalVerdict orders already verified grants; it restores no permits or latches.
func RenewalVerdict(previous, candidate VerifiedGrant) (verdict string, err error) {
	defer refusal(&err)
	if previous.compact == candidate.compact {
		return "replay", nil
	}
	old, newClaims := claimsObject(previous.payload), claimsObject(candidate.payload)
	require(previous.shadow == candidate.shadow, "renewal")
	for _, f := range strings.Fields("workspace_id key_id lookup_digest boot_id stable_slot_id iss aud environment plane region") {
		require(equal(old[f], newClaims[f]), "renewal")
	}
	require(!equal(newClaims["grant_id"], old["grant_id"]) && number(newClaims, "generation") > number(old, "generation") && number(newClaims, "iat") >= number(old, "iat") && number(newClaims, "workspace_epoch") >= number(old, "workspace_epoch") && number(newClaims, "key_epoch") >= number(old, "key_epoch"), "renewal")
	oh, ok := old["history"].(map[string]any)
	require(ok, "input")
	nh, ok := newClaims["history"].(map[string]any)
	require(ok, "input")
	require(number(nh, "sequence") >= number(oh, "sequence"), "renewal")
	return "renewed", nil
}

// DescriptorReplay permits only byte-identical compact retries.
func DescriptorReplay(previous, candidate VerifiedDescriptor) (verdict string, err error) {
	defer refusal(&err)
	require(previous.compact == candidate.compact, "replay_conflict")
	return "replay", nil
}
