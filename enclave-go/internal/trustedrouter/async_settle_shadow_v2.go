package trustedrouter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const shadowPolicyHeader = "X-TR-Settlement-Shadow-Policy"
const shadowPolicyV2 = "shadow-v2"
const shadowCertificateBytes = 2048
const shadowExcludedJSONBytes = 4096
const shadowExcludedHeaderBytes = 5462

// The seam permits an order spy without changing billing's parser or money path.
var parseShadowSnapshot = billingv1.ParseSnapshot
var buildShadowTerminal = buildShadowEnvelope

type shadowReceiptLocator struct {
	Day       string `json:"day"`
	Boot      string `json:"boot"`
	FirstSeq  string `json:"first_seq"`
	EventSeq  string `json:"event_seq"`
	EventHash string `json:"event_sha256"`
}

type shadowExclusionClaims struct {
	V               int                  `json:"v"`
	Policy          string               `json:"policy_version"`
	Iss             string               `json:"iss"`
	Aud             string               `json:"aud"`
	Iat             int64                `json:"iat"`
	Exp             int64                `json:"exp"`
	AuthorizationID string               `json:"authorization_id"`
	GenerationID    string               `json:"generation_id"`
	WorkspaceID     string               `json:"workspace_id"`
	KeyID           string               `json:"key_id"`
	InvocationNonce string               `json:"invocation_nonce"`
	Reservation     string               `json:"reservation_id"`
	Authority       string               `json:"billing_authority"`
	Region          string               `json:"journal_region"`
	Epoch           int64                `json:"epoch"`
	Origin          string               `json:"settle_origin"`
	Route           string               `json:"requested_route"`
	Streamed        bool                 `json:"requested_streamed"`
	Reason          string               `json:"reason"`
	Facts           string               `json:"facts_sha256"`
	Candidates      *string              `json:"candidate_set_sha256"`
	Revision        string               `json:"router_revision"`
	Receipt         shadowReceiptLocator `json:"original_receipt"`
	Eligible        bool                 `json:"async_eligible"`
}

// This is a bounded local reading, NOT signature, expiry, issuer, durable receipt,
// eligibility or booking verification. Only the router can authenticate a proof.
// In particular no locator is created, normalized or used for an enclave lookup.
func shadowCertificateClaims(proof string) (shadowExclusionClaims, bool) {
	var c shadowExclusionClaims
	if len(proof) > shadowCertificateBytes {
		return c, false
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return c, false
	}
	var decoded [3][]byte
	for i, part := range parts {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || part == "" || base64.RawURLEncoding.EncodeToString(raw) != part {
			return c, false
		}
		decoded[i] = raw
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if !shadowExactObject(decoded[0], &header) || header.Alg != "EdDSA" || header.Typ != "tr-async-settle-shadow-exclusion-v2" || !shadowName(header.Kid, 64) || len(decoded[2]) != 64 {
		return c, false
	}
	if !shadowExactObject(decoded[1], &c) {
		return c, false
	}
	for _, v := range []string{c.WorkspaceID, c.KeyID, c.Reservation} {
		if !shadowName(v, 64) {
			return c, false
		}
	}
	for _, v := range []string{c.GenerationID, c.Iss, c.Aud, c.Region, c.Route, c.Reason, c.Authority, c.Origin} {
		if !shadowName(v, 128) {
			return c, false
		}
	}
	if c.V != 2 || c.Policy != shadowPolicyV2 || c.Aud != "router-shadow-exclusion" || c.Eligible || c.Epoch < 1 || c.Iat < 0 || c.Exp < c.Iat || c.Exp-c.Iat != 172800 || !ticketNonce.MatchString(c.AuthorizationID) || !ticketNonce.MatchString(c.InvocationNonce) || c.GenerationID != ticketGenerationID(c.AuthorizationID) || !ticketDigest.MatchString(c.Facts) || (c.Candidates != nil && !ticketDigest.MatchString(*c.Candidates)) || !shadowRevisionPattern.MatchString(c.Revision) {
		return c, false
	}
	return c, shadowLocatorValid(c.Receipt)
}

func shadowName(v string, limit int) bool { return len(v) <= limit && ticketIdentity.MatchString(v) }

// A typed canonical round trip rejects missing/extra/duplicate keys, null scalar
// fields, escapes and noninteger numeric lexemes, including in the nested locator.
func shadowExactObject(raw []byte, into any) bool {
	for _, b := range raw {
		if b < 32 || b > 126 || b == '\\' {
			return false
		}
	}
	if json.Unmarshal(raw, into) != nil {
		return false
	}
	canonical, err := canonicalShadow(into)
	return err == nil && bytes.Equal(raw, canonical)
}

func shadowLocatorValid(v shadowReceiptLocator) bool {
	day, err := time.Parse("2006-01-02", v.Day)
	if err != nil || day.Format("2006-01-02") != v.Day || !ticketNonce.MatchString(v.Boot) || !ticketDigest.MatchString(v.EventHash) {
		return false
	}
	first, err := strconv.ParseUint(v.FirstSeq, 10, 64)
	if err != nil || first == 0 || len(v.FirstSeq) != 20 {
		return false
	}
	event, err := strconv.ParseUint(v.EventSeq, 10, 64)
	if err != nil || event < first || len(v.EventSeq) != 20 {
		return false
	}
	for _, v := range []string{v.FirstSeq, v.EventSeq} {
		for _, b := range v {
			if b < '0' || b > '9' {
				return false
			}
		}
	}
	return true
}

type shadowExclusion struct {
	certificate          string
	authorization, route string
	streamed             bool
	mu                   sync.Mutex
	invoked              bool
	endpoint, adapter    string
}

// Policy dispatch is shared by every authorize route and precedes the snapshot
// parser. An absent marker preserves v1; malformed/contradictory v2 loses only
// diagnostics. Irrelevant snapshots are never inspected for exclusions.
func retainShadowV2(a *Authorization, req *qtypes.OpenAIChatRequest, route string) (v2, stop bool) {
	if len(a.BillingShadowPolicy) == 0 {
		return false, false
	}
	var policy string
	if json.Unmarshal(a.BillingShadowPolicy, &policy) != nil || policy != shadowPolicyV2 {
		shadowReject("json_shape")
		return false, true
	}
	if len(a.BillingShadowExclusion) == 0 {
		if a.BillingShadowBinding == "" || len(a.BillingSnapshot) == 0 {
			shadowReject("json_shape")
			return false, true
		}
		return true, false
	}
	var proof string
	if a.shadowBindingPresent || a.BillingShadowBinding != "" || json.Unmarshal(a.BillingShadowExclusion, &proof) != nil {
		shadowReject("json_shape")
		return false, true
	}
	claims, ok := shadowCertificateClaims(proof)
	if !ok {
		shadowReject("proof_signature")
		return false, true
	}
	if claims.AuthorizationID != a.AuthorizationID || claims.GenerationID != a.GenerationID || claims.WorkspaceID != a.WorkspaceID || claims.KeyID != a.APIKeyHash || claims.InvocationNonce != a.InvocationNonce || claims.Reservation != a.CreditReservationID || claims.Route != route || claims.Streamed != req.Stream {
		shadowReject("identity")
		return false, true
	}
	a.shadowSettlement = &shadowAuthorization{v2: true, exclusion: &shadowExclusion{certificate: proof, authorization: a.AuthorizationID, route: route, streamed: req.Stream}}
	return true, true
}

// RecordShadowInvocation records actual provider entry, not authorization or
// endpoint selection. It is a no-op outside retained v2 exclusions. All provider
// families use this one bounded recorder; no candidate projection is retained.
func (a *Authorization) RecordShadowInvocation(endpoint, provider string) {
	if a == nil || a.shadowSettlement == nil || a.shadowSettlement.exclusion == nil {
		return
	}
	e := a.shadowSettlement.exclusion
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invoked = true
	e.endpoint, e.adapter = "", ""
	if !shadowName(endpoint, 128) || provider == "" {
		return
	}
	e.endpoint, e.adapter = endpoint, "other"
	if provider == "openai" || provider == "anthropic" {
		e.adapter = provider
	}
}

func buildShadowExcluded(e *shadowExclusion, usage Usage, kind, revision string) (map[string]any, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var endpoint, adapter any
	if kind != "settle" && kind != "refund" {
		return nil, false
	}
	if e.invoked {
		if e.endpoint == "" || e.adapter == "" {
			return nil, false
		}
		if kind == "refund" && usage.SelectedEndpoint != "" && usage.SelectedEndpoint != e.endpoint {
			return nil, false
		}
		if kind == "settle" && (usage.SelectedEndpoint != e.endpoint || usage.RouteType != e.route || usage.Streamed != e.streamed) {
			return nil, false
		}
		endpoint, adapter = e.endpoint, e.adapter
	} else if kind == "settle" {
		return nil, false
	}
	return map[string]any{"v": 2, "policy_version": shadowPolicyV2, "variant": "excluded", "certificate": e.certificate, "go_revision": revision, "attempt": map[string]any{"authorization_id": e.authorization, "terminal_kind": kind, "selected_endpoint": endpoint, "adapter": adapter, "route_type": e.route, "streamed": e.streamed}}, true
}

// Both fit measurement and final serialization pass this single wire boundary.
func shadowWireFits(raw []byte, excluded bool) bool {
	decoded, encoded := shadowJSONBytes, shadowHeaderBytes
	if excluded {
		decoded, encoded = shadowExcludedJSONBytes, shadowExcludedHeaderBytes
	}
	return len(raw) <= decoded && base64.RawURLEncoding.EncodedLen(len(raw)) <= encoded
}

// V2 fixtures preserve the router's ensure_ascii canonical string spelling.
// V1's bounded ASCII serialization remains unchanged.
func shadowASCII(raw []byte) []byte {
	var out bytes.Buffer
	for _, r := range string(raw) {
		if r < 128 {
			out.WriteByte(byte(r))
		} else if r <= 0xffff {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
		}
	}
	return out.Bytes()
}

func shadowLocalFits(size, candidates int) bool {
	return size <= shadowLocalBytes && candidates <= 128
}
