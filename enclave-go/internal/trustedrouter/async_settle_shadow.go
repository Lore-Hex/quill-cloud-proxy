package trustedrouter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const shadowSettlementHeader = "X-TR-Settlement-Shadow"
const shadowInlineBytes = 6144
const shadowJSONBytes = 8192
const shadowHeaderBytes = 12288
const shadowLocalBytes = 65536

// ShadowBuildRevision is injected by the image build, never by request data.
// Local VCS builds can use Go's embedded revision. An unknown revision refuses
// diagnostics rather than inventing build provenance.
var ShadowBuildRevision string
var shadowRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var shadowConfigurationConflicts atomic.Uint64
var shadowRejections atomic.Uint64
var shadowDiagnosticCounters = map[string]*atomic.Uint64{
	"proof_signature": {}, "identity": {}, "snapshot_size": {}, "hash": {},
	"json_shape": {}, "revision": {}, "header_size": {},
}

func shadowReject(reason string) {
	shadowRejections.Add(1)
	if counter := shadowDiagnosticCounters[reason]; counter != nil {
		counter.Add(1)
	}
	asyncLog("shadow_rejected", reason)
}

type shadowHeaderKey struct{}
type shadowAuthorization struct {
	snapshot  billingv1.Snapshot
	raw       json.RawMessage
	proof     string
	terminal  billingv1.TerminalEnvelope
	requested billingv1.Eligibility
	mu        sync.Mutex
	frozen    map[string]shadowFrozen
}
type shadowFrozen struct{ key, header string }

// ShadowObservation contains bounded provider facts captured before legacy
// normalization. The timestamp follows Usage through background retries.
// It never enters the legacy body or client stream.
type ShadowObservation struct {
	Present     bool
	ServiceTier string
	AvailableAt time.Time
}

func ObserveShadowUsage(present bool, tier string) ShadowObservation {
	if tier != "" && tier != "default" {
		tier = "unsupported"
	}
	return ShadowObservation{Present: present, ServiceTier: tier, AvailableAt: time.Now()}
}

func shadowFlag(boot *qtypes.BootstrapData) bool {
	enabled := boot != nil && boot.AsyncSettleShadow
	if value, exists := os.LookupEnv("TR_ASYNC_SETTLE_SHADOW"); exists {
		enabled = value == "on"
	}
	if enabled && asyncFlag(boot) {
		shadowConfigurationConflicts.Add(1)
		asyncLog("shadow_configuration_conflict", "negotiation_suppressed")
	}
	return enabled
}

func shadowRevision() string {
	if ShadowBuildRevision != "" {
		return ShadowBuildRevision
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

// These claims are deliberately UNVERIFIED. They only supply diagnostic region
// and epoch; the router authenticates the opaque proof. They cannot bind async.
func shadowClaims(proof string) (asyncTicketClaims, bool) {
	var c asyncTicketClaims
	if len(proof) > 2048 {
		return c, false
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return c, false
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || part == "" || base64.RawURLEncoding.EncodeToString(raw) != part {
			return c, false
		}
		decoded[i] = raw
	}
	var header map[string]string
	if json.Unmarshal(decoded[0], &header) != nil || len(header) != 3 || header["alg"] != "EdDSA" || header["typ"] != "tr-async-settle-shadow-v1" || !ticketIdentity.MatchString(header["kid"]) || len(decoded[2]) != 64 {
		return c, false
	}
	canonicalHeader, _ := json.Marshal(header)
	if !bytes.Equal(canonicalHeader, decoded[0]) {
		return c, false
	}
	// Restrict this small flat claims object before decoding. Canonical equality
	// rejects duplicate keys, whitespace, escapes and trailing data.
	for _, b := range decoded[1] {
		if b < 32 || b > 126 || b == '\\' {
			return c, false
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(decoded[1], &fields) != nil || len(fields) != 19 {
		return c, false
	}
	canonical, _ := json.Marshal(fields)
	if !bytes.Equal(canonical, decoded[1]) || json.Unmarshal(decoded[1], &c) != nil {
		return c, false
	}
	for _, v := range fields {
		if bytes.Equal(v, []byte("null")) {
			return c, false
		}
	}
	for _, v := range []string{c.AuthorizationID, c.WorkspaceID, c.KeyID, c.Reservation} {
		if len(v) > 64 || !ticketIdentity.MatchString(v) {
			return c, false
		}
	}
	for _, v := range []string{c.GenerationID, c.JournalRegion, c.Iss, c.Aud} {
		if len(v) > 128 || !ticketIdentity.MatchString(v) {
			return c, false
		}
	}
	if !ticketNonce.MatchString(c.AuthorizationID) || !ticketNonce.MatchString(c.InvocationNonce) || !ticketDigest.MatchString(c.SnapshotHash) || c.BillingAuthority != "local" || c.Origin != "typed" || c.Aud != "router-shadow" || c.Eligible || c.Epoch < 1 || c.SnapshotVersion != 1 || c.Iat < 0 || c.Exp < c.Iat || c.Exp-c.Iat != 172800 || !asyncCohort(c.RouteType) {
		return c, false
	}
	// Compare a typed round trip too: rejects unknown/replaced/missing fields.
	typed, _ := json.Marshal(c)
	var typedFields map[string]json.RawMessage
	_ = json.Unmarshal(typed, &typedFields)
	typed, _ = json.Marshal(typedFields)
	return c, bytes.Equal(typed, canonical)
}

func (c *Client) retainShadowAuthorization(a *Authorization, req *qtypes.OpenAIChatRequest, route string) {
	if !c.asyncShadow || !asyncCohort(route) {
		return
	}
	claims, ok := shadowClaims(string(a.BillingShadowBinding))
	if !ok {
		shadowReject("proof_signature")
		return
	}
	if claims.AuthorizationID != a.AuthorizationID || claims.GenerationID != a.GenerationID || claims.WorkspaceID != a.WorkspaceID || claims.KeyID != a.APIKeyHash || claims.InvocationNonce != a.InvocationNonce || claims.Reservation != a.CreditReservationID || claims.RouteType != route || claims.Streamed != req.Stream || claims.SnapshotHash != string(a.BillingSnapshotHash) {
		shadowReject("identity")
		return
	}
	var compact bytes.Buffer
	if json.Compact(&compact, a.BillingSnapshot) != nil {
		shadowReject("json_shape")
		return
	}
	if compact.Len() > shadowLocalBytes {
		shadowReject("snapshot_size")
		return
	}
	snapshot, err := billingv1.ParseSnapshot(a.BillingSnapshot)
	if err != nil {
		shadowReject("json_shape")
		return
	}
	raw, err := billingv1.CanonicalBytes(snapshot)
	if err != nil || len(raw) > shadowLocalBytes || len(snapshot.Candidates()) > 128 {
		shadowReject("snapshot_size")
		return
	}
	hash, err := billingv1.CanonicalHash(snapshot)
	if err != nil || hash != claims.SnapshotHash {
		shadowReject("hash")
		return
	}
	for _, candidate := range snapshot.Candidates() {
		if len(candidate.EndpointID) > 128 || len(candidate.ModelID) > 128 {
			shadowReject("identity")
			return
		}
	}
	requested := billingv1.DefaultEligibility()
	requested.RouteType, requested.Streamed, requested.UsageType = route, req.Stream, a.UsageType
	requested.CustomModel, requested.NativeBatch = a.CustomModel != nil, a.NativeBatchEligible
	requested.ToolCost = req.AdditionalCostReservationMicrodollars != 0 || req.AdditionalCostMicrodollars != 0
	requested.Polyphemus = req.Polyphemus != nil
	requested.ReceiptFee = int64(a.ReceiptFeeBasisPoints)
	if req.InferenceReceipt.Requested || a.SpendLease != nil {
		requested.ReceiptFee = 1
	}
	if req.ServiceTier != "" {
		tier := ObserveShadowUsage(true, req.ServiceTier).ServiceTier
		requested.ServiceTier = &tier
	}
	a.shadowSettlement = &shadowAuthorization{snapshot: snapshot, raw: raw, proof: string(a.BillingShadowBinding), terminal: claims.terminal(), requested: requested, frozen: make(map[string]shadowFrozen)}
}

// buildShadowEnvelope never edits usage, authorization, or a legacy request.
func buildShadowEnvelope(a *shadowAuthorization, usage Usage, kind, revision string) map[string]any {
	observed := billingv1.DefaultEligibility()
	observed.RouteType, observed.Streamed = a.terminal.RouteType, a.terminal.Streamed
	observed.ToolCost = usage.AdditionalCostMicrodollars != 0
	observed.PrivateTierBasis = usage.PriceTierInputTokens != 0
	if usage.ShadowObservation.ServiceTier != "" {
		tier := usage.ShadowObservation.ServiceTier
		observed.ServiceTier = &tier
	}
	body := map[string]any{"v": 1, "billing_shadow_binding": a.proof, "billing_snapshot": a.raw, "raw_usage": nil, "observed": observed, "terminal": nil, "payload_hash": nil, "go_error": nil, "go_evaluator": "billing-v1", "go_revision": revision, "handoff_prepare_us": int64(0)}
	fail := func(reason string) map[string]any { body["go_error"] = reason; return body }
	if !usage.ShadowObservation.Present {
		return fail("usage_missing")
	}
	raw := billingv1.RawUsage{InputTokens: int64(usage.InputTokens), OutputTokens: int64(usage.OutputTokens), CacheReadTokens: int64(usage.CacheReadInputTokens), CacheCreationTokens: int64(usage.CacheCreationInputTokens), ReasoningTokens: int64(usage.ReasoningTokens)}
	if _, err := billingv1.CanonicalBytes(raw); err != nil {
		return fail("malformed_usage")
	}
	body["raw_usage"] = raw
	if usage.UsageEstimated {
		return fail("usage_estimated")
	}
	if billingv1.RequireEligible(a.requested) != nil || billingv1.RequireEligible(observed) != nil {
		return fail("unsupported_observed")
	}
	if usage.RouteType != a.terminal.RouteType || usage.Streamed != a.terminal.Streamed || len(usage.SelectedEndpoint) > 128 {
		return fail("evaluator_failed")
	}
	result, err := billingv1.Evaluate(a.snapshot, usage.SelectedEndpoint, raw, observed)
	if err != nil {
		var billingErr *billingv1.Error
		if errors.As(err, &billingErr) {
			switch billingErr.Code {
			case "arithmetic_overflow":
				return fail("arithmetic_overflow")
			case "malformed_usage", "invalid_usage":
				return fail("malformed_usage")
			}
		}
		return fail("evaluator_failed")
	}
	terminal := a.terminal
	terminal.V, terminal.TerminalKind, terminal.SelectedEndpoint, terminal.Usage, terminal.ChargeMicro = 1, kind, usage.SelectedEndpoint, result.Usage, result.ChargeMicro
	if kind == "refund" {
		terminal.ChargeMicro = 0
	}
	if billingv1.ValidateEnvelope(a.snapshot, terminal) != nil {
		return fail("evaluator_failed")
	}
	hash, err := billingv1.CanonicalHash(terminal)
	if err != nil {
		return fail("evaluator_failed")
	}
	body["terminal"], body["payload_hash"] = terminal, hash
	return body
}

// All strings originate in bounded ASCII DTOs. UseNumber preserves int64 and
// the second marshal orders keys at every depth, including RawMessages.
func canonicalShadow(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var object any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&object); err != nil {
		return nil, err
	}
	return json.Marshal(object)
}

func encodeShadow(body map[string]any, snapshotBytes int) (string, error) {
	raw, err := canonicalShadow(body)
	if err != nil {
		return "", err
	}
	if snapshotBytes > shadowInlineBytes || len(raw) > shadowJSONBytes || base64.RawURLEncoding.EncodedLen(len(raw)) > shadowHeaderBytes {
		delete(body, "billing_snapshot") // Never trim candidates; only omit this key.
		raw, err = canonicalShadow(body)
	}
	if err != nil {
		return "", err
	}
	if len(raw) > shadowJSONBytes || base64.RawURLEncoding.EncodedLen(len(raw)) > shadowHeaderBytes {
		return "", errors.New("header_size")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (c *Client) withShadowHeader(ctx context.Context, a *Authorization, usage Usage, kind string) context.Context {
	if !c.asyncShadow {
		return ctx
	}
	// Clear any inherited authorize context even when diagnostics are unavailable.
	ctx = context.WithValue(ctx, asyncModeKey{}, "")
	if a.shadowSettlement == nil {
		return ctx
	}
	shadow := a.shadowSettlement
	revision := shadowRevision()
	if !shadowRevisionPattern.MatchString(revision) {
		shadowReject("revision")
		return ctx
	}
	shadow.mu.Lock()
	defer shadow.mu.Unlock()
	body := buildShadowEnvelope(shadow, usage, kind, revision)
	key, err := canonicalShadow(body)
	if err != nil {
		shadowReject("json_shape")
		return ctx
	}
	if frozen, ok := shadow.frozen[kind]; ok && frozen.key == string(key) {
		return context.WithValue(ctx, shadowHeaderKey{}, frozen.header)
	}
	if !usage.ShadowObservation.AvailableAt.IsZero() {
		body["handoff_prepare_us"] = max(int64(0), time.Since(usage.ShadowObservation.AvailableAt).Microseconds())
	}
	header, err := encodeShadow(body, len(shadow.raw))
	if err != nil {
		shadowReject("header_size")
		return ctx
	}
	shadow.frozen[kind] = shadowFrozen{string(key), header}
	return context.WithValue(ctx, shadowHeaderKey{}, header)
}
