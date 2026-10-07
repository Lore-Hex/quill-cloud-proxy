package trustedrouter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const asyncSettlementHeader = "X-TR-Settlement-Mode"
const asyncTicketMargin = 30 * time.Second // covers the existing 28 second retry budget

type asyncModeKey struct{}
type asyncAuthorization struct {
	attemptMu sync.Mutex
	attempted bool
	accepted  *SettleResult
	snapshot  billingv1.Snapshot
	raw       json.RawMessage
	ticket    string
	terminal  billingv1.TerminalEnvelope
	expires   int64
	requested billingv1.Eligibility
}

// PendingSettlement acknowledges durable responsibility, not ledger finalization.
type PendingSettlement struct {
	wireComplete     bool
	V                int    `json:"v"`
	SettlementID     string `json:"settlement_id"`
	SettlementStatus string `json:"settlement_status"`
	CostMicrodollars int64  `json:"cost_microdollars"`
	StatusURL        string `json:"status_url"`
	PollAfterMS      int    `json:"poll_after_ms"`
}

type asyncSettlementRequest struct {
	Snapshot json.RawMessage            `json:"billing_snapshot"`
	Ticket   string                     `json:"settlement_ticket"`
	Raw      billingv1.RawUsage         `json:"raw_usage"`
	Observed billingv1.Eligibility      `json:"observed"`
	Terminal billingv1.TerminalEnvelope `json:"terminal"`
}

func asyncCohort(route string) bool { return route == "chat.completions" || route == "responses" }
func asyncFlag(boot *qtypes.BootstrapData) bool {
	if value, exists := os.LookupEnv("TR_ASYNC_SETTLE_NEGOTIATE"); exists {
		return strings.EqualFold(strings.TrimSpace(value), "on")
	}
	return boot != nil && boot.AsyncSettleNegotiate
}
func (c *Client) asyncNow() time.Time {
	if c.asyncClock != nil {
		return c.asyncClock()
	}
	return time.Now()
}

// AsyncSettlementNegotiated is enclave-local provenance; parsed wire fields
// alone cannot activate settlement or change streaming behavior.
func (c *Client) AsyncSettlementNegotiated(a *Authorization) bool {
	return c != nil && c.asyncNegotiate && a != nil && a.async != nil
}

func (c *Client) bindAsyncAuthorization(a *Authorization, req *qtypes.OpenAIChatRequest, route string) {
	if !c.asyncNegotiate || !asyncCohort(route) || !bool(a.AsyncEligible) {
		return
	}
	if a.SettlementStatusURL != "/v1/settlements/"+url.PathEscape(a.AuthorizationID+".settle") {
		return
	}
	snapshot, err := billingv1.ParseSnapshot(a.BillingSnapshot)
	if err != nil {
		return
	}
	hash, err := billingv1.CanonicalHash(snapshot)
	if err != nil || hash != string(a.BillingSnapshotHash) {
		return
	}
	parts := strings.Split(a.SettlementTicket, ".")
	if len(parts) != 3 {
		return
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}
	var protected struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(header, &protected) != nil || protected.Alg != "EdDSA" || protected.Typ != "tr-async-settle-v1" || protected.Kid == "" {
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	// This is shape/binding verification only. The router authenticates the
	// signature against its keyring; no router verification key is provisioned here.
	var claims struct {
		billingv1.TerminalEnvelope
		Exp         int64  `json:"exp"`
		Iat         int64  `json:"iat"`
		Eligible    bool   `json:"async_eligible"`
		Iss         string `json:"iss"`
		Aud         string `json:"aud"`
		Origin      string `json:"settle_origin"`
		Reservation string `json:"reservation_id"`
	}
	if json.Unmarshal(raw, &claims) != nil || !claims.Eligible || claims.Iss == "" || claims.Aud != "router-settlement" || claims.Origin != "typed" || claims.Reservation == "" || claims.Iat > c.asyncNow().Unix() || claims.Exp <= claims.Iat {
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return
	}
	for _, field := range []string{"async_eligible", "authorization_id", "generation_id", "workspace_id", "key_id", "invocation_nonce", "billing_authority", "journal_region", "epoch", "snapshot_version", "snapshot_hash", "route_type", "streamed", "iat", "exp"} {
		if len(fields[field]) == 0 || string(fields[field]) == "null" {
			return
		}
	}
	t := claims.TerminalEnvelope
	if t.AuthorizationID != a.AuthorizationID || t.GenerationID != a.GenerationID || t.WorkspaceID != a.WorkspaceID || t.KeyID != a.APIKeyHash || t.InvocationNonce != a.InvocationNonce || t.SnapshotHash != hash || t.RouteType != route || t.Streamed != req.Stream {
		return
	}
	requested := billingv1.DefaultEligibility()
	requested.RouteType, requested.Streamed = route, req.Stream
	requested.UsageType = a.UsageType
	requested.CustomModel = a.CustomModel != nil
	requested.NativeBatch = a.NativeBatchEligible
	requested.ToolCost = req.AdditionalCostReservationMicrodollars != 0 || req.AdditionalCostMicrodollars != 0
	requested.Polyphemus = req.Polyphemus != nil
	if req.ServiceTier != "" {
		tier := req.ServiceTier
		requested.ServiceTier = &tier
	}
	if req.InferenceReceipt.Requested || a.ReceiptFeeBasisPoints != 0 || a.SpendLease != nil {
		return
	}
	if billingv1.RequireEligible(requested) != nil {
		return
	}
	t.V, t.TerminalKind = 1, "settle"
	// Validate all identity fields now as well as the completed envelope later.
	t.SelectedEndpoint = snapshot.Candidates()[0].EndpointID
	if billingv1.ValidateEnvelope(snapshot, t) != nil {
		return
	}
	a.async = &asyncAuthorization{snapshot: snapshot, raw: append(json.RawMessage(nil), a.BillingSnapshot...), ticket: a.SettlementTicket, terminal: t, expires: claims.Exp, requested: requested}
	asyncLog("async_negotiated", "")
}

func buildAsyncSettlement(a *asyncAuthorization, usage Usage) (asyncSettlementRequest, error) {
	var body asyncSettlementRequest
	if usage.UsageEstimated || usage.RouteType != a.terminal.RouteType || usage.Streamed != a.terminal.Streamed || usage.SelectedEndpoint == "" || (usage.FinishReason == "heartbeat_lost" || usage.FinishReason == "cap_reached") {
		return body, errors.New("incomplete_or_mismatched_usage")
	}
	observed := a.requested
	observed.RouteType, observed.Streamed = usage.RouteType, usage.Streamed
	observed.ToolCost = observed.ToolCost || usage.AdditionalCostMicrodollars != 0
	observed.PrivateTierBasis = usage.PriceTierInputTokens != 0
	if usage.ServiceTier != "" {
		observed.ServiceTier = &usage.ServiceTier
	}
	raw := billingv1.RawUsage{InputTokens: int64(usage.InputTokens), OutputTokens: int64(usage.OutputTokens), CacheReadTokens: int64(usage.CacheReadInputTokens), CacheCreationTokens: int64(usage.CacheCreationInputTokens), ReasoningTokens: int64(usage.ReasoningTokens)}
	evaluation, err := billingv1.Evaluate(a.snapshot, usage.SelectedEndpoint, raw, observed)
	if err != nil {
		return body, err
	}
	terminal := a.terminal
	terminal.SelectedEndpoint, terminal.Usage, terminal.ChargeMicro = usage.SelectedEndpoint, evaluation.Usage, evaluation.ChargeMicro
	if err := billingv1.ValidateEnvelope(a.snapshot, terminal); err != nil {
		return body, err
	}
	return asyncSettlementRequest{a.raw, a.ticket, raw, observed, terminal}, nil
}

func asyncLog(event, reason string) {
	fmt.Fprintf(os.Stderr, "enclave.async_settle event=%q reason=%q\n", event, reason)
}

// tryAsyncSettlement returns nil to enter the original synchronous body builder.
// It freezes bytes once, retains the original authority, and never changes an
// accepted amount. Refunds do not enter this function.
func (c *Client) tryAsyncSettlement(ctx context.Context, auth *Authorization, usage Usage) (accepted *SettleResult) {
	if !c.AsyncSettlementNegotiated(auth) {
		return nil
	}
	auth.async.attemptMu.Lock()
	defer auth.async.attemptMu.Unlock()
	if auth.async.attempted {
		return auth.async.accepted
	}
	auth.async.attempted = true
	defer func() { auth.async.accepted = accepted }()
	if time.Unix(auth.async.expires, 0).Sub(c.asyncNow()) < asyncTicketMargin {
		asyncLog("fallback", "ticket_expiry_margin")
		return nil
	}
	body, err := buildAsyncSettlement(auth.async, usage)
	if err != nil {
		asyncLog("fallback", "ineligible_usage")
		return nil
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	hash, err := billingv1.CanonicalHash(body.Terminal)
	if err != nil {
		return nil
	}
	endpoint := auth.pinnedControlPlaneEndpoint()
	if endpoint < 0 {
		asyncLog("fallback", "unpinned_authority")
		return nil
	}
	retryCtx, cancel := context.WithTimeout(context.WithValue(ctx, asyncModeKey{}, true), settlementRetryBudget)
	defer cancel()
	policy := normalizeRetryPolicy(retryPolicy{attempts: 3, baseDelay: 250 * time.Millisecond, maxDelay: time.Second})
	for attempt := 1; attempt <= policy.attempts; attempt++ {
		result, retry, reason := c.asyncSettlementAttempt(retryCtx, endpoint, raw, hash, body.Terminal.ChargeMicro, auth)
		if result != nil {
			return result
		}
		if !retry || attempt == policy.attempts || retryCtx.Err() != nil {
			asyncLog("fallback", reason)
			return nil
		}
		asyncLog("retry", reason)
		if policy.sleep(retryCtx, authorizationRetryDelay(attempt, policy, 0)) != nil {
			break
		}
	}
	asyncLog("fallback", "retry_exhausted")
	return nil
}

func (c *Client) asyncSettlementAttempt(ctx context.Context, endpoint int, raw []byte, hash string, charge int64, auth *Authorization) (*SettleResult, bool, string) {
	resp, _, err := c.postToControlPlane(ctx, "/internal/gateway/settle", raw, endpoint)
	if err != nil {
		return nil, true, "network"
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return nil, true, "unknown"
	}
	var reply struct {
		Data struct {
			Acceptance billingv1.AcceptanceOutcome `json:"acceptance"`
			Pending    *PendingSettlement          `json:"trusted_router_settlement"`
			Reason     string                      `json:"reason"`
		} `json:"data"`
		Error struct {
			Expected *int64 `json:"expected_cost_microdollars"`
			Claimed  *int64 `json:"claimed_cost_microdollars"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &reply) != nil {
		return nil, true, "unknown"
	}
	if resp.StatusCode == http.StatusConflict {
		if reply.Error.Expected != nil && reply.Error.Claimed != nil {
			fmt.Fprintf(os.Stderr, "enclave.async_settle event=amount_mismatch expected_cost_microdollars=%d claimed_cost_microdollars=%d\n", *reply.Error.Expected, *reply.Error.Claimed)
			return nil, false, "amount_mismatch"
		}
		asyncLog("conflict", "")
		return nil, false, "conflict"
	}
	a, p := reply.Data.Acceptance, reply.Data.Pending
	if resp.StatusCode == http.StatusOK && a.Status == "sync_required" {
		asyncLog("sync_required", asyncReason(reply.Data.Reason))
		return nil, false, "sync_required"
	}
	if resp.StatusCode == http.StatusAccepted && (a.Status == "accepted" || a.Status == "duplicate") && a.PayloadHash != nil && *a.PayloadHash == hash && a.SettlementStatus != nil && *a.SettlementStatus == "pending" && p != nil && p.wireComplete && p.V == 1 && p.SettlementStatus == "pending" && p.SettlementID == auth.AuthorizationID+".settle" && p.StatusURL == auth.SettlementStatusURL && p.PollAfterMS >= 0 {
		if p.CostMicrodollars != charge {
			fmt.Fprintf(os.Stderr, "enclave.async_settle event=amount_mismatch expected_cost_microdollars=%d claimed_cost_microdollars=%d\n", charge, p.CostMicrodollars)
			return nil, false, "amount_mismatch"
		}
		asyncLog(a.Status, "")
		return &SettleResult{TrustedRouterSettlement: p, CostMicrodollars: int(p.CostMicrodollars), CostMicrodollarsKnown: true}, false, ""
	}
	return nil, true, "unknown"
}

func asyncReason(reason string) string {
	switch reason {
	case "disabled", "not_eligible", "cap_exceeded", "ticket_expired", "unsupported_cohort", "admission_stale", "reservation_not_open", "drain_unhealthy":
		return reason
	default:
		return "unknown"
	}
}

// Malformed optional additions disable negotiation without changing legacy
// decoding (including structs that embed Authorization at the admission seam).
type AsyncEligibility bool
type BillingSnapshotDigest string

func (v *AsyncEligibility) UnmarshalJSON(raw []byte) error {
	var value bool
	_ = json.Unmarshal(raw, &value)
	*v = AsyncEligibility(value)
	return nil
}
func (v *BillingSnapshotDigest) UnmarshalJSON(raw []byte) error {
	var value string
	_ = json.Unmarshal(raw, &value)
	*v = BillingSnapshotDigest(value)
	return nil
}

// Preserve an explicit zero, but never report an absent/null amount as free.
func (p *PendingSettlement) UnmarshalJSON(raw []byte) error {
	type plain PendingSettlement
	var wire struct {
		plain
		Cost *int64 `json:"cost_microdollars"`
		Poll *int   `json:"poll_after_ms"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*p = PendingSettlement(wire.plain)
	if wire.Cost != nil && wire.Poll != nil {
		p.CostMicrodollars, p.PollAfterMS, p.wireComplete = *wire.Cost, *wire.Poll, true
	}
	return nil
}
