package trustedrouter

import (
	"context"
	"crypto/ed25519"
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
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const asyncSettlementHeader = "X-TR-Settlement-Mode"
const asyncTicketMargin = 30 * time.Second // covers the existing 28 second retry budget

type asyncModeKey struct{}
type asyncAuthorization struct {
	attemptMu  sync.Mutex
	attempted  bool
	accepted   *SettleResult
	frozen     []byte
	hash       string
	charge     int64
	legacy     bool
	ineligible bool
	snapshot   billingv1.Snapshot
	raw        json.RawMessage
	ticket     string
	terminal   billingv1.TerminalEnvelope
	expires    int64
	requested  billingv1.Eligibility
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
	raw, err := receipt.VerifyCompactJWS(a.SettlementTicket, c.asyncTicketKeys, "tr-async-settle-v1")
	if err != nil {
		return
	}
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

// tryAsyncSettlement keeps every recovery on the frozen body and authority.
// nil, nil means the legacy path is permitted (unbound/ineligible or hard failure).
func (c *Client) tryAsyncSettlement(ctx context.Context, auth *Authorization, usage Usage) (*SettleResult, error) {
	if !c.AsyncSettlementNegotiated(auth) {
		return nil, nil
	}
	a := auth.async
	a.attemptMu.Lock()
	defer a.attemptMu.Unlock()
	if a.ineligible {
		return nil, nil
	}
	if a.accepted != nil {
		return a.accepted, nil
	}
	if a.legacy {
		asyncLog("legacy_fallback", "snapshot_sync_hard_failure")
		return nil, nil
	}
	first := !a.attempted
	if first {
		body, err := buildAsyncSettlement(a, usage)
		if err != nil {
			a.ineligible = true
			asyncLog("fallback", "ineligible_usage")
			return nil, nil
		}
		a.frozen, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
		a.hash, err = billingv1.CanonicalHash(body.Terminal)
		if err != nil {
			return nil, err
		}
		a.charge = body.Terminal.ChargeMicro
		a.attempted = true
	}
	endpoint := auth.pinnedControlPlaneEndpoint()
	if endpoint < 0 {
		return nil, errors.New("async settlement: unpinned authority")
	}
	raw, hash := a.frozen, a.hash
	retryCtx, cancel := context.WithTimeout(context.WithValue(ctx, asyncModeKey{}, "async-v1"), settlementRetryBudget)
	defer cancel()
	policy := normalizeRetryPolicy(retryPolicy{attempts: 3, baseDelay: 250 * time.Millisecond, maxDelay: time.Second})
	reason := "ticket_expiry_margin"
	if first && time.Unix(a.expires, 0).Sub(c.asyncNow()) >= asyncTicketMargin {
		for attempt := 1; attempt <= policy.attempts; attempt++ {
			result, retry, why := c.asyncSettlementAttempt(retryCtx, endpoint, raw, hash, a.charge, auth)
			reason = why
			if result != nil {
				a.accepted = result
				return result, nil
			}
			if !retry || attempt == policy.attempts || retryCtx.Err() != nil {
				break
			}
			asyncLog("retry", reason)
			if policy.sleep(retryCtx, authorizationRetryDelay(attempt, policy, 0)) != nil {
				break
			}
		}
	}
	asyncLog("fallback", reason)
	result, hard, err := c.snapshotSyncSettlement(retryCtx, endpoint, raw, hash, a.charge, auth)
	if hard {
		a.legacy = true
		asyncLog("legacy_fallback", "snapshot_sync_"+err.Error())
		return nil, nil
	}
	if err == nil {
		a.accepted = result
	}
	return result, err
}

func (c *Client) snapshotSyncSettlement(ctx context.Context, endpoint int, raw []byte, hash string, charge int64, auth *Authorization) (*SettleResult, bool, error) {
	ctx = context.WithValue(ctx, asyncModeKey{}, "sync")
	policy := normalizeRetryPolicy(retryPolicy{attempts: 3, baseDelay: 250 * time.Millisecond, maxDelay: time.Second})
	for attempt := 1; attempt <= policy.attempts; attempt++ {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		result, hard, err := c.snapshotSyncAttempt(ctx, endpoint, raw, hash, charge, auth)
		if !hard || attempt == policy.attempts {
			return result, hard, err
		}
		if policy.sleep(ctx, authorizationRetryDelay(attempt, policy, 0)) != nil {
			return nil, false, ctx.Err()
		}
	}
	return nil, false, errors.New("snapshot sync retry exhausted")
}

func (c *Client) snapshotSyncAttempt(ctx context.Context, endpoint int, raw []byte, hash string, charge int64, auth *Authorization) (*SettleResult, bool, error) {
	resp, _, err := c.postToControlPlane(ctx, "/internal/gateway/settle", raw, endpoint)
	if err != nil {
		return nil, ctx.Err() == nil, errors.New("network")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, true, errors.New("server_error")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return nil, true, errors.New("network")
	}
	if resp.StatusCode != http.StatusOK || len(data) > 65536 {
		return nil, false, errors.New("snapshot sync rejected")
	}
	// Decode the ordinary settle shape separately: SettleResult's UnmarshalJSON
	// must not swallow the adjacent acceptance/finalization fields.
	var standard struct {
		Data SettleResult `json:"data"`
	}
	if json.Unmarshal(data, &standard) != nil {
		return nil, false, errors.New("snapshot sync invalid result")
	}
	var final struct {
		Data struct {
			Acceptance billingv1.AcceptanceOutcome `json:"acceptance"`
			Final      *struct {
				V      int    `json:"v"`
				ID     string `json:"settlement_id"`
				Status string `json:"settlement_status"`
				Cost   *int64 `json:"cost_microdollars"`
				URL    string `json:"status_url"`
			} `json:"trusted_router_settlement"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &final) != nil {
		return nil, false, errors.New("snapshot sync invalid result")
	}
	result := &standard.Data
	if f := final.Data.Final; f != nil {
		a := final.Data.Acceptance
		if f.V != 1 || f.ID != auth.AuthorizationID+".settle" || f.URL != auth.SettlementStatusURL || f.Cost == nil || (f.Status != "settled" && f.Status != "refunded") || a.Status != "duplicate" || a.PayloadHash == nil || *a.PayloadHash != hash || a.SettlementStatus == nil || *a.SettlementStatus != f.Status {
			return nil, false, errors.New("snapshot sync invalid finalization")
		}
		result = &SettleResult{Settled: f.Status == "settled", AlreadySettled: true, FinalizationOutcome: f.Status, CostMicrodollars: int(*f.Cost), CostMicrodollarsKnown: true}
	}
	if (!result.Settled && !result.AlreadySettled) || !result.HasCost() {
		return nil, false, errors.New("snapshot sync incomplete result")
	}
	logAsyncAmount(charge, result)
	return result, false, nil
}

func logAsyncAmount(expected int64, result *SettleResult) {
	if result != nil && result.HasCost() && int64(result.CostMicrodollars) != expected {
		fmt.Fprintf(os.Stderr, "enclave.async_settle event=amount_mismatch expected_cost_microdollars=%d claimed_cost_microdollars=%d\n", expected, result.CostMicrodollars)
	}
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

// Configuration is a JSON object mapping exact kids to unpadded base64url keys.
// An absent, empty, or malformed keyring fails closed.
func asyncPublicKeys(boot *qtypes.BootstrapData) map[string]ed25519.PublicKey {
	raw, exists := os.LookupEnv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS")
	if !exists && boot != nil {
		raw = boot.AsyncSettleTicketPublicKeys
	}
	var configured map[string]string
	if json.Unmarshal([]byte(raw), &configured) != nil {
		return nil
	}
	keys := make(map[string]ed25519.PublicKey, len(configured))
	for kid, encoded := range configured {
		key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if kid == "" || err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != encoded {
			return nil
		}
		keys[kid] = ed25519.PublicKey(key)
	}
	return keys
}
