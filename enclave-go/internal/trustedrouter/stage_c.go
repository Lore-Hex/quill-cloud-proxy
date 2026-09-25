package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type SpendLeaseAdmissionPlan struct {
	admission  *spendlease.Admission
	lookupHash string
	routeType  string
	Local      *Authorization
	// Private snapshots and registry identity never come from caller receipts.
	owner   *authorizationInvocation
	client  *Client
	key     string
	body    []byte
	frozen  *Authorization
	entered bool // guarded by owner.mu; retained after Release/Cancel
}

func (p *SpendLeaseAdmissionPlan) ReceiptHash() string {
	if p == nil || p.admission == nil {
		return ""
	}
	return p.admission.ReceiptHash
}

func (p *SpendLeaseAdmissionPlan) Cancel() {
	if p != nil && p.admission != nil {
		if p.owner != nil {
			p.owner.mu.Lock()
			p.entered = true
			p.owner.mu.Unlock()
		}
		p.admission.Release()
	}
}

// PrepareSpendLeaseAdmission performs only enclave-local checks. A nil plan is
// an ordinary eligibility miss and tells the caller to use synchronous
// authorize before starting any provider work.
func (c *Client) PrepareSpendLeaseAdmission(
	ctx context.Context,
	bearer string,
	req *qtypes.OpenAIChatRequest,
	routeType string,
	now time.Time,
) (*SpendLeaseAdmissionPlan, error) {
	// Confidential requests require the synchronous endpoint privacy filter,
	// even if a future local routing snapshot supports more provider options.
	if ConfidentialOnly(ctx) {
		if req == nil {
			return nil, ValidateConfidentialRouting(nil)
		}
		if err := ValidateConfidentialRouting(req.Provider); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if c == nil || c.spendLease == nil || c.spendLease.state == nil || !c.spendLease.state.LocalAdmissionEnabled() || req == nil {
		return nil, nil
	}
	if reason := admissionWireMissReason(req); reason != "" {
		fmt.Fprintf(os.Stderr, "spend_lease.admission_local_declined reason=%q\n", reason)
		return nil, nil
	}
	// Without an explicit shared scope, keep the ordinary synchronous path.
	owner := explicitAuthorizationInvocation(ctx)
	if owner == nil {
		return nil, nil
	}
	policyHash, eligible := routingPolicyHash(req, routeType, c.region)
	if !eligible {
		return nil, nil
	}
	idempotencyKey, err := authorizationIdempotencyKey(req.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if _, used := owner.claimed[idempotencyKey]; used || owner.plans[idempotencyKey] != nil {
		return nil, idempotencyReplayConflict()
	}
	req.IdempotencyKey = idempotencyKey
	lookupHash := requestLookupHash(ctx, bearer)
	estimateRequest := spendLeaseRequestForChat(c.region, routeType, req)
	admission, err := c.spendLease.state.TryAdmit(
		lookupHash, idempotencyKey, policyHash, estimateRequest, now, c.spendLease.signer,
	)
	if err != nil {
		// Receipt construction is an optimization precondition, never request
		// authority. A local estimator or signer failure therefore takes the
		// unchanged synchronous path; any completed CAS remains conservatively
		// spent in the enclave's upper bound.
		fmt.Fprintf(os.Stderr, "spend_lease.admission_local_declined reason=%q\n", err.Error())
		return nil, nil
	}
	if admission == nil {
		return nil, nil
	}
	if c.credentialGuard != nil {
		if err := c.credentialGuard.BeforeCredentialCheck(ctx, lookupHash); err != nil {
			admission.Release()
			return nil, err
		}
	}
	local, ok := localAuthorization(admission, estimateRequest)
	if !ok {
		admission.Release()
		return nil, nil
	}
	body, err := json.Marshal(admissionAuthorizeBody(c, lookupHash,
		chatAuthorizeBody(c, lookupHash, idempotencyKey, req, routeType), admission))
	if err != nil {
		admission.Release()
		return nil, err
	}
	frozen := *local
	frozen.RouteCandidates = append([]RouteCandidate(nil), local.RouteCandidates...)
	plan := &SpendLeaseAdmissionPlan{
		admission: admission, lookupHash: lookupHash, routeType: routeType, Local: local,
		owner: owner, client: c, key: idempotencyKey, body: body, frozen: &frozen,
	}
	if owner.plans == nil {
		owner.plans = make(map[string]*SpendLeaseAdmissionPlan)
	}
	owner.plans[idempotencyKey] = plan
	return plan, nil
}

func localAuthorization(admission *spendlease.Admission, request spendlease.EstimateRequest) (*Authorization, bool) {
	if admission == nil || len(admission.Lease.Claims.Catalog.Candidates) == 0 {
		return nil, false
	}
	claims := admission.Lease.Claims
	candidates := make([]RouteCandidate, 0, len(claims.Catalog.Candidates))
	seenEndpoints := make(map[string]struct{})
	for _, candidate := range claims.Catalog.Candidates {
		if candidate.Model != request.Model || candidate.RouteType != request.RouteType ||
			candidate.Region != request.Region || candidate.ServiceTier != request.ServiceTier ||
			(candidate.PriceTierMaxInputTokens != nil && request.EstimatedInputTokens > *candidate.PriceTierMaxInputTokens) ||
			!providerAllowed(candidate.Provider, request.ProviderConstraints) {
			continue
		}
		if candidate.UsageType != "Credits" || candidate.UpstreamModel == "" || candidate.Provider == "" || candidate.EndpointID == "" {
			return nil, false
		}
		if _, duplicate := seenEndpoints[candidate.EndpointID]; duplicate {
			continue
		}
		seenEndpoints[candidate.EndpointID] = struct{}{}
		candidates = append(candidates, RouteCandidate{
			EndpointID: candidate.EndpointID, Model: candidate.Model, UpstreamModel: candidate.UpstreamModel,
			Provider: candidate.Provider, ProviderName: candidate.Provider, UsageType: candidate.UsageType,
			WaferZDRRequired: candidate.WaferZDRRequired,
		})
	}
	if len(candidates) == 0 {
		return nil, false
	}
	first := candidates[0]
	return &Authorization{
		WorkspaceID: claims.WorkspaceID, APIKeyHash: claims.KeyHash,
		Model: first.Model, UpstreamModel: first.UpstreamModel, EndpointID: first.EndpointID,
		Provider: first.Provider, ProviderName: first.ProviderName, UsageType: first.UsageType,
		Region: request.Region, RequestedModel: request.Model,
		LimitUsageType: "Credits", WaferZDRRequired: first.WaferZDRRequired,
		RouteCandidates: candidates, RouteType: request.RouteType,
	}, true
}

func providerAllowed(provider string, constraints []string) bool {
	if len(constraints) == 0 {
		return true
	}
	for _, constraint := range constraints {
		if provider == constraint {
			return true
		}
	}
	return false
}

// ReserveSpendLeaseAdmission sends the receipt-bearing authorize using the
// ordinary byte-stable retry transport. marked=false with nil error is the
// pre-Stage-C version-skew case: the returned ordinary authorization is valid,
// but the speculative provider must be cancelled and re-dispatched from it.
func (c *Client) ReserveSpendLeaseAdmission(
	ctx context.Context,
	plan *SpendLeaseAdmissionPlan,
	req *qtypes.OpenAIChatRequest,
) (authorization *Authorization, marked bool, err error) {
	if c == nil || plan == nil || plan.admission == nil || req == nil {
		return nil, false, errors.New("trustedrouter: invalid spend-lease admission plan")
	}
	if !plan.enterReserve(ctx, c, req.IdempotencyKey) {
		return nil, false, idempotencyReplayConflict()
	}
	defer plan.admission.Release()
	reserveCtx := ctx
	cancel := func() {}
	if deadline := plan.admission.Lease.Deadline; !deadline.IsZero() {
		reserveCtx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()
	decoded, endpoint, err := c.authorizeAtDecodeSeamWithAdmission(
		reserveCtx, plan.lookupHash, nil, spendlease.EstimateRequest{}, plan,
	)
	if err != nil {
		reason := admissionRejectionReason(err)
		c.spendLease.state.ObserveReserve(
			plan.lookupHash, plan.admission.Lease.Claims.LeaseID, plan.admission.Lease.Claims.Generation,
			nil, reason, true,
		)
		c.afterCredentialCheck(ctx, plan.lookupHash, err)
		fmt.Fprintf(os.Stderr, "spend_lease.admission_aborted lease_id=%q reason=%q\n", plan.admission.Lease.Claims.LeaseID, reason)
		return nil, false, err
	}
	c.afterCredentialCheck(ctx, plan.lookupHash, nil)
	decoded.pinControlPlaneEndpoint(endpoint)
	decoded.RouteType = plan.routeType
	marker := decoded.SpendLeaseAdmission
	if marker == nil {
		c.spendLease.state.ObserveReserve(
			plan.lookupHash, plan.admission.Lease.Claims.LeaseID, plan.admission.Lease.Claims.Generation,
			decoded.SpendLeaseRemainingMicro, "", false,
		)
		fmt.Fprintf(os.Stderr, "spend_lease.admission_unmarked lease_id=%q authorization_id=%q\n", plan.admission.Lease.Claims.LeaseID, decoded.AuthorizationID)
		return decoded, false, nil
	}
	c.spendLease.state.ObserveReserve(
		plan.lookupHash, plan.admission.Lease.Claims.LeaseID, plan.admission.Lease.Claims.Generation,
		decoded.SpendLeaseRemainingMicro, "", true,
	)
	return decoded, true, nil
}

// admissionAuthorizationMatches prevents a marker-bearing but internally
// inconsistent response from opening the first-byte gate for a provider route
// that the returned authorization cannot settle. Display-only provider names
// are intentionally excluded; every dispatch- and billing-relevant field is
// bound to the signed lease snapshot.
func admissionAuthorizationMatches(local, reserved *Authorization) bool {
	if local == nil || reserved == nil || reserved.WorkspaceID != local.WorkspaceID ||
		reserved.APIKeyHash != local.APIKeyHash || reserved.Model != local.Model ||
		reserved.UpstreamModel != local.UpstreamModel || reserved.EndpointID != local.EndpointID ||
		reserved.Provider != local.Provider || reserved.UsageType != "Credits" ||
		reserved.Region != local.Region || reserved.RequestedModel != local.RequestedModel ||
		reserved.ResponseModel != "" || reserved.HidePublicMetadata || reserved.CustomModel != nil ||
		reserved.AdditionalCostReservationMicrodollars != 0 || reserved.ReceiptFeeBasisPoints != 0 ||
		reserved.BYOKSecretRef != "" || reserved.BYOKEncryptedSecret != nil || reserved.BYOKCacheKey != "" || reserved.BYOKProvider != "" ||
		reserved.LimitUsageType != "Credits" || reserved.WaferZDRRequired != local.WaferZDRRequired ||
		len(reserved.RouteCandidates) != len(local.RouteCandidates) {
		return false
	}
	for index := range local.RouteCandidates {
		want := local.RouteCandidates[index]
		got := reserved.RouteCandidates[index]
		if got.EndpointID != want.EndpointID || got.Model != want.Model || got.UpstreamModel != want.UpstreamModel ||
			got.Provider != want.Provider || got.UsageType != want.UsageType ||
			got.WaferZDRRequired != want.WaferZDRRequired ||
			got.BYOKSecretRef != "" || got.BYOKEncryptedSecret != nil || got.BYOKCacheKey != "" || got.BYOKProvider != "" {
			return false
		}
	}
	return true
}

func admissionRejectionReason(err error) string {
	var controlErr *ControlPlaneError
	if errors.As(err, &controlErr) && controlErr.Type == "admission_rejected" && controlErr.Reason != "" {
		return controlErr.Reason
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "reserve_timeout"
	}
	return "reserve_error"
}

// enterReserve rejects copied/rebound plans and repeated operations before I/O.
// The registry and tombstone outlive the admission's in-flight scope.
func (p *SpendLeaseAdmissionPlan) enterReserve(ctx context.Context, client *Client, key string) bool {
	owner := explicitAuthorizationInvocation(ctx)
	if owner == nil || owner != p.owner || client != p.client || key != p.key {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	_, claimed := owner.claimed[p.key]
	if owner.plans[p.key] != p || p.entered || claimed {
		return false
	}
	p.entered = true
	return true
}

func (p *SpendLeaseAdmissionPlan) validateAcceptance(a *Authorization) error {
	marker := a.SpendLeaseAdmission
	if marker == nil || !marker.Accepted || marker.ReceiptHash != p.admission.ReceiptHash || a.AuthorizationID == "" ||
		a.SpendLeaseRemainingMicro == nil || *a.SpendLeaseRemainingMicro < 0 ||
		*a.SpendLeaseRemainingMicro > p.admission.Lease.Claims.CapMicro ||
		!admissionAuthorizationMatches(p.frozen, a) {
		return invalidAdmissionResponse()
	}
	return nil
}

func invalidAdmissionResponse() error {
	return &ControlPlaneError{
		Path: spendlease.AuthorizePath, StatusCode: 502, Type: "admission_rejected", Reason: "receipt_invalid",
		Message: "invalid spend-lease admission response",
	}
}
