package spendlease

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const (
	grantActive int32 = iota
	grantExhausted
	grantExpired
	grantTerminal
	grantAdmissionDisabled
)

type grant struct {
	lease     VerifiedLease
	remaining atomic.Int64
	status    atomic.Int32
}

type slot struct {
	mu      sync.Mutex
	current atomic.Pointer[grant]
}

// ShadowState retains one grant per key_hash for this boot_kid. Registered is
// an explicit gate: registration failure leaves echo/signing enabled but all
// grant accounting dormant.
type ShadowState struct {
	verifier       *Verifier
	bootKID        string
	registered     atomic.Bool
	localAdmission atomic.Bool
	mu             sync.Mutex
	slots          map[string]*slot
	inFlight       map[string]struct{}
}

func NewShadowState(verifier *Verifier, bootKID string) *ShadowState {
	return &ShadowState{verifier: verifier, bootKID: bootKID, slots: make(map[string]*slot), inFlight: make(map[string]struct{})}
}

func (s *ShadowState) SetLocalAdmission(enabled bool) {
	if s != nil {
		s.localAdmission.Store(enabled)
	}
}

func (s *ShadowState) LocalAdmissionEnabled() bool {
	return s != nil && s.localAdmission.Load()
}

func (s *ShadowState) SetRegistered(registered bool) {
	if s != nil {
		s.registered.Store(registered)
	}
}

func (s *ShadowState) Registered() bool {
	return s != nil && s.registered.Load()
}

func (s *ShadowState) BeforeRequest(keyHash string, request EstimateRequest, now time.Time) Echo {
	if s == nil || !s.registered.Load() {
		return Echo{State: "dormant"}
	}
	entry := s.lookup(keyHash, false)
	if entry == nil {
		return Echo{State: "no-lease"}
	}
	current := entry.current.Load()
	if current == nil {
		return Echo{State: "no-lease"}
	}
	leaseID := current.lease.Claims.LeaseID
	catalogVersion := current.lease.Claims.Catalog.Version
	base := Echo{LeaseID: &leaseID, CatalogVersion: &catalogVersion}
	if !now.Before(current.lease.Deadline) {
		current.status.CompareAndSwap(grantActive, grantExpired)
	}
	status := current.status.Load()
	remaining := current.remaining.Load()
	base.RemainingMicro = &remaining
	if status != grantActive {
		base.State = stateName(status)
		would := false
		base.WouldAdmit = &would
		return base
	}
	estimate, err := Estimate(current.lease.Claims.Catalog, request)
	if err != nil || estimate == nil {
		base.State = "no-applicable-lease"
		would := false
		base.WouldAdmit = &would
		return base
	}
	base.EnclaveEstimateMicro = estimate
	// Consequential authoritative grants are decremented only by TryAdmit,
	// which also binds a receipt and an in-flight scope. A request that missed
	// any local Stage C precondition must take synchronous authorize without a
	// second, receipt-less decrement here.
	if current.lease.Claims.Authoritative && s.localAdmission.Load() {
		remaining = current.remaining.Load()
		base.RemainingMicro = int64Pointer(remaining)
		would := false
		base.WouldAdmit = &would
		switch {
		case remaining <= 0:
			current.status.CompareAndSwap(grantActive, grantExhausted)
			base.State = "exhausted"
		case remaining < *estimate:
			base.State = "insufficient"
		default:
			base.State = "active"
		}
		return base
	}
	for {
		remaining = current.remaining.Load()
		base.RemainingMicro = int64Pointer(remaining)
		if remaining <= 0 {
			current.status.CompareAndSwap(grantActive, grantExhausted)
			base.State = "exhausted"
			would := false
			base.WouldAdmit = &would
			return base
		}
		if remaining < *estimate {
			base.State = "insufficient"
			would := false
			base.WouldAdmit = &would
			return base
		}
		if current.remaining.CompareAndSwap(remaining, remaining-*estimate) {
			base.State = "active"
			would := true
			base.WouldAdmit = &would
			if remaining-*estimate == 0 {
				current.status.CompareAndSwap(grantActive, grantExhausted)
			}
			return base
		}
	}
}

// TryAdmit performs the Stage C consequential decrement. Every locally visible
// failure returns nil so the caller takes the unchanged synchronous authorize
// path. Once the CAS succeeds the decrement is deliberately never restored:
// rejection and version-skew paths are conservative by design.
func (s *ShadowState) TryAdmit(
	keyHash string,
	idempotencyKey string,
	routingPolicyHash string,
	request EstimateRequest,
	now time.Time,
	signer MessageSigner,
) (*Admission, error) {
	if s == nil || !s.localAdmission.Load() || !s.registered.Load() || signer == nil || signer.Kid() == "" || idempotencyKey == "" {
		return nil, nil
	}
	entry := s.lookup(keyHash, false)
	if entry == nil {
		return nil, nil
	}
	current := entry.current.Load()
	if current == nil {
		return nil, nil
	}
	claims := current.lease.Claims
	if !claims.Authoritative || !claims.LocalAdmissionAllowed || claims.BootKID != s.bootKID || claims.RoutingPolicyHash != routingPolicyHash ||
		now.UnixMilli() < claims.IssuedAt*1000 || !now.Before(current.lease.AdmitUntil) {
		return nil, nil
	}
	if current.status.Load() != grantActive {
		return nil, nil
	}
	estimate, err := Estimate(claims.Catalog, request)
	if err != nil || estimate == nil {
		return nil, err
	}
	idempotencyHash := IdempotencyKeyHash(idempotencyKey)
	scope := claims.WorkspaceID + "#" + claims.KeyHash + "#" + idempotencyHash
	if !s.claimScope(scope) {
		return nil, nil
	}
	release := func() { s.releaseScope(scope) }
	for {
		if current.status.Load() != grantActive {
			release()
			return nil, nil
		}
		remaining := current.remaining.Load()
		if remaining <= 0 {
			current.status.CompareAndSwap(grantActive, grantExhausted)
			release()
			return nil, nil
		}
		if remaining < *estimate {
			release()
			return nil, nil
		}
		remainingAfter := remaining - *estimate
		if !current.remaining.CompareAndSwap(remaining, remainingAfter) {
			continue
		}
		if remainingAfter == 0 {
			current.status.CompareAndSwap(grantActive, grantExhausted)
		}
		echoWouldAdmit := true
		echo := Echo{
			LeaseID: &claims.LeaseID, State: "active", RemainingMicro: int64Pointer(remaining),
			EnclaveEstimateMicro: int64Pointer(*estimate), CatalogVersion: &claims.Catalog.Version,
			WouldAdmit: &echoWouldAdmit,
		}
		receipt, signErr := SignAdmissionReceipt(signer, AdmissionReceiptClaims{
			Version: 1, LeaseID: claims.LeaseID, Generation: claims.Generation,
			KeyHash: claims.KeyHash, WorkspaceID: claims.WorkspaceID, BootKID: claims.BootKID,
			IdempotencyKeySHA256: idempotencyHash, RoutingPolicyHash: claims.RoutingPolicyHash,
			EnclaveEstimateMicro: *estimate, RemainingAfterMicro: remainingAfter,
			AdmittedAtMS: now.UnixMilli(),
		})
		if signErr != nil {
			release()
			return nil, signErr
		}
		return &Admission{
			Receipt: receipt, ReceiptHash: AdmissionReceiptHash(receipt), Scope: scope,
			Lease: current.lease, EstimateMicro: *estimate, RemainingAfterMicro: remainingAfter,
			Echo: echo, release: release,
		}, nil
	}
}

func (s *ShadowState) claimScope(scope string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.inFlight[scope]; exists {
		return false
	}
	s.inFlight[scope] = struct{}{}
	return true
}

func (s *ShadowState) releaseScope(scope string) {
	s.mu.Lock()
	delete(s.inFlight, scope)
	s.mu.Unlock()
}

// ObserveReserve folds authoritative ledger state into the enclave's upper
// bound. It never raises remaining, even if responses complete out of order.
func (s *ShadowState) ObserveReserve(keyHash, leaseID string, generation int64, ledgerRemaining *int64, reason string, marked bool) {
	if s == nil {
		return
	}
	entry := s.lookup(keyHash, false)
	if entry == nil {
		return
	}
	current := entry.current.Load()
	if current == nil || current.lease.Claims.LeaseID != leaseID || current.lease.Claims.Generation != generation {
		return
	}
	if !marked || reason == "not_accepting" || reason == "boot_not_accepted" {
		current.status.Store(grantAdmissionDisabled)
		return
	}
	if reason == "capacity" {
		current.remaining.Store(0)
		current.status.Store(grantExhausted)
		return
	}
	if ledgerRemaining == nil || *ledgerRemaining < 0 {
		return
	}
	for {
		local := current.remaining.Load()
		if *ledgerRemaining >= local || current.remaining.CompareAndSwap(local, *ledgerRemaining) {
			break
		}
	}
	if current.remaining.Load() == 0 {
		current.status.CompareAndSwap(grantActive, grantExhausted)
	}
}

func (s *ShadowState) HandleResponse(keyHash, workspaceID string, response *Response, receivedAt time.Time) error {
	if s == nil || response == nil || response.Token == nil || *response.Token == "" {
		return nil
	}
	if s.verifier == nil {
		return errors.New("spendlease: verifier is unavailable")
	}
	lease, err := s.verifier.VerifyForStateAt(*response.Token, receivedAt, s.localAdmission.Load())
	if err != nil {
		return err
	}
	if lease.Claims.KeyHash != keyHash || lease.Claims.BootKID != s.bootKID || (workspaceID != "" && lease.Claims.WorkspaceID != workspaceID) {
		return errors.New("spendlease: grant binding mismatch")
	}
	if !s.registered.Load() {
		return nil
	}
	entry := s.lookup(keyHash, true)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	current := entry.current.Load()
	switch response.LeaseStatus {
	case "terminal", "expired":
		if current != nil && current.lease.Claims.LeaseID == lease.Claims.LeaseID {
			if response.LeaseStatus == "terminal" {
				current.status.Store(grantTerminal)
			} else {
				current.status.Store(grantExpired)
			}
		}
		return nil
	case "active":
	default:
		return errors.New("spendlease: invalid lease_status")
	}
	if current != nil && grantAlive(current, receivedAt) {
		return nil
	}
	if current != nil && lease.Claims.Generation <= current.lease.Claims.Generation {
		return nil
	}
	next := &grant{lease: lease}
	next.remaining.Store(lease.Claims.CapMicro)
	next.status.Store(grantActive)
	entry.current.Store(next)
	return nil
}

func (s *ShadowState) lookup(keyHash string, create bool) *slot {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.slots[keyHash]
	if entry == nil && create {
		entry = &slot{}
		s.slots[keyHash] = entry
	}
	return entry
}

func grantAlive(g *grant, now time.Time) bool {
	if g.status.Load() != grantActive || g.remaining.Load() <= 0 {
		return false
	}
	if !now.Before(g.lease.Deadline) {
		g.status.CompareAndSwap(grantActive, grantExpired)
		return false
	}
	return true
}

func stateName(status int32) string {
	switch status {
	case grantExhausted:
		return "exhausted"
	case grantExpired:
		return "expired"
	case grantTerminal:
		return "terminal"
	case grantAdmissionDisabled:
		return "admission-disabled"
	default:
		return "active"
	}
}

func int64Pointer(value int64) *int64 { return &value }
