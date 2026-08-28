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
	verifier   *Verifier
	bootKID    string
	registered atomic.Bool
	mu         sync.Mutex
	slots      map[string]*slot
}

func NewShadowState(verifier *Verifier, bootKID string) *ShadowState {
	return &ShadowState{verifier: verifier, bootKID: bootKID, slots: make(map[string]*slot)}
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

func (s *ShadowState) HandleResponse(keyHash, workspaceID string, response *Response, receivedAt time.Time) error {
	if s == nil || response == nil || response.Token == nil || *response.Token == "" {
		return nil
	}
	if s.verifier == nil {
		return errors.New("spendlease: verifier is unavailable")
	}
	lease, err := s.verifier.VerifyShadowAt(*response.Token, receivedAt)
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
	default:
		return "active"
	}
}

func int64Pointer(value int64) *int64 { return &value }
