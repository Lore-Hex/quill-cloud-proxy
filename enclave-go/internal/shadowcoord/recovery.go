package shadowcoord

import "time"

// Epochs survive cache expiry and ownership cleanup. Only a verified higher
// epoch can repair a scoped latch; the issuer owns the actual repair checks.
type epochLatch struct {
	epoch int64
	event uint64
}

type breaker struct {
	failed, first, last time.Time
	event               uint64
	successes           int
	grant               bool
}

func (b breaker) recovered(now time.Time) bool {
	return b.grant && b.successes >= 3 && b.last.Sub(b.first) >= 30*time.Second && now.Sub(b.failed) >= 30*time.Second
}

// All recovery helpers run under mu. Events order refresh sends against denials
// even when the monotonic clock has not advanced between callbacks.
func (c *Coordinator) capacity(code string) {
	c.Emit(Record{Kind: "capacity", ObservationID: newID(), Miss: miss(0, code)})
}
func (c *Coordinator) invalidateCoverage(code string) {
	c.reconfirm = c.event
	c.Emit(Record{Kind: "coverage_invalidated", ObservationID: newID(), Miss: miss(0, code)})
}
func (c *Coordinator) latch(id Identity, lookup, scope string) {
	closed, latches, key := c.workspaceClosed, c.workspaceLatch, id.WorkspaceID
	if scope == "key" {
		closed, latches, key = c.keyClosed, c.keyLatch, lookup
	}
	if !closed[key] && len(closed) >= MaxIdentities {
		c.invalidateCoverage("health-capacity")
		c.capacity("health-capacity")
		return
	}
	epoch := latches[key].epoch
	for identity, s := range c.entries {
		if scope == "workspace" && identity.WorkspaceID == id.WorkspaceID {
			epoch = max(epoch, s.evidence.Health.Workspace.Epoch)
		}
		if scope == "key" && identity.LookupDigest == lookup {
			epoch = max(epoch, s.evidence.Health.Key.Epoch)
		}
	}
	closed[key] = true
	latches[key] = epochLatch{epoch: epoch, event: c.event}
}
func (c *Coordinator) failInfrastructure(lookup string) {
	b := breaker{failed: c.clock.Now(), event: c.event}
	if lookup == "" || !c.infrastructureClosed[lookup] && len(c.infrastructureClosed) >= MaxIdentities {
		c.bootClosed = true
		c.bootBreaker = b
		if lookup != "" {
			c.capacity("infrastructure-capacity")
		}
		return
	}
	c.infrastructureClosed[lookup] = true
	c.breakers[lookup] = b
}
func (c *Coordinator) ordinarySuccess(id Identity, started uint64) {
	now := c.clock.Now()
	advance := func(b breaker) breaker {
		if started < b.event {
			return b
		}
		if b.successes == 0 {
			b.first = now
		}
		b.successes = min(3, b.successes+1)
		b.last = now
		return b
	}
	if c.infrastructureClosed[id.LookupDigest] {
		c.breakers[id.LookupDigest] = advance(c.breakers[id.LookupDigest])
	}
	if c.bootClosed {
		c.bootBreaker = advance(c.bootBreaker)
	}
	c.reopenInfrastructure(id.LookupDigest, now)
}
func (c *Coordinator) reopenInfrastructure(lookup string, now time.Time) {
	if c.infrastructureClosed[lookup] && c.breakers[lookup].recovered(now) {
		delete(c.infrastructureClosed, lookup)
		delete(c.breakers, lookup)
		c.revision++
	}
	if c.bootClosed && c.bootBreaker.recovered(now) {
		c.bootClosed = false
		c.bootBreaker = breaker{}
		c.revision++
	}
}
func (c *Coordinator) recoverGrant(id Identity, s *state, claims map[string]any, sent, receivedEvent uint64) {
	if sent > c.reconfirm {
		s.confirmed = c.reconfirm
	}
	workspaceEpoch, _ := claimInteger(claims["workspace_epoch"])
	keyEpoch, _ := claimInteger(claims["key_epoch"])
	if c.workspaceClosed[id.WorkspaceID] && workspaceEpoch > c.workspaceLatch[id.WorkspaceID].epoch && receivedEvent > c.workspaceLatch[id.WorkspaceID].event {
		delete(c.workspaceClosed, id.WorkspaceID)
		delete(c.workspaceLatch, id.WorkspaceID)
	}
	if c.keyClosed[id.LookupDigest] && keyEpoch > c.keyLatch[id.LookupDigest].epoch && receivedEvent > c.keyLatch[id.LookupDigest].event {
		delete(c.keyClosed, id.LookupDigest)
		delete(c.keyLatch, id.LookupDigest)
	}
	// Keep other cached keys on an older workspace epoch ineligible as well.
	for identity, entry := range c.entries {
		if identity.WorkspaceID == id.WorkspaceID {
			entry.evidence.Health.Workspace.Epoch = max(entry.evidence.Health.Workspace.Epoch, workspaceEpoch)
			updateEpochBindings(entry)
		}
	}
	s.evidence.Health.Key.Epoch = max(s.evidence.Health.Key.Epoch, keyEpoch)
	updateEpochBindings(s)
	if c.infrastructureClosed[id.LookupDigest] {
		b := c.breakers[id.LookupDigest]
		b.grant = b.grant || receivedEvent > b.event
		c.breakers[id.LookupDigest] = b
	}
	if c.bootClosed {
		c.bootBreaker.grant = c.bootBreaker.grant || receivedEvent > c.bootBreaker.event
	}
	c.reopenInfrastructure(id.LookupDigest, c.clock.Now())
}

// Retained unknown loss has no local expiry. Only entries with no retained
// liability or active owner can be evicted, after both grant and policy expire.
// Receipt journals then cannot revive an old grant: the policy must be replaced.
func (c *Coordinator) evictExpired() bool {
	now := c.clock.Now()
	for id, s := range c.entries {
		if s.retained != 0 || c.workspaceBusy[id.WorkspaceID] != "" || now.Before(s.evidenceDeadline) || s.cached.verified.Compact() != "" && c.Mono() < s.cached.startDeadline {
			continue
		}
		delete(c.entries, id)
		delete(c.byLookup, id.LookupDigest)
		for other := range c.entries {
			if other.LookupDigest == id.LookupDigest {
				c.index(other)
			}
		}
		for i, hot := range c.order {
			if hot == id {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		c.cursor = 0
		c.revision++
		c.capacity("identity-evicted")
		return true
	}
	return false
}

// Snapshots share immutable binding maps; never mutate one in place.
func updateEpochBindings(s *state) {
	next := make(map[string]any, len(s.evidence.Local.Bindings))
	for k, v := range s.evidence.Local.Bindings {
		next[k] = v
	}
	next["workspace_epoch"] = s.evidence.Health.Workspace.Epoch
	next["key_epoch"] = s.evidence.Health.Key.Epoch
	s.evidence.Local.Bindings = next
}
