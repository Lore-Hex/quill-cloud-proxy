package shadowcoord

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
)

// Evidence is independently authenticated deployment configuration, never taken
// from a grant. RemoteKnown certifies the aggregate retained allocation, including
// other boots and previous incarnations of this stable slot. Absent facts miss.
type Evidence struct {
	Identity                                       Identity
	Local                                          speculation.LocalContext
	Health                                         speculation.LocalHealth
	ValidUntil                                     int64
	RemoteKnown                                    bool
	WorkspaceRetained, SlotRetained, FleetRetained int64
}
type Config struct {
	Keys                                 []speculation.TrustedKey
	Evidence                             []Evidence
	Plane, Region, RouterSHA, EnclaveSHA string
	ClockUncertainty                     time.Duration
}
type Clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type Refresh = shadowobserve.Refresh

type cached struct {
	historyDeadline time.Time
	verified        speculation.VerifiedGrant
	received        speculation.ReceivedGrant
	grantID         string
	permits         []permit
}
type permit struct{ ordinal, amount int64 }
type state struct {
	evidence         Evidence
	evidenceDeadline time.Time
	cached           cached
	lastMiss         *Miss
	hot              bool
	consumed         map[string]bool
	retained         int64
	unresolved       string
}
type Coordinator struct {
	dropped                     atomic.Uint64
	mu                          sync.Mutex
	config                      Config
	clock                       Clock
	origin                      time.Time
	entries                     map[Identity]*state
	order                       []Identity
	cursor                      int
	workspaceClosed             map[string]bool
	keyClosed                   map[string]bool
	infrastructureClosed        map[string]bool
	bootClosed                  bool
	workspaceBusy               map[string]string
	workspaceRetained           map[string]int64
	slotRetained, fleetRetained int64
	records                     chan Record
}

// New returns before allocation in off mode. There is no enforce constructor.
func New(mode Mode, config Config, clock Clock) *Coordinator {
	if mode != Shadow {
		return nil
	}
	if clock == nil {
		clock = realClock{}
	}
	// Freeze caller-owned maps/certificates before concurrent refresh and traffic.
	b, err := json.Marshal(config)
	if err != nil {
		config = Config{}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber()
		var frozen Config
		if decoder.Decode(&frozen) != nil {
			config = Config{}
		} else {
			config = frozen
		}
	}
	for i := range config.Evidence {
		e := &config.Evidence[i]
		e.Local.Bindings = normalize(e.Local.Bindings).(map[string]any)
		for j := range e.Local.Certificates {
			e.Local.Certificates[j].Route = normalize(e.Local.Certificates[j].Route).(map[string]any)
		}
	}
	c := &Coordinator{config: config, clock: clock, origin: clock.Now(), entries: make(map[Identity]*state), workspaceClosed: make(map[string]bool), keyClosed: make(map[string]bool), infrastructureClosed: make(map[string]bool), workspaceBusy: make(map[string]string), workspaceRetained: make(map[string]int64), records: make(chan Record, 512)}
	for _, e := range config.Evidence {
		if len(c.entries) >= MaxIdentities {
			break
		}
		if !e.Identity.Valid() {
			continue
		}
		c.entries[e.Identity] = &state{evidence: e, evidenceDeadline: c.origin.Add(time.Unix(e.ValidUntil, 0).Sub(c.origin)), consumed: make(map[string]bool)}
	}
	return c
}
func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		if n, err := x.Float64(); err == nil {
			return n
		}
		return nil
	case float64:
		if x == float64(int64(x)) {
			return int64(x)
		}
	case map[string]any:
		for k, v := range x {
			x[k] = normalize(v)
		}
	case []any:
		for i, v := range x {
			x[i] = normalize(v)
		}
	}
	return v
}
func ParseRequest(body []byte) map[string]any {
	var b map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if len(body) > 1<<20 || decoder.Decode(&b) != nil {
		return nil
	}
	return normalize(b).(map[string]any)
}
func (c *Coordinator) Dropped() uint64        { return c.dropped.Load() }
func (c *Coordinator) Records() <-chan Record { return c.records }
func (c *Coordinator) Mono() time.Duration    { return c.clock.Now().Sub(c.origin) }
func (c *Coordinator) Emit(r Record) {
	r.Dropped = c.dropped.Load()
	r.Plane = c.config.Plane
	r.Region = c.config.Region
	r.RouterSHA = c.config.RouterSHA
	r.EnclaveSHA = c.config.EnclaveSHA
	select {
	case c.records <- r:
	default:
		c.dropped.Add(1) // Sticky loss accounting never blocks ordinary execution.
	}
}

// ObserveAuthorized only learns identities from successful ordinary calls. No I/O.
func (c *Coordinator) ObserveAuthorized(id Identity) {
	if c == nil || !id.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.entries[id]
	if s == nil {
		if len(c.entries) >= MaxIdentities {
			return
		}
		s = &state{consumed: make(map[string]bool)}
		c.entries[id] = s
	}
	if !s.hot {
		s.hot = true
		c.order = append(c.order, id)
	}
}
func (c *Coordinator) batch() []Identity {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := min(MaxBatch, len(c.order))
	out := make([]Identity, 0, n)
	for range n {
		out = append(out, c.order[c.cursor%len(c.order)])
		c.cursor++
	}
	return out
}

// Run uses one bounded request per tick; a failure retries at the next >=10s
// tick, never inside the router's per-boot rate window and never on ingress.
func (c *Coordinator) Run(ctx context.Context, refresh Refresh) {
	if c == nil {
		return
	}
	for {
		timer := time.NewTimer(10*time.Second + time.Duration(rand.Int64N(int64(time.Second)))) // #nosec G404 -- scheduling jitter only.
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		c.RefreshOnce(ctx, refresh)
	}
}
func (c *Coordinator) RefreshOnce(ctx context.Context, refresh Refresh) {
	items := c.batch()
	if len(items) == 0 {
		return
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	results, batchMiss := refresh(call, items)
	c.mu.Lock()
	defer c.mu.Unlock()
	if batchMiss != nil {
		for _, id := range items {
			c.setMiss(id, batchMiss)
		}
		return
	}
	for _, r := range results {
		s := c.entries[r.Identity]
		if s == nil {
			continue
		}
		if r.Miss != nil {
			c.setMiss(r.Identity, r.Miss)
			continue
		}
		// An identical response never renews deadlines or allowances.
		if r.Grant == s.cached.verified.Compact() {
			continue
		}
		now := c.clock.Now()
		if !now.Before(s.evidenceDeadline) {
			c.setMiss(r.Identity, miss(200, "policy-stale"))
			continue
		}
		g, err := speculation.VerifyGrant(r.Grant, c.config.Keys, s.evidence.Local.Bindings, now.Unix(), true)
		if err != nil {
			c.setMiss(r.Identity, miss(200, "grant-invalid"))
			continue
		}
		received, reason := speculation.ReceiveGrant(g, now, speculation.Monotonic(now.Sub(c.origin)), c.config.ClockUncertainty)
		if reason != speculation.ReasonEligible {
			c.setMiss(r.Identity, miss(200, string(reason)))
			continue
		}
		claims, _ := g.Claims()
		if claims["lookup_digest"] != r.Identity.LookupDigest || claims["workspace_id"] != r.Identity.WorkspaceID || claims["key_id"] != r.Identity.KeyID {
			c.setMiss(r.Identity, miss(200, "grant-identity-mismatch"))
			continue
		}
		history := claims["history"].(map[string]any)
		next := cached{historyDeadline: now.Add(time.Unix(history["last_success_at"].(int64)+30, 0).Sub(now.Add(c.config.ClockUncertainty))), verified: g, received: received, grantID: claims["grant_id"].(string)}
		for _, p := range claims["permits"].([]any) {
			v := p.(map[string]any)
			next.permits = append(next.permits, permit{v["ordinal"].(int64), v["b_micro"].(int64)})
		}
		s.cached = next
		s.lastMiss = nil
	}
}
func (c *Coordinator) setMiss(id Identity, m *Miss) {
	s := c.entries[id]
	if s == nil {
		return
	}
	s.lastMiss = miss(m.Status, m.Code)
	s.cached = cached{}
	c.Emit(Record{Kind: "refresh_miss", ObservationID: newID(), Identity: &id, Miss: s.lastMiss})
}

// Decision is copied into the execution before authorize. Renewals and outcomes
// cannot mutate it; budgets are conservative retained simulation, never money.

type candidate struct {
	id       string
	identity Identity
	decision Decision
	route    Route
}

func (c *Coordinator) Predecision(lookup string, req speculation.ParsedRequest) *Execution {
	if c == nil {
		return nil
	}
	x := c.decide(lookup, req)
	x.decision.CompletedAt = c.Mono()
	return shadowobserve.NewExecution(c, x.id, x.decision, x.identity, x.route)
}
func (c *Coordinator) Excluded(lookup string) *Execution {
	return c.Predecision(lookup, speculation.ParsedRequest{})
}
func (c *Coordinator) Release(identity Identity, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.workspaceBusy[identity.WorkspaceID] == id {
		delete(c.workspaceBusy, identity.WorkspaceID)
	}
}
func (c *Coordinator) decide(lookup string, req speculation.ParsedRequest) *candidate {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	x := &candidate{id: newID()}
	x.decision = Decision{Reason: "grant_missing", At: c.Mono()}
	var s *state
	for id, v := range c.entries {
		if id.LookupDigest == lookup {
			if s != nil {
				x.decision.Reason = "identity-ambiguous"
				return x
			}
			s = v
			x.identity = id
		}
	}
	if s == nil {
		return x
	}
	if s.cached.verified.Compact() == "" {
		if s.lastMiss != nil {
			x.decision.Reason = s.lastMiss.Code
		}
		return x
	}
	x.decision.GrantID = s.cached.grantID
	health := s.evidence.Health
	if c.workspaceClosed[x.identity.WorkspaceID] {
		health.Workspace.Latched = true
	}
	if c.keyClosed[lookup] {
		health.Key.Latched = true
	}
	if c.bootClosed || c.infrastructureClosed[lookup] {
		health.InfrastructureHealthy = false
	}
	snapshot := speculation.EvaluateEligibility(s.cached.received, s.evidence.Local, req, health, speculation.Monotonic(c.Mono()))
	x.decision.Reason = string(snapshot.Shadow.Reason)
	if !snapshot.Shadow.Eligible {
		return x
	}
	if !c.clock.Now().Before(s.cached.historyDeadline) {
		x.decision.Reason = "history-stale"
		return x
	}
	e := s.evidence
	if p, ok := req.Body["provider"].(map[string]any); ok && len(p) != 1 {
		x.decision.Reason = "request-route-uncertain"
		return x
	}
	if len(e.Local.Certificates) != 1 || len(e.Local.Certificates[0].SystemPrefix) != 0 {
		x.decision.Reason = "payload-context-uncertain"
		return x
	}
	if !c.clock.Now().Before(s.evidenceDeadline) {
		x.decision.Reason = "policy_stale"
		return x
	}
	if !e.RemoteKnown || !c.clock.Now().Before(s.evidenceDeadline) || e.Local.Bindings["stable_slot_id"] == "" {
		x.decision.Reason = "allocation-unknown"
		return x
	}
	if c.workspaceBusy[x.identity.WorkspaceID] != "" {
		x.decision.Reason = "simulated-concurrency"
		return x
	}
	claims, _ := s.cached.verified.Claims()
	allowance, err := speculation.WorkspaceAllowance(e.Local.Bindings["tier_ceiling_micro"], claims["paid_headroom_micro"])
	if err != nil {
		x.decision.Reason = "allocation-unknown"
		return x
	}
	// Independent configuration may tighten, but never widen, the decided tier-2 $0.25 ceiling.
	if claims["tier"] == int64(2) {
		allowance = min(allowance, int64(250000))
	}
	for _, p := range s.cached.permits {
		key := permitKey(s.cached.grantID, p.ordinal)
		if s.consumed[key] {
			continue
		}
		if e.WorkspaceRetained < 0 || e.WorkspaceRetained > 1000000 || e.SlotRetained < 0 || e.SlotRetained > 1000000 || e.FleetRetained < 0 || e.FleetRetained > 10000000 || p.amount > allowance-e.WorkspaceRetained-c.workspaceRetained[x.identity.WorkspaceID] || p.amount > 1000000-e.SlotRetained-c.slotRetained || p.amount > 10000000-e.FleetRetained-c.fleetRetained {
			x.decision.Reason = "simulated-retained-budget"
			return x
		}
		// Bounded retained journal. Exhaustion fails closed; neither refresh nor a
		// billing-cache expiry releases unknown exposure.
		if len(s.consumed) >= 4096 {
			x.decision.Reason = "simulated-journal-capacity"
			return x
		}
		s.consumed[key] = true
		s.retained += p.amount
		c.workspaceRetained[x.identity.WorkspaceID] += p.amount
		c.slotRetained += p.amount
		c.fleetRetained += p.amount
		c.workspaceBusy[x.identity.WorkspaceID] = x.id
		s.unresolved = x.id
		ordinal := p.ordinal
		x.decision.Ordinal = &ordinal
		x.decision.Eligible = true
		x.decision.Reason = "eligible"
		route := claims["route"].(map[string]any)
		x.route = Route{Endpoint: route["endpoint_id"].(string), Provider: route["provider"].(string), Model: route["upstream_model"].(string)}
		return x
	}
	x.decision.Reason = "simulated-permits-exhausted"
	return x
}

func (c *Coordinator) ObserveVerdict(lookup string, status int, reason, rateScope string) {
	if c == nil || status < 400 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if status >= 500 {
		if lookup == "" || len(c.infrastructureClosed) >= MaxIdentities {
			c.bootClosed = true
		} else {
			c.infrastructureClosed[lookup] = true
		}
	}
	for id := range c.entries {
		if id.LookupDigest != lookup {
			continue
		}
		v, err := speculation.ClassifyVerdict(speculation.VerdictInput{Source: "authenticated_router", Status: status, Reason: reason, RateScope: rateScope, WorkspaceID: id.WorkspaceID, KeyID: id.KeyID})
		if err != nil {
			continue
		}
		if v.DurableScope == "workspace" {
			c.workspaceClosed[id.WorkspaceID] = true
		}
		if v.DurableScope == "key" {
			c.keyClosed[lookup] = true
		}
	}
}
func (c *Coordinator) Suppressed(original string) {
	if c == nil {
		return
	}
	c.Emit(Record{Kind: "billing_backoff_suppressed", ObservationID: newID(), OriginalDenialID: original, Applicability: "not-applicable"})
}

func permitKey(id string, ordinal int64) string { return id + ":" + strconv.FormatInt(ordinal, 10) }
