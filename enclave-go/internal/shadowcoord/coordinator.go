package shadowcoord

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	startDeadline   time.Duration
	verified        speculation.VerifiedGrant
	received        speculation.ReceivedGrant
	grantID         string
	permits         []permit
}
type permit struct{ ordinal, amount int64 }
type grantReceipt struct {
	wall time.Time
	mono speculation.Monotonic
}
type lookupEntry struct {
	identity  Identity
	ambiguous bool
}

const MaxUnresolved = 32
const MaxSimulatedMemory = 8 << 20

// Reserve the 64 KiB spool plus 64 KiB parser/frame state before admission.
const InvocationMemory = 128 << 10

type state struct {
	confirmed        uint64
	receipts         map[[32]byte]grantReceipt
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
	refreshMu sync.Mutex
	shadowobserve.Boundary
	byLookup                    map[string]lookupEntry
	revision                    uint64
	unresolved                  int
	memory                      int
	emitMu                      sync.Mutex
	emitWindow                  time.Time
	emitCount                   int
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
	event                       uint64
	reconfirm                   uint64
	workspaceLatch              map[string]epochLatch
	keyLatch                    map[string]epochLatch
	breakers                    map[string]breaker
	bootBreaker                 breaker
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
	c := &Coordinator{workspaceLatch: make(map[string]epochLatch), keyLatch: make(map[string]epochLatch), breakers: make(map[string]breaker), config: config, clock: clock, origin: clock.Now(), entries: make(map[Identity]*state), byLookup: make(map[string]lookupEntry), workspaceClosed: make(map[string]bool), keyClosed: make(map[string]bool), infrastructureClosed: make(map[string]bool), workspaceBusy: make(map[string]string), workspaceRetained: make(map[string]int64), records: make(chan Record, 512)}
	for _, e := range config.Evidence {
		if len(c.entries) >= MaxIdentities {
			c.capacity("identity-capacity")
			break
		}
		if !e.Identity.Valid() {
			continue
		}
		c.index(e.Identity)
		c.entries[e.Identity] = &state{evidence: e, evidenceDeadline: c.origin.Add(time.Unix(e.ValidUntil, 0).Sub(c.origin)), consumed: make(map[string]bool), receipts: make(map[[32]byte]grantReceipt)}
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
func (c *Coordinator) index(id Identity) {
	c.revision++
	old, exists := c.byLookup[id.LookupDigest]
	c.byLookup[id.LookupDigest] = lookupEntry{id, old.ambiguous || exists && old.identity != id}
}
func ParseRequest(body []byte) map[string]any {
	if speculation.CheckInputLength(len(body)) != speculation.ReasonEligible || !InputDepthOK(body) {
		return nil
	}
	var b map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&b) != nil {
		return nil
	}
	return normalize(b).(map[string]any)
}
func (c *Coordinator) Dropped() uint64        { return c.dropped.Load() + c.Failures() }
func (c *Coordinator) Records() <-chan Record { return c.records }
func (c *Coordinator) Mono() time.Duration    { return c.clock.Now().Sub(c.origin) }

// Emit admits at most 100 records per second (200 across a window boundary).
// Every later admitted record carries cumulative queue/rate/fault loss.
func (c *Coordinator) Emit(r Record) {
	now := c.clock.Now()
	c.emitMu.Lock()
	if c.emitWindow.IsZero() || now.Sub(c.emitWindow) >= time.Second {
		c.emitWindow = now
		c.emitCount = 0
	}
	if c.emitCount >= 100 {
		c.dropped.Add(1)
		c.emitMu.Unlock()
		return
	}
	c.emitCount++
	c.emitMu.Unlock()
	r.Dropped = c.dropped.Load() + c.Failures()
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
	c.ObserveAuthorizedSince(id, c.ObservationVersion())
}

func (c *Coordinator) ObservationVersion() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.event
}
func (c *Coordinator) ObserveAuthorizedSince(id Identity, started uint64) {
	if c == nil || !id.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ordinarySuccess(id, started)
	s := c.entries[id]
	if s == nil {
		if len(c.entries) >= MaxIdentities && !c.evictExpired() {
			c.capacity("identity-capacity")
			return
		}
		s = &state{consumed: make(map[string]bool), receipts: make(map[[32]byte]grantReceipt)}
		c.entries[id] = s
		c.index(id)
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
	defer c.Recover()
	items := c.batch()
	if len(items) == 0 {
		return
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.Lock()
	c.event++
	sent := c.event
	c.mu.Unlock()
	results, batchMiss := refresh(call, items)
	if batchMiss != nil {
		for _, id := range items {
			c.setMiss(id, batchMiss)
		}
		return
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	for _, r := range results {
		c.refreshResultSent(r, sent)
	}
}
func (c *Coordinator) refreshResult(r Result) {
	c.mu.Lock()
	c.event++
	sent := c.event
	c.mu.Unlock()
	c.refreshResultSent(r, sent)
}
func (c *Coordinator) refreshResultSent(r Result, sent uint64) {
	fingerprint := sha256.Sum256([]byte(r.Grant))
	c.mu.Lock()
	original := c.entries[r.Identity]
	if original == nil {
		c.mu.Unlock()
		return
	}
	c.event++
	receivedEvent := c.event
	saved := *original
	receipt, seen := original.receipts[fingerprint]
	receiptCount := len(original.receipts)
	c.mu.Unlock()
	s := &saved
	if r.Miss != nil {
		c.setMiss(r.Identity, r.Miss)
		return
	}
	now := c.clock.Now()
	if r.Grant == s.cached.verified.Compact() && c.Mono() >= s.cached.startDeadline {
		return
	}
	if !now.Before(s.evidenceDeadline) {
		c.setMiss(r.Identity, miss(200, "policy-stale"))
		return
	}
	g, err := speculation.VerifyShadowRefreshGrant(r.Grant, c.config.Keys, s.evidence.Local.Bindings, now.Unix())
	if err != nil {
		c.setMiss(r.Identity, miss(200, "grant-invalid"))
		return
	}
	if !seen {
		if receiptCount >= 256 {
			c.setMiss(r.Identity, miss(200, "grant-journal-capacity"))
			return
		}
		receipt = grantReceipt{now, speculation.Monotonic(now.Sub(c.origin))}
	}
	received, reason := speculation.ReceiveGrant(g, receipt.wall, receipt.mono, c.config.ClockUncertainty)
	if reason != speculation.ReasonEligible {
		c.setMiss(r.Identity, miss(200, string(reason)))
		return
	}
	claims, _ := g.Claims()
	if claims["lookup_digest"] != r.Identity.LookupDigest || claims["workspace_id"] != r.Identity.WorkspaceID || claims["key_id"] != r.Identity.KeyID {
		c.setMiss(r.Identity, miss(200, "grant-identity-mismatch"))
		return
	}
	history, historyOK := claims["history"].(map[string]any)
	lastSuccess, successOK := claimInteger(history["last_success_at"])
	grantID, grantOK := claims["grant_id"].(string)
	permits, permitsOK := claims["permits"].([]any)
	if !historyOK || !successOK || !grantOK || !permitsOK {
		c.setMiss(r.Identity, miss(200, "grant-shape"))
		return
	}
	next := cached{historyDeadline: receipt.wall.Add(time.Unix(lastSuccess+30, 0).Sub(receipt.wall.Add(c.config.ClockUncertainty))), startDeadline: time.Duration(receipt.mono) + time.Unix(g.StartDeadline(), 0).Sub(receipt.wall.Add(c.config.ClockUncertainty)), verified: g, received: received, grantID: grantID}
	for _, p := range permits {
		v, ok := p.(map[string]any)
		ordinal, okO := claimInteger(v["ordinal"])
		amount, okA := claimInteger(v["b_micro"])
		if !ok || !okO || !okA {
			next.permits = nil
			break
		}
		next.permits = append(next.permits, permit{ordinal, amount})
	}
	c.mu.Lock()
	if c.entries[r.Identity] != original {
		c.mu.Unlock()
		return
	}
	if !seen {
		original.receipts[fingerprint] = receipt
	}
	c.revision++
	original.cached = next
	original.lastMiss = nil
	c.recoverGrant(r.Identity, original, claims, sent, receivedEvent)
	c.mu.Unlock()
}
func (c *Coordinator) setMiss(id Identity, m *Miss) {
	c.mu.Lock()
	s := c.entries[id]
	if s == nil {
		c.mu.Unlock()
		return
	}
	c.revision++
	bounded := miss(m.Status, m.Code)
	s.lastMiss = bounded
	s.cached = cached{}
	c.mu.Unlock()
	c.Emit(Record{Kind: "refresh_miss", ObservationID: newID(), Identity: &id, Miss: bounded})
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
	defer c.Recover()
	x := c.decide(lookup, req)
	defer func() {
		if recover() != nil {
			c.Fault()
			c.Release(x.identity, x.id)
		}
	}()
	x.decision.CompletedAt = c.Mono()
	return shadowobserve.NewExecution(c, x.id, x.decision, x.identity, x.route)
}
func (c *Coordinator) Excluded(lookup string) *Execution {
	return c.Predecision(lookup, speculation.ParsedRequest{})
}
func (c *Coordinator) Release(identity Identity, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != "" && c.workspaceBusy[identity.WorkspaceID] == id {
		delete(c.workspaceBusy, identity.WorkspaceID)
		c.unresolved--
		c.memory -= InvocationMemory
	}
}
func (c *Coordinator) decide(lookup string, req speculation.ParsedRequest) *candidate {
	if c == nil {
		return nil
	}
	x := &candidate{id: newID()}
	x.decision = Decision{Reason: "grant_missing", At: c.Mono()}
	if c.Failures() != 0 {
		x.decision.Reason = "observer-failed"
		return x
	}
	var saved state
	var health speculation.LocalHealth
	var revision uint64
	// Only indexed lookup and scalar snapshots are inside this critical section.
	c.mu.Lock()
	entry, found := c.byLookup[lookup]
	if !found || entry.ambiguous {
		c.mu.Unlock()
		if entry.ambiguous {
			x.decision.Reason = "identity-ambiguous"
		}
		return x
	}
	x.identity = entry.identity
	saved = *c.entries[x.identity]
	revision = c.revision
	if saved.confirmed < c.reconfirm {
		c.mu.Unlock()
		x.decision.Reason = "coverage-unconfirmed"
		return x
	}
	health = saved.evidence.Health
	if c.workspaceClosed[x.identity.WorkspaceID] {
		health.Workspace.Latched = true
	}
	if c.keyClosed[lookup] {
		health.Key.Latched = true
	}
	if c.bootClosed || c.infrastructureClosed[lookup] {
		health.InfrastructureHealthy = false
	}
	c.mu.Unlock()
	s := &saved
	if s.cached.verified.Compact() == "" {
		if s.lastMiss != nil {
			x.decision.Reason = s.lastMiss.Code
		}
		return x
	}
	x.decision.GrantID = s.cached.grantID
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
	claims, _ := s.cached.verified.Claims()
	route, routeOK := claimRoute(claims)
	tier, tierOK := claimInteger(claims["tier"])
	if !routeOK || !tierOK || (tier != 2 && tier != 3) {
		x.decision.Reason = "grant-shape"
		return x
	}
	allowance, err := speculation.WorkspaceAllowance(e.Local.Bindings["tier_ceiling_micro"], claims["paid_headroom_micro"])
	if err != nil {
		x.decision.Reason = "allocation-unknown"
		return x
	}
	// Independent configuration may tighten, but never widen, the decided tier-2 $0.25 ceiling.
	if tier == 2 {
		allowance = min(allowance, int64(250000))
	}
	// Revalidate the snapshot before atomically depleting ownership, capacity and money.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revision != revision || c.Failures() != 0 {
		x.decision.Reason = "snapshot-changed"
		return x
	}
	if !c.clock.Now().Before(s.cached.historyDeadline) || !c.clock.Now().Before(s.evidenceDeadline) || c.Mono() >= s.cached.startDeadline {
		x.decision.Reason = "start_deadline"
		return x
	}
	s = c.entries[x.identity]
	if c.workspaceBusy[x.identity.WorkspaceID] != "" {
		x.decision.Reason = "simulated-concurrency"
		return x
	}
	if c.unresolved >= MaxUnresolved {
		x.decision.Reason = "simulated-enclave-concurrency"
		return x
	}
	if c.memory > MaxSimulatedMemory-InvocationMemory {
		x.decision.Reason = "simulated-memory"
		return x
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
		c.unresolved++
		c.memory += InvocationMemory
		s.unresolved = x.id
		ordinal := p.ordinal
		x.decision.Ordinal = &ordinal
		x.decision.Eligible = true
		x.decision.Reason = "eligible"
		x.route = route
		return x
	}
	x.decision.Reason = "simulated-permits-exhausted"
	return x
}

func (c *Coordinator) ObserveVerdict(lookup string, status int, reason, rateScope string) {
	c.ObserveResolvedVerdict(lookup, status, reason, rateScope, Identity{})
}
func (c *Coordinator) ObserveResolvedVerdict(lookup string, status int, reason, rateScope string, resolved Identity) {
	if c == nil || status < 400 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revision++
	c.event++
	entry, known := c.byLookup[lookup]
	conflict := entry.ambiguous
	if resolved.ResolvedWorkspace() {
		conflict = conflict || resolved.LookupDigest != "" && resolved.LookupDigest != lookup || known && (entry.identity.WorkspaceID != resolved.WorkspaceID || resolved.KeyID != "" && entry.identity.KeyID != resolved.KeyID)
		if !conflict {
			if known && resolved.KeyID == "" {
				resolved.KeyID = entry.identity.KeyID // Independently known binding survives partial metadata.
			}
			entry = lookupEntry{identity: resolved}
			known = true
		}
	}
	// Classify before invalidating coverage. Placeholder scopes determine only the
	// kind of verdict, never a stored identity or durable assignment.
	kind, _ := speculation.ClassifyVerdict(speculation.VerdictInput{Source: "authenticated_router", Status: status, Reason: reason, RateScope: rateScope, WorkspaceID: "scope", KeyID: "scope"})
	if kind.LocalInfrastructureBreaker != "none" {
		c.failInfrastructure(lookup)
		return
	}
	if kind.DurableScope == "none" {
		return
	}
	if !known || conflict {
		// An unknown invalid credential has no rights. A conflicting known
		// binding is uncertainty, and must still fence the observed denial.
		if !known && reason == "key_invalid" && !conflict {
			return
		}
		c.invalidateCoverage("unresolved-denial")
		return
	}
	id := entry.identity
	if kind.DurableScope == "key" && id.KeyID == "" {
		c.invalidateCoverage("unresolved-denial")
		return
	}
	c.latch(id, lookup, kind.DurableScope)
}
func (c *Coordinator) Suppressed(original string) {
	if c == nil {
		return
	}
	c.Emit(Record{Kind: "billing_backoff_suppressed", ObservationID: newID(), OriginalDenialID: original, Applicability: "not-applicable"})
}

func permitKey(id string, ordinal int64) string { return id + ":" + strconv.FormatInt(ordinal, 10) }

// VerifyGrant currently returns int64. Accept only exact integral JSON-domain
// representations; malformed or fractional tiers never bypass the ceiling.
func claimInteger(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
func claimRoute(claims map[string]any) (Route, bool) {
	r, ok := claims["route"].(map[string]any)
	if !ok {
		return Route{}, false
	}
	endpoint, a := r["endpoint_id"].(string)
	provider, b := r["provider"].(string)
	model, c := r["upstream_model"].(string)
	return Route{Endpoint: endpoint, Provider: provider, Model: model}, a && b && c && endpoint != "" && provider != "" && model != ""
}

func (c *Coordinator) InputMiss() *Execution {
	defer c.Recover()
	now := c.Mono()
	return shadowobserve.NewExecution(c, newID(), Decision{Reason: string(speculation.ReasonInputBound), At: now, CompletedAt: now}, Identity{}, Route{})
}
