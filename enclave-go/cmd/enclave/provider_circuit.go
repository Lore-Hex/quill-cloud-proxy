package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

const defaultProviderCircuitMaxStates = 4096

// defaultProviderRouteMemorySeconds bounds how long a remembered candidate set
// may refuse requests before authorize. A refusal never refreshes it; only a
// completed authorize does, so a provider the control plane adds is seen within
// this window after the last authorize.
const defaultProviderRouteMemorySeconds = 30

// maxProviderRouteMemoryCircuits caps one remembered set. A larger union is
// marked incomplete and never refuses a request.
const maxProviderRouteMemoryCircuits = 64

// providerCircuitProbeRetry is the Retry-After for an attempt turned away
// because a half-open circuit's one probe is still in flight.
const providerCircuitProbeRetry = time.Second

// providerCircuitStreakWindows ages out failure streaks. A streak that has not
// opened its circuit within this many open windows of its first failure (or a
// circuit not reopened within this many windows of its last open) starts over.
// The incident pattern collects three failures in under a second, and a real
// outage on a quiet route is seen by its tenants within minutes; three
// sporadic failures more than five windows (five minutes by default) apart are
// independent noise, not an outage.
const providerCircuitStreakWindows = 5

// providerCircuitRegistry is the per-gateway-instance provider circuit breaker.
// Every circuit is keyed by provider|region|full model id, and there are two
// kinds:
//
//   - A tenant circuit (the authorizing workspace, or the key when there is no
//     workspace): threshold consecutive provider-down failures by that tenant
//     open it. It is what refuses a tenant that keeps retrying a dead route,
//     before authorize. BYOK routes only ever have this kind: a tenant's own
//     provider account says nothing about anyone else's.
//   - A shared circuit per Credits route: it opens only when threshold
//     DISTINCT tenants failed provider-down since the last success, so no one
//     tenant, whose failures are refunded and cost it nothing, can take a route
//     away from everyone else.
//
// An open circuit refuses attempts for openFor. Then it is half-open: one probe
// at a time, the others still refused. Only a success from an attempt that
// started after the circuit opened (or, before it opens, after its first
// failure) closes it; a stream that was already running proves nothing about
// the outage. Failures keep counting: a tenant circuit reopens on its next
// failure, a shared one once threshold distinct tenants failed since it last
// opened.
//
// Every field is read under mu: tests reconfigure the process-wide registry
// while goroutines left over from earlier tests may still consult it.
type providerCircuitRegistry struct {
	mu        sync.Mutex
	enabled   bool
	threshold int
	openFor   time.Duration
	maxStates int
	now       func() time.Time
	states    map[string]providerCircuitState

	// routes remembers, per credential and routing policy, which circuits the
	// control plane last authorized. Candidates are only known after
	// authorize, so this is what lets a request be refused BEFORE authorize
	// (no hold, no refund) when every one of them refuses. See FastFail.
	routes   map[string]providerRouteMemory
	routeTTL time.Duration

	opens     atomic.Uint64
	fastFails atomic.Uint64
	skips     atomic.Uint64
	// probeSeq numbers half-open probes so only the current holder can
	// resolve one (a probe whose lease lapsed must not clear its successor).
	probeSeq uint64
}

type providerCircuitState struct {
	// failures counts a tenant circuit's consecutive provider-down failures.
	failures int
	// tenants holds the distinct tenants that failed a shared circuit since
	// its last success or open (at most threshold digests).
	tenants     []string
	streakStart time.Time
	openedAt    time.Time
	openUntil   time.Time
	probeUntil  time.Time
	probeID     uint64
	updatedAt   time.Time
}

func (s providerCircuitState) open(now time.Time) bool {
	return !s.openUntil.IsZero() && now.Before(s.openUntil)
}

func (s providerCircuitState) halfOpen(now time.Time) bool {
	return !s.openedAt.IsZero() && !s.open(now)
}

// expired reports whether a streak aged out: the circuit is not open and more
// than providerCircuitStreakWindows open windows passed since it last opened,
// or since its first failure when it never opened.
func (s providerCircuitState) expired(now time.Time, openFor time.Duration) bool {
	start := s.freshSince()
	return !s.open(now) && !start.IsZero() && now.Sub(start) > time.Duration(providerCircuitStreakWindows)*openFor
}

// freshSince is the earliest attempt start whose outcome still describes this
// circuit: after it opened, or after its first failure.
func (s providerCircuitState) freshSince() time.Time {
	if !s.openedAt.IsZero() {
		return s.openedAt
	}
	return s.streakStart
}

// providerCircuitRoute names the circuits one candidate passes through.
type providerCircuitRoute struct {
	shared string
	tenant string
}

func (r providerCircuitRoute) keys() []string {
	keys := make([]string, 0, 2)
	if r.shared != "" {
		keys = append(keys, r.shared)
	}
	if r.tenant != "" {
		keys = append(keys, r.tenant)
	}
	return keys
}

func (r providerCircuitRoute) tracked() bool { return r.shared != "" || r.tenant != "" }

func providerCircuitRouteFor(option llm.InvokeOptions, tenant string) providerCircuitRoute {
	if !providerCircuitTracked(option) {
		return providerCircuitRoute{}
	}
	base := providerCircuitKey(option)
	byok := strings.EqualFold(strings.TrimSpace(option.UsageType), "BYOK")
	route := providerCircuitRoute{}
	if !byok {
		route.shared = base
	}
	if tenant != "" {
		usage := "credits"
		if byok {
			usage = "byok"
		}
		route.tenant = "tenant:" + tenant + "|" + usage + "|" + base
	}
	return route
}

// providerCircuitTenant is a digest of who is paying for the attempt: the
// workspace, or the API key when the authorization names no workspace. A
// tenant can mint keys freely, so the workspace is what is counted. Empty when
// unknown; such attempts are not counted.
func providerCircuitTenant(authorization *trustedrouter.Authorization) string {
	if authorization == nil {
		return ""
	}
	kind, id := "workspace", strings.TrimSpace(authorization.WorkspaceID)
	if id == "" {
		kind, id = "key", strings.TrimSpace(authorization.APIKeyHash)
	}
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("quill/provider-circuit-tenant/v1\x00" + kind + "\x00" + id))
	return hex.EncodeToString(sum[:16])
}

// providerRouteMemory holds circuit keys only: provider, region, model and a
// tenant digest. No credential, endpoint secret, prompt or request content.
type providerRouteMemory struct {
	circuits  []providerCircuitRoute
	complete  bool
	minDemand int
	expiresAt time.Time
}

// providerRouteDemand is the one number authorize fits endpoints by:
// estimated input tokens plus max_tokens, or 0 when the caller set none
// (quill-router candidates_fitting_context). A larger demand can only remove
// candidates, so a set remembered from a request no larger than this one still
// covers it.
type providerRouteDemand int

func providerRouteDemandFor(req *types.OpenAIChatRequest) providerRouteDemand {
	if req == nil {
		return 0
	}
	demand := trustedrouter.EstimateInputTokens(req)
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		demand += *req.MaxTokens
	}
	return providerRouteDemand(demand)
}

func newProviderCircuitRegistryFromEnv() *providerCircuitRegistry {
	enabled := strings.ToLower(strings.TrimSpace(os.Getenv("QUILL_PROVIDER_CIRCUIT_BREAKER"))) != "false"
	threshold := circuitEnvInt("QUILL_PROVIDER_CIRCUIT_FAILURE_THRESHOLD", 3)
	openSeconds := circuitEnvInt("QUILL_PROVIDER_CIRCUIT_OPEN_SECONDS", 60)
	maxStates := circuitEnvInt("QUILL_PROVIDER_CIRCUIT_MAX_STATES", defaultProviderCircuitMaxStates)
	routeSeconds := circuitEnvInt("QUILL_PROVIDER_CIRCUIT_ROUTE_MEMORY_SECONDS", defaultProviderRouteMemorySeconds)
	if threshold < 1 {
		threshold = 1
	}
	if openSeconds < 1 {
		openSeconds = 1
	}
	if maxStates < 1 {
		maxStates = 1
	}
	if routeSeconds < 0 {
		routeSeconds = 0 // 0 disables the pre-authorize refusal only.
	}
	return &providerCircuitRegistry{
		enabled:   enabled,
		threshold: threshold,
		openFor:   time.Duration(openSeconds) * time.Second,
		maxStates: maxStates,
		now:       time.Now,
		states:    map[string]providerCircuitState{},
		routes:    map[string]providerRouteMemory{},
		routeTTL:  time.Duration(routeSeconds) * time.Second,
	}
}

func circuitEnvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

// providerCircuitTracked excludes options without a provider. They are the
// legacy single-upstream path with no authorize or refund to protect.
func providerCircuitTracked(option llm.InvokeOptions) bool {
	return strings.TrimSpace(option.Provider) != ""
}

// activeLocked reports whether the registry is enabled and returns its clock
// reading. Callers hold r.mu.
func (r *providerCircuitRegistry) activeLocked() (time.Time, bool) {
	if !r.enabled {
		return time.Time{}, false
	}
	if r.now == nil {
		return time.Now(), true
	}
	return r.now(), true
}

// blockedLocked reports whether key refuses new attempts: open, or half-open
// with its probe in flight.
func (r *providerCircuitRegistry) blockedLocked(key string, now time.Time) (time.Duration, bool) {
	if key == "" {
		return 0, false
	}
	state, ok := r.states[key]
	if !ok {
		return 0, false
	}
	if state.open(now) {
		return state.openUntil.Sub(now), true
	}
	if state.halfOpen(now) && now.Before(state.probeUntil) {
		return providerCircuitProbeRetry, true
	}
	return 0, false
}

// routeBlockedLocked: an attempt needs every circuit on its route, so it waits
// for the last of them.
func (r *providerCircuitRegistry) routeBlockedLocked(route providerCircuitRoute, now time.Time) (time.Duration, bool) {
	var wait time.Duration
	blocked := false
	for _, key := range route.keys() {
		if keyWait, keyBlocked := r.blockedLocked(key, now); keyBlocked {
			blocked = true
			wait = max(wait, keyWait)
		}
	}
	return wait, blocked
}

// Blocked reports whether a candidate's circuits refuse new attempts, and how
// long until they might not.
func (r *providerCircuitRegistry) Blocked(option llm.InvokeOptions, tenant string) (time.Duration, bool) {
	route := providerCircuitRouteFor(option, tenant)
	if r == nil || !route.tracked() {
		return 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active {
		return 0, false
	}
	return r.routeBlockedLocked(route, now)
}

// providerCircuitTicket is one admitted attempt. The first of Succeed, Fail
// or Release resolves it (later calls do nothing), which also frees any
// half-open probe it holds. The provider accepting the call resolves it as a
// success at once, so a probe never holds its circuit for a whole generation.
type providerCircuitTicket struct {
	route     providerCircuitRoute
	tenant    string
	startedAt time.Time
	probes    map[string]uint64
	resolved  bool // guarded by the registry's mu
}

// Admit decides whether an attempt may call the provider. A half-open
// circuit admits one probe; until that probe resolves (or its lease of one
// open window passes) every other attempt is refused. It returns nil, true for
// an attempt no circuit tracks.
func (r *providerCircuitRegistry) Admit(option llm.InvokeOptions, tenant string) (*providerCircuitTicket, time.Duration, bool) {
	route := providerCircuitRouteFor(option, tenant)
	if r == nil || !route.tracked() {
		return nil, 0, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active {
		return nil, 0, true
	}
	for _, key := range route.keys() {
		if state, ok := r.states[key]; ok && state.expired(now, r.openFor) {
			delete(r.states, key)
		}
	}
	if wait, blocked := r.routeBlockedLocked(route, now); blocked {
		return nil, wait, false
	}
	ticket := &providerCircuitTicket{route: route, tenant: tenant, startedAt: now}
	for _, key := range route.keys() {
		if state, ok := r.states[key]; ok && state.halfOpen(now) {
			r.probeSeq++
			state.probeUntil = now.Add(r.openFor)
			state.probeID = r.probeSeq
			r.states[key] = state
			if ticket.probes == nil {
				ticket.probes = map[string]uint64{}
			}
			ticket.probes[key] = r.probeSeq
		}
	}
	return ticket, 0, true
}

// releaseProbeLocked frees key's probe slot if this ticket still holds it.
func (r *providerCircuitRegistry) releaseProbeLocked(ticket *providerCircuitTicket, key string, state *providerCircuitState) {
	if id, held := ticket.probes[key]; held && state.probeID == id {
		state.probeUntil = time.Time{}
		state.probeID = 0
	}
}

// ReleaseProbe frees the half-open probe slots this attempt holds without
// resolving it: the provider answered, so the slot need not wait for the
// outcome, which content or a failure decides later.
func (r *providerCircuitRegistry) ReleaseProbe(ticket *providerCircuitTicket) {
	if r == nil || ticket == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ticket.resolved || len(ticket.probes) == 0 {
		return
	}
	for _, key := range ticket.route.keys() {
		if state, ok := r.states[key]; ok {
			r.releaseProbeLocked(ticket, key, &state)
			r.states[key] = state
		}
	}
	ticket.probes = nil
}

// resolveLocked marks the ticket resolved and reports whether it was not yet.
func (r *providerCircuitRegistry) resolveLocked(ticket *providerCircuitTicket) bool {
	if ticket == nil || ticket.resolved {
		return false
	}
	ticket.resolved = true
	return true
}

// Release resolves an attempt whose outcome says nothing about the provider
// (a client disconnect, a client error, a local failure).
func (r *providerCircuitRegistry) Release(ticket *providerCircuitTicket) {
	if r == nil || ticket == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.resolveLocked(ticket) {
		return
	}
	for _, key := range ticket.route.keys() {
		if state, ok := r.states[key]; ok {
			r.releaseProbeLocked(ticket, key, &state)
			r.states[key] = state
		}
	}
}

// Tripped reports whether one of the attempt's circuits has opened in its
// current streak (open or half-open), or the attempt is a probe. Such an
// attempt gets one try instead of same-provider retries.
func (r *providerCircuitRegistry) Tripped(ticket *providerCircuitTicket) bool {
	if r == nil || ticket == nil {
		return false
	}
	// ticket.probes is written under r.mu by ReleaseProbe, which a provider
	// client that ignores cancellation could reach from a straggler goroutine,
	// so it is read under the same lock.
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(ticket.probes) > 0 {
		return true
	}
	for _, key := range ticket.route.keys() {
		if state, ok := r.states[key]; ok && !state.openedAt.IsZero() {
			return true
		}
	}
	return false
}

// Succeed closes the attempt's circuits, unless the attempt started before
// the circuit's current failures (or its open) began.
func (r *providerCircuitRegistry) Succeed(ticket *providerCircuitTicket) {
	if r == nil || ticket == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.resolveLocked(ticket) {
		return
	}
	if _, active := r.activeLocked(); !active {
		return
	}
	for _, key := range ticket.route.keys() {
		state, ok := r.states[key]
		if !ok {
			continue
		}
		if ticket.startedAt.Before(state.freshSince()) {
			r.releaseProbeLocked(ticket, key, &state)
			r.states[key] = state
			continue
		}
		delete(r.states, key)
	}
}

// Fail counts one provider-down failure and reports whether it opened a
// circuit (from closed or half-open). A failure from an attempt that started
// before the circuit last opened is stale and does not count.
func (r *providerCircuitRegistry) Fail(ticket *providerCircuitTicket) bool {
	if r == nil || ticket == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.resolveLocked(ticket) {
		return false
	}
	now, active := r.activeLocked()
	if !active {
		return false
	}
	opened := false
	if key := ticket.route.tenant; key != "" {
		state, exists := r.stateForFailureLocked(key, now)
		if state.openedAt.IsZero() || !ticket.startedAt.Before(state.openedAt) {
			state.failures++
			opened = r.markFailureLocked(&state, now, state.failures >= r.threshold) || opened
		}
		r.storeAfterFailureLocked(ticket, key, state, exists)
	}
	if key := ticket.route.shared; key != "" {
		state, exists := r.stateForFailureLocked(key, now)
		if ticket.tenant != "" && (state.openedAt.IsZero() || !ticket.startedAt.Before(state.openedAt)) {
			known := false
			for _, tenant := range state.tenants {
				known = known || tenant == ticket.tenant
			}
			if !known {
				state.tenants = append(state.tenants, ticket.tenant)
			}
			trip := len(state.tenants) >= r.threshold
			opened = r.markFailureLocked(&state, now, trip) || opened
			if trip {
				// Reopening needs threshold NEW distinct tenants.
				state.tenants = nil
			}
		}
		r.storeAfterFailureLocked(ticket, key, state, exists)
	}
	if opened {
		r.opens.Add(1)
	}
	return opened
}

// stateForFailureLocked returns key's state, started over when its streak
// aged out (the probe slot survives so its holder can still be matched).
func (r *providerCircuitRegistry) stateForFailureLocked(key string, now time.Time) (providerCircuitState, bool) {
	if r.states == nil {
		r.states = map[string]providerCircuitState{}
	}
	state, exists := r.states[key]
	if !exists && len(r.states) >= r.stateLimit() {
		r.evictOldestLocked()
	}
	if exists && state.expired(now, r.openFor) {
		state = providerCircuitState{probeUntil: state.probeUntil, probeID: state.probeID, updatedAt: state.updatedAt}
	}
	return state, exists
}

func (r *providerCircuitRegistry) markFailureLocked(state *providerCircuitState, now time.Time, trip bool) bool {
	if state.streakStart.IsZero() {
		state.streakStart = now
	}
	state.updatedAt = now
	if !trip {
		return false
	}
	wasOpen := state.open(now)
	state.openUntil = now.Add(r.openFor)
	if wasOpen {
		return false
	}
	state.openedAt = now
	return true
}

func (r *providerCircuitRegistry) storeAfterFailureLocked(ticket *providerCircuitTicket, key string, state providerCircuitState, exists bool) {
	r.releaseProbeLocked(ticket, key, &state)
	if !exists && state.updatedAt.IsZero() {
		// A failure that counted nowhere (stale, or an unknown tenant on a
		// shared circuit) leaves no state behind.
		return
	}
	r.states[key] = state
}

func (r *providerCircuitRegistry) stateLimit() int {
	if r.maxStates > 0 {
		return r.maxStates
	}
	return defaultProviderCircuitMaxStates
}

func (r *providerCircuitRegistry) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for key, state := range r.states {
		if oldestKey == "" || state.updatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = state.updatedAt
		}
	}
	if oldestKey != "" {
		delete(r.states, oldestKey)
	}
}

// RememberRoutes records the circuits an authorize returned for this
// credential and routing policy. Sets for the same key are unioned and the
// smallest demand kept, so the memory only ever grows more conservative until
// it expires. A new entry is written only when one of the candidates already
// has a recorded failure: healthy traffic never touches the table.
func (r *providerCircuitRegistry) RememberRoutes(key string, demand providerRouteDemand, options []llm.InvokeOptions, tenant string) {
	if r == nil || key == "" || len(options) == 0 {
		return
	}
	routes := make([]providerCircuitRoute, 0, len(options))
	complete := true
	for _, option := range options {
		route := providerCircuitRouteFor(option, tenant)
		if !route.tracked() {
			complete = false
			continue
		}
		routes = append(routes, route)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active || r.routeTTL <= 0 {
		return
	}
	memory, ok := r.routes[key]
	if ok && !now.Before(memory.expiresAt) {
		ok = false
	}
	if !ok {
		failing := false
		for _, route := range routes {
			for _, circuit := range route.keys() {
				_, recorded := r.states[circuit]
				failing = failing || recorded
			}
		}
		if !failing {
			delete(r.routes, key)
			return
		}
		if r.routes == nil {
			r.routes = map[string]providerRouteMemory{}
		}
		if _, exists := r.routes[key]; !exists && len(r.routes) >= r.stateLimit() {
			r.evictOldestRouteLocked()
		}
		memory = providerRouteMemory{complete: true, minDemand: int(demand)}
	}
	memory.complete = memory.complete && complete
	memory.minDemand = min(memory.minDemand, int(demand))
	for _, route := range routes {
		known := false
		for _, existing := range memory.circuits {
			known = known || existing == route
		}
		if known {
			continue
		}
		if len(memory.circuits) >= maxProviderRouteMemoryCircuits {
			memory.complete = false
			break
		}
		memory.circuits = append(memory.circuits, route)
	}
	memory.expiresAt = now.Add(r.routeTTL)
	r.routes[key] = memory
}

func (r *providerCircuitRegistry) evictOldestRouteLocked() {
	var oldestKey string
	var oldest time.Time
	for key, memory := range r.routes {
		if oldestKey == "" || memory.expiresAt.Before(oldest) {
			oldestKey = key
			oldest = memory.expiresAt
		}
	}
	if oldestKey != "" {
		delete(r.routes, oldestKey)
	}
}

// FastFail decides, before authorize, whether this request can only meet
// refusing circuits: the remembered set for its credential and routing policy
// is complete and unexpired, its demand is at least the smallest remembered
// demand, and every remembered candidate's circuits refuse. It returns the
// time until the earliest candidate might admit an attempt.
func (r *providerCircuitRegistry) FastFail(key string, demand providerRouteDemand) (time.Duration, bool) {
	if r == nil || key == "" {
		return 0, false
	}
	r.mu.Lock()
	now, active := r.activeLocked()
	if !active || r.routeTTL <= 0 {
		r.mu.Unlock()
		return 0, false
	}
	memory, ok := r.routes[key]
	if !ok {
		r.mu.Unlock()
		return 0, false
	}
	if !now.Before(memory.expiresAt) {
		delete(r.routes, key)
		r.mu.Unlock()
		return 0, false
	}
	if !memory.complete || len(memory.circuits) == 0 || int(demand) < memory.minDemand {
		r.mu.Unlock()
		return 0, false
	}
	earliest := time.Duration(-1)
	for _, route := range memory.circuits {
		wait, blocked := r.routeBlockedLocked(route, now)
		if !blocked {
			r.mu.Unlock()
			return 0, false
		}
		if earliest < 0 || wait < earliest {
			earliest = wait
		}
	}
	r.mu.Unlock()
	r.fastFails.Add(1)
	return earliest, true
}

type providerCircuitStats struct {
	Opens            uint64
	FastFailRefusals uint64
	SkippedCircuits  uint64
	OpenCircuits     int
	TrackedCircuits  int
	RouteMemory      int
}

func (r *providerCircuitRegistry) Stats() providerCircuitStats {
	if r == nil {
		return providerCircuitStats{}
	}
	stats := providerCircuitStats{
		Opens:            r.opens.Load(),
		FastFailRefusals: r.fastFails.Load(),
		SkippedCircuits:  r.skips.Load(),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active {
		return stats
	}
	stats.TrackedCircuits = len(r.states)
	stats.RouteMemory = len(r.routes)
	for _, state := range r.states {
		if state.open(now) {
			stats.OpenCircuits++
		}
	}
	return stats
}

// startProviderCircuitStats emits the cumulative counters and table occupancy
// once per interval, like enclave.abuse_stats. No request content or keys.
func startProviderCircuitStats(ctx context.Context, w io.Writer, interval time.Duration) {
	if w == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := providerCircuits.Stats()
				fmt.Fprintf(w,
					"enclave.provider_circuit_stats opens=%d fast_fail_refusals=%d skipped_candidates=%d open_circuits=%d tracked_circuits=%d route_memory=%d\n",
					stats.Opens, stats.FastFailRefusals, stats.SkippedCircuits,
					stats.OpenCircuits, stats.TrackedCircuits, stats.RouteMemory,
				)
			}
		}
	}()
}

// providerCircuitKey is provider|region|model with the full model id: one
// model's outage must not refuse its siblings on the same provider.
func providerCircuitKey(option llm.InvokeOptions) string {
	provider := strings.TrimSpace(option.Provider)
	if provider == "" {
		provider = "unknown"
	}
	model := strings.TrimSpace(option.Model)
	if model == "" {
		model = "unknown"
	}
	return provider + "|" + currentRegion() + "|" + model
}

func currentRegion() string {
	for _, name := range []string{"TR_REGION", "GCP_REGION", "AWS_REGION"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return "unknown"
}

var providerCircuits = newProviderCircuitRegistryFromEnv()

// providerRouteMemoryKey identifies the credential and every request field
// authorize routes by, except token demand (compared separately). Request
// content, attribution and idempotency do not route and are left out. The key
// is a digest; neither the bearer nor its lookup hash is retained.
func providerRouteMemoryKey(ctx context.Context, bearer, routeType string, req *types.OpenAIChatRequest) string {
	if req == nil {
		return ""
	}
	credential := trustedrouter.RequestLookupHash(ctx, bearer)
	if strings.TrimSpace(bearer) == "" && credential == trustedrouter.LookupHash("") {
		return ""
	}
	policy := struct {
		Version        int                    `json:"v"`
		Credential     string                 `json:"credential"`
		RouteType      string                 `json:"route_type"`
		Region         string                 `json:"region"`
		Confidential   bool                   `json:"confidential"`
		Model          string                 `json:"model"`
		Models         []string               `json:"models"`
		AllowFallbacks *bool                  `json:"allow_fallbacks"`
		Provider       *types.ProviderRouting `json:"provider"`
		ServiceTier    string                 `json:"service_tier"`
		Parameters     []string               `json:"requested_parameters"`
		Modalities     []string               `json:"input_modalities"`
		Receipt        bool                   `json:"inference_receipt"`
		Stream         bool                   `json:"stream"`
		HostedTools    bool                   `json:"hosted_tools"`
	}{
		Version:        1,
		Credential:     credential,
		RouteType:      routeType,
		Region:         currentRegion(),
		Confidential:   trustedrouter.ConfidentialOnly(ctx),
		Model:          req.Model,
		Models:         req.Models,
		AllowFallbacks: req.AllowFallbacks,
		Provider:       req.Provider,
		ServiceTier:    req.ServiceTier,
		Parameters:     req.RequestedParameters,
		Modalities:     types.RequestInputModalities(req),
		Receipt:        req.InferenceReceipt.Requested,
		Stream:         req.Stream,
		HostedTools:    req.AdditionalCostReservationMicrodollars > 0,
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("quill/provider-route-memory/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

// providerCircuitFastFail refuses a request before authorize when every
// candidate its credential and routing policy last authorized is refused by a
// circuit, so no credit or key hold is taken and no refund follows. It writes
// the 503 and reports true when it refused.
func providerCircuitFastFail(ctx context.Context, w io.Writer, key string, demand providerRouteDemand, routeType, model, requestLogID string) bool {
	refusal := providerCircuitRefusal(ctx, key, demand, routeType, model, requestLogID)
	if refusal == nil {
		return false
	}
	writeProviderCircuitOpen(w, routeType, refusal)
	return true
}

// providerCircuitRefusal is providerCircuitFastFail for callers that render
// their own errors (orchestration model calls): it logs the refusal and
// returns it instead of writing it. Nil when the request may go to authorize.
func providerCircuitRefusal(ctx context.Context, key string, demand providerRouteDemand, routeType, model, requestLogID string) *providerCircuitOpenError {
	wait, refused := providerCircuits.FastFail(key, demand)
	if !refused {
		return nil
	}
	fmt.Fprintf(os.Stderr,
		"enclave.provider_circuit_fast_fail request_log_id=%q route=%q model=%q retry_after_seconds=%d\n",
		requestLogID, routeType, model, retryAfterSeconds(wait),
	)
	return &providerCircuitOpenError{retryAfter: wait, spent: polyphemusSelectionCharged(ctx)}
}

// polyphemusSelectionCharged reports whether this request already paid for a
// Polyphemus model selection, so re-sending it would pay for another.
func polyphemusSelectionCharged(ctx context.Context) bool {
	receipt := polyphemusReceiptFromContext(ctx)
	return receipt != nil && receipt.CostMicrodollars > 0
}

const providerCircuitOpenMessage = "All providers for this model are temporarily unavailable. Retry after the Retry-After interval."

// providerCircuitOpenError is returned when every authorized candidate was
// refused by a circuit, so no provider was called.
type providerCircuitOpenError struct {
	retryAfter time.Duration
	// spent: something on this request was already charged (a Polyphemus
	// selection), so re-sending is not free.
	spent bool
}

func (e *providerCircuitOpenError) Error() string { return "provider circuit open" }

func providerCircuitOpenFrom(err error) (*providerCircuitOpenError, bool) {
	var circuitErr *providerCircuitOpenError
	if errors.As(err, &circuitErr) && circuitErr != nil {
		return circuitErr, true
	}
	return nil, false
}

func retryAfterSeconds(wait time.Duration) int {
	seconds := int((wait + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

// providerCircuitRetryHeaders: Retry-After is when the earliest circuit might
// admit an attempt. x-should-retry is true because no provider ran and nothing
// was billed (writeRetryableError's convention), and false when the request
// already paid for something (writeSpentError's).
func providerCircuitRetryHeaders(err *providerCircuitOpenError) map[string]string {
	if err == nil {
		err = &providerCircuitOpenError{}
	}
	shouldRetry := "true"
	if err.spent {
		shouldRetry = "false"
	}
	return map[string]string{
		"Retry-After":     strconv.Itoa(retryAfterSeconds(err.retryAfter)),
		shouldRetryHeader: shouldRetry,
	}
}

func writeProviderCircuitOpen(w io.Writer, routeType string, err *providerCircuitOpenError) {
	headers := providerCircuitRetryHeaders(err)
	if routeType == "messages" {
		writeAnthropicErrorWithSourceHeaders(w, 503, providerCircuitOpenMessage, "provider", headers)
		return
	}
	writeErrorWithSourceHeaders(w, 503, providerCircuitOpenMessage, "provider", headers)
}

// writeProviderCircuitError renders err as the circuit refusal when it is one,
// for routes with their own error renderers (images, fusion, decide).
func writeProviderCircuitError(w io.Writer, routeType string, err error) bool {
	circuitErr, ok := providerCircuitOpenFrom(err)
	if !ok {
		return false
	}
	writeProviderCircuitOpen(w, routeType, circuitErr)
	return true
}

// providerCircuitTransportFailures are errorClass values meaning the provider
// never answered: no connection, no TLS session, or the connection closed or
// timed out before any response.
var providerCircuitTransportFailures = map[string]bool{
	"connect_dial_timeout":      true,
	"connect_tls_timeout":       true,
	"ctx_deadline":              true,
	"conn_reset":                true,
	"conn_refused":              true,
	"broken_pipe":               true,
	"io_timeout":                true,
	"dns_no_such_host":          true,
	"tls_certificate":           true,
	"tls_handshake":             true,
	"cert_fingerprint_mismatch": true,
	"unexpected_eof":            true,
	"eof":                       true,
}

// providerDownFailure reports whether a pre-acceptance failure says the
// provider is down rather than that this request was refused:
//   - HTTP 502, 503 and 504. Not 500, which providers also return for one bad
//     input, and not 429: a throttling provider is up, the throttle is often
//     per key, and same-provider retry and failover already handle it.
//   - Transport failures before any response (refused, reset, DNS, TLS,
//     connect timeout, EOF).
//   - The final candidate's time-to-first-byte budget, which is a hang
//     detector. A non-final candidate's short budget is a failover trigger that
//     silent-reasoning models legitimately exceed, so it never counts.
//
// Client errors (4xx), local input errors, the gateway's own failures
// (credentials, policy checks), a 2xx with no bytes, a closed downstream pipe
// and cancellation never count.
func providerDownFailure(err error, finalFirstByteBudget bool) bool {
	if err == nil || isClientInputError(err) || upstreamerror.IsLocal(err) {
		return false
	}
	var aerr *adapter.AdapterError
	if asAdapterErr(err, &aerr) {
		return false
	}
	if errors.Is(err, errEmptyUpstreamResponse) {
		return false
	}
	if _, ok := providerCircuitOpenFrom(err); ok {
		return false
	}
	if strings.Contains(err.Error(), "time-to-first-byte exceeded") {
		return finalFirstByteBudget
	}
	if status, ok := upstreamerror.Status(err); ok {
		return status == 502 || status == 503 || status == 504
	}
	return providerCircuitTransportFailures[errorClass(err)]
}

// recordProviderCircuitOutcome resolves one candidate attempt (after its
// same-provider retries) unless its first content byte already resolved it as
// a success. Completion is a success. A failure counts only when the request
// was still live and the provider never answered (no 2xx head, no output);
// an attempt that was answered and then failed before content, or that a
// client disconnect cancelled, counts as neither.
func recordProviderCircuitOutcome(
	ctx context.Context,
	ticket *providerCircuitTicket,
	option llm.InvokeOptions,
	err error,
	writer *routeSelectingWriter,
	finalFirstByteBudget bool,
	requestLogID string,
) {
	if ticket == nil {
		return
	}
	if err == nil {
		providerCircuits.Succeed(ticket)
		return
	}
	if ctx.Err() != nil || writer.Accepted() || !providerDownFailure(err, finalFirstByteBudget) {
		providerCircuits.Release(ticket)
		return
	}
	if providerCircuits.Fail(ticket) {
		fmt.Fprintf(os.Stderr,
			"enclave.provider_circuit_open request_log_id=%q provider=%q model=%q byok=%t err=%q\n",
			requestLogID, option.Provider, option.Model, ticket.route.shared == "", errorClass(err),
		)
	}
}

// laterCandidateAllowed reports whether any later candidate's circuits admit
// an attempt. Candidates without a model inherit the current one, as in the
// invocation loop.
func laterCandidateAllowed(options []llm.InvokeOptions, model, tenant string) bool {
	for _, option := range options {
		if option.Model == "" {
			option.Model = model
		}
		if _, blocked := providerCircuits.Blocked(option, tenant); !blocked {
			return true
		}
	}
	return false
}

type requestChargesKey struct{}

// requestCharges records that some call of this request reached settlement,
// so a later failure must not tell the client a retry is free.
type requestCharges struct{ charged atomic.Bool }

// withRequestCharges gives ctx a charge tracker unless it already has one.
func withRequestCharges(ctx context.Context) context.Context {
	if _, ok := ctx.Value(requestChargesKey{}).(*requestCharges); ok {
		return ctx
	}
	return context.WithValue(ctx, requestChargesKey{}, &requestCharges{})
}

func markRequestCharged(ctx context.Context) {
	if charges, ok := ctx.Value(requestChargesKey{}).(*requestCharges); ok {
		charges.charged.Store(true)
	}
}

func requestCharged(ctx context.Context) bool {
	charges, ok := ctx.Value(requestChargesKey{}).(*requestCharges)
	return ok && charges.charged.Load()
}
