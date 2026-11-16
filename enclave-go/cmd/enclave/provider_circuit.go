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

// providerCircuitRegistry is a per-gateway-instance circuit breaker keyed by
// provider|region|model-family. threshold consecutive provider-down failures
// open a circuit for openFor. When the window passes the circuit is half-open:
// traffic probes it, a success closes it, and a failure reopens it at once,
// because failures are only reset by a success.
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
	// (no hold, no refund) when every one of them is open. See FastFail.
	routes   map[string]providerRouteMemory
	routeTTL time.Duration

	opens     atomic.Uint64
	fastFails atomic.Uint64
	skips     atomic.Uint64
}

type providerCircuitState struct {
	failures  int
	openUntil time.Time
	updatedAt time.Time
}

// providerRouteMemory holds circuit keys only (provider, region and model
// family): no credential, endpoint secret, prompt or request content.
type providerRouteMemory struct {
	circuits  []string
	complete  bool
	minInput  int
	minOutput int
	expiresAt time.Time
}

// providerRouteDemand is what authorize filters endpoints by besides the
// routing policy: estimated input tokens and requested output tokens. A larger
// demand can only remove candidates (context window, output cap), so a set
// remembered from a request no larger than this one still covers it.
type providerRouteDemand struct {
	input  int
	output int
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
// legacy single-upstream path with no authorize or refund to protect, and they
// would all share one "unknown" circuit.
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

func (r *providerCircuitRegistry) Allow(option llm.InvokeOptions) bool {
	_, open := r.OpenRemaining(option)
	return !open
}

// OpenRemaining reports whether the option's circuit is open now and how long
// until its window passes.
func (r *providerCircuitRegistry) OpenRemaining(option llm.InvokeOptions) (time.Duration, bool) {
	if r == nil || !providerCircuitTracked(option) {
		return 0, false
	}
	key := providerCircuitKey(option)
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active {
		return 0, false
	}
	state, ok := r.states[key]
	if !ok || state.openUntil.IsZero() || !now.Before(state.openUntil) {
		return 0, false
	}
	return state.openUntil.Sub(now), true
}

// Tripped reports whether failures reached the threshold: the circuit is open,
// or its window passed and it is half-open. A tripped provider gets one try per
// request instead of same-provider retries, so a failed probe reopens the
// circuit after one round trip.
func (r *providerCircuitRegistry) Tripped(option llm.InvokeOptions) bool {
	if r == nil || !providerCircuitTracked(option) {
		return false
	}
	key := providerCircuitKey(option)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, active := r.activeLocked(); !active {
		return false
	}
	state, ok := r.states[key]
	return ok && state.failures >= r.threshold
}

func (r *providerCircuitRegistry) RecordSuccess(option llm.InvokeOptions) {
	if r == nil || !providerCircuitTracked(option) {
		return
	}
	key := providerCircuitKey(option)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, active := r.activeLocked(); !active {
		return
	}
	delete(r.states, key)
}

// RecordFailure counts one provider-down failure and reports whether it opened
// the circuit: a closed or half-open circuit that reached the threshold. A
// failure while the circuit is already open extends the window but is not a
// new open.
func (r *providerCircuitRegistry) RecordFailure(option llm.InvokeOptions) bool {
	if r == nil || !providerCircuitTracked(option) {
		return false
	}
	key := providerCircuitKey(option)
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active {
		return false
	}
	state, exists := r.states[key]
	if !exists && len(r.states) >= r.stateLimit() {
		r.evictOldestLocked()
	}
	wasOpen := !state.openUntil.IsZero() && now.Before(state.openUntil)
	state.failures++
	state.updatedAt = now
	opened := false
	if state.failures >= r.threshold {
		state.openUntil = now.Add(r.openFor)
		opened = !wasOpen
	}
	if r.states == nil {
		r.states = map[string]providerCircuitState{}
	}
	r.states[key] = state
	if opened {
		r.opens.Add(1)
	}
	return opened
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

// allOpenLocked reports whether every circuit key is open, and the time until
// the earliest window passes.
func (r *providerCircuitRegistry) allOpenLocked(now time.Time, circuits []string) (time.Duration, bool) {
	if len(circuits) == 0 {
		return 0, false
	}
	var earliest time.Time
	for _, key := range circuits {
		state, ok := r.states[key]
		if !ok || state.openUntil.IsZero() || !now.Before(state.openUntil) {
			return 0, false
		}
		if earliest.IsZero() || state.openUntil.Before(earliest) {
			earliest = state.openUntil
		}
	}
	return earliest.Sub(now), true
}

// RememberRoutes records the circuits an authorize returned for this
// credential and routing policy. Sets for the same key are unioned and the
// smallest demand kept, so the memory only ever grows more conservative until
// it expires.
func (r *providerCircuitRegistry) RememberRoutes(key string, demand providerRouteDemand, options []llm.InvokeOptions) {
	if r == nil || key == "" || len(options) == 0 {
		return
	}
	circuits := make([]string, 0, len(options))
	complete := true
	for _, option := range options {
		if !providerCircuitTracked(option) {
			complete = false
			continue
		}
		circuits = append(circuits, providerCircuitKey(option))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now, active := r.activeLocked()
	if !active || r.routeTTL <= 0 {
		return
	}
	if r.routes == nil {
		r.routes = map[string]providerRouteMemory{}
	}
	memory, ok := r.routes[key]
	if ok && !now.Before(memory.expiresAt) {
		ok = false
	}
	if !ok {
		if _, exists := r.routes[key]; !exists && len(r.routes) >= r.stateLimit() {
			r.evictOldestRouteLocked()
		}
		memory = providerRouteMemory{complete: true, minInput: demand.input, minOutput: demand.output}
	}
	memory.complete = memory.complete && complete
	memory.minInput = min(memory.minInput, demand.input)
	memory.minOutput = min(memory.minOutput, demand.output)
	for _, circuit := range circuits {
		known := false
		for _, existing := range memory.circuits {
			if existing == circuit {
				known = true
				break
			}
		}
		if known {
			continue
		}
		if len(memory.circuits) >= maxProviderRouteMemoryCircuits {
			memory.complete = false
			break
		}
		memory.circuits = append(memory.circuits, circuit)
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

// FastFail decides, before authorize, whether this request can only meet open
// circuits: the remembered set for its credential and routing policy is
// complete and unexpired, its demand is at least the remembered smallest
// demand, and every remembered circuit is open. It returns the time until the
// earliest circuit's window passes.
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
	if !memory.complete || demand.input < memory.minInput || demand.output < memory.minOutput {
		r.mu.Unlock()
		return 0, false
	}
	wait, refused := r.allOpenLocked(now, memory.circuits)
	r.mu.Unlock()
	if refused {
		r.fastFails.Add(1)
	}
	return wait, refused
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
		if !state.openUntil.IsZero() && now.Before(state.openUntil) {
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

func providerCircuitKey(option llm.InvokeOptions) string {
	provider := strings.TrimSpace(option.Provider)
	if provider == "" {
		provider = "unknown"
	}
	region := currentRegion()
	modelFamily := providerCircuitModelFamily(option.Model)
	return provider + "|" + region + "|" + modelFamily
}

func providerCircuitModelFamily(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return "unknown"
	}
	if before, _, ok := strings.Cut(model, ":"); ok {
		model = before
	}
	parts := strings.Split(model, "/")
	if len(parts) < 2 {
		return model
	}
	slug := parts[1]
	for _, sep := range []string{"-", "_", "."} {
		if idx := strings.Index(slug, sep); idx > 0 {
			slug = slug[:idx]
			break
		}
	}
	return parts[0] + "/" + slug
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

func providerRouteDemandFor(req *types.OpenAIChatRequest) providerRouteDemand {
	if req == nil {
		return providerRouteDemand{}
	}
	return providerRouteDemand{
		input:  trustedrouter.EstimateInputTokens(req),
		output: trustedrouter.AuthorizeOutputTokenEstimate(req),
	}
}

// providerCircuitFastFail refuses a request before authorize when every
// circuit its credential and routing policy last authorized is open, so no
// credit or key hold is taken and no refund follows. It writes the 503 and
// reports true when it refused.
func providerCircuitFastFail(w io.Writer, key string, demand providerRouteDemand, routeType, model, requestLogID string) bool {
	wait, refused := providerCircuits.FastFail(key, demand)
	if !refused {
		return false
	}
	fmt.Fprintf(os.Stderr,
		"enclave.provider_circuit_fast_fail request_log_id=%q route=%q model=%q retry_after_seconds=%d\n",
		requestLogID, routeType, model, retryAfterSeconds(wait),
	)
	writeProviderCircuitOpen(w, routeType, wait)
	return true
}

const providerCircuitOpenMessage = "All providers for this model are temporarily unavailable. Retry after the Retry-After interval."

// providerCircuitOpenError is returned when every authorized candidate was
// skipped by an open circuit, so no provider was called.
type providerCircuitOpenError struct {
	retryAfter time.Duration
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

// providerCircuitRetryHeaders: Retry-After is when the earliest circuit's
// window passes; x-should-retry is true because no provider ran and nothing was
// billed (writeRetryableError's convention).
func providerCircuitRetryHeaders(wait time.Duration) map[string]string {
	return map[string]string{
		"Retry-After":     strconv.Itoa(retryAfterSeconds(wait)),
		shouldRetryHeader: "true",
	}
}

func writeProviderCircuitOpen(w io.Writer, routeType string, wait time.Duration) {
	headers := providerCircuitRetryHeaders(wait)
	if routeType == "messages" {
		writeAnthropicErrorWithSourceHeaders(w, 503, providerCircuitOpenMessage, "provider", headers)
		return
	}
	writeErrorWithSourceHeaders(w, 503, providerCircuitOpenMessage, "provider", headers)
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
// Client errors (4xx), local input errors, a 2xx with no bytes, a closed
// downstream pipe and cancellation never count.
func providerDownFailure(err error, finalFirstByteBudget bool) bool {
	if err == nil || isClientInputError(err) {
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

// recordProviderCircuitOutcome records one candidate attempt (after its
// same-provider retries). A completed response closes the circuit. A failure
// counts only when the request was still live and the provider never accepted
// the call (no 2xx head, no output): once a provider answers, a later error is
// about this stream, not the provider being down. A client disconnect cancels
// ctx and counts as nothing.
func recordProviderCircuitOutcome(
	ctx context.Context,
	option llm.InvokeOptions,
	err error,
	writer *routeSelectingWriter,
	finalFirstByteBudget bool,
	requestLogID string,
) {
	if !providerCircuitTracked(option) {
		return
	}
	if err == nil {
		providerCircuits.RecordSuccess(option)
		return
	}
	if ctx.Err() != nil || writer.Accepted() || !providerDownFailure(err, finalFirstByteBudget) {
		return
	}
	if providerCircuits.RecordFailure(option) {
		fmt.Fprintf(os.Stderr,
			"enclave.provider_circuit_open request_log_id=%q circuit=%q err=%q\n",
			requestLogID, providerCircuitKey(option), errorClass(err),
		)
	}
}

// laterCandidateAllowed reports whether any later candidate's circuit admits
// traffic. Candidates without a model inherit the current one, as in the
// invocation loop.
func laterCandidateAllowed(options []llm.InvokeOptions, model string) bool {
	for _, option := range options {
		if option.Model == "" {
			option.Model = model
		}
		if providerCircuits.Allow(option) {
			return true
		}
	}
	return false
}
