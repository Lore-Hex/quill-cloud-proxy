package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestProviderCircuitOpensAndThenHalfOpens(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	registry := &providerCircuitRegistry{
		enabled:   true,
		threshold: 2,
		openFor:   time.Minute,
		now:       func() time.Time { return now },
		states:    map[string]providerCircuitState{},
	}
	option := llm.InvokeOptions{
		Provider:   "anthropic",
		Model:      "anthropic/claude-haiku-4.5",
		EndpointID: "anthropic/claude-haiku-4.5@anthropic/prepaid",
	}

	if !registry.Allow(option) {
		t.Fatal("fresh circuit should allow")
	}
	if opened := registry.RecordFailure(option); opened {
		t.Fatal("first failure should not open circuit")
	}
	if !registry.Allow(option) {
		t.Fatal("circuit should stay closed before threshold")
	}
	if opened := registry.RecordFailure(option); !opened {
		t.Fatal("second failure should open circuit")
	}
	if registry.Allow(option) {
		t.Fatal("open circuit should reject while TTL has not elapsed")
	}

	now = now.Add(61 * time.Second)
	if !registry.Allow(option) {
		t.Fatal("expired circuit should half-open")
	}
	registry.RecordSuccess(option)
	if !registry.Allow(option) {
		t.Fatal("success should close the circuit")
	}
}

func TestProviderCircuitKeyIncludesProviderRegionAndFamily(t *testing.T) {
	t.Setenv("TR_REGION", "europe-west4")
	key := providerCircuitKey(llm.InvokeOptions{
		Provider:   "openai",
		Model:      "openai/gpt-4.1-mini:free",
		EndpointID: "openai/gpt-4.1-mini@openai/byok",
	})

	want := "openai|europe-west4|openai/gpt"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

func TestProviderCircuitStateIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	registry := &providerCircuitRegistry{
		enabled:   true,
		threshold: 3,
		openFor:   time.Minute,
		maxStates: 2,
		now:       func() time.Time { return now },
		states:    map[string]providerCircuitState{},
	}
	options := []llm.InvokeOptions{
		{Provider: "first", Model: "first/model-a"},
		{Provider: "second", Model: "second/model-b"},
		{Provider: "third", Model: "third/model-c"},
	}

	for _, option := range options {
		registry.RecordFailure(option)
		now = now.Add(time.Second)
	}

	if len(registry.states) != 2 {
		t.Fatalf("circuit states = %d, want 2", len(registry.states))
	}
	if _, ok := registry.states[providerCircuitKey(options[0])]; ok {
		t.Fatal("oldest circuit state was not evicted")
	}
}

func TestParseFirstByteBudgetDefaultsToProductionBudget(t *testing.T) {
	for _, raw := range []string{"", "0", "-1", "not-a-number"} {
		if got := parseFirstByteBudget(raw); got != 20*time.Second {
			t.Errorf("parseFirstByteBudget(%q) = %s, want 20s", raw, got)
		}
	}
	if got := parseFirstByteBudget("35"); got != 35*time.Second {
		t.Fatalf("parseFirstByteBudget(valid) = %s, want 35s", got)
	}
}

func newTestProviderCircuitRegistry(now *time.Time) *providerCircuitRegistry {
	return &providerCircuitRegistry{
		enabled:   true,
		threshold: 3,
		openFor:   time.Minute,
		now:       func() time.Time { return *now },
		states:    map[string]providerCircuitState{},
		routes:    map[string]providerRouteMemory{},
		routeTTL:  30 * time.Second,
	}
}

func TestProviderCircuitReportsOpensAndReopensHalfOpenOnFirstFailure(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	option := llm.InvokeOptions{Provider: "solo", Model: "solo/glm-5.3-flash"}

	for i := 1; i <= 2; i++ {
		if registry.RecordFailure(option) || registry.Tripped(option) || !registry.Allow(option) {
			t.Fatalf("failure %d must not trip the circuit", i)
		}
	}
	if !registry.RecordFailure(option) || !registry.Tripped(option) || registry.Allow(option) {
		t.Fatal("third failure must open the circuit")
	}
	if registry.RecordFailure(option) {
		t.Fatal("a failure while already open is not a new open")
	}
	if wait, open := registry.OpenRemaining(option); !open || wait != time.Minute {
		t.Fatalf("remaining=%s open=%t, want 1m true", wait, open)
	}

	now = now.Add(61 * time.Second)
	if !registry.Allow(option) || !registry.Tripped(option) {
		t.Fatal("after the window the circuit is half-open: allowed and still tripped")
	}
	if !registry.RecordFailure(option) || registry.Allow(option) {
		t.Fatal("a half-open failure must reopen immediately")
	}
	now = now.Add(61 * time.Second)
	registry.RecordSuccess(option)
	if registry.Tripped(option) || !registry.Allow(option) {
		t.Fatal("a success must close the circuit")
	}
	if registry.RecordFailure(option) {
		t.Fatal("after a success the count starts over")
	}
	if got := registry.Stats().Opens; got != 2 {
		t.Fatalf("opens=%d, want 2", got)
	}
}

func TestProviderCircuitIgnoresUntrackedAndDisabled(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	untracked := llm.InvokeOptions{Model: "legacy-model"}
	for range 5 {
		registry.RecordFailure(untracked)
	}
	if !registry.Allow(untracked) || len(registry.states) != 0 {
		t.Fatal("an option without a provider must never be tracked")
	}
	registry.enabled = false
	tracked := llm.InvokeOptions{Provider: "solo", Model: "solo/glm"}
	for range 5 {
		registry.RecordFailure(tracked)
	}
	if !registry.Allow(tracked) || registry.Tripped(tracked) {
		t.Fatal("a disabled registry must allow everything")
	}
}

func TestProviderDownFailureClassification(t *testing.T) {
	status := func(code int) error { return &upstreamerror.Error{Status: code, Body: "{}"} }
	for _, tc := range []struct {
		name  string
		err   error
		final bool
		want  bool
	}{
		{"502", status(502), false, true},
		{"503", status(503), false, true},
		{"504", status(504), false, true},
		{"wrapped 503", fmt.Errorf("llm/solo: %w", status(503)), false, true},
		{"500", status(500), false, false},
		{"429", status(429), false, false},
		{"400", status(400), false, false},
		{"401", status(401), false, false},
		{"404", status(404), false, false},
		{"connection refused", errors.New("llm/solo: invoke: dial tcp: connect: connection refused"), false, true},
		{"connection reset", errors.New("llm/solo: invoke: read: connection reset by peer"), false, true},
		{"dns", errors.New("llm/solo: invoke: dial tcp: lookup solo.invalid: no such host"), false, true},
		{"eof before response", fmt.Errorf("llm/solo: invoke: %w", io.EOF), false, true},
		{"tls handshake", errors.New("llm/solo: invoke: remote error: tls: handshake failure"), false, true},
		{"client disconnect", fmt.Errorf("llm/solo: %w", context.Canceled), false, false},
		{"downstream closed", fmt.Errorf("write: %w", io.ErrClosedPipe), false, false},
		{"empty 2xx", errEmptyUpstreamResponse, false, false},
		{"circuit refusal", &providerCircuitOpenError{retryAfter: time.Second}, false, false},
		{"adapter error", &adapter.AdapterError{Status: 400, Message: "bad"}, false, false},
		{"unknown", errors.New("something odd"), false, false},
		{"first byte on a non-final candidate", fmt.Errorf("llm/upstream: time-to-first-byte exceeded 20s: %w", context.Canceled), false, false},
		{"first byte on the final candidate", fmt.Errorf("llm/upstream: time-to-first-byte exceeded 5m0s: %w", context.Canceled), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerDownFailure(tc.err, tc.final); got != tc.want {
				t.Fatalf("providerDownFailure(%v, %t) = %t, want %t", tc.err, tc.final, got, tc.want)
			}
		})
	}
}

func TestRecordProviderCircuitOutcomeSkipsDisconnectsAndAcceptedCalls(t *testing.T) {
	enableProviderCircuitsForTest(t)
	option := llm.InvokeOptions{Provider: "circuit-outcome", Model: "circuit-outcome/glm"}
	failure := &upstreamerror.Error{Status: 502, Body: "{}"}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for range 5 {
		recordProviderCircuitOutcome(canceled, option, failure, &routeSelectingWriter{}, false, "test")
		recordProviderCircuitOutcome(context.Background(), option, failure, &routeSelectingWriter{opened: true}, false, "test")
		recordProviderCircuitOutcome(context.Background(), option, failure, &routeSelectingWriter{committed: true}, false, "test")
	}
	if providerCircuits.Tripped(option) {
		t.Fatal("disconnects and failures after the provider answered must not count")
	}
	for range 3 {
		recordProviderCircuitOutcome(context.Background(), option, failure, &routeSelectingWriter{}, false, "test")
	}
	if providerCircuits.Allow(option) {
		t.Fatal("three pre-acceptance 502s must open the circuit")
	}
	recordProviderCircuitOutcome(context.Background(), option, nil, &routeSelectingWriter{}, false, "test")
	if providerCircuits.Tripped(option) {
		t.Fatal("a success must close the circuit")
	}
}

func TestInvokeProviderStreamCountsOnlyTheFinalFirstByteBudget(t *testing.T) {
	enableProviderCircuitsForTest(t)
	oldBudget, oldFinal := firstByteBudget, finalCandidateFirstByteBudget
	firstByteBudget, finalCandidateFirstByteBudget = 20*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { firstByteBudget, finalCandidateFirstByteBudget = oldBudget, oldFinal })
	silent := llm.InvokeOptions{Model: "circuit-silent/reasoner", Provider: "circuit-silent", EndpointID: "silent"}
	backup := llm.InvokeOptions{Model: "circuit-silent/reasoner", Provider: "circuit-backup", EndpointID: "backup"}
	provider := streamingProviderFunc(func(ctx context.Context, w io.Writer, option llm.InvokeOptions) error {
		if option.Provider == "circuit-silent" {
			<-ctx.Done()
			return ctx.Err()
		}
		_, err := io.WriteString(w, providerStreamTestResponse)
		return err
	})
	run := func(options []llm.InvokeOptions) {
		pr, pw := io.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			invokeProviderStream(context.Background(), provider, &types.OpenAIChatRequest{Model: "circuit-silent/reasoner"},
				&types.AnthropicMessagesRequest{}, pw, options, true, nil, newSelectedRouteTracker(), "ttfb-test", true, false)
		}()
		_, _ = io.ReadAll(pr)
		<-done
	}
	// A slow first byte on a candidate with a fallback is a failover trigger,
	// not an outage.
	for range 4 {
		run([]llm.InvokeOptions{silent, backup})
	}
	if providerCircuits.Tripped(silent) {
		t.Fatal("non-final first-byte budget expiries must not count")
	}
	// On the final candidate the budget is the hang detector and counts.
	for range 3 {
		run([]llm.InvokeOptions{silent})
	}
	if providerCircuits.Allow(silent) {
		t.Fatal("three final-candidate hangs must open the circuit")
	}
}

func TestProviderRouteMemoryFastFail(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	alpha := llm.InvokeOptions{Provider: "alpha", Model: "pair/glm-5.3-flash"}
	beta := llm.InvokeOptions{Provider: "beta", Model: "pair/glm-5.3-flash"}
	small := providerRouteDemand{input: 10, output: 512}
	large := providerRouteDemand{input: 100_000, output: 512}
	open := func(option llm.InvokeOptions) {
		for range 3 {
			registry.RecordFailure(option)
		}
	}

	registry.RememberRoutes("key", large, []llm.InvokeOptions{alpha})
	open(alpha)
	if _, refused := registry.FastFail("key", small); refused {
		t.Fatal("a smaller request may have candidates a larger one was filtered from")
	}
	if wait, refused := registry.FastFail("key", large); !refused || wait != time.Minute {
		t.Fatalf("an equal request whose only circuit is open must be refused: wait=%s refused=%t", wait, refused)
	}
	if _, refused := registry.FastFail("other-key", large); refused {
		t.Fatal("another credential or routing policy has no memory")
	}

	// A smaller authorize widens the set and lowers the demand floor; one
	// closed circuit in the union means no refusal.
	registry.RememberRoutes("key", small, []llm.InvokeOptions{alpha, beta})
	if _, refused := registry.FastFail("key", small); refused {
		t.Fatal("a closed circuit in the remembered set must not be refused")
	}
	open(beta)
	if _, refused := registry.FastFail("key", small); !refused {
		t.Fatal("every remembered circuit open must be refused")
	}
	if got := registry.Stats().FastFailRefusals; got != 2 {
		t.Fatalf("fast fail refusals=%d, want 2", got)
	}

	// Refusals do not refresh the memory; it expires 30 s after the last
	// authorize even while every circuit is still open.
	now = now.Add(31 * time.Second)
	if _, refused := registry.FastFail("key", small); refused {
		t.Fatal("expired memory must not refuse")
	}
	if _, kept := registry.routes["key"]; kept {
		t.Fatal("expired memory must be dropped")
	}

	// A candidate without a provider can never be open, so the set is
	// incomplete and never refuses.
	registry.RememberRoutes("legacy", small, []llm.InvokeOptions{alpha, {Model: "pair/glm-5.3-flash"}})
	if _, refused := registry.FastFail("legacy", small); refused {
		t.Fatal("an incomplete set must not refuse")
	}

	registry.routeTTL = 0
	registry.RememberRoutes("disabled", small, []llm.InvokeOptions{alpha})
	if _, refused := registry.FastFail("disabled", small); refused {
		t.Fatal("route memory disabled must not refuse")
	}
}

func TestProviderRouteMemoryKeyCoversRoutingNotContent(t *testing.T) {
	base := func() *types.OpenAIChatRequest {
		return &types.OpenAIChatRequest{
			Model:    "solo/glm-5.3-flash",
			Messages: []types.OpenAIChatMessage{{Role: "user", Content: "first prompt"}},
		}
	}
	key := providerRouteMemoryKey(context.Background(), "secret-bearer", "chat.completions", base())
	if key == "" || strings.Contains(key, "secret-bearer") || strings.Contains(key, trustedrouter.LookupHash("secret-bearer")) {
		t.Fatalf("key must be a digest that retains neither the bearer nor its lookup hash: %q", key)
	}
	same := base()
	same.Messages = []types.OpenAIChatMessage{{Role: "user", Content: "a different prompt"}}
	same.User, same.SessionID, same.IdempotencyKey = "user-1", "session-1", "idem-1"
	if got := providerRouteMemoryKey(context.Background(), "secret-bearer", "chat.completions", same); got != key {
		t.Fatal("content, attribution and idempotency do not route and must not change the key")
	}
	fallbacks := false
	for name, mutate := range map[string]func(*types.OpenAIChatRequest){
		"model":           func(r *types.OpenAIChatRequest) { r.Model = "solo/glm-5.2" },
		"models":          func(r *types.OpenAIChatRequest) { r.Models = []string{"solo/glm-5.2"} },
		"provider order":  func(r *types.OpenAIChatRequest) { r.Provider = &types.ProviderRouting{Order: types.StringList{"solo"}} },
		"allow fallbacks": func(r *types.OpenAIChatRequest) { r.AllowFallbacks = &fallbacks },
		"service tier":    func(r *types.OpenAIChatRequest) { r.ServiceTier = "flex" },
		"parameters":      func(r *types.OpenAIChatRequest) { r.RequestedParameters = []string{"tools"} },
		"stream":          func(r *types.OpenAIChatRequest) { r.Stream = true },
	} {
		changed := base()
		mutate(changed)
		if providerRouteMemoryKey(context.Background(), "secret-bearer", "chat.completions", changed) == key {
			t.Fatalf("%s routes and must change the key", name)
		}
	}
	if providerRouteMemoryKey(context.Background(), "other-bearer", "chat.completions", base()) == key {
		t.Fatal("a different credential must change the key")
	}
	if providerRouteMemoryKey(context.Background(), "secret-bearer", "messages", base()) == key {
		t.Fatal("a different route type must change the key")
	}
	if providerRouteMemoryKey(context.Background(), "", "chat.completions", base()) != "" {
		t.Fatal("no credential means no memory")
	}
}

func TestRetryAfterSecondsRoundsUpToAtLeastOne(t *testing.T) {
	for _, tc := range []struct {
		wait time.Duration
		want int
	}{{0, 1}, {-time.Second, 1}, {time.Millisecond, 1}, {time.Second, 1}, {1500 * time.Millisecond, 2}, {time.Minute, 60}} {
		if got := retryAfterSeconds(tc.wait); got != tc.want {
			t.Fatalf("retryAfterSeconds(%s)=%d, want %d", tc.wait, got, tc.want)
		}
	}
}
