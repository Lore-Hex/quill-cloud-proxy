package main

import (
	"bytes"
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

// fail admits one attempt for tenant and fails it provider-down.
func failCircuitAttempt(t *testing.T, registry *providerCircuitRegistry, option llm.InvokeOptions, tenant string) bool {
	t.Helper()
	ticket, _, ok := registry.Admit(option, tenant)
	if !ok {
		t.Fatalf("attempt for tenant %q was refused", tenant)
	}
	return registry.Fail(ticket)
}

func circuitBlocked(registry *providerCircuitRegistry, option llm.InvokeOptions, tenant string) bool {
	_, blocked := registry.Blocked(option, tenant)
	return blocked
}

func TestProviderCircuitKeyUsesFullModelID(t *testing.T) {
	t.Setenv("TR_REGION", "europe-west4")
	key := providerCircuitKey(llm.InvokeOptions{Provider: "openai", Model: "openai/gpt-4.1-mini:free", EndpointID: "openai/gpt-4.1-mini@openai/byok"})
	if want := "openai|europe-west4|openai/gpt-4.1-mini:free"; key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
	if providerCircuitKey(llm.InvokeOptions{Provider: "openai", Model: "openai/gpt-5.5"}) == providerCircuitKey(llm.InvokeOptions{Provider: "openai", Model: "openai/gpt-4.1-mini"}) {
		t.Fatal("sibling models on one provider must not share a circuit")
	}
}

func TestProviderCircuitTenantCircuitOpensProbesOnceAndReopens(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	option := llm.InvokeOptions{Provider: "solo", Model: "solo/glm-5.3-flash"}

	for i := 1; i <= 2; i++ {
		if failCircuitAttempt(t, registry, option, "tenant-a") || circuitBlocked(registry, option, "tenant-a") {
			t.Fatalf("failure %d must not open the tenant circuit", i)
		}
	}
	if !failCircuitAttempt(t, registry, option, "tenant-a") {
		t.Fatal("third consecutive failure must open the tenant circuit")
	}
	if wait, blocked := registry.Blocked(option, "tenant-a"); !blocked || wait != time.Minute {
		t.Fatalf("tenant-a: wait=%s blocked=%t, want 1m true", wait, blocked)
	}
	if circuitBlocked(registry, option, "tenant-b") {
		t.Fatal("one tenant's failures must not refuse another tenant")
	}

	// Half-open: exactly one probe in flight; the others keep being refused.
	now = now.Add(61 * time.Second)
	probe, _, ok := registry.Admit(option, "tenant-a")
	if !ok || !registry.Tripped(probe) {
		t.Fatal("half-open circuit must admit one probe, and it gets one try")
	}
	if wait, blocked := registry.Blocked(option, "tenant-a"); !blocked || wait != providerCircuitProbeRetry {
		t.Fatalf("second attempt during the probe: wait=%s blocked=%t", wait, blocked)
	}
	// A neutral outcome frees the probe for the next attempt.
	registry.Release(probe)
	probe, _, ok = registry.Admit(option, "tenant-a")
	if !ok {
		t.Fatal("released probe must let the next attempt probe")
	}
	if !registry.Fail(probe) || !circuitBlocked(registry, option, "tenant-a") {
		t.Fatal("a failed probe must reopen the tenant circuit immediately")
	}
	now = now.Add(61 * time.Second)
	probe, _, ok = registry.Admit(option, "tenant-a")
	if !ok {
		t.Fatal("probe after the second window")
	}
	registry.Succeed(probe)
	if circuitBlocked(registry, option, "tenant-a") || len(registry.states) != 0 {
		t.Fatal("a fresh success must close every circuit on the route")
	}
	if got := registry.Stats().Opens; got != 2 {
		t.Fatalf("opens=%d, want 2", got)
	}
}

func TestProviderCircuitSharedOpensOnlyForDistinctTenants(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	option := llm.InvokeOptions{Provider: "shared", Model: "shared/glm-5.3-flash"}

	// One tenant failing many times (its failures are refunded, so they cost
	// it nothing) never refuses anyone else.
	for i := 0; i < 3; i++ {
		failCircuitAttempt(t, registry, option, "tenant-a")
	}
	now = now.Add(61 * time.Second)
	for i := 0; i < 5; i++ {
		ticket, _, ok := registry.Admit(option, "tenant-a")
		if ok {
			registry.Fail(ticket)
		}
		now = now.Add(61 * time.Second)
	}
	if circuitBlocked(registry, option, "tenant-b") {
		t.Fatal("one tenant must not open the shared circuit")
	}
	failCircuitAttempt(t, registry, option, "tenant-b")
	if circuitBlocked(registry, option, "tenant-c") {
		t.Fatal("two tenants must not open the shared circuit")
	}
	if !failCircuitAttempt(t, registry, option, "tenant-c") {
		t.Fatal("the third distinct tenant must open the shared circuit")
	}
	if !circuitBlocked(registry, option, "tenant-new") {
		t.Fatal("an open shared circuit refuses every tenant")
	}

	// Half-open: one probe at a time, and reopening needs three NEW distinct
	// tenants; one tenant probing repeatedly cannot keep it shut for others.
	now = now.Add(61 * time.Second)
	for i := 0; i < 2; i++ {
		probe, _, ok := registry.Admit(option, "tenant-d")
		if !ok {
			t.Fatalf("probe %d refused", i)
		}
		if circuitBlocked(registry, option, "tenant-e") != true {
			t.Fatal("other tenants must wait while a probe is in flight")
		}
		registry.Fail(probe)
	}
	if circuitBlocked(registry, option, "tenant-e") {
		t.Fatal("one tenant's probe failures must not reopen the shared circuit")
	}
	failCircuitAttempt(t, registry, option, "tenant-e")
	if !failCircuitAttempt(t, registry, option, "tenant-f") || !circuitBlocked(registry, option, "tenant-new") {
		t.Fatal("three distinct tenants failing in half-open must reopen it")
	}
}

func TestProviderCircuitBYOKIsNeverShared(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	byok := llm.InvokeOptions{Provider: "openai", Model: "openai/gpt-5.5", UsageType: "BYOK"}
	credits := llm.InvokeOptions{Provider: "openai", Model: "openai/gpt-5.5", UsageType: "Credits"}
	for _, tenant := range []string{"tenant-a", "tenant-b", "tenant-c"} {
		for i := 0; i < 3; i++ {
			failCircuitAttempt(t, registry, byok, tenant)
		}
	}
	if !circuitBlocked(registry, byok, "tenant-a") {
		t.Fatal("a tenant's own BYOK failures must refuse that tenant's BYOK route")
	}
	if circuitBlocked(registry, byok, "tenant-d") || circuitBlocked(registry, credits, "tenant-a") || circuitBlocked(registry, credits, "tenant-d") {
		t.Fatal("BYOK failures must never refuse another tenant or the platform route")
	}
	if registry.Admit(byok, ""); circuitBlocked(registry, byok, "") {
		t.Fatal("BYOK without a tenant is untracked")
	}
}

func TestProviderCircuitStaleOutcomesDoNotCount(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	option := llm.InvokeOptions{Provider: "stale", Model: "stale/glm-5.3-flash"}

	// Two attempts admitted before the outage...
	longStream, _, _ := registry.Admit(option, "tenant-a")
	slowFailure, _, _ := registry.Admit(option, "tenant-f")
	now = now.Add(time.Second)
	for _, tenant := range []string{"tenant-b", "tenant-c", "tenant-d"} {
		failCircuitAttempt(t, registry, option, tenant)
	}
	// ...a stream that completes during it must not close the circuit...
	registry.Succeed(longStream)
	if !circuitBlocked(registry, option, "tenant-e") {
		t.Fatal("a success from an attempt that started before the circuit opened closed it")
	}
	// ...and a failure that lands in half-open does not count toward
	// reopening, nor take the probe.
	now = now.Add(61 * time.Second)
	registry.Fail(slowFailure)
	failCircuitAttempt(t, registry, option, "tenant-g")
	failCircuitAttempt(t, registry, option, "tenant-h")
	if circuitBlocked(registry, option, "tenant-i") {
		t.Fatal("a stale failure counted toward reopening the shared circuit")
	}
}

func TestProviderCircuitStateIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	registry.maxStates = 2
	options := []llm.InvokeOptions{
		{Provider: "first", Model: "first/model-a"},
		{Provider: "second", Model: "second/model-b"},
		{Provider: "third", Model: "third/model-c"},
	}
	for _, option := range options {
		failCircuitAttempt(t, registry, option, "")
		now = now.Add(time.Second)
	}
	// An unattributed failure records nothing at all.
	if len(registry.states) != 0 {
		t.Fatalf("unattributed failures stored %d states", len(registry.states))
	}
	for _, option := range options {
		failCircuitAttempt(t, registry, option, "tenant-a")
		now = now.Add(time.Second)
	}
	if len(registry.states) != 2 {
		t.Fatalf("circuit states = %d, want 2", len(registry.states))
	}
	if _, ok := registry.states[providerCircuitKey(options[0])]; ok {
		t.Fatal("oldest circuit state was not evicted")
	}
}

func TestProviderCircuitIgnoresUntrackedAndDisabled(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	untracked := llm.InvokeOptions{Model: "legacy-model"}
	for range 5 {
		failCircuitAttempt(t, registry, untracked, "tenant-a")
	}
	if circuitBlocked(registry, untracked, "tenant-a") || len(registry.states) != 0 {
		t.Fatal("an option without a provider must never be tracked")
	}
	registry.enabled = false
	tracked := llm.InvokeOptions{Provider: "solo", Model: "solo/glm"}
	for range 5 {
		failCircuitAttempt(t, registry, tracked, "tenant-a")
	}
	if circuitBlocked(registry, tracked, "tenant-a") {
		t.Fatal("a disabled registry must admit everything")
	}
}

func TestProviderDownFailureClassification(t *testing.T) {
	status := func(code int) error { return &upstreamerror.Error{Status: code, Body: "{}"} }
	_, redact := upstreamerror.WithCredentialRedaction(context.Background(), "token")
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
		{"402 out of funds", status(402), false, true},
		{"400 credit balance too low", &upstreamerror.Error{Status: 400, Body: `{"error":{"message":"Your credit balance is too low"}}`}, false, true},
		{"gateway local 402", &upstreamerror.Local{Err: status(402)}, false, false},
		{"connection refused", errors.New("llm/solo: invoke: dial tcp: connect: connection refused"), false, true},
		{"connection reset", errors.New("llm/solo: invoke: read: connection reset by peer"), false, true},
		{"dns", errors.New("llm/solo: invoke: dial tcp: lookup solo.invalid: no such host"), false, true},
		{"eof before response", fmt.Errorf("llm/solo: invoke: %w", io.EOF), false, true},
		{"tls handshake", errors.New("llm/solo: invoke: remote error: tls: handshake failure"), false, true},
		{"gateway metadata token 503", &upstreamerror.Local{Err: errors.New("llm/gcp: metadata token http 503: unavailable")}, false, false},
		{"gateway metadata token 503 after redaction", redact(&upstreamerror.Local{Err: errors.New("llm/gcp: metadata token http 503: unavailable")}), false, false},
		{"gateway metadata server refused", &upstreamerror.Local{Err: errors.New("llm/gcp: metadata token: connection refused")}, false, false},
		{"gateway retention check", &upstreamerror.Local{Err: status(503)}, false, false},
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
	attempt := func(ctx context.Context, err error, writer *routeSelectingWriter) {
		ticket, _, ok := providerCircuits.Admit(option, "tenant-outcome")
		if !ok {
			t.Fatal("attempt refused")
		}
		recordProviderCircuitOutcome(ctx, ticket, option, err, writer, false, "test")
	}
	for range 5 {
		attempt(canceled, failure, &routeSelectingWriter{})
		attempt(context.Background(), failure, &routeSelectingWriter{opened: true})
		attempt(context.Background(), failure, &routeSelectingWriter{committed: true})
	}
	if _, blocked := providerCircuits.Blocked(option, "tenant-outcome"); blocked {
		t.Fatal("disconnects and failures after the provider answered must not count")
	}
	for range 3 {
		attempt(context.Background(), failure, &routeSelectingWriter{})
	}
	if _, blocked := providerCircuits.Blocked(option, "tenant-outcome"); !blocked {
		t.Fatal("three pre-acceptance 502s must open the tenant circuit")
	}
}

func TestRouteSelectingWriterAnsweredDoesNotCommit(t *testing.T) {
	writer := &routeSelectingWriter{w: io.Discard, streaming: true, tracker: newSelectedRouteTracker()}
	upstreamerror.Answered(recordedWriter{out: writer, recorder: &generationRecorder{}})
	if !writer.Accepted() || writer.ResponseCommitted() {
		t.Fatalf("answered=%t committed=%t, want accepted without commitment", writer.Accepted(), writer.ResponseCommitted())
	}
	opened := &routeSelectingWriter{w: io.Discard, tracker: newSelectedRouteTracker()}
	upstreamerror.Open(recordedWriter{out: opened, recorder: &generationRecorder{}})
	if !opened.Accepted() {
		t.Fatal("Open through a writer without UpstreamOpened must still mark the provider as answered")
	}
}

func TestInvokeProviderStreamCountsOnlyTheFinalFirstByteBudget(t *testing.T) {
	enableProviderCircuitsForTest(t)
	oldBudget, oldFinal := firstByteBudget, finalCandidateFirstByteBudget
	firstByteBudget, finalCandidateFirstByteBudget = 20*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { firstByteBudget, finalCandidateFirstByteBudget = oldBudget, oldFinal })
	silent := llm.InvokeOptions{Model: "circuit-silent/reasoner", Provider: "circuit-silent", EndpointID: "silent"}
	backup := llm.InvokeOptions{Model: "circuit-silent/reasoner", Provider: "circuit-backup", EndpointID: "backup"}
	authorization := &trustedrouter.Authorization{WorkspaceID: "ws-silent"}
	tenant := providerCircuitTenant(authorization)
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
				&types.AnthropicMessagesRequest{}, pw, options, true, authorization, newSelectedRouteTracker(), "ttfb-test", true, false)
		}()
		_, _ = io.ReadAll(pr)
		<-done
	}
	// A slow first byte on a candidate with a fallback is a failover trigger,
	// not an outage.
	for range 4 {
		run([]llm.InvokeOptions{silent, backup})
	}
	if _, blocked := providerCircuits.Blocked(silent, tenant); blocked {
		t.Fatal("non-final first-byte budget expiries must not count")
	}
	// On the final candidate the budget is the hang detector and counts.
	for range 3 {
		run([]llm.InvokeOptions{silent})
	}
	if _, blocked := providerCircuits.Blocked(silent, tenant); !blocked {
		t.Fatal("three final-candidate hangs must open the tenant circuit")
	}
}

func TestProviderRouteMemoryFastFail(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	alpha := llm.InvokeOptions{Provider: "alpha", Model: "pair/glm-5.3-flash"}
	beta := llm.InvokeOptions{Provider: "beta", Model: "pair/glm-5.3-flash"}
	const tenant = "tenant-a"
	open := func(option llm.InvokeOptions) {
		for range 3 {
			failCircuitAttempt(t, registry, option, tenant)
		}
	}

	failCircuitAttempt(t, registry, alpha, tenant)
	registry.RememberRoutes("key", 100_000, []llm.InvokeOptions{alpha}, tenant)
	failCircuitAttempt(t, registry, alpha, tenant)
	failCircuitAttempt(t, registry, alpha, tenant)
	if _, refused := registry.FastFail("key", 10); refused {
		t.Fatal("a smaller request may have candidates a larger one was filtered from")
	}
	if wait, refused := registry.FastFail("key", 100_000); !refused || wait != time.Minute {
		t.Fatalf("an equal request whose only circuit refuses must be refused: wait=%s refused=%t", wait, refused)
	}
	if _, refused := registry.FastFail("other-key", 100_000); refused {
		t.Fatal("another credential or routing policy has no memory")
	}

	// A smaller authorize widens the set and lowers the demand floor; one
	// admitting candidate in the union means no refusal.
	registry.RememberRoutes("key", 10, []llm.InvokeOptions{alpha, beta}, tenant)
	if _, refused := registry.FastFail("key", 10); refused {
		t.Fatal("an admitting candidate in the remembered set must not be refused")
	}
	open(beta)
	if _, refused := registry.FastFail("key", 10); !refused {
		t.Fatal("every remembered candidate refusing must be refused")
	}
	if got := registry.Stats().FastFailRefusals; got != 2 {
		t.Fatalf("fast fail refusals=%d, want 2", got)
	}

	// Refusals do not refresh the memory; it expires 30 s after the last
	// authorize even while every circuit is still open.
	now = now.Add(31 * time.Second)
	if _, refused := registry.FastFail("key", 10); refused {
		t.Fatal("expired memory must not refuse")
	}
	if _, kept := registry.routes["key"]; kept {
		t.Fatal("expired memory must be dropped")
	}

	// A candidate without a provider can never refuse, so the set is
	// incomplete and never refuses.
	registry.RememberRoutes("legacy", 10, []llm.InvokeOptions{alpha, {Model: "pair/glm-5.3-flash"}}, tenant)
	if _, refused := registry.FastFail("legacy", 10); refused {
		t.Fatal("an incomplete set must not refuse")
	}

	registry.routeTTL = 0
	registry.RememberRoutes("disabled", 10, []llm.InvokeOptions{alpha}, tenant)
	if _, refused := registry.FastFail("disabled", 10); refused {
		t.Fatal("route memory disabled must not refuse")
	}
}

func TestProviderRouteMemoryIsWrittenOnlyForFailingCandidates(t *testing.T) {
	now := time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC)
	registry := newTestProviderCircuitRegistry(&now)
	healthy := llm.InvokeOptions{Provider: "healthy", Model: "healthy/model"}
	for i := 0; i < 50; i++ {
		registry.RememberRoutes(fmt.Sprintf("key-%d", i), 10, []llm.InvokeOptions{healthy}, "tenant-a")
	}
	if len(registry.routes) != 0 {
		t.Fatalf("healthy authorizes wrote %d route memory entries", len(registry.routes))
	}
	failCircuitAttempt(t, registry, healthy, "tenant-b")
	registry.RememberRoutes("key-0", 10, []llm.InvokeOptions{healthy}, "tenant-a")
	if len(registry.routes) != 1 {
		t.Fatalf("a candidate with recorded failures must be remembered, got %d entries", len(registry.routes))
	}
}

func TestProviderRouteDemandMatchesControlPlaneContextFit(t *testing.T) {
	maxTokens := 300
	req := &types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	input := trustedrouter.EstimateInputTokens(req)
	if got := providerRouteDemandFor(req); int(got) != input {
		t.Fatalf("demand without max_tokens = %d, want input only %d (the control plane uses 0)", got, input)
	}
	req.MaxTokens = &maxTokens
	if got := providerRouteDemandFor(req); int(got) != input+maxTokens {
		t.Fatalf("demand = %d, want input+max_tokens %d", got, input+maxTokens)
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

func TestProviderCircuitRetryHeaders(t *testing.T) {
	for _, tc := range []struct {
		wait time.Duration
		want int
	}{{0, 1}, {-time.Second, 1}, {time.Millisecond, 1}, {time.Second, 1}, {1500 * time.Millisecond, 2}, {time.Minute, 60}} {
		if got := retryAfterSeconds(tc.wait); got != tc.want {
			t.Fatalf("retryAfterSeconds(%s)=%d, want %d", tc.wait, got, tc.want)
		}
	}
	if got := providerCircuitRetryHeaders(&providerCircuitOpenError{retryAfter: time.Minute}); got["Retry-After"] != "60" || got[shouldRetryHeader] != "true" {
		t.Fatalf("free refusal headers = %v", got)
	}
	if got := providerCircuitRetryHeaders(&providerCircuitOpenError{retryAfter: time.Minute, spent: true}); got[shouldRetryHeader] != "false" {
		t.Fatalf("a request that already paid for something must not be told retrying is free: %v", got)
	}
	ctx := context.WithValue(context.Background(), polyphemusContextKey{}, &polyphemusReceipt{CostMicrodollars: 7})
	if !polyphemusSelectionCharged(ctx) || polyphemusSelectionCharged(context.WithValue(context.Background(), polyphemusContextKey{}, &polyphemusReceipt{Pinned: true})) {
		t.Fatal("only a charged Polyphemus selection makes the refusal spent")
	}
}

// A Polyphemus request already paid for its model selection, so a circuit
// refusal after authorize must not tell the client a retry is free.
func TestProviderCircuitRefusalAfterAChargedSelectionIsNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	option := llm.InvokeOptions{Provider: "circuit-polyphemus", Model: "circuit-polyphemus/model", EndpointID: "down", UsageType: "Credits"}
	authorization := &trustedrouter.Authorization{WorkspaceID: "ws-polyphemus"}
	tenant := providerCircuitTenant(authorization)
	for range 3 {
		ticket, _, _ := providerCircuits.Admit(option, tenant)
		providerCircuits.Fail(ticket)
	}
	for _, charged := range []bool{false, true} {
		ctx := context.Background()
		if charged {
			ctx = context.WithValue(ctx, polyphemusContextKey{}, &polyphemusReceipt{CostMicrodollars: 9})
		}
		pr, pw := io.Pipe()
		go invokeProviderStream(ctx, streamingProviderFunc(func(context.Context, io.Writer, llm.InvokeOptions) error {
			t.Error("an open circuit was called")
			return nil
		}), &types.OpenAIChatRequest{Model: option.Model}, &types.AnthropicMessagesRequest{}, pw,
			[]llm.InvokeOptions{option}, true, authorization, newSelectedRouteTracker(), "polyphemus-circuit", true, true)
		_, err := io.ReadAll(pr)
		var out bytes.Buffer
		writeUpstreamError(&out, "responses", err, authorization)
		response, body := readRawHTTPResponse(t, out.Bytes())
		want := "true"
		if charged {
			want = "false"
		}
		if response.StatusCode != 503 || response.Header.Get("Retry-After") != "60" || response.Header.Get("X-Should-Retry") != want {
			t.Fatalf("charged=%t: status=%d headers=%v body=%s", charged, response.StatusCode, response.Header, body)
		}
	}
}
