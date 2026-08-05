package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type fakeNativeAuthorizer struct {
	mu                 sync.Mutex
	provider           string
	managed            bool
	custom             bool
	ineligible         bool
	failAuthorization  bool
	failIndex          int
	authorizationError error
	authorized         []int
	settled            []int
	settleCalls        []int
	usages             []NativeUsage
	refunded           []int
	refundCalls        []int
	settledUsage       map[int]Usage
	refundedIndexes    map[int]bool
	settleError        error
}

func (a *fakeNativeAuthorizer) Authorize(
	_ context.Context,
	_ string,
	_ string,
	_ []byte,
	idempotencyKey string,
) (NativeAuthorization, error) {
	separator := strings.LastIndexByte(idempotencyKey, ':')
	index, _ := strconv.Atoi(idempotencyKey[separator+1:])
	a.mu.Lock()
	if a.failAuthorization && index == a.failIndex {
		a.mu.Unlock()
		if a.authorizationError != nil {
			return NativeAuthorization{}, a.authorizationError
		}
		return NativeAuthorization{}, errors.New("native authorization rejected")
	}
	a.authorized = append(a.authorized, index)
	a.mu.Unlock()
	handle, _ := json.Marshal(map[string]int{"index": index})
	return NativeAuthorization{
		Handle:              handle,
		NativeBatchEligible: !a.ineligible,
		ManagedPathOnly:     a.managed,
		CustomModel:         a.custom,
		Routes: []NativeRoute{{
			Provider:      a.provider,
			EndpointID:    "endpoint-native",
			Model:         "test/model",
			UpstreamModel: "upstream/model",
			UsageType:     NativeUsageTypeCredit,
		}},
	}, nil
}

type concurrencyNativeAuthorizer struct {
	base    *fakeNativeAuthorizer
	mu      sync.Mutex
	active  int
	maximum int
	started chan struct{}
	release <-chan struct{}
}

func (a *concurrencyNativeAuthorizer) Authorize(
	ctx context.Context,
	key string,
	endpoint string,
	body []byte,
	idempotencyKey string,
) (NativeAuthorization, error) {
	a.mu.Lock()
	a.active++
	if a.active > a.maximum {
		a.maximum = a.active
	}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.active--
		a.mu.Unlock()
	}()
	a.started <- struct{}{}
	select {
	case <-a.release:
	case <-ctx.Done():
		return NativeAuthorization{}, ctx.Err()
	}
	return a.base.Authorize(ctx, key, endpoint, body, idempotencyKey)
}

func (a *concurrencyNativeAuthorizer) Settle(
	ctx context.Context,
	authorization NativeAuthorization,
	usage NativeUsage,
) (Usage, error) {
	return a.base.Settle(ctx, authorization, usage)
}

func (a *concurrencyNativeAuthorizer) Refund(
	ctx context.Context,
	authorization NativeAuthorization,
	status int,
	reason string,
	elapsed time.Duration,
) (NativeRefund, error) {
	return a.base.Refund(ctx, authorization, status, reason, elapsed)
}

func TestNativeRetentionEligibilityFailsClosed(t *testing.T) {
	t.Parallel()

	baseJob := job{Batch: Batch{Endpoint: "/v1/chat/completions", Model: "openai/gpt-5.5"}}
	tests := []struct {
		name     string
		job      job
		body     string
		eligible bool
	}{
		{name: "direct", job: baseJob, body: `{"messages":[{"role":"user","content":"hi"}]}`, eligible: true},
		{name: "zdr alias", job: job{Batch: Batch{Endpoint: "/v1/chat/completions", Model: "trustedrouter/zdr"}}, body: `{}`},
		{name: "model variant suffix", job: baseJob, body: `{"model":"openai/gpt-5.5:zdr"}`},
		{name: "orchestration alias", job: job{Batch: Batch{Endpoint: "/v1/chat/completions", Model: "trustedrouter/synth"}}, body: `{}`},
		{name: "fallback array", job: baseJob, body: `{"models":["openai/gpt-5.5"]}`},
		{name: "deny collection", job: baseJob, body: `{"provider":{"data_collection":"deny"}}`},
		{name: "privacy tier", job: baseJob, body: `{"provider":{"min_privacy":"e2e"}}`},
		{name: "jurisdiction", job: baseJob, body: `{"provider":{"jurisdiction":"eu"}}`},
		{name: "byok", job: baseJob, body: `{"provider":{"usage":"byok"}}`},
		{name: "unknown provider privacy", job: baseJob, body: `{"provider":{"zdr":true}}`},
		{name: "unknown top-level privacy", job: baseJob, body: `{"messages":[],"future_privacy_mode":"deny"}`},
		{name: "unknown top-level option", job: baseJob, body: `{"messages":[],"future_parameter":true}`},
		{name: "top-level e2e", job: baseJob, body: `{"e2e":true}`},
		{name: "regional routing", job: baseJob, body: `{"region":"eu"}`},
		{name: "service tier", job: baseJob, body: `{"service_tier":"priority"}`},
		{name: "store false", job: baseJob, body: `{"store":false}`},
		{name: "reasoning effort only", job: baseJob, body: `{"messages":[],"reasoning":{"effort":"high"}}`, eligible: true},
		{name: "router reasoning max tokens", job: baseJob, body: `{"messages":[],"reasoning":{"max_tokens":1000}}`},
		{name: "responses", job: job{Batch: Batch{Endpoint: "/v1/responses", Model: "openai/gpt-5.5"}}, body: `{}`},
		{name: "invalid json", job: baseJob, body: `{`},
		{name: "embedding direct", job: job{Batch: Batch{Endpoint: "/v1/embeddings", Model: "openai/text-embedding-3-small"}}, body: `{"model":"openai/text-embedding-3-small","input":"hi","dimensions":256}`, eligible: true},
		{name: "embedding input type", job: job{Batch: Batch{Endpoint: "/v1/embeddings", Model: "openai/text-embedding-3-small"}}, body: `{"input":"hi","input_type":"query"}`},
		{name: "embedding unknown field", job: job{Batch: Batch{Endpoint: "/v1/embeddings", Model: "openai/text-embedding-3-small"}}, body: `{"input":"hi","future_privacy_mode":"deny"}`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := nativeRetentionAllowed(test.job, []Request{{Body: json.RawMessage(test.body)}})
			if got != test.eligible {
				t.Fatalf("nativeRetentionAllowed = %t, want %t", got, test.eligible)
			}
		})
	}
}

func TestNativeStateValidationFailsClosed(t *testing.T) {
	t.Parallel()

	valid := nativeState{
		Version:       1,
		Stage:         nativeStageSubmitted,
		Token:         "tr_batch_token",
		Provider:      "parasail",
		EndpointID:    "endpoint",
		Model:         "test/model",
		UpstreamModel: "upstream/model",
		Submission: NativeProviderJob{
			Provider: "parasail",
			ID:       "provider-job",
			Token:    "tr_batch_token",
		},
	}
	if !valid.valid() {
		t.Fatal("expected valid submitted state")
	}

	tests := map[string]nativeState{
		"unknown stage":         func() nativeState { state := valid; state.Stage = "mystery"; return state }(),
		"missing provider job":  func() nativeState { state := valid; state.Submission.ID = ""; return state }(),
		"provider mismatch":     func() nativeState { state := valid; state.Submission.Provider = "openai"; return state }(),
		"idempotency mismatch":  func() nativeState { state := valid; state.Submission.Token = "other"; return state }(),
		"negative submit count": func() nativeState { state := valid; state.SubmitAttempts = -1; return state }(),
	}
	for name, state := range tests {
		state := state
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if state.valid() {
				t.Fatalf("malformed state was accepted: %#v", state)
			}
		})
	}
}

func TestCommonNativeRouteAcceptsControlPlaneCreditsCasing(t *testing.T) {
	t.Parallel()

	service := newNativeService(
		t,
		newMemoryObjectStore(),
		&fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	route := NativeRoute{
		Provider: "openai", EndpointID: "openai-endpoint",
		Model: "openai/gpt-5.5", UpstreamModel: "gpt-5.5", UsageType: "Credits",
	}
	selected, ok := service.commonNativeRoute(
		"/v1/chat/completions",
		[]NativeAuthorization{
			{NativeBatchEligible: true, Routes: []NativeRoute{route}},
			{NativeBatchEligible: true, Routes: []NativeRoute{route}},
		},
	)
	if !ok || selected != route {
		t.Fatalf("selected=%#v ok=%t", selected, ok)
	}
}

func TestCommonNativeRouteDoesNotOverrideFirstProviderPreference(t *testing.T) {
	t.Parallel()

	service := newNativeService(
		t,
		newMemoryObjectStore(),
		&fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	nonNative := NativeRoute{
		Provider: "together", EndpointID: "together-endpoint",
		Model: "test/model", UpstreamModel: "upstream/model", UsageType: NativeUsageTypeCredit,
	}
	native := NativeRoute{
		Provider: "openai", EndpointID: "openai-endpoint",
		Model: "test/model", UpstreamModel: "upstream/model", UsageType: NativeUsageTypeCredit,
	}
	_, ok := service.commonNativeRoute(
		"/v1/chat/completions",
		[]NativeAuthorization{
			{NativeBatchEligible: true, Routes: []NativeRoute{nonNative, native}},
			{NativeBatchEligible: true, Routes: []NativeRoute{nonNative, native}},
		},
	)
	if ok {
		t.Fatal("native route overrode the first provider preference")
	}
}

func TestNativeBatchLargerThanProviderLimitStaysOnManagedPath(t *testing.T) {
	t.Parallel()

	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai"}
	service := newNativeService(
		t, newMemoryObjectStore(), authorizer, provider, &fakeManagedExecutor{}, time.Now,
	)
	requests := make([]Request, nativeMaxProviderItems+1)
	pending := make([]int, len(requests))
	for index := range requests {
		pending[index] = index
		requests[index] = Request{
			CustomID: fmt.Sprintf("item-%d", index),
			Body:     json.RawMessage(`{"model":"test/model","messages":[]}`),
		}
	}
	outcome, err := service.tryNative(
		t.Context(),
		job{Batch: Batch{ID: "batch_native_item_limit", Endpoint: "/v1/chat/completions", Model: "test/model"}},
		"lookup-hash", pending, requests,
	)
	if err != nil || outcome != nativeNotHandled {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if len(authorizer.authorized) != 0 || provider.submitCalls != 0 {
		t.Fatalf("authorized=%d submitted=%d", len(authorizer.authorized), provider.submitCalls)
	}
}

func TestNativeSubmitRetrySafetyDistinguishesPreSubmitFromAmbiguousCreate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "upload transport", err: &nativeProviderTransportError{operation: "upload"}, want: true},
		{name: "create transport", err: &nativeProviderTransportError{operation: "/batches"}},
		{name: "upload 500", err: &nativeProviderHTTPError{operation: "upload", status: 500}, want: true},
		{name: "create 500", err: &nativeProviderHTTPError{operation: "/batches", status: 500}},
		{name: "create 408", err: &nativeProviderHTTPError{operation: "/batches", status: 408}},
		{name: "create 409", err: &nativeProviderHTTPError{operation: "/batches", status: 409}},
		{name: "create 425", err: &nativeProviderHTTPError{operation: "/batches", status: 425}, want: true},
		{name: "create 429", err: &nativeProviderHTTPError{operation: "/batches", status: 429}, want: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := nativeSubmitCanRetryDirectly(test.err); got != test.want {
				t.Fatalf("nativeSubmitCanRetryDirectly = %t, want %t", got, test.want)
			}
		})
	}
}

func (a *fakeNativeAuthorizer) Settle(
	_ context.Context,
	authorization NativeAuthorization,
	usage NativeUsage,
) (Usage, error) {
	index := fakeNativeAuthorizationIndex(authorization)
	a.mu.Lock()
	a.settleCalls = append(a.settleCalls, index)
	if a.settleError != nil {
		err := a.settleError
		a.mu.Unlock()
		return Usage{}, err
	}
	if settled, ok := a.settledUsage[index]; ok {
		a.mu.Unlock()
		return settled, nil
	}
	if a.refundedIndexes != nil && a.refundedIndexes[index] {
		a.mu.Unlock()
		return Usage{}, ErrNativeAuthorizationRefunded
	}
	a.settled = append(a.settled, index)
	a.usages = append(a.usages, usage)
	cost := index + 7
	settled := Usage{
		PromptTokens:     usage.InputTokens,
		CompletionTokens: usage.OutputTokens,
		TotalTokens:      usage.InputTokens + usage.OutputTokens,
		CostMicrodollars: cost,
		Cost:             float64(cost) / 1_000_000,
		GenerationID:     fmt.Sprintf("gen-%d", index),
		Provider:         a.provider,
		Region:           "test-region",
	}
	if a.settledUsage == nil {
		a.settledUsage = make(map[int]Usage)
	}
	a.settledUsage[index] = settled
	a.mu.Unlock()
	return settled, nil
}

func (a *fakeNativeAuthorizer) Refund(
	_ context.Context,
	authorization NativeAuthorization,
	_ int,
	_ string,
	_ time.Duration,
) (NativeRefund, error) {
	index := fakeNativeAuthorizationIndex(authorization)
	a.mu.Lock()
	a.refundCalls = append(a.refundCalls, index)
	if _, settled := a.settledUsage[index]; settled {
		settledUsage := a.settledUsage[index]
		a.mu.Unlock()
		return NativeRefund{AlreadySettled: true, SettledUsage: settledUsage}, nil
	}
	if a.refundedIndexes != nil && a.refundedIndexes[index] {
		a.mu.Unlock()
		return NativeRefund{}, nil
	}
	a.refunded = append(a.refunded, index)
	if a.refundedIndexes == nil {
		a.refundedIndexes = make(map[int]bool)
	}
	a.refundedIndexes[index] = true
	a.mu.Unlock()
	return NativeRefund{}, nil
}

func fakeNativeAuthorizationIndex(authorization NativeAuthorization) int {
	var handle map[string]int
	_ = json.Unmarshal(authorization.Handle, &handle)
	return handle["index"]
}

type fakeNativeProvider struct {
	mu              sync.Mutex
	name            string
	submitCalls     int
	recoverCalls    int
	recoverMisses   int
	pollCalls       int
	pollErrors      int
	resultsCalls    int
	cancelCalls     int
	cleanupCalls    int
	cleanupFailures int
	pendingPolls    int
	pollStatus      string
	pollJob         NativeProviderJob
	pollError       string
	ambiguousSubmit bool
	submitStatus    int
	resultsErr      error
	cancelFailures  int
	afterSubmit     func()
	requests        []NativeProviderRequest
	results         []NativeProviderResult
}

type leaseCheckingNativeAuthorizer struct {
	*fakeNativeAuthorizer
	store    ObjectStore
	batchID  string
	mu       sync.Mutex
	sawLease bool
}

type blockingNativeAuthorizer struct {
	*fakeNativeAuthorizer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *blockingNativeAuthorizer) Refund(
	ctx context.Context,
	authorization NativeAuthorization,
	status int,
	reason string,
	elapsed time.Duration,
) (NativeRefund, error) {
	a.once.Do(func() { close(a.entered) })
	select {
	case <-a.release:
	case <-ctx.Done():
		return NativeRefund{}, ctx.Err()
	}
	return a.fakeNativeAuthorizer.Refund(ctx, authorization, status, reason, elapsed)
}

func (a *leaseCheckingNativeAuthorizer) Refund(
	ctx context.Context,
	authorization NativeAuthorization,
	status int,
	reason string,
	elapsed time.Duration,
) (NativeRefund, error) {
	stored, err := a.store.Get(ctx, activeJobName(a.batchID))
	if err != nil {
		return NativeRefund{}, err
	}
	claimed, err := decodeJob(stored.Data)
	if err != nil {
		return NativeRefund{}, err
	}
	if claimed.LeaseOwner == "" || claimed.LeaseUntil <= 0 {
		return NativeRefund{}, errors.New("native expiration ran without a job lease")
	}
	a.mu.Lock()
	a.sawLease = true
	a.mu.Unlock()
	return a.fakeNativeAuthorizer.Refund(ctx, authorization, status, reason, elapsed)
}

func (p *fakeNativeProvider) Name() string { return p.name }

func (p *fakeNativeProvider) Supports(endpoint string) bool {
	return endpoint == "/v1/chat/completions"
}

func (p *fakeNativeProvider) Submit(
	_ context.Context,
	token string,
	_ string,
	_ string,
	requests []NativeProviderRequest,
	_ bool,
) (NativeProviderJob, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.submitCalls++
	p.requests = append([]NativeProviderRequest(nil), requests...)
	job := NativeProviderJob{Provider: p.name, Token: token, InputFileID: "input"}
	if p.submitStatus != 0 {
		return job, &nativeProviderHTTPError{
			provider:  p.name,
			operation: "/batches",
			status:    p.submitStatus,
		}
	}
	if p.ambiguousSubmit && p.submitCalls == 1 {
		return job, errors.New("connection closed after submit")
	}
	job.ID = "provider-job"
	if p.afterSubmit != nil {
		p.afterSubmit()
	}
	return job, nil
}

type failArmedNativeStateStore struct {
	ObjectStore
	mu        sync.Mutex
	remaining int
}

func (s *failArmedNativeStateStore) arm() {
	s.mu.Lock()
	// Fail the immediate post-submit checkpoint and the retry checkpoint to
	// simulate process loss before either can make the provider ID durable.
	s.remaining = 2
	s.mu.Unlock()
}

func (s *failArmedNativeStateStore) Put(
	ctx context.Context,
	name string,
	data []byte,
	condition PutCondition,
) (StoredObject, error) {
	s.mu.Lock()
	if s.remaining > 0 && strings.HasSuffix(name, "/native/state.enc") {
		s.remaining--
		s.mu.Unlock()
		return StoredObject{}, errors.New("temporary post-submit state failure")
	}
	s.mu.Unlock()
	return s.ObjectStore.Put(ctx, name, data, condition)
}

type failAuthorizationCheckpointOnceStore struct {
	ObjectStore
	mu     sync.Mutex
	failed bool
}

func (s *failAuthorizationCheckpointOnceStore) Put(
	ctx context.Context,
	name string,
	data []byte,
	condition PutCondition,
) (StoredObject, error) {
	s.mu.Lock()
	if !s.failed && strings.Contains(name, "/native/authorizations/") {
		s.failed = true
		s.mu.Unlock()
		return StoredObject{}, errors.New("temporary authorization checkpoint failure")
	}
	s.mu.Unlock()
	return s.ObjectStore.Put(ctx, name, data, condition)
}

type failNativeLedgerCheckpointOnceStore struct {
	ObjectStore
	mu         sync.Mutex
	failed     bool
	pathSuffix string
}

type countingItemGetStore struct {
	ObjectStore
	mu       sync.Mutex
	itemGets int
}

type syntheticItemListStore struct {
	ObjectStore
	mu        sync.Mutex
	total     int
	listCalls int
	itemGets  int
}

func (s *syntheticItemListStore) Get(ctx context.Context, name string) (StoredObject, error) {
	if strings.Contains(name, "/items/") {
		s.mu.Lock()
		s.itemGets++
		s.mu.Unlock()
	}
	return s.ObjectStore.Get(ctx, name)
}

func (s *syntheticItemListStore) List(
	_ context.Context,
	prefix string,
	limit int,
	pageToken string,
) ([]ObjectMeta, string, error) {
	s.mu.Lock()
	s.listCalls++
	s.mu.Unlock()
	start := 0
	if pageToken != "" {
		base := strings.TrimSuffix(strings.TrimPrefix(pageToken, prefix), ".enc")
		last, err := strconv.Atoi(base)
		if err != nil {
			return nil, "", err
		}
		start = last + 1
	}
	end := min(start+limit, s.total)
	objects := make([]ObjectMeta, 0, end-start)
	for index := start; index < end; index++ {
		objects = append(objects, ObjectMeta{Name: fmt.Sprintf("%s%08d.enc", prefix, index)})
	}
	next := ""
	if end < s.total {
		next = fmt.Sprintf("%s%08d.enc", prefix, end-1)
	}
	return objects, next, nil
}

func (s *countingItemGetStore) Get(ctx context.Context, name string) (StoredObject, error) {
	if strings.Contains(name, "/items/") {
		s.mu.Lock()
		s.itemGets++
		s.mu.Unlock()
	}
	return s.ObjectStore.Get(ctx, name)
}

type failItemCheckpointOnceStore struct {
	ObjectStore
	mu     sync.Mutex
	failed bool
}

func (s *failItemCheckpointOnceStore) Put(
	ctx context.Context,
	name string,
	data []byte,
	condition PutCondition,
) (StoredObject, error) {
	s.mu.Lock()
	if !s.failed && strings.Contains(name, "/items/") {
		s.failed = true
		s.mu.Unlock()
		return StoredObject{}, errors.New("temporary item checkpoint failure")
	}
	s.mu.Unlock()
	return s.ObjectStore.Put(ctx, name, data, condition)
}

func (s *failNativeLedgerCheckpointOnceStore) Put(
	ctx context.Context,
	name string,
	data []byte,
	condition PutCondition,
) (StoredObject, error) {
	s.mu.Lock()
	matchesPath := strings.Contains(name, "/native/ledger/") &&
		(s.pathSuffix == "" || strings.HasSuffix(name, s.pathSuffix))
	if !s.failed && matchesPath {
		s.failed = true
		s.mu.Unlock()
		return StoredObject{}, errors.New("temporary native ledger checkpoint failure")
	}
	s.mu.Unlock()
	return s.ObjectStore.Put(ctx, name, data, condition)
}

func (p *fakeNativeProvider) Recover(_ context.Context, token string) (NativeProviderJob, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recoverCalls++
	if p.recoverCalls <= p.recoverMisses {
		return NativeProviderJob{}, ErrNativeNotFound
	}
	return NativeProviderJob{Provider: p.name, Token: token, ID: "provider-job", InputFileID: "input"}, nil
}

func (p *fakeNativeProvider) Poll(_ context.Context, job NativeProviderJob) (NativeProviderPoll, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pollCalls++
	if p.pollCalls <= p.pollErrors {
		return NativeProviderPoll{}, errors.New("temporary provider poll failure")
	}
	if p.pollCalls <= p.pendingPolls {
		return NativeProviderPoll{Status: NativeStatusPending, Job: job}, nil
	}
	status := p.pollStatus
	if status == "" {
		status = NativeStatusComplete
	}
	if p.pollJob.ID != "" {
		job = p.pollJob
	}
	return NativeProviderPoll{Status: status, Job: job, Error: p.pollError}, nil
}

func (p *fakeNativeProvider) Results(
	_ context.Context,
	_ NativeProviderJob,
	consume func(NativeProviderResult) error,
) error {
	p.mu.Lock()
	p.resultsCalls++
	results := append([]NativeProviderResult(nil), p.results...)
	resultsErr := p.resultsErr
	p.mu.Unlock()
	for _, result := range results {
		if err := consume(result); err != nil {
			return err
		}
	}
	return resultsErr
}

func (p *fakeNativeProvider) Cancel(_ context.Context, _ NativeProviderJob) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancelCalls++
	if p.cancelCalls <= p.cancelFailures {
		return errors.New("temporary provider cancel failure")
	}
	p.pendingPolls = 0
	p.pollStatus = NativeStatusFailed
	return nil
}

func (p *fakeNativeProvider) Cleanup(context.Context, NativeProviderJob) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupCalls++
	if p.cleanupCalls <= p.cleanupFailures {
		return errors.New("temporary provider cleanup failure")
	}
	return nil
}

type fakeManagedExecutor struct {
	mu    sync.Mutex
	calls int
}

func (e *fakeManagedExecutor) Execute(
	_ context.Context,
	_ string,
	_ string,
	_ []byte,
	_ string,
) (int, string, []byte, error) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	return 200, "ordinary-fallback", []byte(`{"id":"ordinary","model":"test/model","choices":[{"message":{"role":"assistant","content":"fallback"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"cost_microdollars":9}}`), nil
}

func newNativeService(
	t *testing.T,
	store ObjectStore,
	authorizer NativeAuthorizer,
	provider NativeProvider,
	executor Executor,
	now func() time.Time,
) *Service {
	t.Helper()
	service, err := New(Options{
		Store:                 store,
		Protector:             copyProtector{},
		Keys:                  allowKeys{"sk-tr-owner": true},
		Executor:              executor,
		NativeAuthorizer:      authorizer,
		NativeProviders:       []NativeProvider{provider},
		NativeSubmitProviders: []string{provider.Name()},
		WorkerID:              "native-worker",
		Concurrency:           2,
		PollInterval:          time.Hour,
		LeaseDuration:         time.Minute,
		Now:                   now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return service
}

func TestNativeBatchSubmitsOnceSettlesEachItemAndNeverUsesManagedExecutor(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", results: []NativeProviderResult{
		{Index: 1, StatusCode: 200, RequestID: "native-1", Body: json.RawMessage(`{"id":"result-1","model":"upstream/model","choices":[{"message":{"content":"one"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`)},
		{Index: 0, StatusCode: 200, RequestID: "native-0", Body: json.RawMessage(`{"id":"result-0","model":"upstream/model","choices":[{"message":{"content":"zero"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	var logsMu sync.Mutex
	var logs []string
	service.logf = func(format string, args ...any) {
		logsMu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		logsMu.Unlock()
	}
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil {
		t.Fatalf("Get: %v", apiErr)
	}
	if completed.Status != StatusCompleted || completed.RequestCounts.Completed != 2 || completed.RequestCounts.Failed != 0 {
		t.Fatalf("completed = %#v", completed)
	}
	if completed.Usage == nil || completed.Usage.Cost != 0.000015 {
		t.Fatalf("usage = %#v", completed.Usage)
	}
	if model := completed.Results[0].Response.Body.(map[string]any)["model"]; model != "test/model" {
		t.Fatalf("visible model = %#v", model)
	}
	provider.mu.Lock()
	if provider.submitCalls != 1 || len(provider.requests) != 2 {
		t.Fatalf("submit calls=%d requests=%d", provider.submitCalls, len(provider.requests))
	}
	provider.mu.Unlock()
	if executor.calls != 0 {
		t.Fatalf("managed executor calls = %d", executor.calls)
	}
	if len(authorizer.settled) != 2 || len(authorizer.refunded) != 0 {
		t.Fatalf("settled=%v refunded=%v", authorizer.settled, authorizer.refunded)
	}
	logsMu.Lock()
	joinedLogs := strings.Join(logs, "\n")
	logsMu.Unlock()
	for _, event := range []string{"batch.native_prepared", "batch.native_submitted", "batch.native_completed"} {
		if !strings.Contains(joinedLogs, event) {
			t.Fatalf("missing %q in logs: %s", event, joinedLogs)
		}
	}
	if strings.Contains(joinedLogs, "first") || strings.Contains(joinedLogs, "second") {
		t.Fatalf("request content leaked to native logs: %s", joinedLogs)
	}
}

func TestNativeAuthorizationFailureRefundsPriorHoldsAndUsesManagedPath(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{
		provider:          "parasail",
		failAuthorization: true,
		failIndex:         1,
	}
	provider := &fakeNativeProvider{name: "parasail"}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("Get = %#v, %v", completed, apiErr)
	}
	if provider.submitCalls != 0 || executor.calls != 2 {
		t.Fatalf("submit calls=%d managed calls=%d", provider.submitCalls, executor.calls)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if len(authorizer.refunded) != len(authorizer.authorized) {
		t.Fatalf("authorized=%v refunded=%v", authorizer.authorized, authorizer.refunded)
	}
	for _, index := range authorizer.authorized {
		if !authorizer.refundedIndexes[index] {
			t.Fatalf("authorization %d was not refunded: %v", index, authorizer.refunded)
		}
	}
}

func TestNativeBatchAuthorizesItemsWithBoundedConcurrency(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	authorizer := &concurrencyNativeAuthorizer{
		base:    &fakeNativeAuthorizer{provider: "openai"},
		started: make(chan struct{}, 4),
		release: release,
	}
	service := newNativeService(
		t,
		newMemoryObjectStore(),
		authorizer,
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	service.concurrency = 2
	requests := make([]Request, 4)
	for index := range requests {
		requests[index] = Request{Body: json.RawMessage(`{"model":"test/model","messages":[]}`)}
	}
	type result struct {
		state nativeState
		err   error
	}
	finished := make(chan result, 1)
	go func() {
		state, _, err := service.prepareNative(
			t.Context(),
			job{Batch: Batch{ID: "batch_bounded_authorize", Endpoint: "/v1/chat/completions"}},
			"lookup-hash",
			[]int{0, 1, 2, 3},
			requests,
		)
		finished <- result{state: state, err: err}
	}()
	for range 2 {
		select {
		case <-authorizer.started:
		case <-time.After(time.Second):
			t.Fatal("native authorization did not reach configured concurrency")
		}
	}
	authorizer.mu.Lock()
	maximum := authorizer.maximum
	authorizer.mu.Unlock()
	if maximum != 2 {
		t.Fatalf("maximum concurrent authorizations = %d, want 2", maximum)
	}
	close(release)
	select {
	case completed := <-finished:
		if completed.err != nil || completed.state.Stage != nativeStagePrepared {
			t.Fatalf("prepare state=%#v err=%v", completed.state, completed.err)
		}
	case <-time.After(time.Second):
		t.Fatal("native authorization workers did not finish")
	}
	authorizer.mu.Lock()
	maximum = authorizer.maximum
	authorizer.mu.Unlock()
	if maximum > 2 {
		t.Fatalf("maximum concurrent authorizations = %d, exceeded 2", maximum)
	}
}

func TestNativeBatchRetriesAmbiguousAuthorizationWithSameCheckpoint(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{
		provider:           "openai",
		failAuthorization:  true,
		failIndex:          0,
		authorizationError: fmt.Errorf("%w: lost response", ErrNativeAuthorizationRetryable),
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(
		t, store, authorizer, &fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{}, func() time.Time { return now },
	)
	request := Request{
		CustomID: "item-0",
		Body:     json.RawMessage(`{"model":"test/model","messages":[]}`),
	}
	batchJob := job{Batch: Batch{
		ID: "batch_retry_authorize", Endpoint: "/v1/chat/completions", Model: "test/model",
	}}
	state, _, err := service.prepareNative(
		t.Context(), batchJob, "lookup-hash", []int{0}, []Request{request},
	)
	if err != nil || state.Stage != nativeStagePreparing || state.RetryAttempts != 1 ||
		state.NextPollAt <= now.Unix() {
		t.Fatalf("prepare state=%#v error=%v", state, err)
	}
	if _, _, found, loadErr := service.loadNativeState(t.Context(), batchJob.ID); loadErr != nil || !found {
		t.Fatalf("retryable authorization state: found=%t err=%v", found, loadErr)
	}

	authorizer.failAuthorization = false
	now = now.Add(nativeRetryBase + time.Second)
	state, _, err = service.prepareNative(
		t.Context(), batchJob, "lookup-hash", []int{0}, []Request{request},
	)
	if err != nil || state.Stage != nativeStagePrepared {
		t.Fatalf("retry state=%#v err=%v", state, err)
	}
	if fmt.Sprint(authorizer.authorized) != "[0]" {
		t.Fatalf("authorized = %v", authorizer.authorized)
	}
}

func TestNativeBatchPrepareRetriesAreBoundedAndCheckpointedHoldsRefund(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{
		provider:           "openai",
		failAuthorization:  true,
		failIndex:          1,
		authorizationError: fmt.Errorf("%w: control plane unavailable", ErrNativeAuthorizationRetryable),
	}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(
		t, store, authorizer, &fakeNativeProvider{name: "openai"}, executor,
		func() time.Time { return now },
	)
	service.concurrency = 1
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}

	for attempt := 1; attempt <= nativePrepareMaxAttempts; attempt++ {
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("prepare pass %d: %v", attempt, err)
		}
		if attempt == nativePrepareMaxAttempts {
			break
		}
		state, _, found, err := service.loadNativeState(t.Context(), created.ID)
		if err != nil || !found || state.Stage != nativeStagePreparing ||
			state.RetryAttempts != attempt {
			t.Fatalf("attempt %d state=%#v found=%t err=%v", attempt, state, found, err)
		}
		now = time.Unix(state.NextPollAt+1, 0)
	}

	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if executor.calls != 2 || fmt.Sprint(authorizer.refunded) != "[0]" {
		t.Fatalf("managed=%d refunded=%v", executor.calls, authorizer.refunded)
	}
}

func TestNativeAuthorizationCheckpointFailureKeepsDeterministicHoldRetryable(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failAuthorizationCheckpointOnceStore{ObjectStore: baseStore}
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	service := newNativeService(
		t,
		store,
		authorizer,
		&fakeNativeProvider{name: "parasail"},
		&fakeManagedExecutor{},
		time.Now,
	)
	batchJob := job{Batch: Batch{ID: "batch_checkpoint", Endpoint: "/v1/chat/completions"}}
	body := []byte(`{"model":"test/model","messages":[{"role":"user","content":"private"}]}`)

	if _, err := service.loadOrAuthorizeNative(
		t.Context(), batchJob, "lookup-hash", 0, body,
	); err == nil {
		t.Fatal("expected the first authorization checkpoint to fail")
	}
	if len(authorizer.refunded) != 0 {
		t.Fatalf("checkpoint failure terminally refunded retryable hold: %v", authorizer.refunded)
	}
	if _, err := service.loadOrAuthorizeNative(
		t.Context(), batchJob, "lookup-hash", 0, body,
	); err != nil {
		t.Fatalf("retry after storage recovery: %v", err)
	}
	if _, err := service.loadNativeAuthorization(t.Context(), batchJob.ID, 0); err != nil {
		t.Fatalf("authorization checkpoint missing after retry: %v", err)
	}
}

func TestNativeAuthorizationCheckpointFailureRetriesNativeInsteadOfFreezingManaged(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failAuthorizationCheckpointOnceStore{ObjectStore: baseStore}
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", results: []NativeProviderResult{
		{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if provider.submitCalls != 0 || executor.calls != 0 {
		t.Fatalf("checkpoint outage changed execution path: native=%d managed=%d", provider.submitCalls, executor.calls)
	}
	now = now.Add(2 * time.Minute)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || executor.calls != 0 || len(authorizer.settled) != 2 {
		t.Fatalf("native=%d managed=%d settled=%v", provider.submitCalls, executor.calls, authorizer.settled)
	}
}

func TestNativeSubmitRejectionCleansUploadedInputBeforeManagedFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", submitStatus: http.StatusBadRequest}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.cleanupCalls != 1 {
		t.Fatalf("cleanup calls=%d; rejected submit input was retained", provider.cleanupCalls)
	}
	if executor.calls != 2 || len(authorizer.refunded) != 2 {
		t.Fatalf("managed=%d refunded=%v", executor.calls, authorizer.refunded)
	}
}

func TestNativeBatchPendingPollReleasesLeaseWithoutResubmission(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pendingPolls: 1, results: []NativeProviderResult{
		{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	inProgress, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || inProgress.Status != StatusInProgress {
		t.Fatalf("in progress=%#v err=%#v", inProgress, apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("early second run: %v", err)
	}
	if provider.pollCalls != 1 {
		t.Fatalf("provider was polled before backoff elapsed: %d", provider.pollCalls)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("second due run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || provider.pollCalls != 2 {
		t.Fatalf("submit=%d poll=%d", provider.submitCalls, provider.pollCalls)
	}
}

func TestNativeBatchProviderItemFailureRefundsThenUsesManagedFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", results: []NativeProviderResult{
		{Index: 0, StatusCode: 429, Error: json.RawMessage(`{"message":"busy"}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted || completed.RequestCounts.Completed != 2 {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if executor.calls != 1 || len(authorizer.refunded) != 1 || authorizer.refunded[0] != 0 {
		t.Fatalf("fallback calls=%d refunded=%v", executor.calls, authorizer.refunded)
	}
}

func TestNativeBatchTerminalSettlementRejectionRefundsThenFallsBackOnce(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{
		provider:    "openai",
		settleError: fmt.Errorf("%w: selected route rejected", ErrNativeSettlementRejected),
	}
	provider := &fakeNativeProvider{name: "openai", results: []NativeProviderResult{
		{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted || len(completed.Results) != 2 {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if len(authorizer.settleCalls) != 2 || len(authorizer.refundCalls) != 2 ||
		len(authorizer.refunded) != 2 || len(authorizer.settled) != 0 {
		t.Fatalf(
			"settle calls=%v refund calls=%v refunded=%v settled=%v",
			authorizer.settleCalls, authorizer.refundCalls,
			authorizer.refunded, authorizer.settled,
		)
	}
	if executor.calls != 2 {
		t.Fatalf("managed fallback calls = %d, want 2", executor.calls)
	}
}

func TestNativeBatchFailedJobConsumesPartialResultsBeforeFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:       "openai",
		pollStatus: NativeStatusFailed,
		pollError:  "expired",
		pollJob: NativeProviderJob{
			Provider:     "openai",
			ID:           "provider-job",
			InputFileID:  "input",
			OutputFileID: "partial-output",
		},
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if completed.RequestCounts.Completed != 2 || completed.RequestCounts.Failed != 0 {
		t.Fatalf("counts = %#v", completed.RequestCounts)
	}
	if executor.calls != 1 {
		t.Fatalf("managed fallback calls = %d, want 1 missing item", executor.calls)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if fmt.Sprint(authorizer.settled) != "[0]" || fmt.Sprint(authorizer.refunded) != "[1]" {
		t.Fatalf("settled=%v refunded=%v", authorizer.settled, authorizer.refunded)
	}
	if provider.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d", provider.cleanupCalls)
	}
}

func TestNativeBatchRecoversAmbiguousCreateWithoutDuplicateSubmit(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", ambiguousSubmit: true, results: []NativeProviderResult{
		{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first runAvailable: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("recovery runAvailable: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || provider.recoverCalls != 1 {
		t.Fatalf("submit=%d recover=%d", provider.submitCalls, provider.recoverCalls)
	}
}

func TestNativeBatchPersistsSubmitIntentBeforeProviderCreate(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failArmedNativeStateStore{ObjectStore: baseStore}
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{
		name: "parasail",
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
			{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	provider.afterSubmit = store.arm
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	service.logf = t.Logf
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first runAvailable: %v", err)
	}
	now = now.Add(time.Hour + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("recovery runAvailable: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || provider.recoverCalls != 1 {
		t.Fatalf("submit=%d recover=%d", provider.submitCalls, provider.recoverCalls)
	}
}

func TestNativeBatchTransientPollErrorUsesBoundedBackoff(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pollErrors: 1, results: []NativeProviderResult{
		{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("early second run: %v", err)
	}
	if provider.pollCalls != 1 {
		t.Fatalf("provider was polled before backoff elapsed: %d", provider.pollCalls)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("second due run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || provider.pollCalls != 2 {
		t.Fatalf("submit=%d poll=%d", provider.submitCalls, provider.pollCalls)
	}
}

func TestNativeBatchNeverResubmitsWhileAmbiguousSubmissionIsUnresolved(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{
		name:            "parasail",
		ambiguousSubmit: true,
		recoverMisses:   3,
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
			{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit run: %v", err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		now = now.Add(nativeRetryMax + time.Second)
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("run %d: %v", attempt, err)
		}
	}
	if provider.submitCalls != 1 || provider.recoverCalls != 3 {
		t.Fatalf("premature resubmit: submit=%d recover=%d", provider.submitCalls, provider.recoverCalls)
	}
	now = now.Add(nativeRetryMax + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("recovered run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || provider.recoverCalls != 4 {
		t.Fatalf("submit=%d recover=%d", provider.submitCalls, provider.recoverCalls)
	}
	if provider.cleanupCalls != 1 {
		t.Fatalf("cleanup=%d; input must survive ambiguous-create recovery and only clean after completion", provider.cleanupCalls)
	}
}

func TestNativeBatchFailsClosedAfterBoundedAmbiguousCreateRecovery(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{
		name:            "parasail",
		ambiguousSubmit: true,
		recoverMisses:   100,
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
			{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("initial ambiguous submit: %v", err)
	}
	const recoveryPasses = 3
	for range recoveryPasses {
		now = now.Add(10 * time.Minute)
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("recovery pass: %v", err)
		}
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || provider.recoverCalls != recoveryPasses ||
		provider.cleanupCalls != 1 || completed.RequestCounts.Failed != 2 || len(completed.Results) != 2 {
		t.Fatalf(
			"submit=%d recover=%d cleanup=%d",
			provider.submitCalls, provider.recoverCalls, provider.cleanupCalls,
		)
	}
}

func TestNativeBatchAmbiguousCreateWaitsForUploadCleanupBeforeRefund(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{
		name:            "parasail",
		ambiguousSubmit: true,
		recoverMisses:   100,
		cleanupFailures: 1,
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("initial ambiguous submit: %v", err)
	}
	for attempt := 0; attempt < nativeRecoveryNotFoundLimit-1; attempt++ {
		now = now.Add(10 * time.Minute)
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("recovery pass %d: %v", attempt, err)
		}
	}
	now = now.Add(10 * time.Minute)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first cleanup pass: %v", err)
	}
	if provider.cleanupCalls != 1 || len(authorizer.refunded) != 0 {
		t.Fatalf("cleanup=%d refunded=%v before provider cleanup", provider.cleanupCalls, authorizer.refunded)
	}
	inProgress, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || inProgress.Status != StatusInProgress {
		t.Fatalf("in_progress=%#v err=%#v", inProgress, apiErr)
	}

	now = now.Add(time.Hour + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted || completed.RequestCounts.Failed != 2 {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.cleanupCalls != 2 || len(authorizer.refunded) != 2 {
		t.Fatalf("cleanup=%d refunded=%v", provider.cleanupCalls, authorizer.refunded)
	}
}

func TestNativeBatchMalformedImmutableResultsTerminateThroughManagedFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{
		name:       "parasail",
		resultsErr: fmt.Errorf("%w: duplicate custom id", ErrNativeInvalidResult),
	}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted || len(completed.Results) != 2 {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if executor.calls != 2 || provider.cancelCalls != 1 || provider.cleanupCalls != 1 {
		t.Fatalf(
			"managed=%d cancel=%d cleanup=%d",
			executor.calls, provider.cancelCalls, provider.cleanupCalls,
		)
	}
}

func TestNativeBatchCancelFailureEventuallyReleasesManagedFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:           "openai",
		resultsErr:     fmt.Errorf("%w: malformed provider result", ErrNativeInvalidResult),
		cancelFailures: nativeCleanupMaxAttempts + 1,
	}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}

	for attempt := 1; attempt <= nativeCleanupMaxAttempts; attempt++ {
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("cancel pass %d: %v", attempt, err)
		}
		if attempt == nativeCleanupMaxAttempts {
			break
		}
		state, _, found, err := service.loadNativeState(t.Context(), created.ID)
		if err != nil || !found || state.Stage != nativeStageDisabled ||
			state.RetryAttempts != attempt {
			t.Fatalf("attempt %d state=%#v found=%t err=%v", attempt, state, found, err)
		}
		now = time.Unix(state.NextPollAt+1, 0)
	}

	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.cancelCalls != nativeCleanupMaxAttempts || provider.cleanupCalls != 1 ||
		executor.calls != 2 || len(authorizer.refunded) != 2 {
		t.Fatalf(
			"cancel=%d cleanup=%d managed=%d refunded=%v",
			provider.cancelCalls, provider.cleanupCalls, executor.calls, authorizer.refunded,
		)
	}
}

func TestDarkNativeConfigurationDoesNotRescanEveryManagedItem(t *testing.T) {
	t.Parallel()

	store := &countingItemGetStore{ObjectStore: newMemoryObjectStore()}
	executor := &fakeManagedExecutor{}
	service := newNativeService(
		t, store, &fakeNativeAuthorizer{provider: "parasail"},
		&fakeNativeProvider{name: "parasail"}, executor, time.Now,
	)
	service.nativeSubmitProviders = map[string]struct{}{}
	if _, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch()); apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	store.mu.Lock()
	itemGets := store.itemGets
	store.mu.Unlock()
	if itemGets != 0 || executor.calls != 2 {
		t.Fatalf("item gets=%d managed calls=%d", itemGets, executor.calls)
	}
}

func TestNativePendingScanUsesBoundedPagesAtFiftyThousandItems(t *testing.T) {
	t.Parallel()

	store := &syntheticItemListStore{
		ObjectStore: newMemoryObjectStore(),
		total:       50_000,
	}
	service := newNativeService(
		t, store, &fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"}, &fakeManagedExecutor{}, time.Now,
	)
	pending, err := service.nativePendingIndexes(t.Context(), job{
		Batch: Batch{ID: "batch_scale", RequestCounts: RequestCounts{Total: 50_000}},
	})
	if err != nil {
		t.Fatalf("nativePendingIndexes: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(pending) != 0 || store.listCalls != 50 || store.itemGets != 0 {
		t.Fatalf(
			"pending=%d list calls=%d item gets=%d",
			len(pending), store.listCalls, store.itemGets,
		)
	}
}

func TestPrepareGetValidatesFiftyThousandResultsWithoutReadingBodies(t *testing.T) {
	t.Parallel()

	backing := newMemoryObjectStore()
	store := &syntheticItemListStore{ObjectStore: backing, total: 50_000}
	service := newNativeService(
		t, store, &fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"}, &fakeManagedExecutor{}, time.Now,
	)
	id := "batch_00000000000000000000000000000000"
	finalized := time.Now().Unix()
	createdAt := finalized - 1
	metadata, err := json.Marshal(job{
		Batch: Batch{
			ID:               id,
			Object:           ObjectType,
			Endpoint:         "/v1/chat/completions",
			Model:            "test/model",
			CompletionWindow: CompletionWindow,
			Status:           StatusCompleted,
			CreatedAt:        createdAt,
			FinalizedAt:      &finalized,
			RequestCounts: RequestCounts{
				Total: 50_000, Completed: 50_000,
			},
		},
		OwnerLookupHash: trustedrouter.LookupHash("sk-tr-owner"),
		InputObject:     inputObjectName(id),
		ExpiresAt:       createdAt + int64((24*time.Hour)/time.Second),
	})
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	if _, err := backing.Put(t.Context(), terminalJobName(id), metadata, PutCondition{Generation: 0}); err != nil {
		t.Fatalf("seed terminal job: %v", err)
	}
	prepared, apiErr := service.PrepareGet(t.Context(), "sk-tr-owner", id)
	if apiErr != nil || !prepared.ResultSet {
		t.Fatalf("prepared=%#v apiErr=%#v", prepared, apiErr)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.listCalls != 50 || store.itemGets != 0 {
		t.Fatalf("list calls=%d item gets=%d", store.listCalls, store.itemGets)
	}
}

func TestProgressRecoveryReadsCompactStateInsteadOfResultBodies(t *testing.T) {
	t.Parallel()

	store := &countingItemGetStore{ObjectStore: newMemoryObjectStore()}
	service := newNativeService(
		t, store, &fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"}, &fakeManagedExecutor{}, time.Now,
	)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	stored, err := store.ObjectStore.Get(t.Context(), terminalJobName(created.ID))
	if err != nil {
		t.Fatalf("terminal job: %v", err)
	}
	terminal, err := decodeJob(stored.Data)
	if err != nil {
		t.Fatalf("decode terminal job: %v", err)
	}
	store.mu.Lock()
	store.itemGets = 0
	store.mu.Unlock()
	states, pending, err := service.loadItemStatesAndPending(t.Context(), terminal)
	if err != nil {
		t.Fatalf("load states: %v", err)
	}
	store.mu.Lock()
	itemGets := store.itemGets
	store.mu.Unlock()
	if len(states) != 2 || len(pending) != 0 || itemGets != 0 {
		t.Fatalf("states=%d pending=%d full-result gets=%d", len(states), len(pending), itemGets)
	}
}

func TestNativeBatchPrivacyAndOrchestrationRequestsStayManaged(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail"}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	body := []byte(`{"endpoint":"/v1/chat/completions","model":"trustedrouter/zdr","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"private"}],"provider":{"data_collection":"deny"}}}]}`)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", body)
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if executor.calls != 1 || provider.submitCalls != 0 || len(authorizer.settled) != 0 {
		t.Fatalf("managed=%d native_submit=%d native_settle=%v", executor.calls, provider.submitCalls, authorizer.settled)
	}
}

func TestNativeBatchPluginAndInternalToolRequestsStayManaged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "plugin orchestration",
			body: `{"messages":[{"role":"user","content":"work"}],"plugins":[{"id":"synth","models":["a","b"]}]}`,
		},
		{
			name: "internal tool orchestration",
			body: `{"messages":[{"role":"user","content":"work"}],"tools":[{"type":"trustedrouter:synth","models":["a","b"]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := newMemoryObjectStore()
			authorizer := &fakeNativeAuthorizer{provider: "parasail"}
			provider := &fakeNativeProvider{name: "parasail"}
			executor := &fakeManagedExecutor{}
			service := newNativeService(t, store, authorizer, provider, executor, time.Now)
			request := fmt.Sprintf(
				`{"endpoint":"/v1/chat/completions","model":"openai/gpt-5.5","requests":[{"custom_id":"one","body":%s}]}`,
				test.body,
			)
			created, apiErr := service.Create(t.Context(), "sk-tr-owner", []byte(request))
			if apiErr != nil {
				t.Fatalf("Create: %v", apiErr)
			}
			if err := service.runAvailable(t.Context()); err != nil {
				t.Fatalf("run: %v", err)
			}
			completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
			if apiErr != nil || completed.Status != StatusCompleted {
				t.Fatalf("completed=%#v err=%#v", completed, apiErr)
			}
			if executor.calls != 1 || provider.submitCalls != 0 {
				t.Fatalf("managed=%d native=%d", executor.calls, provider.submitCalls)
			}
		})
	}
}

func TestNativeBatchBroadcastAuthorizationRefundsNativeHoldsAndStaysManaged(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail", managed: true}
	provider := &fakeNativeProvider{name: "parasail"}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 0 || executor.calls != 2 || len(authorizer.refunded) != 2 {
		t.Fatalf("native=%d managed=%d refunded=%v", provider.submitCalls, executor.calls, authorizer.refunded)
	}
}

func TestNativeBatchWithoutCommonEligibleRouteRefundsAndStaysManaged(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "deepseek"}
	provider := &fakeNativeProvider{name: "openai"}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 0 || executor.calls != 2 || len(authorizer.refunded) != 2 {
		t.Fatalf("native=%d managed=%d refunded=%v", provider.submitCalls, executor.calls, authorizer.refunded)
	}
}

func TestNativeBatchExpirationCancelsProviderAndRefundsUnfinishedItems(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pendingPolls: 100}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expire: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired {
		t.Fatalf("expired=%#v err=%#v", expired, apiErr)
	}
	if provider.cancelCalls != 1 {
		t.Fatalf("cancel calls = %d", provider.cancelCalls)
	}
	if len(authorizer.refunded) != 2 {
		t.Fatalf("refunded = %v", authorizer.refunded)
	}
	if executor.calls != 0 {
		t.Fatalf("managed calls = %d", executor.calls)
	}
}

func TestNativeBatchExpirationClaimsLeaseBeforeRefunding(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	baseAuthorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pendingPolls: 100}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, baseAuthorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	checking := &leaseCheckingNativeAuthorizer{
		fakeNativeAuthorizer: baseAuthorizer,
		store:                store,
		batchID:              created.ID,
	}
	service.nativeAuthorizer = checking
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expire: %v", err)
	}
	checking.mu.Lock()
	sawLease := checking.sawLease
	checking.mu.Unlock()
	if !sawLease {
		t.Fatal("native expiration did not hold the active-job lease")
	}
}

func TestNativeBatchExpirationRenewsLeaseWhileRefunding(t *testing.T) {
	store := newMemoryObjectStore()
	baseAuthorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pendingPolls: 100}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(
		t, store, baseAuthorizer, provider, &fakeManagedExecutor{},
		func() time.Time { return now },
	)
	service.logf = t.Logf
	service.lease = 3 * time.Second
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	blocking := &blockingNativeAuthorizer{
		fakeNativeAuthorizer: baseAuthorizer,
		entered:              make(chan struct{}),
		release:              make(chan struct{}),
	}
	service.nativeAuthorizer = blocking
	done := make(chan error, 1)
	go func() { done <- service.runAvailable(t.Context()) }()
	select {
	case <-blocking.entered:
	case err := <-done:
		t.Fatalf("expiration returned before refund: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("expiration did not reach refund")
	}
	before, err := store.Get(t.Context(), activeJobName(created.ID))
	if err != nil {
		t.Fatalf("get claimed job: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	after, err := store.Get(t.Context(), activeJobName(created.ID))
	if err != nil {
		t.Fatalf("get renewed job: %v", err)
	}
	close(blocking.release)
	if err := <-done; err != nil {
		t.Fatalf("expire: %v", err)
	}
	if after.Generation <= before.Generation {
		t.Fatalf("lease generation did not advance: before=%d after=%d", before.Generation, after.Generation)
	}
}

func TestNativeBatchExpirationHarvestsDurableResultsBeforeRefundingMissingItems(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pendingPolls: 1, results: []NativeProviderResult{
		{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"zero","choices":[{"message":{"content":"done"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expire: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired {
		t.Fatalf("expired=%#v err=%#v", expired, apiErr)
	}
	if expired.RequestCounts.Completed != 1 || expired.RequestCounts.Failed != 1 {
		t.Fatalf("counts = %#v", expired.RequestCounts)
	}
	if len(expired.Results) != 2 || expired.Results[0].Response == nil || expired.Results[1].Error == nil {
		t.Fatalf("expired results = %#v", expired.Results)
	}
	if expired.Usage == nil || expired.Usage.PromptTokens != 3 || expired.Usage.CompletionTokens != 2 {
		t.Fatalf("usage = %#v", expired.Usage)
	}
	if provider.cancelCalls != 0 {
		t.Fatalf("completed provider job was cancelled: %d", provider.cancelCalls)
	}
	if fmt.Sprint(authorizer.settled) != "[0]" || fmt.Sprint(authorizer.refunded) != "[1]" {
		t.Fatalf("settled=%v refunded=%v", authorizer.settled, authorizer.refunded)
	}
	if executor.calls != 0 {
		t.Fatalf("expired native batch used managed fallback: %d", executor.calls)
	}
}

func TestNativeBatchExpirationCleanupRetryDoesNotRedownloadResults(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:            "openai",
		pendingPolls:    100,
		cleanupFailures: 1,
		results: []NativeProviderResult{
			{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":3,"completion_tokens":2}}`)},
		},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(
		t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now },
	)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first expiration pass: %v", err)
	}
	if provider.resultsCalls != 1 || provider.cleanupCalls != 1 {
		t.Fatalf("results=%d cleanup=%d", provider.resultsCalls, provider.cleanupCalls)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expiration cleanup retry: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired {
		t.Fatalf("expired=%#v err=%#v", expired, apiErr)
	}
	if provider.resultsCalls != 1 || provider.cleanupCalls != 2 {
		t.Fatalf("results=%d cleanup=%d", provider.resultsCalls, provider.cleanupCalls)
	}
}

func TestNativeBatchMissingProviderResultsFallsBackAfterCancelling(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:       "openai",
		resultsErr: &nativeProviderHTTPError{provider: "openai", operation: "result", status: http.StatusNotFound},
	}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.cancelCalls != 1 || provider.cleanupCalls != 1 || executor.calls != 2 {
		t.Fatalf("cancel=%d cleanup=%d managed=%d", provider.cancelCalls, provider.cleanupCalls, executor.calls)
	}
}

func TestNativeBatchProviderResultAfterRefundUsesManagedFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:         "openai",
		pendingPolls: 1,
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
			{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	authorization, err := service.loadNativeAuthorization(t.Context(), created.ID, 0)
	if err != nil {
		t.Fatalf("load authorization: %v", err)
	}
	if err := service.refundNativeAuthorizationOnce(
		t.Context(), created.ID, 0, Request{CustomID: "slow-success"}, authorization,
		http.StatusBadGateway, "simulated_refund_winner",
	); err != nil {
		t.Fatalf("refund: %v", err)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("finish: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if fmt.Sprint(authorizer.settled) != "[1]" || fmt.Sprint(authorizer.refunded) != "[0]" || executor.calls != 1 {
		t.Fatalf("settled=%v refunded=%v managed=%d", authorizer.settled, authorizer.refunded, executor.calls)
	}
}

func TestNativeBatchTerminalResultErrorRestoresSettledItemBeforeManagedFallback(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failItemCheckpointOnceStore{ObjectStore: baseStore}
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name: "openai",
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
		resultsErr: &nativeProviderHTTPError{provider: "openai", operation: "result", status: http.StatusNotFound},
	}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if fmt.Sprint(authorizer.settled) != "[0]" || fmt.Sprint(authorizer.refunded) != "[1]" || executor.calls != 1 {
		t.Fatalf("settled=%v refunded=%v managed=%d", authorizer.settled, authorizer.refunded, executor.calls)
	}
}

func TestNativeBatchExpirationBacksOffAfterTransientCancelFailure(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", pendingPolls: 100, cancelFailures: 1}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first expiration pass: %v", err)
	}
	activeObject, err := store.Get(t.Context(), activeJobName(created.ID))
	if err != nil {
		t.Fatalf("active job: %v", err)
	}
	active, err := decodeJob(activeObject.Data)
	if err != nil {
		t.Fatalf("decode active job: %v", err)
	}
	if provider.cancelCalls != 1 || active.ExpiryAttempts != 1 || active.NextAttemptAt <= now.Unix() {
		t.Fatalf("cancel=%d attempts=%d next=%d now=%d", provider.cancelCalls, active.ExpiryAttempts, active.NextAttemptAt, now.Unix())
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("early expiration retry: %v", err)
	}
	if provider.cancelCalls != 1 {
		t.Fatalf("cancel retried before backoff: %d", provider.cancelCalls)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expiration retry: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired || provider.cancelCalls != 2 {
		t.Fatalf("expired=%#v err=%#v cancel=%d", expired, apiErr, provider.cancelCalls)
	}
}

func TestNativeBatchExpirationBoundsPersistentCancelFailure(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:           "openai",
		pendingPolls:   100,
		cancelFailures: nativeCleanupMaxAttempts + 1,
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(
		t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now },
	)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)

	for attempt := 1; attempt <= nativeCleanupMaxAttempts; attempt++ {
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("expiration pass %d: %v", attempt, err)
		}
		if attempt == nativeCleanupMaxAttempts {
			break
		}
		activeObject, err := store.Get(t.Context(), activeJobName(created.ID))
		if err != nil {
			t.Fatalf("active job after pass %d: %v", attempt, err)
		}
		active, err := decodeJob(activeObject.Data)
		if err != nil || active.ExpiryAttempts != attempt || active.NextAttemptAt <= now.Unix() {
			t.Fatalf("attempt %d active=%#v err=%v", attempt, active, err)
		}
		now = time.Unix(active.NextAttemptAt+1, 0)
	}

	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired || expired.RequestCounts.Failed != 2 {
		t.Fatalf("expired=%#v err=%#v", expired, apiErr)
	}
	if provider.cancelCalls != nativeCleanupMaxAttempts || len(authorizer.refunded) != 2 {
		t.Fatalf("cancel=%d refunded=%v", provider.cancelCalls, authorizer.refunded)
	}
}

func TestNativeBatchExpirationTreatsMissingResultFileAsFailedItems(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:         "openai",
		pendingPolls: 100,
		resultsErr: &nativeProviderHTTPError{
			provider: "openai", operation: "result", status: http.StatusNotFound,
		},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expire: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired ||
		expired.RequestCounts.Failed != 2 || len(expired.Results) != 2 {
		t.Fatalf("expired=%#v err=%#v", expired, apiErr)
	}
}

func TestNativeBatchExpirationRecoversAndCancelsAmbiguousCreate(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{
		name:            "parasail",
		ambiguousSubmit: true,
		pendingPolls:    100,
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("expire: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || expired.Status != StatusExpired {
		t.Fatalf("expired=%#v err=%#v", expired, apiErr)
	}
	if provider.submitCalls != 1 || provider.recoverCalls != 1 || provider.cancelCalls != 1 {
		t.Fatalf(
			"submit=%d recover=%d cancel=%d",
			provider.submitCalls,
			provider.recoverCalls,
			provider.cancelCalls,
		)
	}
}

func TestNativeBatchMissingUsageEstimatesVisibleOutputBeforeSettlement(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", results: []NativeProviderResult{
		{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","choices":[{"message":{"content":"12345678"}}]}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","choices":[{"message":{"content":"1234"}}]}`)},
	}}
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if completed.Usage == nil || completed.Usage.CompletionTokens != 3 {
		t.Fatalf("usage = %#v", completed.Usage)
	}
	providerUsage := completed.Results[0].Response.Body.(map[string]any)["usage"].(map[string]any)["provider_usage"].(map[string]any)
	if providerUsage["usage_estimated"] != true {
		t.Fatalf("provider usage = %#v; estimated usage was not disclosed", providerUsage)
	}
}

func TestNativeBatchMissingUsageEstimatesStructuredOutput(t *testing.T) {
	t.Parallel()

	decoded := map[string]any{
		"choices": []any{map[string]any{
			"message": map[string]any{
				"content": []any{
					map[string]any{"type": "output_text", "text": "structured result"},
				},
				"tool_calls": []any{map[string]any{
					"type":     "function",
					"function": map[string]any{"name": "lookup", "arguments": `{"id":42}`},
				}},
			},
		}},
	}
	got := estimateNativeOutputTokens(decoded)
	if got < 20 {
		t.Fatalf("structured output estimate = %d; structured content was undercounted", got)
	}
}

func TestNativeVisibleBodyIncludesSettlementAttribution(t *testing.T) {
	t.Parallel()

	visible := nativeVisibleBody(
		map[string]any{"usage": map[string]any{
			"prompt_tokens_details":     map[string]any{"cached_tokens": 2},
			"completion_tokens_details": map[string]any{"reasoning_tokens": 1},
		}},
		"openai/gpt-5.5",
		Usage{
			PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5,
			CostMicrodollars: 7, Cost: 0.000007,
			GenerationID: "gen-native", Provider: "openai", Region: "us-east4",
		},
		nativeState{Provider: "stale-provider", EndpointID: "openai-endpoint", Model: "openai/gpt-5.5"},
		false,
	).(map[string]any)
	providerUsage := visible["usage"].(map[string]any)["provider_usage"].(map[string]any)
	if providerUsage["generation_id"] != "gen-native" ||
		providerUsage["region"] != "us-east4" ||
		providerUsage["selected_provider"] != "openai" ||
		providerUsage["selected_endpoint"] != "openai-endpoint" ||
		providerUsage["usage_type"] != "Credits" ||
		providerUsage["contains_prompt_or_completion"] != false ||
		providerUsage["cache_read_input_tokens"] != 2 ||
		providerUsage["uncached_input_tokens"] != 1 ||
		providerUsage["reasoning_tokens"] != 1 ||
		providerUsage["total_cost_microdollars"] != 7 {
		t.Fatalf("provider_usage = %#v", providerUsage)
	}
	usageMap := visible["usage"].(map[string]any)
	trustedRouter := visible["trustedrouter"].(map[string]any)
	routing := trustedRouter["routing"].(map[string]any)
	if usageMap["total_cost_microdollars"] != 7 ||
		routing["selected_provider"] != "openai" ||
		routing["selected_endpoint"] != "openai-endpoint" {
		t.Fatalf("visible response = %#v", visible)
	}
}

func TestNativeBatchCarriesCacheAndReasoningUsageIntoSettlement(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", results: []NativeProviderResult{
		{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","choices":[{"finish_reason":"length","message":{"content":"a"}}],"usage":{"prompt_tokens":9,"completion_tokens":4,"prompt_tokens_details":{"cached_tokens":7},"completion_tokens_details":{"reasoning_tokens":3}}}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, time.Now)
	if _, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch()); apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(authorizer.usages) != 2 {
		t.Fatalf("usages = %#v", authorizer.usages)
	}
	var detailed *NativeUsage
	for index := range authorizer.usages {
		if authorizer.usages[index].CacheReadTokens == 7 {
			detailed = &authorizer.usages[index]
			break
		}
	}
	if detailed == nil || detailed.ReasoningTokens != 3 || detailed.FinishReason != "length" {
		t.Fatalf("usages = %#v", authorizer.usages)
	}
}

func TestNativeBatchSettlementRetryAfterCheckpointFailureMovesMoneyOnce(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failNativeLedgerCheckpointOnceStore{
		ObjectStore: baseStore,
		pathSuffix:  "/native/ledger/00000000.enc",
	}
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", results: []NativeProviderResult{
		{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	settleCalls := map[int]int{}
	for _, index := range authorizer.settleCalls {
		settleCalls[index]++
	}
	if len(authorizer.settleCalls) != 3 || settleCalls[0]+settleCalls[1] != 3 ||
		(settleCalls[0] != 2 && settleCalls[1] != 2) {
		t.Fatalf("settle calls = %v; expected one safe control-plane replay", authorizer.settleCalls)
	}
	if len(authorizer.settled) != 2 || authorizer.settled[0] == authorizer.settled[1] {
		t.Fatalf("money movements = %v; settlement was not idempotent", authorizer.settled)
	}
}

func TestNativeBatchItemCheckpointRetryRestoresSettledResultWithoutResettling(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failItemCheckpointOnceStore{ObjectStore: baseStore}
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", results: []NativeProviderResult{
		{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"zero","choices":[{"message":{"content":"zero"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"one","choices":[{"message":{"content":"one"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted || len(completed.Results) != 2 {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if len(authorizer.settleCalls) != 2 || len(authorizer.settled) != 2 {
		t.Fatalf("settle calls=%v money movements=%v", authorizer.settleCalls, authorizer.settled)
	}
}

func TestNativeBatchRefundRetryAfterCheckpointFailureMovesMoneyOnce(t *testing.T) {
	t.Parallel()

	baseStore := newMemoryObjectStore()
	store := &failNativeLedgerCheckpointOnceStore{
		ObjectStore: baseStore,
		pathSuffix:  "/native/ledger/00000000.enc",
	}
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", results: []NativeProviderResult{
		{Index: 0, StatusCode: http.StatusTooManyRequests, Error: json.RawMessage(`{"message":"busy"}`)},
		{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if fmt.Sprint(authorizer.refundCalls) != "[0 0]" || fmt.Sprint(authorizer.refunded) != "[0]" {
		t.Fatalf("refund calls=%v money movements=%v", authorizer.refundCalls, authorizer.refunded)
	}
	if executor.calls != 1 {
		t.Fatalf("managed fallback calls = %d, want 1", executor.calls)
	}
}

func TestNativeBatchNeverFallsBackAfterNativeSettlement(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	service := newNativeService(
		t,
		store,
		authorizer,
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	authorization := NativeAuthorization{Handle: json.RawMessage(`{"index":0}`)}
	if _, err := service.storeNativeLedgerCheckpoint(
		t.Context(),
		"batch_settled_no_fallback",
		0,
		nativeLedgerCheckpoint{
			Version: nativeLedgerVersion,
			Action:  nativeLedgerSettled,
			Usage:   Usage{PromptTokens: 1, TotalTokens: 1},
			Result: &Result{
				ID:       "batch_req_settled",
				CustomID: "settled",
				Response: &ResultResponse{StatusCode: http.StatusOK},
			},
		},
	); err != nil {
		t.Fatalf("store settled checkpoint: %v", err)
	}
	if err := service.refundNativeAuthorizationOnce(
		t.Context(),
		"batch_settled_no_fallback",
		0,
		Request{CustomID: "settled"},
		authorization,
		http.StatusBadGateway,
		"provider_result_changed",
	); err != nil {
		t.Fatalf("restore settled checkpoint: %v", err)
	}
	if len(authorizer.refundCalls) != 0 {
		t.Fatalf("refund calls = %v; settled authorization must remain settled", authorizer.refundCalls)
	}
	if _, err := store.Get(t.Context(), itemResultName("batch_settled_no_fallback", 0)); err != nil {
		t.Fatalf("settled item checkpoint was not restored: %v", err)
	}
}

func TestNativeBatchLateSettlementRecoverySkipsManagedProviderCall(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	executor := &fakeManagedExecutor{}
	service := newNativeService(
		t, store, authorizer, &fakeNativeProvider{name: "openai"}, executor, time.Now,
	)
	authorization := NativeAuthorization{Handle: json.RawMessage(`{"index":0}`)}
	if _, err := authorizer.Settle(
		t.Context(), authorization, NativeUsage{InputTokens: 4, OutputTokens: 2},
	); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	err := service.fallbackNativeItem(
		t.Context(),
		job{Batch: Batch{
			ID: "batch_late_settlement", Endpoint: "/v1/chat/completions",
			Model: "openai/gpt-5.5", RequestCounts: RequestCounts{Total: 1},
		}},
		"lookup-hash",
		0,
		Request{CustomID: "late", Body: json.RawMessage(`{"messages":[]}`)},
		authorization,
		http.StatusBadGateway,
		"native_batch_item_failed",
	)
	if err != nil {
		t.Fatalf("fallbackNativeItem: %v", err)
	}
	if executor.calls != 0 {
		t.Fatalf("managed fallback calls = %d; charged native result was rerun", executor.calls)
	}
	stored, err := store.Get(t.Context(), itemResultName("batch_late_settlement", 0))
	if err != nil {
		t.Fatalf("load recovered result: %v", err)
	}
	result, err := service.openItemResult(t.Context(), "batch_late_settlement", 0, stored.Data)
	if err != nil || result.Usage.CostMicrodollars != 7 || result.Usage.GenerationID != "gen-0" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestNativeBatchLateRefundLearnsControlPlaneSettlementWon(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	service := newNativeService(
		t,
		store,
		authorizer,
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	authorization := NativeAuthorization{Handle: json.RawMessage(`{"index":0}`)}
	if _, err := authorizer.Settle(t.Context(), authorization, NativeUsage{InputTokens: 1}); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	err := service.refundNativeAuthorizationOnce(
		t.Context(), "batch_control_plane_won", 0, Request{CustomID: "late"}, authorization,
		http.StatusBadGateway, "late_refund",
	)
	if err != nil {
		t.Fatalf("recover late settlement: %v", err)
	}
	checkpoint, found, loadErr := service.loadNativeLedgerCheckpoint(
		t.Context(), "batch_control_plane_won", 0,
	)
	if loadErr != nil || !found || checkpoint.Action != nativeLedgerSettled {
		t.Fatalf("settlement checkpoint=%#v found=%t err=%v", checkpoint, found, loadErr)
	}
	if checkpoint.Result == nil || checkpoint.Result.CustomID != "late" ||
		checkpoint.GenerationID != "gen-0" {
		t.Fatalf("recovered settlement result = %#v", checkpoint.Result)
	}
	stored, err := store.Get(t.Context(), itemResultName("batch_control_plane_won", 0))
	if err != nil {
		t.Fatalf("load recovered item: %v", err)
	}
	result, err := service.openItemResult(t.Context(), "batch_control_plane_won", 0, stored.Data)
	if err != nil || fmt.Sprint(result.Error) == "<nil>" {
		t.Fatalf("recovered item=%#v err=%v", result, err)
	}
}

func TestNativeProviderResultWithoutAuthorizationIsTerminal(t *testing.T) {
	t.Parallel()

	service := newNativeService(
		t,
		newMemoryObjectStore(),
		&fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	err := service.finishNativeProviderResult(
		t.Context(),
		job{Batch: Batch{
			ID: "batch_unsubmitted", Model: "openai/gpt-5.5",
			Endpoint: "/v1/chat/completions", RequestCounts: RequestCounts{Total: 1},
		}},
		"lookup-hash",
		[]Request{{CustomID: "unexpected", Body: json.RawMessage(`{"messages":[]}`)}},
		nativeState{Provider: "openai"},
		NativeProviderResult{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"unexpected"}`)},
		true,
	)
	if !errors.Is(err, ErrNativeInvalidResult) || !strings.Contains(err.Error(), "was not submitted") {
		t.Fatalf("error = %v", err)
	}
}

func TestPreparedNativeStateWithNoPendingItemsResolvesWithoutSubmission(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	provider := &fakeNativeProvider{name: "openai"}
	service := newNativeService(
		t, store, &fakeNativeAuthorizer{provider: "openai"}, provider,
		&fakeManagedExecutor{}, time.Now,
	)
	batchID := "batch_prepared_empty"
	state := nativeState{
		Version: 1, Stage: nativeStagePrepared, Token: nativeSubmissionToken(batchID),
		Provider: "openai", EndpointID: "openai-endpoint", Model: "openai/gpt-5.5",
		UpstreamModel: "gpt-5.5",
		Submission:    NativeProviderJob{Provider: "openai", Token: nativeSubmissionToken(batchID)},
	}
	if _, _, err := service.createNativeState(t.Context(), batchID, state); err != nil {
		t.Fatalf("create state: %v", err)
	}
	outcome, err := service.tryNative(
		t.Context(),
		job{Batch: Batch{
			ID: batchID, Endpoint: "/v1/chat/completions", Model: "openai/gpt-5.5",
			RequestCounts: RequestCounts{Total: 1},
		}},
		"lookup-hash", nil,
		[]Request{{CustomID: "done", Body: json.RawMessage(`{"messages":[]}`)}},
	)
	if err != nil || outcome != nativeCompleted {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	resolved, _, found, err := service.loadNativeState(t.Context(), batchID)
	if err != nil || !found || resolved.Stage != nativeStageResolved || provider.submitCalls != 0 {
		t.Fatalf("state=%#v found=%t submit=%d err=%v", resolved, found, provider.submitCalls, err)
	}
}

func TestFutureNativeStateVersionDefersWithoutMutation(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	service := newNativeService(
		t, store, &fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"}, &fakeManagedExecutor{}, time.Now,
	)
	batchID := "batch_future_state"
	encoded, err := json.Marshal(nativeState{Version: 2, Stage: "future"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := store.Put(
		t.Context(), nativeStateName(batchID), encoded, PutCondition{Generation: 0},
	); err != nil {
		t.Fatalf("store: %v", err)
	}
	_, deferred, err := service.nativeDeferred(t.Context(), batchID)
	if err != nil || !deferred {
		t.Fatalf("deferred=%t err=%v", deferred, err)
	}
	stored, err := store.Get(t.Context(), nativeStateName(batchID))
	if err != nil || !bytes.Equal(stored.Data, encoded) {
		t.Fatalf("future state was mutated: %q err=%v", stored.Data, err)
	}
}

func TestNativeBatchCleanupFailureRetriesWithoutRepeatingResults(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:            "openai",
		cleanupFailures: 1,
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
			{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	inProgress, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || inProgress.Status != StatusInProgress {
		t.Fatalf("in progress=%#v err=%#v", inProgress, apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("early retry: %v", err)
	}
	if provider.cleanupCalls != 1 {
		t.Fatalf("cleanup retried before backoff: %d", provider.cleanupCalls)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("due retry: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.cleanupCalls != 2 || provider.pollCalls != 1 {
		t.Fatalf("cleanup=%d poll=%d", provider.cleanupCalls, provider.pollCalls)
	}
	if len(authorizer.settleCalls) != 2 || len(authorizer.settled) != 2 {
		t.Fatalf("settle calls=%v money movements=%v", authorizer.settleCalls, authorizer.settled)
	}
}

func TestNativeBatchCleanupFailureEventuallyReleasesCompletedBatch(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{
		name:            "openai",
		cleanupFailures: nativeCleanupMaxAttempts + 5,
		results: []NativeProviderResult{
			{Index: 0, StatusCode: 200, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
			{Index: 1, StatusCode: 200, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(
		t, store, authorizer, provider, &fakeManagedExecutor{}, func() time.Time { return now },
	)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	for attempt := 0; attempt < nativeCleanupMaxAttempts; attempt++ {
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("cleanup attempt %d: %v", attempt+1, err)
		}
		now = now.Add(nativeRetryMax + time.Second)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.cleanupCalls != nativeCleanupMaxAttempts || provider.resultsCalls != 1 {
		t.Fatalf("cleanup=%d results=%d", provider.cleanupCalls, provider.resultsCalls)
	}
	if len(authorizer.settleCalls) != 2 || len(authorizer.settled) != 2 {
		t.Fatalf("settle calls=%v money movements=%v", authorizer.settleCalls, authorizer.settled)
	}
}

func TestNativeResultByteBudgetBlocksAtConfiguredLimit(t *testing.T) {
	budget := newNativeResultByteBudget()
	full, err := budget.acquire(t.Context(), nativeResultInFlightBytes)
	if err != nil {
		t.Fatalf("acquire full budget: %v", err)
	}
	type acquisition struct {
		units int
		err   error
	}
	done := make(chan acquisition, 1)
	go func() {
		units, err := budget.acquire(t.Context(), 1)
		done <- acquisition{units: units, err: err}
	}()
	select {
	case result := <-done:
		t.Fatalf("budget exceeded configured limit: %#v", result)
	case <-time.After(20 * time.Millisecond):
	}
	budget.release(full)
	select {
	case result := <-done:
		if result.err != nil || result.units != 1 {
			t.Fatalf("acquire after release: %#v", result)
		}
		budget.release(result.units)
	case <-time.After(time.Second):
		t.Fatal("budget did not unblock after release")
	}
}

func TestNativeBatchRequiresExplicitControlPlaneEligibility(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai", ineligible: true}
	provider := &fakeNativeProvider{name: "openai"}
	executor := &fakeManagedExecutor{}
	service := newNativeService(t, store, authorizer, provider, executor, time.Now)
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 0 || executor.calls != 2 || len(authorizer.refunded) != 2 {
		t.Fatalf("native=%d managed=%d refunded=%v", provider.submitCalls, executor.calls, authorizer.refunded)
	}
}

func TestNativeBatchSubmitRateLimitBacksOffWithoutManagedFallback(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", submitStatus: http.StatusTooManyRequests}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("early retry: %v", err)
	}
	if provider.submitCalls != 1 {
		t.Fatalf("submit retried before backoff: %d", provider.submitCalls)
	}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("due retry: %v", err)
	}
	inProgress, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || inProgress.Status != StatusInProgress {
		t.Fatalf("in progress=%#v err=%#v", inProgress, apiErr)
	}
	if provider.submitCalls != 2 || executor.calls != 0 || len(authorizer.refunded) != 0 {
		t.Fatalf("submit=%d managed=%d refunded=%v", provider.submitCalls, executor.calls, authorizer.refunded)
	}
}

func TestNativeBatchSubmitRateLimitExhaustionFallsBackAfterBoundedAttempts(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "openai"}
	provider := &fakeNativeProvider{name: "openai", submitStatus: http.StatusTooManyRequests}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	for attempt := 0; attempt <= nativeSubmitMaxAttempts; attempt++ {
		if err := service.runAvailable(t.Context()); err != nil {
			t.Fatalf("run %d: %v", attempt, err)
		}
		now = now.Add(nativeRetryMax + time.Second)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != nativeSubmitMaxAttempts || executor.calls != 2 ||
		len(authorizer.refunded) != 2 {
		t.Fatalf(
			"submit=%d managed=%d refunded=%v",
			provider.submitCalls, executor.calls, authorizer.refunded,
		)
	}
}

func TestNativeBatchKillSwitchStopsNewSubmissionsButRecoversExistingJob(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	authorizer := &fakeNativeAuthorizer{provider: "parasail"}
	provider := &fakeNativeProvider{name: "parasail", pendingPolls: 1, results: []NativeProviderResult{
		{Index: 0, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"zero","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
		{Index: 1, StatusCode: http.StatusOK, Body: json.RawMessage(`{"id":"one","usage":{"prompt_tokens":1,"completion_tokens":1}}`)},
	}}
	executor := &fakeManagedExecutor{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newNativeService(t, store, authorizer, provider, executor, func() time.Time { return now })
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("submit run: %v", err)
	}
	service.nativeSubmitProviders = map[string]struct{}{}
	now = now.Add(nativeRetryBase + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil || completed.Status != StatusCompleted {
		t.Fatalf("completed=%#v err=%#v", completed, apiErr)
	}
	if provider.submitCalls != 1 || executor.calls != 0 {
		t.Fatalf("submit=%d managed=%d", provider.submitCalls, executor.calls)
	}
}

func TestCreateNativeStateAdoptsConcurrentWinner(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	service := newNativeService(
		t,
		store,
		&fakeNativeAuthorizer{provider: "openai"},
		&fakeNativeProvider{name: "openai"},
		&fakeManagedExecutor{},
		time.Now,
	)
	batchID := "batch_state_race"
	winner := nativeState{
		Version: 1,
		Stage:   nativeStageDisabled,
		Token:   nativeSubmissionToken(batchID),
	}
	encoded, err := json.Marshal(winner)
	if err != nil {
		t.Fatalf("encode winner: %v", err)
	}
	stored, err := store.Put(t.Context(), nativeStateName(batchID), encoded, PutCondition{Generation: 0})
	if err != nil {
		t.Fatalf("store winner: %v", err)
	}
	proposed := nativeState{
		Version:       1,
		Stage:         nativeStagePrepared,
		Token:         nativeSubmissionToken(batchID),
		Provider:      "openai",
		EndpointID:    "endpoint",
		Model:         "test/model",
		UpstreamModel: "upstream/model",
		Submission: NativeProviderJob{
			Provider: "openai",
			Token:    nativeSubmissionToken(batchID),
		},
	}
	got, generation, err := service.createNativeState(t.Context(), batchID, proposed)
	if err != nil {
		t.Fatalf("createNativeState: %v", err)
	}
	if got.Stage != nativeStageDisabled || generation != stored.Generation {
		t.Fatalf("state=%#v generation=%d; concurrent winner was not adopted", got, generation)
	}
}
