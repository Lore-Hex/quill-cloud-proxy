package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type memoryObjectStore struct {
	mu         sync.Mutex
	next       int64
	objects    map[string]StoredObject
	putFailure error
}

type rejectingPageTokenStore struct {
	ObjectStore
	rejected string
}

func (s *rejectingPageTokenStore) List(
	ctx context.Context,
	prefix string,
	limit int,
	pageToken string,
) ([]ObjectMeta, string, error) {
	if pageToken == s.rejected {
		return nil, "", errors.New("stale page token")
	}
	return s.ObjectStore.List(ctx, prefix, limit, pageToken)
}

func getBatchForTest(
	ctx context.Context,
	service *Service,
	bearer string,
	id string,
) (*Batch, *APIError) {
	prepared, apiErr := service.PrepareGet(ctx, bearer, id)
	if apiErr != nil {
		return nil, apiErr
	}
	result := prepared.Batch
	if prepared.ResultSet {
		result.Results = make([]Result, 0, result.RequestCounts.Completed+result.RequestCounts.Failed)
		for {
			item, ok, err := prepared.Next(ctx)
			if err != nil {
				return nil, internalAPIError("batch results unavailable")
			}
			if !ok {
				break
			}
			result.Results = append(result.Results, item)
		}
	}
	return &result, nil
}

func newMemoryObjectStore() *memoryObjectStore {
	return &memoryObjectStore{next: 1, objects: map[string]StoredObject{}}
}

func (s *memoryObjectStore) Get(_ context.Context, name string) (StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[name]
	if !ok {
		return StoredObject{}, ErrNotFound
	}
	object.Data = append([]byte(nil), object.Data...)
	return object, nil
}

func (s *memoryObjectStore) Put(_ context.Context, name string, data []byte, condition PutCondition) (StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putFailure != nil {
		return StoredObject{}, s.putFailure
	}
	existing, exists := s.objects[name]
	if condition.Generation == 0 && exists {
		return StoredObject{}, ErrPrecondition
	}
	if condition.Generation > 0 && (!exists || existing.Generation != condition.Generation) {
		return StoredObject{}, ErrPrecondition
	}
	object := StoredObject{Name: name, Data: append([]byte(nil), data...), Generation: s.next}
	s.next++
	s.objects[name] = object
	return object, nil
}

func (s *memoryObjectStore) Delete(_ context.Context, name string, generation int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.objects[name]
	if !exists {
		return nil
	}
	if generation > 0 && existing.Generation != generation {
		return ErrPrecondition
	}
	delete(s.objects, name)
	return nil
}

func (s *memoryObjectStore) List(
	_ context.Context,
	prefix string,
	limit int,
	pageToken string,
) ([]ObjectMeta, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0)
	for name := range s.objects {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if pageToken != "" {
		start := sort.SearchStrings(names, pageToken)
		if start < len(names) && names[start] == pageToken {
			start++
		}
		names = names[start:]
	}
	nextPageToken := ""
	if limit > 0 && len(names) > limit {
		nextPageToken = names[limit-1]
		names = names[:limit]
	}
	out := make([]ObjectMeta, 0, len(names))
	for _, name := range names {
		out = append(out, ObjectMeta{Name: name, Generation: s.objects[name].Generation})
	}
	return out, nextPageToken, nil
}

type copyProtector struct{}

func (copyProtector) Seal(_ context.Context, _, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (copyProtector) Open(_ context.Context, _, _ string, encoded []byte) ([]byte, error) {
	return append([]byte(nil), encoded...), nil
}

type allowKeys map[string]bool

func (keys allowKeys) ValidateKey(_ context.Context, bearer, _ string) error {
	if keys[bearer] {
		return nil
	}
	return &trustedrouter.ControlPlaneError{StatusCode: 401, Message: "Invalid API key", Type: "invalid_api_key"}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

type httpTestExecutor struct{ client *http.Client }

func (e httpTestExecutor) Execute(ctx context.Context, apiKeyLookupHash, endpoint string, body []byte, idempotencyKey string) (int, string, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://regional-api.invalid"+endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	request.Header.Set("Authorization", "Bearer "+apiKeyLookupHash)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := e.client.Do(request)
	if err != nil {
		return 0, "", nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, "", nil, err
	}
	return response.StatusCode, response.Header.Get("X-Request-ID"), responseBody, nil
}

type concurrencyTrackingExecutor struct {
	mu        sync.Mutex
	active    int
	maxActive int
	calls     int
	release   <-chan struct{}
	started   chan<- struct{}
}

func (e *concurrencyTrackingExecutor) Execute(context.Context, string, string, []byte, string) (int, string, []byte, error) {
	e.mu.Lock()
	e.active++
	e.calls++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
	e.mu.Unlock()
	if e.started != nil {
		e.started <- struct{}{}
	}
	<-e.release
	e.mu.Lock()
	e.active--
	e.mu.Unlock()
	return 200, "request-bounded", []byte(`{"id":"chatcmpl-bounded","usage":{"prompt_tokens":1,"completion_tokens":1,"cost_microdollars":1}}`), nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newTestService(t *testing.T, store ObjectStore, protector Protector, client *http.Client, now func() time.Time, workerID string) *Service {
	t.Helper()
	service, err := New(Options{
		Store:         store,
		Protector:     protector,
		Keys:          allowKeys{"sk-tr-owner": true, "sk-tr-other": true},
		Executor:      httpTestExecutor{client: client},
		WorkerID:      workerID,
		Concurrency:   4,
		PollInterval:  time.Hour,
		LeaseDuration: time.Minute,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return service
}

func twoRequestBatch() []byte {
	return []byte(`{
      "endpoint":"/v1/chat/completions",
      "model":"test/model",
      "requests":[
        {"custom_id":"slow-success","body":{"messages":[{"role":"user","content":"A"}]}},
        {"custom_id":"hard-failure","body":{"messages":[{"role":"user","content":"B"}]}}
      ]
    }`)
}

func TestServiceCompletesPartialBatchWithExactAccountingAndNoOuterRetry(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	var mu sync.Mutex
	attempts := map[string]int{}
	idempotency := map[string]map[string]struct{}{}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		if request.URL.Path != "/v1/chat/completions" || request.Header.Get("Authorization") != "Bearer "+trustedrouter.LookupHash("sk-tr-owner") {
			t.Fatalf("unexpected request: %s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if decoded["model"] != "test/model" {
			t.Fatalf("model = %#v", decoded["model"])
		}
		messages := decoded["messages"].([]any)
		content := messages[0].(map[string]any)["content"].(string)
		mu.Lock()
		attempts[content]++
		if idempotency[content] == nil {
			idempotency[content] = map[string]struct{}{}
		}
		idempotency[content][request.Header.Get("Idempotency-Key")] = struct{}{}
		mu.Unlock()
		if content == "B" {
			return jsonResponse(429, `{"error":{"message":"busy","type":"rate_limit_error"}}`), nil
		}
		response := jsonResponse(200, `{"id":"chatcmpl-a","choices":[{"message":{"role":"assistant","content":"A done"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"cost_microdollars":7,"provider_usage":{"usage_type":"credits"}}}`)
		response.Header.Set("X-Request-ID", "request-a")
		return response, nil
	})}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, store, copyProtector{}, client, func() time.Time { return now }, "worker-a")

	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if created.Status != StatusValidating || created.FinalizedAt != nil || created.Usage != nil || created.Results != nil {
		t.Fatalf("create response = %#v", created)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	if _, err := store.Get(t.Context(), finalResultsName(created.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("worker wrote duplicate aggregate results object: %v", err)
	}

	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil {
		t.Fatalf("Get: %v", apiErr)
	}
	if completed.Status != StatusCompleted || completed.FinalizedAt == nil {
		t.Fatalf("status = %q finalized = %#v", completed.Status, completed.FinalizedAt)
	}
	if completed.RequestCounts != (RequestCounts{Total: 2, Completed: 1, Failed: 1}) {
		t.Fatalf("request counts = %#v", completed.RequestCounts)
	}
	if len(completed.Results) != 2 || completed.Results[0].CustomID != "slow-success" || completed.Results[1].CustomID != "hard-failure" {
		t.Fatalf("results changed order: %#v", completed.Results)
	}
	if completed.Results[0].Response == nil || completed.Results[0].Error != nil || completed.Results[0].Response.RequestID != "request-a" {
		t.Fatalf("successful result = %#v", completed.Results[0])
	}
	if completed.Results[1].Response != nil || completed.Results[1].Error == nil {
		t.Fatalf("failed result = %#v", completed.Results[1])
	}
	if completed.Usage == nil || completed.Usage.PromptTokens != 3 || completed.Usage.CompletionTokens != 2 || completed.Usage.TotalTokens != 5 || completed.Usage.Cost != 0.000007 || completed.Usage.IsBYOK {
		t.Fatalf("usage = %#v", completed.Usage)
	}
	if attempts["A"] != 1 || attempts["B"] != 1 || len(idempotency["A"]) != 1 || len(idempotency["B"]) != 1 {
		t.Fatalf("attempts=%#v idempotency=%#v", attempts, idempotency)
	}

	if _, apiErr := getBatchForTest(t.Context(), service, "sk-tr-other", created.ID); apiErr == nil || apiErr.Status != 404 {
		t.Fatalf("cross-owner Get apiErr = %#v", apiErr)
	}
}

func TestRunAvailableRotatesAcrossEveryActiveObjectPage(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	service := newTestService(
		t,
		store,
		copyProtector{},
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("terminal jobs must not execute")
			return nil, nil
		})},
		time.Now,
		"page-worker",
	)
	for index := 0; index <= maxActiveScan; index++ {
		id := fmt.Sprintf("batch_page_%04d", index)
		encoded, err := json.Marshal(job{Batch: Batch{
			ID:               id,
			Object:           ObjectType,
			Endpoint:         "/v1/chat/completions",
			Model:            "test/model",
			CompletionWindow: CompletionWindow,
			Status:           StatusCompleted,
			CreatedAt:        1,
			RequestCounts:    RequestCounts{Total: 1, Completed: 1},
		}, ExpiresAt: time.Now().Add(time.Hour).Unix()})
		if err != nil {
			t.Fatalf("encode job %d: %v", index, err)
		}
		if _, err := store.Put(t.Context(), activeJobName(id), encoded, PutCondition{Generation: 0}); err != nil {
			t.Fatalf("seed job %d: %v", index, err)
		}
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("first page: %v", err)
	}
	if service.scanPageToken == "" {
		t.Fatal("first page did not preserve a continuation token")
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("second page: %v", err)
	}
	if service.scanPageToken != "" {
		t.Fatalf("scan did not reach the final page: %q", service.scanPageToken)
	}
}

func TestRunAvailableClearsRejectedPageToken(t *testing.T) {
	t.Parallel()

	store := &rejectingPageTokenStore{
		ObjectStore: newMemoryObjectStore(),
		rejected:    "stale-token",
	}
	service := newTestService(
		t,
		store,
		copyProtector{},
		&http.Client{},
		time.Now,
		"page-worker",
	)
	service.scanPageToken = store.rejected
	if err := service.runAvailable(t.Context()); err == nil {
		t.Fatal("expected stale page token error")
	}
	if service.scanPageToken != "" {
		t.Fatalf("scan page token was not reset: %q", service.scanPageToken)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("root scan after reset: %v", err)
	}
}

func TestRunAvailableBoundsParallelBatchJobs(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	release := make(chan struct{}, 3)
	started := make(chan struct{}, 3)
	executor := &concurrencyTrackingExecutor{release: release, started: started}
	service, err := New(Options{
		Store:         store,
		Protector:     copyProtector{},
		Keys:          allowKeys{"sk-tr-owner": true},
		Executor:      executor,
		WorkerID:      "bounded-job-worker",
		Concurrency:   1,
		JobWorkers:    2,
		PollInterval:  time.Hour,
		LeaseDuration: time.Minute,
		Now:           time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	request := []byte(`{"endpoint":"/v1/chat/completions","model":"test/model","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"A"}]}}]}`)
	for index := 0; index < 3; index++ {
		if _, apiErr := service.Create(t.Context(), "sk-tr-owner", request); apiErr != nil {
			t.Fatalf("Create %d: %v", index, apiErr)
		}
	}
	done := make(chan error, 1)
	go func() { done <- service.runAvailable(t.Context()) }()
	<-started
	<-started
	select {
	case <-started:
		t.Fatal("third batch started above the configured two-job bound")
	case <-time.After(20 * time.Millisecond):
	}
	store.mu.Lock()
	leased := 0
	for name, object := range store.objects {
		if !strings.HasPrefix(name, activePrefix) {
			continue
		}
		var active job
		if err := json.Unmarshal(object.Data, &active); err != nil {
			store.mu.Unlock()
			t.Fatalf("decode active job: %v", err)
		}
		if active.LeaseOwner != "" {
			leased++
		}
	}
	store.mu.Unlock()
	if leased != 2 {
		t.Fatalf("leased jobs = %d, want exactly the two jobs with active workers", leased)
	}
	release <- struct{}{}
	<-started
	release <- struct{}{}
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.calls != 3 || executor.maxActive != 2 {
		t.Fatalf("calls=%d max_active=%d", executor.calls, executor.maxActive)
	}
}

func TestServiceStoresBearerAndContentOnlyInEncryptedArtifacts(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	protector := &EnvelopeProtector{
		KMS:     &fakeKMS{},
		KeyName: "projects/p/locations/us/keyRings/r/cryptoKeys/batch",
		Rand:    bytes.NewReader(bytes.Repeat([]byte{0x44}, 128)),
	}
	service := newTestService(t, store, protector, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("must not execute during create")
	})}, time.Now, "worker-a")
	body := []byte(`{"endpoint":"/v1/chat/completions","model":"test/model","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"private-prompt-marker"}]}}]}`)
	if _, apiErr := service.Create(t.Context(), "sk-tr-owner", body); apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for name, object := range store.objects {
		for _, forbidden := range [][]byte{[]byte("sk-tr-owner"), []byte("private-prompt-marker")} {
			if bytes.Contains(object.Data, forbidden) {
				t.Fatalf("object %q contains plaintext %q", name, forbidden)
			}
		}
	}
}

func TestServiceNeverPersistsRawAPIKeyBeforeEnvelopeEncryption(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	rawKey := "sk-tr-never-persist-this-key"
	service, err := New(Options{
		Store:         store,
		Protector:     copyProtector{},
		Keys:          allowKeys{rawKey: true},
		Executor:      httpTestExecutor{client: http.DefaultClient},
		WorkerID:      "worker-no-raw-key",
		PollInterval:  time.Hour,
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, apiErr := service.Create(t.Context(), rawKey, []byte(`{"endpoint":"/v1/chat/completions","model":"test/model","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"private prompt"}]}}]}`)); apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for name, object := range store.objects {
		if bytes.Contains(object.Data, []byte(rawKey)) {
			t.Fatalf("object %q persisted raw API key", name)
		}
	}
}

func TestServiceItemLogsContainMetadataOnly(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	var logsMu sync.Mutex
	var logs []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		if bytes.Contains(body, []byte("provider-error-prompt-marker")) {
			return jsonResponse(400, `{"error":{"message":"provider-error-output-marker","type":"invalid_request_error"}}`), nil
		}
		return jsonResponse(200, `{"id":"chatcmpl-log","choices":[{"message":{"role":"assistant","content":"private-output-marker"}}],"usage":{"prompt_tokens":13,"completion_tokens":5,"total_tokens":18,"cost_microdollars":23,"provider_usage":{"usage_type":"credits"}}}`), nil
	})}
	service, err := New(Options{
		Store:         store,
		Protector:     copyProtector{},
		Keys:          allowKeys{"sk-tr-log-secret": true},
		Executor:      httpTestExecutor{client: client},
		WorkerID:      "worker-log-test",
		Concurrency:   2,
		PollInterval:  time.Hour,
		LeaseDuration: time.Minute,
		Now:           time.Now,
		Logf: func(format string, args ...any) {
			logsMu.Lock()
			defer logsMu.Unlock()
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	created, apiErr := service.Create(t.Context(), "sk-tr-log-secret", []byte(`{
      "endpoint":"/v1/chat/completions",
      "model":"test/model",
      "requests":[
        {"custom_id":"private-custom-id-marker","body":{"messages":[{"role":"user","content":"private-prompt-marker"}]}},
        {"custom_id":"private-error-id-marker","body":{"messages":[{"role":"user","content":"provider-error-prompt-marker"}]}}
      ]
    }`))
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}

	logsMu.Lock()
	joined := strings.Join(logs, "\n")
	logsMu.Unlock()
	for _, forbidden := range []string{
		"sk-tr-log-secret",
		"private-custom-id-marker",
		"private-error-id-marker",
		"private-prompt-marker",
		"private-output-marker",
		"provider-error-prompt-marker",
		"provider-error-output-marker",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("batch logs contain private marker %q: %s", forbidden, joined)
		}
	}
	for _, required := range []string{
		"batch.item_end",
		"outcome=\"success\"",
		"outcome=\"http_error\"",
		"attempts=1",
		"prompt_tokens=13",
		"completion_tokens=5",
		"cost_microdollars=23",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("batch logs missing %q: %s", required, joined)
		}
	}
	if !strings.Contains(joined, fmt.Sprintf("id=%q", created.ID)) {
		t.Fatalf("batch logs do not contain batch id: %s", joined)
	}
}

func TestServiceRecoversFromItemCheckpointsWithoutReinvoking(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(request.Body)
		if bytes.Contains(body, []byte(`"content":"A"`)) {
			t.Fatal("checkpointed first item was invoked again")
		}
		return jsonResponse(200, `{"id":"chatcmpl-b","usage":{"prompt_tokens":2,"completion_tokens":1,"cost_microdollars":4,"provider_usage":{"usage_type":"byok"}}}`), nil
	})}
	service := newTestService(t, store, copyProtector{}, client, time.Now, "worker-a")
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", twoRequestBatch())
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	checkpoint := Result{
		ID:       resultID(created.ID, "slow-success"),
		CustomID: "slow-success",
		Response: &ResultResponse{StatusCode: 200, RequestID: "request-a", Body: map[string]any{"id": "chatcmpl-a"}},
		Usage:    Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2, CostMicrodollars: 3, IsBYOK: true},
	}
	encoded, _ := json.Marshal(itemCheckpoint{
		Result:           checkpoint,
		Usage:            checkpoint.Usage,
		CostMicrodollars: checkpoint.Usage.CostMicrodollars,
	})
	if _, err := store.Put(t.Context(), itemResultName(created.ID, 0), encoded, PutCondition{Generation: 0}); err != nil {
		t.Fatalf("store checkpoint: %v", err)
	}
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	completed, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil {
		t.Fatalf("Get: %v", apiErr)
	}
	if calls != 1 || completed.RequestCounts.Completed != 2 || len(completed.Results) != 2 {
		t.Fatalf("calls=%d batch=%#v", calls, completed)
	}
	if completed.Results[0].Response.RequestID != "request-a" || completed.Results[1].CustomID != "hard-failure" {
		t.Fatalf("recovered results = %#v", completed.Results)
	}
	if completed.Usage == nil || completed.Usage.Cost != 0.000007 || !completed.Usage.IsBYOK {
		t.Fatalf("aggregate usage = %#v", completed.Usage)
	}
}

func TestServiceLeaseAllowsOnlyOneRegionalWorker(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, `{}`), nil
	})}
	first := newTestService(t, store, copyProtector{}, client, func() time.Time { return now }, "worker-a")
	second := newTestService(t, store, copyProtector{}, client, func() time.Time { return now }, "worker-b")
	created, apiErr := first.Create(t.Context(), "sk-tr-owner", []byte(`{"endpoint":"/v1/responses","model":"m","requests":[{"custom_id":"one","body":{"input":"hi"}}]}`))
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	if _, _, ok, err := first.claim(t.Context(), activeJobName(created.ID)); err != nil || !ok {
		t.Fatalf("first claim ok=%v err=%v", ok, err)
	}
	if _, _, ok, err := second.claim(t.Context(), activeJobName(created.ID)); err != nil || ok {
		t.Fatalf("second claim ok=%v err=%v", ok, err)
	}
}

func TestServiceExpiresAfterCompletionWindowWithoutInvoking(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	var calls int
	service := newTestService(t, store, copyProtector{}, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(200, `{}`), nil
	})}, func() time.Time { return now }, "worker-a")
	created, apiErr := service.Create(t.Context(), "sk-tr-owner", []byte(`{"endpoint":"/v1/messages","model":"m","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"hi"}]}}]}`))
	if apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	now = now.Add(24*time.Hour + time.Second)
	if err := service.runAvailable(t.Context()); err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	expired, apiErr := getBatchForTest(t.Context(), service, "sk-tr-owner", created.ID)
	if apiErr != nil {
		t.Fatalf("Get: %v", apiErr)
	}
	if calls != 0 || expired.Status != StatusExpired || expired.FinalizedAt == nil ||
		expired.Results == nil || len(expired.Results) != 0 || expired.Usage != nil {
		t.Fatalf("calls=%d expired=%#v", calls, expired)
	}
}

func TestServiceRejectsInvalidKeyBeforeWritingObjects(t *testing.T) {
	t.Parallel()

	store := newMemoryObjectStore()
	service := newTestService(t, store, copyProtector{}, http.DefaultClient, time.Now, "worker-a")
	// Authentication must happen before expensive JSON validation.
	_, apiErr := service.Create(t.Context(), "sk-tr-invalid", []byte(`not-json`))
	if apiErr == nil || apiErr.Status != 401 {
		t.Fatalf("apiErr = %#v", apiErr)
	}
	if len(store.objects) != 0 {
		t.Fatalf("invalid key wrote objects: %#v", store.objects)
	}
}

func TestServiceBoundsConcurrentItemExecution(t *testing.T) {
	store := newMemoryObjectStore()
	release := make(chan struct{})
	executor := &concurrencyTrackingExecutor{release: release}
	service, err := New(Options{
		Store:         store,
		Protector:     copyProtector{},
		Keys:          allowKeys{"sk-tr-owner": true},
		Executor:      executor,
		WorkerID:      "worker-bounded",
		Concurrency:   3,
		PollInterval:  time.Hour,
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	requests := make([]Request, 24)
	for index := range requests {
		requests[index] = Request{CustomID: fmt.Sprintf("item-%02d", index), Body: json.RawMessage(`{"messages":[{"role":"user","content":"hello"}]}`)}
	}
	createBody, err := json.Marshal(CreateRequest{Endpoint: "/v1/chat/completions", Model: "test/model", Requests: requests})
	if err != nil {
		t.Fatalf("marshal create: %v", err)
	}
	if _, apiErr := service.Create(t.Context(), "sk-tr-owner", createBody); apiErr != nil {
		t.Fatalf("Create: %v", apiErr)
	}
	done := make(chan error, 1)
	go func() { done <- service.runAvailable(t.Context()) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		executor.mu.Lock()
		active := executor.active
		maxActive := executor.maxActive
		executor.mu.Unlock()
		if active == 3 {
			if maxActive != 3 {
				t.Fatalf("max active = %d", maxActive)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("workers did not reach configured concurrency: active=%d max=%d", active, maxActive)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("runAvailable: %v", err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.calls != len(requests) || executor.maxActive > 3 {
		t.Fatalf("calls=%d max_active=%d", executor.calls, executor.maxActive)
	}
}

func TestUsageParsingPreservesIntegerMicrodollars(t *testing.T) {
	t.Parallel()

	decoded, err := decodeJSONValue([]byte(`{"usage":{"prompt_tokens":9007199254740993,"completion_tokens":2,"cost_microdollars":9007199254740995}}`))
	if err != nil {
		t.Fatalf("decodeJSONValue: %v", err)
	}
	usage := usageFromBody(decoded)
	if usage.PromptTokens != 9007199254740993 || usage.CompletionTokens != 2 || usage.CostMicrodollars != 9007199254740995 {
		t.Fatalf("usage lost integer precision: %#v", usage)
	}
}

func TestAggregateUsageIncludesChargedRecoveryFailure(t *testing.T) {
	t.Parallel()

	usage := aggregateUsageStates([]itemState{
		{
			finished: true,
			usage: Usage{
				PromptTokens: 10, CompletionTokens: 2, CostMicrodollars: 7,
			},
		},
		{
			finished: true,
			failed:   true,
			usage: Usage{
				PromptTokens: 20, CompletionTokens: 3, CostMicrodollars: 11,
			},
		},
		{finished: true, failed: true},
	})
	if usage.PromptTokens != 30 || usage.CompletionTokens != 5 ||
		usage.TotalTokens != 35 || usage.CostMicrodollars != 18 || usage.Cost != 0.000018 {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestDecodeJobRejectsRedirectedArtifactsAndInvalidOwnership(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	valid := newJob(
		"batch_0123456789abcdef0123456789abcdef",
		trustedrouter.LookupHash("owner"),
		CreateRequest{
			Endpoint: "/v1/chat/completions",
			Model:    "test/model",
			Requests: []Request{{CustomID: "one", Body: json.RawMessage(`{}`)}},
		},
		now,
	)
	for name, mutate := range map[string]func(*job){
		"redirected input":   func(value *job) { value.InputObject = "attacker/input.enc" },
		"redirected results": func(value *job) { value.ResultsObject = "attacker/results.enc" },
		"invalid owner":      func(value *job) { value.OwnerLookupHash = strings.Repeat("z", 64) },
		"extended expiry":    func(value *job) { value.ExpiresAt++ },
		"invalid counts":     func(value *job) { value.RequestCounts.Completed = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := decodeJob(encoded); err == nil {
				t.Fatalf("decodeJob accepted %s", name)
			}
		})
	}
}
