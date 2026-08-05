package batch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const (
	activePrefix       = "trustedrouter-batches/v1/active/"
	terminalPrefix     = "trustedrouter-batches/v1/jobs/"
	artifactPrefix     = "trustedrouter-batches/v1/artifacts/"
	defaultConcurrency = 8
	maxActiveScan      = 1000
	maxResponseBytes   = 64 * 1024 * 1024
)

type KeyValidator interface {
	ValidateKey(context.Context, string, string) error
}

type Executor interface {
	Execute(context.Context, string, string, []byte, string) (int, string, []byte, error)
}

type Options struct {
	Store         ObjectStore
	Protector     Protector
	Keys          KeyValidator
	Executor      Executor
	WorkerID      string
	Concurrency   int
	PollInterval  time.Duration
	LeaseDuration time.Duration
	Now           func() time.Time
	Logf          func(string, ...any)
}

type Service struct {
	store       ObjectStore
	protector   Protector
	keys        KeyValidator
	executor    Executor
	workerID    string
	concurrency int
	poll        time.Duration
	lease       time.Duration
	now         func() time.Time
	logf        func(string, ...any)
	wake        chan struct{}
}

var errLeaseLost = errors.New("batch lease lost")

type itemState struct {
	finished bool
	failed   bool
	usage    Usage
}

// jobLease serializes metadata checkpoints with lease heartbeats. Without a
// shared generation, a heartbeat and a completed item could race their GCS
// compare-and-set writes and make a healthy worker appear to have lost its
// lease.
type jobLease struct {
	service *Service

	mu         sync.Mutex
	job        job
	generation int64
}

func (l *jobLease) update(ctx context.Context, mutate func(*job)) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if mutate != nil {
		mutate(&l.job)
	}
	generation, err := l.service.saveProgress(ctx, l.job, l.generation)
	if errors.Is(err, ErrPrecondition) {
		return errLeaseLost
	}
	if err != nil {
		return err
	}
	l.generation = generation
	return nil
}

func (l *jobLease) snapshot() (job, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.job, l.generation
}

func (l *jobLease) maintain(ctx context.Context, cancel context.CancelFunc) func() {
	interval := l.service.lease / 3
	if interval < time.Second {
		interval = time.Second
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				if err := l.update(ctx, nil); err != nil {
					l.service.logf("batch.lease_renewal_failed id=%q err=%q", l.job.ID, err.Error())
					cancel()
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}

func New(options Options) (*Service, error) {
	if options.Store == nil || options.Protector == nil || options.Keys == nil || options.Executor == nil {
		return nil, fmt.Errorf("batch service: store, protector, key validator, and executor are required")
	}
	if options.Concurrency <= 0 {
		options.Concurrency = defaultConcurrency
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 5 * time.Second
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 2 * time.Minute
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logf == nil {
		options.Logf = func(string, ...any) {}
	}
	if options.WorkerID == "" {
		options.WorkerID = randomID("batch_worker_", 8)
	}
	return &Service{
		store:       options.Store,
		protector:   options.Protector,
		keys:        options.Keys,
		executor:    options.Executor,
		workerID:    options.WorkerID,
		concurrency: options.Concurrency,
		poll:        options.PollInterval,
		lease:       options.LeaseDuration,
		now:         options.Now,
		logf:        options.Logf,
		wake:        make(chan struct{}, 1),
	}, nil
}

func (s *Service) Start(ctx context.Context) {
	go s.workerLoop(ctx)
}

func (s *Service) Create(ctx context.Context, bearer string, raw []byte) (*Batch, *APIError) {
	if err := s.keys.ValidateKey(ctx, bearer, "batch"); err != nil {
		return nil, controlPlaneAPIError(err)
	}
	req, apiErr := ParseCreate(raw)
	if apiErr != nil {
		return nil, apiErr
	}

	id := randomID("batch_", 16)
	now := s.now()
	ownerLookupHash := trustedrouter.LookupHash(bearer)
	job := newJob(id, ownerLookupHash, req, now)
	payload, err := json.Marshal(encryptedPayload{APIKeyLookupHash: ownerLookupHash, Requests: req.Requests})
	if err != nil {
		return nil, internalAPIError("could not encode batch")
	}
	encrypted, err := s.protector.Seal(ctx, id, "input", payload)
	clear(payload)
	if err != nil {
		return nil, internalAPIError("batch storage encryption unavailable")
	}
	inputObject, err := s.store.Put(ctx, job.InputObject, encrypted, PutCondition{Generation: 0})
	if err != nil {
		return nil, internalAPIError("batch storage unavailable")
	}
	jobData, err := json.Marshal(job)
	if err != nil {
		_ = s.store.Delete(ctx, inputObject.Name, inputObject.Generation)
		return nil, internalAPIError("could not encode batch")
	}
	if _, err := s.store.Put(ctx, activeJobName(id), jobData, PutCondition{Generation: 0}); err != nil {
		_ = s.store.Delete(ctx, inputObject.Name, inputObject.Generation)
		return nil, internalAPIError("batch storage unavailable")
	}
	s.logf("batch.created id=%q endpoint=%q request_count=%d", id, req.Endpoint, len(req.Requests))
	s.signalWorker()
	batch := job.Batch
	return &batch, nil
}

func (s *Service) Get(ctx context.Context, bearer, id string) (*Batch, *APIError) {
	if err := s.keys.ValidateKey(ctx, bearer, "batch"); err != nil {
		return nil, controlPlaneAPIError(err)
	}
	if !validBatchID(id) {
		return nil, &APIError{Status: 404, Message: "batch not found", Type: "invalid_request_error", Code: "not_found"}
	}
	stored, err := s.store.Get(ctx, activeJobName(id))
	if errors.Is(err, ErrNotFound) {
		stored, err = s.store.Get(ctx, terminalJobName(id))
	}
	if errors.Is(err, ErrNotFound) {
		return nil, &APIError{Status: 404, Message: "batch not found", Type: "invalid_request_error", Code: "not_found"}
	}
	if err != nil {
		return nil, internalAPIError("batch storage unavailable")
	}
	job, err := decodeJob(stored.Data)
	if err != nil {
		return nil, internalAPIError("batch metadata unavailable")
	}
	if job.OwnerLookupHash != trustedrouter.LookupHash(bearer) {
		return nil, &APIError{Status: 404, Message: "batch not found", Type: "invalid_request_error", Code: "not_found"}
	}
	batch := job.Batch
	if batch.Status == StatusCompleted {
		if job.ResultsObject != "" {
			// Compatibility with batches finalized by the first beta build.
			resultObject, err := s.store.Get(ctx, job.ResultsObject)
			if err != nil {
				return nil, internalAPIError("batch results unavailable")
			}
			plaintext, err := s.protector.Open(ctx, id, "results", resultObject.Data)
			if err != nil {
				return nil, internalAPIError("batch results unavailable")
			}
			if err := json.Unmarshal(plaintext, &batch.Results); err != nil {
				clear(plaintext)
				return nil, internalAPIError("batch results unavailable")
			}
			clear(plaintext)
		} else {
			batch.Results = make([]Result, batch.RequestCounts.Total)
			for index := range batch.Results {
				stored, err := s.store.Get(ctx, itemResultName(id, index))
				if err != nil {
					return nil, internalAPIError("batch results unavailable")
				}
				result, err := s.openItemResult(ctx, id, index, stored.Data)
				if err != nil {
					return nil, internalAPIError("batch results unavailable")
				}
				batch.Results[index] = result
			}
		}
		if batch.Results == nil {
			batch.Results = []Result{}
		}
	}
	return &batch, nil
}

func (s *Service) workerLoop(ctx context.Context) {
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		if err := s.runAvailable(ctx); err != nil && ctx.Err() == nil {
			s.logf("batch.worker_error worker_id=%q err=%q", s.workerID, err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}

func (s *Service) signalWorker() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) runAvailable(ctx context.Context) error {
	objects, err := s.store.List(ctx, activePrefix, maxActiveScan)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		claimed, generation, ok, err := s.claim(ctx, object.Name)
		if err != nil {
			s.logf("batch.claim_failed object=%q err=%q", object.Name, err.Error())
			continue
		}
		if !ok {
			continue
		}
		if err := s.process(ctx, claimed, generation); err != nil {
			s.logf("batch.process_failed id=%q err=%q", claimed.ID, err.Error())
		}
	}
	return nil
}

func (s *Service) claim(ctx context.Context, name string) (job, int64, bool, error) {
	stored, err := s.store.Get(ctx, name)
	if err != nil {
		return job{}, 0, false, err
	}
	job, err := decodeJob(stored.Data)
	if err != nil {
		return job, 0, false, err
	}
	now := s.now()
	if job.terminal() {
		return job, stored.Generation, false, nil
	}
	if job.LeaseUntil > now.Unix() && job.LeaseOwner != s.workerID {
		return job, stored.Generation, false, nil
	}
	if now.Unix() >= job.ExpiresAt {
		job.Status = StatusExpired
		finalized := now.Unix()
		job.FinalizedAt = &finalized
		return s.finishTerminal(ctx, job, stored.Generation)
	}
	job.Status = StatusInProgress
	job.LeaseOwner = s.workerID
	job.LeaseUntil = now.Add(s.lease).Unix()
	encoded, err := json.Marshal(job)
	if err != nil {
		return job, 0, false, err
	}
	updated, err := s.store.Put(ctx, name, encoded, PutCondition{Generation: stored.Generation})
	if errors.Is(err, ErrPrecondition) {
		return job, 0, false, nil
	}
	if err != nil {
		return job, 0, false, err
	}
	return job, updated.Generation, true, nil
}

func (s *Service) finishTerminal(ctx context.Context, job job, activeGeneration int64) (job, int64, bool, error) {
	job.LeaseOwner = ""
	job.LeaseUntil = 0
	job.Results = nil
	encoded, err := json.Marshal(job)
	if err != nil {
		return job, 0, false, err
	}
	if _, err := s.store.Put(ctx, terminalJobName(job.ID), encoded, PutCondition{Generation: 0}); err != nil && !errors.Is(err, ErrPrecondition) {
		return job, 0, false, err
	}
	if err := s.store.Delete(ctx, activeJobName(job.ID), activeGeneration); err != nil && !errors.Is(err, ErrPrecondition) {
		return job, 0, false, err
	}
	return job, 0, false, nil
}

func (s *Service) process(ctx context.Context, job job, generation int64) error {
	remaining := time.Unix(job.ExpiresAt, 0).Sub(s.now())
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	processCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	input, err := s.store.Get(processCtx, job.InputObject)
	if err != nil {
		return err
	}
	plaintext, err := s.protector.Open(processCtx, job.ID, "input", input.Data)
	if err != nil {
		return err
	}
	var payload encryptedPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		clear(plaintext)
		return err
	}
	clear(plaintext)
	if payload.APIKeyLookupHash != job.OwnerLookupHash || len(payload.Requests) != job.RequestCounts.Total {
		return fmt.Errorf("batch input metadata mismatch")
	}

	states := make([]itemState, len(payload.Requests))
	pending := make([]int, 0, len(payload.Requests))
	for index := range payload.Requests {
		stored, err := s.store.Get(processCtx, itemResultName(job.ID, index))
		if err == nil {
			result, err := s.openItemResult(processCtx, job.ID, index, stored.Data)
			if err != nil {
				return err
			}
			states[index] = stateForResult(result)
			continue
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		pending = append(pending, index)
	}
	job.RequestCounts = countsForStates(states)
	lease := &jobLease{service: s, job: job, generation: generation}
	if err := lease.update(processCtx, nil); err != nil {
		return err
	}
	stopHeartbeat := lease.maintain(processCtx, cancel)
	defer stopHeartbeat()

	type completedItem struct {
		index int
		state itemState
		err   error
	}
	workerCtx, stopWorkers := context.WithCancel(processCtx)
	defer stopWorkers()
	workerCount := min(s.concurrency, len(pending))
	completed := make(chan completedItem, workerCount)
	work := make(chan int)
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range work {
				state, err := s.executeAndCheckpoint(workerCtx, job, payload.APIKeyLookupHash, index, payload.Requests[index])
				select {
				case completed <- completedItem{index: index, state: state, err: err}:
				case <-workerCtx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() {
		defer close(work)
		for _, index := range pending {
			select {
			case work <- index:
			case <-workerCtx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(completed)
	}()

	var processErr error
	for item := range completed {
		if item.err != nil {
			if processErr == nil {
				processErr = item.err
				stopWorkers()
			}
			continue
		}
		if processErr != nil {
			continue
		}
		states[item.index] = item.state
		counts := countsForStates(states)
		if err := lease.update(processCtx, func(meta *jobMetadata) {
			meta.RequestCounts = counts
		}); err != nil {
			processErr = err
			stopWorkers()
		}
	}
	if processErr != nil {
		return processErr
	}

	if err := lease.update(processCtx, func(meta *jobMetadata) {
		meta.Status = StatusFinalizing
	}); err != nil {
		return err
	}
	stopHeartbeat()
	job, generation = lease.snapshot()
	job.Usage = aggregateUsageStates(states)
	job.Status = StatusCompleted
	finalized := s.now().Unix()
	job.FinalizedAt = &finalized
	_, _, _, err = s.finishTerminal(processCtx, job, generation)
	if err == nil {
		s.logf("batch.completed id=%q total=%d completed=%d failed=%d cost_microdollars=%d", job.ID, job.RequestCounts.Total, job.RequestCounts.Completed, job.RequestCounts.Failed, job.Usage.CostMicrodollars)
	}
	return err
}

func (s *Service) executeAndCheckpoint(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	index int,
	request Request,
) (itemState, error) {
	result := s.executeItem(ctx, job, apiKeyLookupHash, index, request)
	encoded, err := json.Marshal(itemCheckpoint{
		Result:           result,
		Usage:            result.Usage,
		CostMicrodollars: result.Usage.CostMicrodollars,
	})
	if err == nil {
		encoded, err = s.protector.Seal(ctx, job.ID, itemResultKind(index), encoded)
	}
	if err == nil {
		_, err = s.store.Put(ctx, itemResultName(job.ID, index), encoded, PutCondition{Generation: 0})
		if errors.Is(err, ErrPrecondition) {
			var stored StoredObject
			stored, err = s.store.Get(ctx, itemResultName(job.ID, index))
			if err == nil {
				result, err = s.openItemResult(ctx, job.ID, index, stored.Data)
			}
		}
	}
	if err != nil {
		return itemState{}, err
	}
	return stateForResult(result), nil
}

func (s *Service) saveProgress(ctx context.Context, job job, generation int64) (int64, error) {
	job.LeaseOwner = s.workerID
	job.LeaseUntil = s.now().Add(s.lease).Unix()
	job.Results = nil
	encoded, err := json.Marshal(job)
	if err != nil {
		return 0, err
	}
	updated, err := s.store.Put(ctx, activeJobName(job.ID), encoded, PutCondition{Generation: generation})
	if err != nil {
		return 0, err
	}
	return updated.Generation, nil
}

func (s *Service) openItemResult(ctx context.Context, batchID string, index int, encoded []byte) (Result, error) {
	plaintext, err := s.protector.Open(ctx, batchID, itemResultKind(index), encoded)
	if err != nil {
		return Result{}, err
	}
	defer clear(plaintext)
	var checkpoint itemCheckpoint
	if err := json.Unmarshal(plaintext, &checkpoint); err != nil {
		return Result{}, err
	}
	checkpoint.Usage.CostMicrodollars = checkpoint.CostMicrodollars
	checkpoint.Result.Usage = checkpoint.Usage
	return checkpoint.Result, nil
}

func (s *Service) executeItem(ctx context.Context, job job, apiKeyLookupHash string, index int, item Request) Result {
	defer clear(item.Body)
	started := time.Now()
	result := Result{ID: resultID(job.ID, item.CustomID), CustomID: item.CustomID}
	status, requestID, body, attempts, err := s.invokeOnce(ctx, job, apiKeyLookupHash, index, item.Body)
	if err != nil {
		result.Error = map[string]any{
			"message": err.Error(),
			"type":    "server_error",
			"code":    "batch_request_failed",
		}
		s.logItemEnd(job.ID, index, 0, attempts, "transport_error", time.Since(started), Usage{})
		return result
	}
	defer clear(body)
	if status < 200 || status >= 300 {
		result.Error = errorFromResponse(status, body)
		s.logItemEnd(job.ID, index, status, attempts, "http_error", time.Since(started), Usage{})
		return result
	}
	decoded, err := decodeJSONValue(body)
	if err != nil {
		result.Error = map[string]any{
			"message": "upstream returned invalid JSON",
			"type":    "server_error",
			"code":    "invalid_upstream_response",
		}
		s.logItemEnd(job.ID, index, status, attempts, "invalid_response", time.Since(started), Usage{})
		return result
	}
	result.Response = &ResultResponse{StatusCode: status, RequestID: requestID, Body: decoded}
	result.Usage = usageFromBody(decoded)
	s.logItemEnd(job.ID, index, status, attempts, "success", time.Since(started), result.Usage)
	return result
}

func (s *Service) logItemEnd(batchID string, index, status, attempts int, outcome string, elapsed time.Duration, usage Usage) {
	s.logf(
		"batch.item_end id=%q index=%d status=%d attempts=%d outcome=%q elapsed_ms=%d prompt_tokens=%d completion_tokens=%d cost_microdollars=%d is_byok=%t",
		batchID,
		index,
		status,
		attempts,
		outcome,
		elapsed.Milliseconds(),
		usage.PromptTokens,
		usage.CompletionTokens,
		usage.CostMicrodollars,
		usage.IsBYOK,
	)
}

func (s *Service) invokeOnce(ctx context.Context, job job, apiKeyLookupHash string, index int, body []byte) (int, string, []byte, int, error) {
	// The ordinary enclave path already performs provider fallback. Once it
	// returns, its authorization has been settled or refunded. Retrying that
	// whole path here could reuse a terminal authorization and invoke a provider
	// without a fresh billable reservation, so a final HTTP error becomes this
	// item's stable error result.
	idempotencyKey := fmt.Sprintf("tr-batch:%s:%d", job.ID, index)
	status, requestID, responseBody, err := s.executor.Execute(ctx, apiKeyLookupHash, job.Endpoint, body, idempotencyKey)
	if err != nil {
		return 0, "", nil, 1, err
	}
	if len(responseBody) > maxResponseBytes {
		return 0, "", nil, 1, fmt.Errorf("batch response too large")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = bodyRequestID(responseBody)
	}
	if requestID == "" {
		requestID = randomID("request_", 12)
	}
	return status, requestID, responseBody, 1, nil
}

func usageFromBody(body any) Usage {
	payload, _ := body.(map[string]any)
	usageMap, _ := payload["usage"].(map[string]any)
	input := intValue(usageMap, "prompt_tokens", "input_tokens")
	output := intValue(usageMap, "completion_tokens", "output_tokens")
	cost := intValue(usageMap, "cost_microdollars", "total_cost_microdollars")
	providerUsage, _ := usageMap["provider_usage"].(map[string]any)
	isBYOK := strings.EqualFold(stringValue(providerUsage, "usage_type"), "byok")
	return Usage{
		PromptTokens:     input,
		CompletionTokens: output,
		TotalTokens:      input + output,
		CostMicrodollars: cost,
		Cost:             float64(cost) / 1_000_000,
		IsBYOK:           isBYOK,
	}
}

func decodeJSONValue(data []byte) (any, error) {
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func stateForResult(result Result) itemState {
	return itemState{
		finished: result.Response != nil || result.Error != nil,
		failed:   result.Response == nil && result.Error != nil,
		usage:    result.Usage,
	}
}

func countsForStates(states []itemState) RequestCounts {
	counts := RequestCounts{Total: len(states)}
	for _, state := range states {
		if !state.finished {
			continue
		}
		if state.failed {
			counts.Failed++
		} else {
			counts.Completed++
		}
	}
	return counts
}

func aggregateUsageStates(states []itemState) *Usage {
	usage := &Usage{IsBYOK: true}
	successes := 0
	for _, state := range states {
		if !state.finished || state.failed {
			continue
		}
		successes++
		usage.PromptTokens += state.usage.PromptTokens
		usage.CompletionTokens += state.usage.CompletionTokens
		usage.CostMicrodollars += state.usage.CostMicrodollars
		usage.IsBYOK = usage.IsBYOK && state.usage.IsBYOK
	}
	if successes == 0 {
		usage.IsBYOK = false
	}
	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	usage.Cost = float64(usage.CostMicrodollars) / 1_000_000
	return usage
}

func errorFromResponse(status int, body []byte) any {
	value, err := decodeJSONValue(body)
	decoded, _ := value.(map[string]any)
	if err == nil {
		if errValue, ok := decoded["error"]; ok {
			return errValue
		}
	}
	return map[string]any{
		"message": fmt.Sprintf("request failed with HTTP %d", status),
		"type":    "api_error",
		"code":    "batch_request_failed",
	}
}

func intValue(values map[string]any, keys ...string) int {
	for _, key := range keys {
		switch value := values[key].(type) {
		case float64:
			return int(value)
		case int:
			return value
		case json.Number:
			n, _ := value.Int64()
			return int(n)
		}
	}
	return 0
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func bodyRequestID(body []byte) string {
	value, err := decodeJSONValue(body)
	if err != nil {
		return ""
	}
	decoded, _ := value.(map[string]any)
	id, _ := decoded["id"].(string)
	return id
}

func decodeJob(data []byte) (job, error) {
	var job job
	if err := json.Unmarshal(data, &job); err != nil {
		return job, err
	}
	if !validBatchID(job.ID) || !validLookupHash(job.OwnerLookupHash) ||
		job.Object != ObjectType || job.CompletionWindow != CompletionWindow ||
		job.InputObject != inputObjectName(job.ID) ||
		(job.ResultsObject != "" && job.ResultsObject != finalResultsName(job.ID)) ||
		job.Model == "" || job.CreatedAt <= 0 || job.ExpiresAt != job.CreatedAt+int64((24*time.Hour)/time.Second) ||
		job.RequestCounts.Total <= 0 || job.RequestCounts.Completed < 0 || job.RequestCounts.Failed < 0 ||
		job.RequestCounts.Completed+job.RequestCounts.Failed > job.RequestCounts.Total {
		return job, fmt.Errorf("invalid batch metadata")
	}
	if _, ok := supportedEndpoints[job.Endpoint]; !ok || !validBatchStatus(job.Status) {
		return job, fmt.Errorf("invalid batch metadata")
	}
	return job, nil
}

func validLookupHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validBatchStatus(value string) bool {
	switch value {
	case StatusValidating, StatusInProgress, StatusFinalizing, StatusCompleted,
		StatusFailed, StatusExpired, StatusCancelling, StatusCancelled:
		return true
	default:
		return false
	}
}

func activeJobName(id string) string    { return activePrefix + id + ".json" }
func terminalJobName(id string) string  { return terminalPrefix + id + ".json" }
func inputObjectName(id string) string  { return artifactPrefix + id + "/input.enc" }
func finalResultsName(id string) string { return artifactPrefix + id + "/results.enc" }
func itemResultName(id string, index int) string {
	return fmt.Sprintf("%s%s/items/%08d.enc", artifactPrefix, id, index)
}
func itemResultKind(index int) string { return fmt.Sprintf("result:%d", index) }

func resultID(batchID, customID string) string {
	sum := sha256.Sum256([]byte(batchID + "\x00" + customID))
	return "batch_req_" + hex.EncodeToString(sum[:12])
}

func randomID(prefix string, size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(buffer)
}

func validBatchID(id string) bool {
	if !strings.HasPrefix(id, "batch_") || len(id) != len("batch_")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "batch_"))
	return err == nil
}

func controlPlaneAPIError(err error) *APIError {
	var cpErr *trustedrouter.ControlPlaneError
	if errors.As(err, &cpErr) {
		status := cpErr.StatusCode
		if status < 400 || status > 599 {
			status = 503
		}
		message := cpErr.Message
		if message == "" {
			message = "batch authorization failed"
		}
		return &APIError{Status: status, Message: message, Type: "authentication_error", Code: cpErr.Type}
	}
	return &APIError{Status: 503, Message: "batch authorization unavailable", Type: "server_error", Code: "control_plane_unavailable"}
}

func internalAPIError(message string) *APIError {
	return &APIError{Status: 503, Message: message, Type: "server_error", Code: "batch_unavailable"}
}
