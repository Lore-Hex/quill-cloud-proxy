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
	"net/http"
	"strconv"
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
	defaultJobWorkers  = 2
	maxActiveScan      = 1000
	maxItemResultScan  = 1000
	maxResponseBytes   = 64 * 1024 * 1024
	// Envelope encryption base64-encodes ciphertext. Keep a full MiB of room
	// for the wrapped DEK and JSON envelope below GCS's object limit.
	maxBatchPlaintextBytes = (maxGCSObjectSize * 3 / 4) - (1024 * 1024)
)

type KeyValidator interface {
	ValidateKey(context.Context, string, string) error
}

type Executor interface {
	Execute(context.Context, string, string, []byte, string) (int, string, []byte, error)
}

type Options struct {
	Store            ObjectStore
	Protector        Protector
	Keys             KeyValidator
	Executor         Executor
	NativeAuthorizer NativeAuthorizer
	NativeProviders  []NativeProvider
	// NativeSubmitProviders is a measured, fail-closed allowlist for new
	// provider-retained Batch submissions. NativeProviders may contain more
	// adapters so an image with submissions disabled can still recover, cancel,
	// and clean up jobs created by an earlier image.
	NativeSubmitProviders []string
	WorkerID              string
	Concurrency           int
	JobWorkers            int
	PollInterval          time.Duration
	LeaseDuration         time.Duration
	Now                   func() time.Time
	Logf                  func(string, ...any)
}

type Service struct {
	store                 ObjectStore
	protector             Protector
	keys                  KeyValidator
	executor              Executor
	nativeAuthorizer      NativeAuthorizer
	nativeProviders       map[string]NativeProvider
	nativeSubmitProviders map[string]struct{}
	workerID              string
	concurrency           int
	jobWorkers            int
	poll                  time.Duration
	lease                 time.Duration
	now                   func() time.Time
	logf                  func(string, ...any)
	wake                  chan struct{}
	scanPageToken         string
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

func (l *jobLease) release(ctx context.Context) error {
	return l.releaseAt(ctx, 0)
}

func (l *jobLease) releaseAt(ctx context.Context, nextAttemptAt int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.job.LeaseOwner = ""
	l.job.LeaseUntil = 0
	l.job.NextAttemptAt = max(nextAttemptAt, 0)
	l.job.Results = nil
	encoded, err := json.Marshal(l.job)
	if err != nil {
		return err
	}
	updated, err := l.service.store.Put(
		ctx,
		activeJobName(l.job.ID),
		encoded,
		PutCondition{Generation: l.generation},
	)
	if errors.Is(err, ErrPrecondition) {
		return errLeaseLost
	}
	if err != nil {
		return err
	}
	l.generation = updated.Generation
	return nil
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
	if options.JobWorkers <= 0 {
		options.JobWorkers = defaultJobWorkers
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
	nativeProviders := make(map[string]NativeProvider, len(options.NativeProviders))
	for _, provider := range options.NativeProviders {
		if provider == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(provider.Name()))
		if name == "" {
			continue
		}
		nativeProviders[name] = provider
	}
	nativeSubmitProviders := make(map[string]struct{}, len(options.NativeSubmitProviders))
	for _, configured := range options.NativeSubmitProviders {
		name := strings.ToLower(strings.TrimSpace(configured))
		if _, available := nativeProviders[name]; name != "" && available {
			nativeSubmitProviders[name] = struct{}{}
		}
	}
	return &Service{
		store:                 options.Store,
		protector:             options.Protector,
		keys:                  options.Keys,
		executor:              options.Executor,
		nativeAuthorizer:      options.NativeAuthorizer,
		nativeProviders:       nativeProviders,
		nativeSubmitProviders: nativeSubmitProviders,
		workerID:              options.WorkerID,
		concurrency:           options.Concurrency,
		jobWorkers:            options.JobWorkers,
		poll:                  options.PollInterval,
		lease:                 options.LeaseDuration,
		now:                   options.Now,
		logf:                  options.Logf,
		wake:                  make(chan struct{}, 1),
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
	if batchPlaintextTooLarge(len(payload)) {
		clear(payload)
		return nil, &APIError{
			Status:  http.StatusRequestEntityTooLarge,
			Message: "batch input is too large",
			Type:    "invalid_request_error",
			Code:    "batch_too_large",
			Param:   "requests",
		}
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

func batchPlaintextTooLarge(size int) bool {
	return size > maxBatchPlaintextBytes
}

// PrepareGet authenticates a batch read and validates its complete result
// index before callers write response headers. Result bodies remain encrypted
// in object storage until Next asks for one.
func (s *Service) PrepareGet(ctx context.Context, bearer, id string) (*PreparedBatch, *APIError) {
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
	prepared := &PreparedBatch{Batch: job.Batch, service: s, batchID: id}
	if prepared.Batch.Status == StatusCompleted || prepared.Batch.Status == StatusExpired {
		prepared.ResultSet = true
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
			if err := json.Unmarshal(plaintext, &prepared.legacy); err != nil {
				clear(plaintext)
				return nil, internalAPIError("batch results unavailable")
			}
			clear(plaintext)
		} else {
			prepared.present, err = s.listItemResultPresence(
				ctx, id, prepared.Batch.RequestCounts.Total,
			)
			if err != nil {
				return nil, internalAPIError("batch results unavailable")
			}
			if prepared.Batch.Status == StatusCompleted {
				for _, exists := range prepared.present {
					if !exists {
						return nil, internalAPIError("batch results unavailable")
					}
				}
			}
		}
	}
	return prepared, nil
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
	objects, nextPageToken, err := s.store.List(ctx, activePrefix, maxActiveScan, s.scanPageToken)
	if err != nil {
		return err
	}
	s.scanPageToken = nextPageToken
	workers := max(1, s.jobWorkers)
	limit := make(chan struct{}, workers)
	var wait sync.WaitGroup
objectsLoop:
	for _, object := range objects {
		if ctx.Err() != nil {
			break
		}
		select {
		case limit <- struct{}{}:
		case <-ctx.Done():
			break objectsLoop
		}
		wait.Add(1)
		go func(name string) {
			defer wait.Done()
			defer func() { <-limit }()
			claimed, generation, ok, err := s.claim(ctx, name)
			if err != nil {
				s.logf("batch.claim_failed object=%q err=%q", name, err.Error())
				return
			}
			if !ok {
				return
			}
			if err := s.process(ctx, claimed, generation); err != nil {
				s.logf("batch.process_failed id=%q err=%q", claimed.ID, err.Error())
			}
		}(object.Name)
	}
	wait.Wait()
	return ctx.Err()
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
	if job.NextAttemptAt > now.Unix() {
		return job, stored.Generation, false, nil
	}
	expired := now.Unix() >= job.ExpiresAt
	job.Status = StatusInProgress
	job.LeaseOwner = s.workerID
	job.LeaseUntil = now.Add(s.lease).Unix()
	job.NextAttemptAt = 0
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
	if expired {
		// Expiration can stream a large provider result file and reconcile many
		// ledger rows. Maintain the same generation-guarded lease throughout so
		// another region cannot settle and refund the same item concurrently.
		expireCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		lease := &jobLease{service: s, job: job, generation: updated.Generation}
		stopHeartbeat := lease.maintain(expireCtx, cancel)
		if err := s.expireNative(expireCtx, job); err != nil {
			if errors.Is(err, errNativeStateNewerVersion) {
				stopHeartbeat()
				releaseErr := lease.releaseAt(ctx, s.now().Add(s.poll).Unix())
				return job, updated.Generation, false, releaseErr
			}
			attempt := job.ExpiryAttempts + 1
			updateErr := lease.update(ctx, func(meta *jobMetadata) {
				meta.ExpiryAttempts = attempt
			})
			stopHeartbeat()
			if updateErr != nil {
				return job, updated.Generation, false, errors.Join(err, updateErr)
			}
			releaseErr := lease.releaseAt(
				ctx, s.now().Add(nativeRetryDelay(attempt)).Unix(),
			)
			return job, updated.Generation, false, errors.Join(err, releaseErr)
		}
		states, err := s.loadItemStates(expireCtx, job)
		if err != nil {
			stopHeartbeat()
			return job, updated.Generation, false, err
		}
		finalized := s.now().Unix()
		counts := countsForStates(states)
		usage := aggregateUsageStates(states)
		if counts.Completed+counts.Failed == 0 {
			usage = nil
		}
		if err := lease.update(expireCtx, func(meta *jobMetadata) {
			meta.Status = StatusExpired
			meta.FinalizedAt = &finalized
			meta.RequestCounts = counts
			meta.Usage = usage
			meta.ExpiryAttempts = 0
		}); err != nil {
			stopHeartbeat()
			return job, updated.Generation, false, err
		}
		stopHeartbeat()
		job, generation := lease.snapshot()
		return s.finishTerminal(ctx, job, generation)
	}
	return job, updated.Generation, true, nil
}

func (s *Service) loadItemStates(ctx context.Context, job job) ([]itemState, error) {
	states, _, err := s.loadItemStatesAndPending(ctx, job)
	return states, err
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
	lease := &jobLease{service: s, job: job, generation: generation}
	if err := lease.update(processCtx, nil); err != nil {
		return err
	}
	stopHeartbeat := lease.maintain(processCtx, cancel)
	defer stopHeartbeat()
	if nextAttemptAt, deferred, err := s.nativeDeferred(processCtx, job.ID); err != nil {
		return err
	} else if deferred {
		stopHeartbeat()
		return lease.releaseAt(processCtx, nextAttemptAt)
	}

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
	defer clearRequests(payload.Requests)
	if payload.APIKeyLookupHash != job.OwnerLookupHash || len(payload.Requests) != job.RequestCounts.Total {
		return fmt.Errorf("batch input metadata mismatch")
	}

	states, pending, err := s.loadItemStatesAndPending(processCtx, job)
	if err != nil {
		return err
	}
	job.RequestCounts = countsForStates(states)
	if err := lease.update(processCtx, func(meta *jobMetadata) {
		meta.RequestCounts = job.RequestCounts
	}); err != nil {
		return err
	}

	_, _, hasNativeState, err := s.loadNativeState(processCtx, job.ID)
	if err != nil {
		return err
	}
	if len(pending) > 0 || hasNativeState {
		outcome, err := s.tryNative(
			processCtx, job, payload.APIKeyLookupHash, pending, payload.Requests,
		)
		if err != nil {
			if outcome == nativePending {
				stopHeartbeat()
				if releaseErr := lease.releaseAt(processCtx, s.nativeNextAttemptAt(processCtx, job.ID)); releaseErr != nil {
					return errors.Join(err, releaseErr)
				}
			}
			return err
		}
		if outcome == nativePending {
			stopHeartbeat()
			return lease.releaseAt(processCtx, s.nativeNextAttemptAt(processCtx, job.ID))
		}
		if outcome == nativeCompleted {
			states, pending, err = s.loadItemStatesAndPending(processCtx, job)
			if err != nil {
				return err
			}
			if len(pending) != 0 {
				return fmt.Errorf("native batch completed with %d missing item checkpoints", len(pending))
			}
			if err := lease.update(processCtx, func(meta *jobMetadata) {
				meta.RequestCounts = countsForStates(states)
			}); err != nil {
				return err
			}
		} else if outcome == nativeManagedFallback {
			// Native reconciliation may have checkpointed some provider results
			// before falling back. Refresh the pending set so managed execution
			// never repeats a result that was already settled and made durable.
			states, pending, err = s.loadItemStatesAndPending(processCtx, job)
			if err != nil {
				return err
			}
			if err := lease.update(processCtx, func(meta *jobMetadata) {
				meta.RequestCounts = countsForStates(states)
			}); err != nil {
				return err
			}
		}
	}

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
	err := s.storeItemCheckpoint(ctx, job.ID, index, result)
	if errors.Is(err, ErrPrecondition) {
		var stored StoredObject
		stored, err = s.store.Get(ctx, itemResultName(job.ID, index))
		if err == nil {
			result, err = s.openItemResult(ctx, job.ID, index, stored.Data)
		}
		if err == nil {
			err = s.storeItemStateCheckpoint(ctx, job.ID, index, stateForResult(result))
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
	checkpoint.Usage.GenerationID = checkpoint.GenerationID
	checkpoint.Usage.Provider = checkpoint.Provider
	checkpoint.Usage.Region = checkpoint.Region
	checkpoint.Result.Usage = checkpoint.Usage
	return checkpoint.Result, nil
}

func (s *Service) openItemState(ctx context.Context, batchID string, index int, encoded []byte) (itemState, error) {
	plaintext, err := s.protector.Open(ctx, batchID, itemStateKind(index), encoded)
	if err != nil {
		return itemState{}, err
	}
	defer clear(plaintext)
	var checkpoint itemStateCheckpoint
	if err := json.Unmarshal(plaintext, &checkpoint); err != nil {
		return itemState{}, err
	}
	checkpoint.Usage.CostMicrodollars = checkpoint.CostMicrodollars
	checkpoint.Usage.GenerationID = checkpoint.GenerationID
	checkpoint.Usage.Provider = checkpoint.Provider
	checkpoint.Usage.Region = checkpoint.Region
	return itemState{
		finished: checkpoint.Finished,
		failed:   checkpoint.Failed,
		usage:    checkpoint.Usage,
	}, nil
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
	contributors := 0
	for _, state := range states {
		if !state.finished {
			continue
		}
		// A settlement may commit before its provider result checkpoint is
		// durable. Recovery deliberately records that item as failed while
		// preserving the real charge. Include such charged failures in aggregate
		// usage; ordinary failed items carry zero usage and remain excluded.
		if state.failed && state.usage.PromptTokens == 0 &&
			state.usage.CompletionTokens == 0 && state.usage.CostMicrodollars == 0 {
			continue
		}
		contributors++
		usage.PromptTokens += state.usage.PromptTokens
		usage.CompletionTokens += state.usage.CompletionTokens
		usage.CostMicrodollars += state.usage.CostMicrodollars
		usage.IsBYOK = usage.IsBYOK && state.usage.IsBYOK
	}
	if contributors == 0 {
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
func itemStateName(id string, index int) string {
	return fmt.Sprintf("%s%s/states/%08d.enc", artifactPrefix, id, index)
}

func itemResultPrefix(id string) string { return artifactPrefix + id + "/items/" }

func (s *Service) listItemResultPresence(
	ctx context.Context,
	batchID string,
	total int,
) ([]bool, error) {
	present := make([]bool, total)
	prefix := itemResultPrefix(batchID)
	pageToken := ""
	for {
		objects, nextPageToken, err := s.store.List(
			ctx, prefix, maxItemResultScan, pageToken,
		)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			base := strings.TrimPrefix(object.Name, prefix)
			if base == object.Name || !strings.HasSuffix(base, ".enc") {
				return nil, fmt.Errorf("batch item result object name is invalid")
			}
			rawIndex := strings.TrimSuffix(base, ".enc")
			index, parseErr := strconv.Atoi(rawIndex)
			if parseErr != nil || index < 0 || index >= total || object.Name != itemResultName(batchID, index) {
				return nil, fmt.Errorf("batch item result object index is invalid")
			}
			if present[index] {
				return nil, fmt.Errorf("batch item result object is duplicated")
			}
			present[index] = true
		}
		if nextPageToken == "" {
			return present, nil
		}
		if nextPageToken == pageToken {
			return nil, fmt.Errorf("batch item result listing did not advance")
		}
		pageToken = nextPageToken
	}
}

func (s *Service) loadListedItemStates(
	ctx context.Context,
	batchID string,
	present []bool,
) ([]itemState, error) {
	type loadedItem struct {
		index int
		state itemState
		err   error
	}
	count := 0
	for _, exists := range present {
		if exists {
			count++
		}
	}
	loaded := make([]itemState, len(present))
	if count == 0 {
		return loaded, nil
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workers := min(max(1, s.concurrency), count)
	indexes := make(chan int)
	completed := make(chan loadedItem, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range indexes {
				stored, err := s.store.Get(workCtx, itemStateName(batchID, index))
				var state itemState
				if err == nil {
					state, err = s.openItemState(workCtx, batchID, index, stored.Data)
				} else if errors.Is(err, ErrNotFound) {
					// A crash can leave the full result durable before its compact
					// state companion. Repair from the source-of-truth result.
					stored, err = s.store.Get(workCtx, itemResultName(batchID, index))
					if err == nil {
						var result Result
						result, err = s.openItemResult(workCtx, batchID, index, stored.Data)
						state = stateForResult(result)
					}
					if err == nil {
						err = s.storeItemStateCheckpoint(workCtx, batchID, index, state)
					}
				}
				select {
				case completed <- loadedItem{index: index, state: state, err: err}:
				case <-workCtx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(indexes)
		for index, exists := range present {
			if !exists {
				continue
			}
			select {
			case indexes <- index:
			case <-workCtx.Done():
				return
			}
		}
	}()
	go func() {
		wait.Wait()
		close(completed)
	}()
	var firstErr error
	for item := range completed {
		if item.err != nil && firstErr == nil {
			firstErr = item.err
			cancel()
			continue
		}
		loaded[item.index] = item.state
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return loaded, nil
}

func (s *Service) loadItemStatesAndPending(
	ctx context.Context,
	job job,
) ([]itemState, []int, error) {
	present, err := s.listItemResultPresence(ctx, job.ID, job.RequestCounts.Total)
	if err != nil {
		return nil, nil, err
	}
	states, err := s.loadListedItemStates(ctx, job.ID, present)
	if err != nil {
		return nil, nil, err
	}
	pending := make([]int, 0, len(present))
	for index, exists := range present {
		if !exists {
			pending = append(pending, index)
		}
	}
	return states, pending, nil
}
func itemResultKind(index int) string { return fmt.Sprintf("result:%d", index) }
func itemStateKind(index int) string  { return fmt.Sprintf("state:%d", index) }

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
