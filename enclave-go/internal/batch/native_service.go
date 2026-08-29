package batch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	nativeResultBudgetUnitBytes = 1 * 1024 * 1024
	nativeResultInFlightBytes   = 128 * 1024 * 1024
)

type nativeResultByteBudget struct {
	tokens chan struct{}
}

func newNativeResultByteBudget() *nativeResultByteBudget {
	return &nativeResultByteBudget{
		tokens: make(chan struct{}, nativeResultInFlightBytes/nativeResultBudgetUnitBytes),
	}
}

func (budget *nativeResultByteBudget) acquire(ctx context.Context, size int) (int, error) {
	units := max(1, (max(0, size)+nativeResultBudgetUnitBytes-1)/nativeResultBudgetUnitBytes)
	if units > cap(budget.tokens) {
		return 0, fmt.Errorf("native batch result exceeds in-flight byte budget")
	}
	acquired := 0
	for acquired < units {
		select {
		case budget.tokens <- struct{}{}:
			acquired++
		case <-ctx.Done():
			budget.release(acquired)
			return 0, ctx.Err()
		}
	}
	return acquired, nil
}

func (budget *nativeResultByteBudget) release(units int) {
	for range units {
		<-budget.tokens
	}
}

type queuedNativeProviderResult struct {
	result      NativeProviderResult
	budgetUnits int
}

type nativeOutcome int

const (
	nativeNotHandled nativeOutcome = iota
	nativePending
	nativeCompleted
	nativeManagedFallback
)

const (
	nativeRetryBase              = 15 * time.Second
	nativeRetryMax               = 5 * time.Minute
	nativePrepareMaxAttempts     = 12
	nativeSubmitMaxAttempts      = 12
	nativeCleanupMaxAttempts     = 12
	nativeRecoveryNotFoundLimit  = 3
	nativeAmbiguousRecoveryGrace = 30 * time.Minute
	nativeMaxProviderItems       = 1_000
)

func nativeProviderErrorIsTerminal(err error) bool {
	var statusErr *nativeProviderHTTPError
	if !errors.As(err, &statusErr) || statusErr.status < 400 || statusErr.status >= 500 {
		return false
	}
	switch statusErr.status {
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}

func nativeProviderObjectGone(err error) bool {
	var statusErr *nativeProviderHTTPError
	return errors.As(err, &statusErr) &&
		(statusErr.status == http.StatusNotFound || statusErr.status == http.StatusGone)
}

func nativeSubmitCanRetryDirectly(err error) bool {
	var transportErr *nativeProviderTransportError
	if errors.As(err, &transportErr) {
		// Upload/file-recovery failures happen before POST /batches. Retrying
		// Submit is safe because it first recovers the deterministic filename.
		// A transport failure from POST /batches is ambiguous and must recover.
		return transportErr.operation != "/batches"
	}
	var statusErr *nativeProviderHTTPError
	if !errors.As(err, &statusErr) {
		return false
	}
	preSubmit := statusErr.operation != "/batches"
	if preSubmit {
		return statusErr.status >= 500 || statusErr.status == http.StatusRequestTimeout ||
			statusErr.status == http.StatusConflict || statusErr.status == http.StatusTooEarly ||
			statusErr.status == http.StatusTooManyRequests
	}
	// Neither Parasail nor the shared OpenAI-compatible contract guarantees
	// idempotency for POST /batches. A 408 or 409 may arrive after the provider
	// created work, so recover by the opaque metadata token before doing
	// anything else. A 425 or 429 explicitly rejects execution and is safe to
	// retry with bounded backoff.
	switch statusErr.status {
	case http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func nativeRetryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return nativeRetryBase
	}
	shift := min(attempt-1, 8)
	delay := nativeRetryBase * time.Duration(1<<shift)
	return min(delay, nativeRetryMax)
}

func (s *Service) nativeDeferred(
	ctx context.Context,
	batchID string,
) (int64, bool, error) {
	state, _, found, err := s.loadNativeState(ctx, batchID)
	if errors.Is(err, errNativeStateNewerVersion) {
		return s.now().Add(s.poll).Unix(), true, nil
	}
	if err != nil || !found || state.NextPollAt <= s.now().Unix() {
		return 0, false, err
	}
	return state.NextPollAt, true, nil
}

func (s *Service) nativeNextAttemptAt(ctx context.Context, batchID string) int64 {
	state, _, found, err := s.loadNativeState(ctx, batchID)
	if err == nil && found && state.NextPollAt > s.now().Unix() {
		return state.NextPollAt
	}
	return s.now().Add(s.poll).Unix()
}

func (s *Service) tryNative(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	pending []int,
	requests []Request,
) (nativeOutcome, error) {
	if s.nativeAuthorizer == nil {
		return nativeNotHandled, nil
	}

	state, generation, found, err := s.loadNativeState(ctx, job.ID)
	if err != nil {
		return nativeNotHandled, err
	}
	if !found {
		if len(s.nativeSubmitProviders) == 0 || len(pending) > nativeMaxProviderItems ||
			!nativeRetentionAllowed(job, requests) {
			return nativeNotHandled, nil
		}
	}
	if !found || state.Stage == nativeStagePreparing {
		state, generation, err = s.prepareNative(ctx, job, apiKeyLookupHash, pending, requests)
		if err != nil {
			return nativePending, err
		}
	}
	if state.Stage == nativeStagePreparing {
		return nativePending, nil
	}
	if state.Stage == nativeStageDisabled {
		return s.finishNativeDisabled(ctx, job, pending, requests, state, generation, "native_batch_fallback")
	}
	if state.Stage == nativeStageResolved {
		return nativeCompleted, nil
	}
	if state.Stage == nativeStageComplete {
		return nativeCompleted, nil
	}
	if state.Stage == nativeStagePrepared && len(pending) == 0 {
		state.Stage = nativeStageResolved
		state.NextPollAt = 0
		state.RetryAttempts = 0
		if _, err := s.saveNativeState(ctx, job.ID, state, generation); err != nil {
			return nativePending, err
		}
		return nativeCompleted, nil
	}

	provider := s.nativeProviders[strings.ToLower(state.Provider)]
	if provider == nil || !provider.Supports(job.Endpoint) {
		return s.disableNative(ctx, job, pending, requests, state, generation, "native_provider_unavailable")
	}
	if state.Stage == nativeStageCleanup {
		return s.finishNativeCleanup(ctx, job, provider, state, generation)
	}
	if len(pending) == 0 && state.Stage == nativeStageSubmitted {
		// Every item result was durably checkpointed, but a prior worker may
		// have crashed before advancing the provider job to cleanup. Do not
		// download or settle the result files again; finish deleting them.
		state.Stage = nativeStageCleanup
		state.ResultsHarvested = true
		state.NextPollAt = 0
		state.RetryAttempts = 0
		generation, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return nativePending, err
		}
		return s.finishNativeCleanup(ctx, job, provider, state, generation)
	}
	if state.NextPollAt > s.now().Unix() {
		return nativePending, nil
	}

	if state.Stage == nativeStagePrepared {
		providerRequests := make([]NativeProviderRequest, 0, len(pending))
		for _, index := range pending {
			providerRequests = append(providerRequests, NativeProviderRequest{
				Index:    index,
				CustomID: requests[index].CustomID,
				Body:     requests[index].Body,
			})
		}
		state, generation, err = s.ensureNativeSubmitted(
			ctx, job, provider, providerRequests, state, generation,
		)
		if err != nil {
			if errors.Is(err, errNativeRecoveryExhausted) {
				return s.resolveNativeFailure(
					ctx, job, provider, pending, requests, state, generation,
					"native_batch_create_unrecoverable",
				)
			}
			if errors.Is(err, errNativeSubmitExhausted) {
				return s.disableNative(ctx, job, pending, requests, state, generation, "native_submit_retry_exhausted")
			}
			if nativeProviderErrorIsTerminal(err) {
				return s.disableNative(ctx, job, pending, requests, state, generation, "native_submit_rejected")
			}
			state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
			if saveErr != nil {
				return nativePending, errors.Join(err, saveErr)
			}
			if !errors.Is(err, errNativeRecoveryPending) {
				s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "submit", state.RetryAttempts)
			}
			return nativePending, nil
		}
	}

	poll, err := provider.Poll(ctx, state.Submission)
	if err != nil {
		if nativeProviderErrorIsTerminal(err) {
			return s.disableNative(ctx, job, pending, requests, state, generation, "native_poll_rejected")
		}
		state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
		if saveErr != nil {
			return nativePending, errors.Join(err, saveErr)
		}
		s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "poll", state.RetryAttempts)
		return nativePending, nil
	}
	if poll.Job.ID != "" && poll.Job != state.Submission {
		state.Submission = poll.Job
	}
	switch poll.Status {
	case NativeStatusPending:
		_, _, err = s.scheduleNativeRetry(ctx, job.ID, state, generation)
		if err != nil {
			return nativePending, err
		}
		return nativePending, nil
	case NativeStatusFailed, NativeStatusComplete:
		// OpenAI-compatible Batch APIs can expose partial output/error files
		// after an expired, cancelled, or failed job. Consume every durable
		// result before falling back missing items so completed provider work is
		// never repeated or billed twice.
		state.Submission = poll.Job
		state.NextPollAt = 0
		state.RetryAttempts = 0
		generation, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return nativePending, err
		}
		if err := s.finishNativeResults(
			ctx, job, apiKeyLookupHash, pending, requests, state, provider, true,
		); err != nil {
			if nativeProviderObjectGone(err) || errors.Is(err, ErrNativeInvalidResult) {
				return s.disableNative(
					ctx, job, pending, requests, state, generation, "native_results_invalid_or_unavailable",
				)
			}
			state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
			if saveErr != nil {
				return nativePending, errors.Join(err, saveErr)
			}
			s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "results", state.RetryAttempts)
			return nativePending, nil
		}
		if poll.Status == NativeStatusFailed {
			s.logf("batch.native_partial id=%q provider=%q reason=%q", job.ID, state.Provider, poll.Error)
		}
		state.Stage = nativeStageCleanup
		state.ResultsHarvested = true
		generation, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return nativePending, err
		}
		return s.finishNativeCleanup(ctx, job, provider, state, generation)
	default:
		return nativePending, fmt.Errorf("native batch provider %s returned invalid status", provider.Name())
	}
}

func nativeRetentionAllowed(job job, requests []Request) bool {
	// Native provider Batch APIs persist request state. Privacy aliases,
	// orchestration aliases, and custom models continue through the ordinary
	// attested path rather than silently weakening their contract.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(job.Model)), "trustedrouter/") ||
		strings.Contains(job.Model, ":") {
		return false
	}
	if job.Endpoint != "/v1/chat/completions" && job.Endpoint != "/v1/embeddings" {
		return false
	}
	for _, request := range requests {
		var rawBody map[string]json.RawMessage
		if json.Unmarshal(request.Body, &rawBody) != nil || rawBody == nil {
			return false
		}
		allowedFields := nativeChatRequestFields
		if job.Endpoint == "/v1/embeddings" {
			allowedFields = nativeEmbeddingRequestFields
		}
		for key := range rawBody {
			if _, allowed := allowedFields[key]; !allowed {
				// Native Batch APIs retain request content. A future request field
				// may introduce a privacy or routing guarantee that this release
				// does not understand, so unknown fields stay on the managed path.
				return false
			}
		}
		for _, key := range []string{
			"zdr", "e2e", "confidential", "data_collection", "min_privacy", "jurisdiction",
			"region", "service_tier", "store",
		} {
			if _, present := rawBody[key]; present {
				return false
			}
		}
		var body struct {
			Model    string   `json:"model"`
			Models   []string `json:"models"`
			Provider *struct {
				DataCollection string `json:"data_collection"`
				MinPrivacy     string `json:"min_privacy"`
				Jurisdiction   string `json:"jurisdiction"`
				Usage          string `json:"usage"`
			} `json:"provider"`
		}
		if json.Unmarshal(request.Body, &body) != nil || len(body.Models) > 0 ||
			strings.Contains(body.Model, ":") {
			return false
		}
		if rawTools, present := rawBody["tools"]; present {
			var tools []struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(rawTools, &tools) != nil {
				return false
			}
			for _, tool := range tools {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tool.Type)), "trustedrouter:") {
					return false
				}
			}
		}
		if rawReasoning, present := rawBody["reasoning"]; present {
			var reasoning map[string]json.RawMessage
			if json.Unmarshal(rawReasoning, &reasoning) != nil {
				return false
			}
			for key := range reasoning {
				if key != "effort" {
					return false
				}
			}
		}
		if body.Provider == nil {
			continue
		}
		var providerFields map[string]json.RawMessage
		if json.Unmarshal(rawBody["provider"], &providerFields) != nil || providerFields == nil {
			return false
		}
		for key := range providerFields {
			switch key {
			case "order", "allow_fallbacks", "require_parameters", "data_collection",
				"min_privacy", "jurisdiction", "usage", "only", "ignore",
				"quantizations", "sort", "max_price":
			default:
				// Unknown routing fields may introduce a privacy guarantee in a
				// newer API revision. Keep them on the managed path until audited.
				return false
			}
		}
		if strings.EqualFold(body.Provider.DataCollection, "deny") ||
			strings.TrimSpace(body.Provider.MinPrivacy) != "" ||
			strings.TrimSpace(body.Provider.Jurisdiction) != "" ||
			strings.EqualFold(body.Provider.Usage, "byok") {
			return false
		}
	}
	return true
}

var nativeChatRequestFields = map[string]struct{}{
	"model": {}, "messages": {}, "stream": {}, "stream_options": {},
	"temperature": {}, "top_p": {}, "top_k": {}, "top_a": {}, "min_p": {},
	"repetition_penalty": {}, "max_tokens": {},
	"max_completion_tokens": {}, "max_output_tokens": {}, "stop": {},
	"seed": {}, "frequency_penalty": {}, "presence_penalty": {}, "n": {},
	"logit_bias": {}, "logprobs": {}, "top_logprobs": {}, "prediction": {},
	"prompt_cache_key": {}, "prompt_cache_options": {}, "reasoning": {},
	"reasoning_effort": {}, "service_tier": {}, "provider": {}, "metadata": {},
	"trace": {}, "user": {}, "session_id": {}, "tags": {},
	"response_format": {}, "tools": {}, "tool_choice": {},
	"parallel_tool_calls": {},
}

var nativeEmbeddingRequestFields = map[string]struct{}{
	"model": {}, "input": {}, "encoding_format": {}, "dimensions": {},
	"user": {}, "session_id": {}, "metadata": {},
	"trace": {}, "tags": {},
}

func (s *Service) prepareNative(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	pending []int,
	requests []Request,
) (nativeState, int64, error) {
	state, generation, found, err := s.loadNativeState(ctx, job.ID)
	if err != nil {
		return nativeState{}, 0, err
	}
	if !found {
		state = nativeState{
			Version: 1,
			Stage:   nativeStagePreparing,
			Token:   nativeSubmissionToken(job.ID),
		}
		state, generation, err = s.createNativeState(ctx, job.ID, state)
		if err != nil {
			return nativeState{}, 0, err
		}
	}
	if state.Stage != nativeStagePreparing || state.NextPollAt > s.now().Unix() {
		return state, generation, nil
	}

	authorizations := make([]NativeAuthorization, len(pending))
	work := make(chan int, len(pending))
	for offset := range pending {
		work <- offset
	}
	close(work)

	var workers sync.WaitGroup
	var errorMu sync.Mutex
	var firstError error
	workerCount := min(max(1, s.concurrency), len(pending))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for offset := range work {
				errorMu.Lock()
				stopped := firstError != nil
				errorMu.Unlock()
				if stopped {
					return
				}
				index := pending[offset]
				authorization, err := s.loadOrAuthorizeNative(
					ctx,
					job,
					apiKeyLookupHash,
					index,
					requests[index].Body,
				)
				if err != nil {
					errorMu.Lock()
					if firstError == nil {
						firstError = err
					}
					errorMu.Unlock()
					return
				}
				authorizations[offset] = authorization
			}
		}()
	}
	workers.Wait()
	if firstError != nil {
		if errors.Is(firstError, errNativeAuthorizationCheckpoint) ||
			errors.Is(firstError, ErrNativeAuthorizationRetryable) {
			if state.RetryAttempts+1 < nativePrepareMaxAttempts {
				state, generation, err = s.scheduleNativeRetry(ctx, job.ID, state, generation)
				if err != nil {
					return state, generation, errors.Join(firstError, err)
				}
				s.logf(
					"batch.native_retry id=%q stage=%q attempt=%d",
					job.ID, "prepare", state.RetryAttempts,
				)
				return state, generation, nil
			}
			s.logf(
				"batch.native_prepare_abandoned id=%q attempts=%d",
				job.ID, state.RetryAttempts+1,
			)
		}
		// Native execution is an optimization. If one item cannot reserve a
		// native route, freeze the batch onto the managed path. tryNative
		// refunds every authorization checkpoint written by all completed
		// workers before ordinary per-item execution starts.
		state.Stage = nativeStageDisabled
		state.NextPollAt = 0
		state.RetryAttempts = 0
		generation, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return state, generation, errors.Join(firstError, err)
		}
		return state, generation, nil
	}

	route, ok := s.commonNativeRoute(job.Endpoint, authorizations)
	state.Stage = nativeStageDisabled
	state.NextPollAt = 0
	state.RetryAttempts = 0
	if ok {
		state.Stage = nativeStagePrepared
		state.Provider = strings.ToLower(strings.TrimSpace(route.Provider))
		state.EndpointID = route.EndpointID
		state.Model = route.Model
		state.UpstreamModel = route.UpstreamModel
		state.Submission = NativeProviderJob{Provider: route.Provider, Token: state.Token}
	}
	generation, err = s.saveNativeState(ctx, job.ID, state, generation)
	if err != nil {
		return state, generation, err
	}
	if state.Stage == nativeStagePrepared {
		s.logf("batch.native_prepared id=%q provider=%q items=%d", job.ID, state.Provider, len(pending))
	} else {
		s.logf("batch.native_managed id=%q reason=%q", job.ID, "no_common_native_route")
	}
	return state, generation, nil
}

func (s *Service) commonNativeRoute(
	endpoint string,
	authorizations []NativeAuthorization,
) (NativeRoute, bool) {
	if len(authorizations) == 0 {
		return NativeRoute{}, false
	}
	var selected NativeRoute
	for index, authorization := range authorizations {
		if !authorization.NativeBatchEligible || authorization.CustomModel ||
			authorization.ManagedPathOnly || len(authorization.Routes) == 0 {
			return NativeRoute{}, false
		}
		route := authorization.Routes[0]
		providerName := strings.ToLower(strings.TrimSpace(route.Provider))
		provider := s.nativeProviders[providerName]
		_, submitAllowed := s.nativeSubmitProviders[providerName]
		if !strings.EqualFold(route.UsageType, NativeUsageTypeCredit) ||
			provider == nil || !provider.Supports(endpoint) || !submitAllowed {
			return NativeRoute{}, false
		}
		if index == 0 {
			selected = route
		} else if nativeRouteKey(route) != nativeRouteKey(selected) {
			return NativeRoute{}, false
		}
	}
	return selected, true
}

func nativeRouteKey(route NativeRoute) string {
	return strings.ToLower(strings.TrimSpace(route.Provider)) + "\x00" + route.EndpointID + "\x00" + route.Model + "\x00" + route.UpstreamModel
}

func (s *Service) ensureNativeSubmitted(
	ctx context.Context,
	job job,
	provider NativeProvider,
	requests []NativeProviderRequest,
	state nativeState,
	generation int64,
) (nativeState, int64, error) {
	if state.Submission.ID == "" && state.SubmitUncertain {
		recovered, err := provider.Recover(ctx, state.Token)
		if err == nil {
			state.Submission = recovered
			state.Stage = nativeStageSubmitted
			state.SubmitUncertain = false
			state.SubmitUncertainAt = 0
			state.RecoveryNotFound = 0
			generation, err = s.saveNativeState(ctx, job.ID, state, generation)
			return state, generation, err
		}
		if !errors.Is(err, ErrNativeNotFound) {
			return state, generation, err
		}
		state.RecoveryNotFound++
		uncertainFor := time.Duration(0)
		if state.SubmitUncertainAt > 0 {
			uncertainFor = s.now().Sub(time.Unix(state.SubmitUncertainAt, 0))
		}
		if state.RecoveryNotFound >= nativeRecoveryNotFoundLimit &&
			uncertainFor >= nativeAmbiguousRecoveryGrace {
			generation, err = s.saveNativeState(ctx, job.ID, state, generation)
			if err != nil {
				return state, generation, err
			}
			return state, generation, errNativeRecoveryExhausted
		}
		generation, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return state, generation, err
		}
		// A transport failure or 5xx during create is ambiguous. Never submit a
		// second provider job without first recovering the original ID. This
		// intentionally prefers eventual expiry/refund over duplicate provider
		// spend and duplicate prompt retention.
		return state, generation, errNativeRecoveryPending
	}
	if state.Submission.ID == "" {
		if state.SubmitAttempts >= nativeSubmitMaxAttempts {
			return state, generation, errNativeSubmitExhausted
		}
		// Persist intent before the provider create call. A crash after the
		// provider accepts the request must recover by token rather than submit
		// duplicate work and retain a second copy of every prompt.
		state.SubmitAttempts++
		state.SubmitUncertain = true
		state.SubmitUncertainAt = s.now().Unix()
		state.RecoveryNotFound = 0
		var err error
		generation, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return state, generation, err
		}
		submission, err := provider.Submit(
			ctx,
			state.Token,
			job.Endpoint,
			state.UpstreamModel,
			requests,
			state.SubmitAttempts > 1,
		)
		state.Submission = submission
		state.SubmitUncertain = err != nil && !nativeSubmitCanRetryDirectly(err)
		if !state.SubmitUncertain {
			state.SubmitUncertainAt = 0
			state.RecoveryNotFound = 0
		}
		if err == nil {
			state.Stage = nativeStageSubmitted
			state.SubmitUncertain = false
		}
		generation, saveErr := s.saveNativeState(ctx, job.ID, state, generation)
		if saveErr != nil {
			return state, generation, saveErr
		}
		if err == nil {
			s.logf("batch.native_submitted id=%q provider=%q", job.ID, state.Provider)
		}
		return state, generation, err
	}
	state.Stage = nativeStageSubmitted
	state.SubmitUncertain = false
	state.SubmitUncertainAt = 0
	state.RecoveryNotFound = 0
	generation, err := s.saveNativeState(ctx, job.ID, state, generation)
	return state, generation, err
}

func (s *Service) scheduleNativeRetry(
	ctx context.Context,
	batchID string,
	state nativeState,
	generation int64,
) (nativeState, int64, error) {
	state.RetryAttempts++
	state.NextPollAt = s.now().Add(nativeRetryDelay(state.RetryAttempts)).Unix()
	updated, err := s.saveNativeState(ctx, batchID, state, generation)
	return state, updated, err
}

func (s *Service) finishNativeCleanup(
	ctx context.Context,
	job job,
	provider NativeProvider,
	state nativeState,
	generation int64,
) (nativeOutcome, error) {
	if state.NextPollAt > s.now().Unix() {
		return nativePending, nil
	}
	if err := provider.Cleanup(ctx, state.Submission); err != nil {
		if state.RetryAttempts+1 >= nativeCleanupMaxAttempts {
			s.logf(
				"batch.native_cleanup_abandoned id=%q provider=%q attempts=%d",
				job.ID, state.Provider, state.RetryAttempts+1,
			)
			return s.completeNativeState(ctx, job.ID, state, generation)
		}
		state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
		if saveErr != nil {
			return nativePending, errors.Join(err, saveErr)
		}
		s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "cleanup", state.RetryAttempts)
		return nativePending, nil
	}
	return s.completeNativeState(ctx, job.ID, state, generation)
}

func (s *Service) completeNativeState(
	ctx context.Context,
	batchID string,
	state nativeState,
	generation int64,
) (nativeOutcome, error) {
	state.Stage = nativeStageComplete
	state.NextPollAt = 0
	state.RetryAttempts = 0
	if _, err := s.saveNativeState(ctx, batchID, state, generation); err != nil {
		return nativePending, err
	}
	s.logf("batch.native_completed id=%q provider=%q", batchID, state.Provider)
	return nativeCompleted, nil
}

func (s *Service) finishNativeDisabled(
	ctx context.Context,
	job job,
	pending []int,
	requests []Request,
	state nativeState,
	generation int64,
	reason string,
) (nativeOutcome, error) {
	if state.NextPollAt > s.now().Unix() {
		return nativePending, nil
	}
	if provider := s.nativeProviders[strings.ToLower(state.Provider)]; provider != nil {
		if strings.TrimSpace(state.Submission.ID) != "" {
			if err := provider.Cancel(ctx, state.Submission); err != nil {
				if state.RetryAttempts+1 < nativeCleanupMaxAttempts {
					state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
					if saveErr != nil {
						return nativePending, errors.Join(err, saveErr)
					}
					s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "cancel", state.RetryAttempts)
					return nativePending, nil
				}
				s.logf(
					"batch.native_cancel_abandoned id=%q provider=%q attempts=%d",
					job.ID, state.Provider, state.RetryAttempts+1,
				)
			}
		}
		if err := provider.Cleanup(ctx, state.Submission); err != nil {
			if state.RetryAttempts+1 < nativeCleanupMaxAttempts {
				state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
				if saveErr != nil {
					return nativePending, errors.Join(err, saveErr)
				}
				s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "cleanup", state.RetryAttempts)
				return nativePending, nil
			}
			s.logf(
				"batch.native_cleanup_abandoned id=%q provider=%q attempts=%d",
				job.ID, state.Provider, state.RetryAttempts+1,
			)
		}
	} else if nativeProviderJobNeedsCleanup(state.Submission) {
		if state.RetryAttempts+1 < nativeCleanupMaxAttempts {
			state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
			if saveErr != nil {
				return nativePending, saveErr
			}
			s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "cleanup_provider_unavailable", state.RetryAttempts)
			return nativePending, nil
		}
		s.logf(
			"batch.native_cleanup_abandoned id=%q provider=%q attempts=%d",
			job.ID, state.Provider, state.RetryAttempts+1,
		)
	}
	if err := s.refundNativeAuthorizations(ctx, job, pending, requests, reason); err != nil {
		return nativeNotHandled, err
	}
	return nativeManagedFallback, nil
}

func (s *Service) resolveNativeFailure(
	ctx context.Context,
	job job,
	provider NativeProvider,
	indexes []int,
	requests []Request,
	state nativeState,
	generation int64,
	reason string,
) (nativeOutcome, error) {
	// The create response was ambiguous, but the upload response was durably
	// captured. Delete that exact provider-side prompt file before refunding.
	// Cleanup failures are retryable and leave the job fail-closed until the
	// bounded provider-retention fallback takes over.
	if err := provider.Cleanup(ctx, state.Submission); err != nil {
		if state.RetryAttempts+1 < nativeCleanupMaxAttempts {
			state, _, saveErr := s.scheduleNativeRetry(ctx, job.ID, state, generation)
			if saveErr != nil {
				return nativePending, errors.Join(err, saveErr)
			}
			s.logf("batch.native_retry id=%q provider=%q stage=%q attempt=%d", job.ID, state.Provider, "cleanup", state.RetryAttempts)
			return nativePending, nil
		}
		s.logf(
			"batch.native_cleanup_abandoned id=%q provider=%q attempts=%d",
			job.ID, state.Provider, state.RetryAttempts+1,
		)
	}
	for _, index := range indexes {
		if _, err := s.store.Get(ctx, itemResultName(job.ID, index)); err == nil {
			continue
		} else if !errors.Is(err, ErrNotFound) {
			return nativePending, err
		}
		if restored, err := s.restoreSettledNativeItem(ctx, job.ID, index); err != nil {
			return nativePending, err
		} else if restored {
			continue
		}
		authorization, err := s.loadNativeAuthorization(ctx, job.ID, index)
		if err != nil {
			return nativePending, err
		}
		if err := s.refundNativeAuthorizationOnce(
			ctx, job.ID, index, requests[index], authorization, http.StatusBadGateway, reason,
		); err != nil {
			return nativePending, err
		}
		if err := s.storeNativeFailureResult(ctx, job, index, requests[index], reason); err != nil {
			return nativePending, err
		}
	}
	state.Stage = nativeStageResolved
	state.NextPollAt = 0
	state.RetryAttempts = 0
	if _, err := s.saveNativeState(ctx, job.ID, state, generation); err != nil {
		return nativePending, err
	}
	s.logf("batch.native_resolved_failed id=%q provider=%q reason=%q", job.ID, state.Provider, reason)
	return nativeCompleted, nil
}

func (s *Service) storeNativeFailureResult(
	ctx context.Context,
	job job,
	index int,
	request Request,
	reason string,
) error {
	result := Result{
		ID:       resultID(job.ID, request.CustomID),
		CustomID: request.CustomID,
		Error: map[string]any{
			"message": "provider-native batch item could not be completed",
			"type":    "server_error",
			"code":    reason,
		},
	}
	err := s.storeItemCheckpoint(ctx, job.ID, index, result)
	if errors.Is(err, ErrPrecondition) {
		return nil
	}
	return err
}

func (s *Service) fallbackNativeItem(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	index int,
	request Request,
	authorization NativeAuthorization,
	status int,
	reason string,
) error {
	settlementRecovered, err := s.refundNativeAuthorizationOnceDetailed(
		ctx, job.ID, index, request, authorization, status, reason,
	)
	if err != nil {
		return err
	}
	if settlementRecovered {
		return nil
	}
	_, err = s.executeAndCheckpoint(ctx, job, apiKeyLookupHash, index, request)
	return err
}

func (s *Service) finishNativeResults(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	pending []int,
	requests []Request,
	state nativeState,
	provider NativeProvider,
	allowManagedFallback bool,
) error {
	if len(requests) != job.RequestCounts.Total {
		return fmt.Errorf("native batch input count changed")
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerCount := min(max(1, s.concurrency), max(1, len(pending)))
	results := make(chan queuedNativeProviderResult, workerCount*2)
	byteBudget := newNativeResultByteBudget()
	seen := make(map[int]struct{}, job.RequestCounts.Total)
	var seenMu sync.Mutex
	var workers sync.WaitGroup
	var firstError error
	var errorOnce sync.Once
	recordError := func(err error) {
		if err == nil {
			return
		}
		errorOnce.Do(func() {
			firstError = err
			cancel()
		})
	}
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case queued, ok := <-results:
					if !ok {
						return
					}
					providerResult := queued.result
					err := s.finishNativeProviderResult(
						workCtx, job, apiKeyLookupHash, requests, state, providerResult,
						allowManagedFallback,
					)
					clear(providerResult.Body)
					clear(providerResult.Error)
					byteBudget.release(queued.budgetUnits)
					if err != nil {
						recordError(err)
						return
					}
				}
			}
		}()
	}
	readErr := provider.Results(workCtx, state.Submission, func(providerResult NativeProviderResult) error {
		index := providerResult.Index
		if index < 0 || index >= job.RequestCounts.Total {
			return fmt.Errorf(
				"%w: provider %s returned unexpected item %d",
				ErrNativeInvalidResult, state.Provider, index,
			)
		}
		seenMu.Lock()
		_, duplicate := seen[index]
		if !duplicate {
			seen[index] = struct{}{}
		}
		seenMu.Unlock()
		if duplicate {
			return fmt.Errorf(
				"%w: provider %s returned duplicate item %d",
				ErrNativeInvalidResult, state.Provider, index,
			)
		}
		budgetUnits, err := byteBudget.acquire(
			workCtx, len(providerResult.Body)+len(providerResult.Error),
		)
		if err != nil {
			return err
		}
		queued := queuedNativeProviderResult{result: NativeProviderResult{
			Index:      index,
			StatusCode: providerResult.StatusCode,
			RequestID:  providerResult.RequestID,
			Body:       cloneRaw(providerResult.Body),
			Error:      cloneRaw(providerResult.Error),
		}, budgetUnits: budgetUnits}
		select {
		case results <- queued:
			return nil
		case <-workCtx.Done():
			clear(queued.result.Body)
			clear(queued.result.Error)
			byteBudget.release(queued.budgetUnits)
			return workCtx.Err()
		}
	})
	close(results)
	workers.Wait()
	for queued := range results {
		clear(queued.result.Body)
		clear(queued.result.Error)
		byteBudget.release(queued.budgetUnits)
	}
	if firstError != nil {
		return firstError
	}
	if readErr != nil {
		return readErr
	}
	present, err := s.listItemResultPresence(ctx, job.ID, job.RequestCounts.Total)
	if err != nil {
		return err
	}
	for _, index := range pending {
		seenMu.Lock()
		_, found := seen[index]
		seenMu.Unlock()
		if found {
			continue
		}
		if present[index] {
			continue
		}
		if restored, err := s.restoreSettledNativeItem(ctx, job.ID, index); err != nil {
			return err
		} else if restored {
			continue
		}
		if !allowManagedFallback {
			continue
		}
		authorization, err := s.loadNativeAuthorization(ctx, job.ID, index)
		if err != nil {
			return err
		}
		if err := s.fallbackNativeItem(
			ctx, job, apiKeyLookupHash, index, requests[index], authorization,
			http.StatusBadGateway, "native_batch_item_missing",
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) finishNativeProviderResult(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	requests []Request,
	state nativeState,
	providerResult NativeProviderResult,
	allowManagedFallback bool,
) error {
	index := providerResult.Index
	if _, err := s.store.Get(ctx, itemResultName(job.ID, index)); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if restored, err := s.restoreSettledNativeItem(ctx, job.ID, index); err != nil {
		return err
	} else if restored {
		return nil
	}
	authorization, err := s.loadNativeAuthorization(ctx, job.ID, index)
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf(
			"%w: provider %s returned item %d that was not submitted",
			ErrNativeInvalidResult, state.Provider, index,
		)
	}
	if err != nil {
		return err
	}
	if providerResult.StatusCode < 200 || providerResult.StatusCode >= 300 || len(providerResult.Body) == 0 {
		status := providerResult.StatusCode
		if status < 100 {
			status = http.StatusBadGateway
		}
		if !allowManagedFallback {
			return s.refundNativeAuthorizationOnce(
				ctx, job.ID, index, requests[index], authorization, status, "native_batch_item_failed",
			)
		}
		return s.fallbackNativeItem(
			ctx, job, apiKeyLookupHash, index, requests[index], authorization,
			status, "native_batch_item_failed",
		)
	}
	decoded, err := decodeJSONValue(providerResult.Body)
	if err != nil {
		if !allowManagedFallback {
			return s.refundNativeAuthorizationOnce(
				ctx, job.ID, index, requests[index], authorization,
				http.StatusBadGateway, "native_batch_invalid_response",
			)
		}
		return s.fallbackNativeItem(
			ctx, job, apiKeyLookupHash, index, requests[index], authorization,
			http.StatusBadGateway, "native_batch_invalid_response",
		)
	}
	err = s.checkpointNativeSuccess(
		ctx, job, index, requests[index], authorization, state, providerResult, decoded,
	)
	if errors.Is(err, ErrNativeUsageMissing) {
		if allowManagedFallback {
			return s.fallbackNativeItem(
				ctx, job, apiKeyLookupHash, index, requests[index], authorization,
				http.StatusBadGateway, "native_batch_usage_missing",
			)
		}
		if refundErr := s.refundNativeAuthorizationOnce(
			ctx, job.ID, index, requests[index], authorization,
			http.StatusBadGateway, "native_batch_usage_missing",
		); refundErr != nil {
			return refundErr
		}
		return s.storeNativeFailureResult(
			ctx, job, index, requests[index], "native_batch_usage_missing",
		)
	}
	if errors.Is(err, ErrNativeSettlementRejected) {
		if allowManagedFallback {
			return s.fallbackNativeItem(
				ctx, job, apiKeyLookupHash, index, requests[index], authorization,
				http.StatusBadGateway, "native_batch_settlement_rejected",
			)
		}
		if refundErr := s.refundNativeAuthorizationOnce(
			ctx, job.ID, index, requests[index], authorization,
			http.StatusBadGateway, "native_batch_settlement_rejected",
		); refundErr != nil {
			return refundErr
		}
		return s.storeNativeFailureResult(
			ctx, job, index, requests[index], "native_batch_settlement_rejected",
		)
	}
	if !errors.Is(err, ErrNativeAuthorizationRefunded) {
		return err
	}
	if allowManagedFallback {
		_, fallbackErr := s.executeAndCheckpoint(
			ctx, job, apiKeyLookupHash, index, requests[index],
		)
		return fallbackErr
	}
	return s.storeNativeFailureResult(
		ctx, job, index, requests[index], "native_batch_result_after_refund",
	)
}

func (s *Service) checkpointNativeSuccess(
	ctx context.Context,
	job job,
	index int,
	request Request,
	authorization NativeAuthorization,
	state nativeState,
	providerResult NativeProviderResult,
	decoded any,
) error {
	if !nativeUsageComplete(decoded, job.Endpoint) {
		return ErrNativeUsageMissing
	}
	usage := usageFromBody(decoded)
	details := nativeResponseDetails(decoded)
	result, err := s.settleNativeAuthorizationResultOnce(ctx, job.ID, index, authorization, NativeUsage{
		RequestID:       firstNonEmpty(providerResult.RequestID, bodyRequestID(providerResult.Body)),
		InputTokens:     usage.PromptTokens,
		OutputTokens:    usage.CompletionTokens,
		CacheReadTokens: details.cacheReadTokens,
		ReasoningTokens: details.reasoningTokens,
		FinishReason:    details.finishReason,
		UsageEstimated:  false,
		Elapsed:         time.Millisecond,
		Route: NativeRoute{
			Provider:      state.Provider,
			EndpointID:    state.EndpointID,
			Model:         state.Model,
			UpstreamModel: state.UpstreamModel,
			UsageType:     NativeUsageTypeCredit,
		},
	}, func(settled Usage) Result {
		visible := nativeVisibleBody(decoded, job.Model, settled, state, false)
		return Result{
			ID:       resultID(job.ID, request.CustomID),
			CustomID: request.CustomID,
			Response: &ResultResponse{
				StatusCode: providerResult.StatusCode,
				RequestID:  firstNonEmpty(providerResult.RequestID, bodyRequestID(providerResult.Body)),
				Body:       visible,
			},
			Usage: settled,
		}
	})
	if err != nil {
		return err
	}
	err = s.storeItemCheckpoint(ctx, job.ID, index, result)
	if errors.Is(err, ErrPrecondition) {
		return nil
	}
	return err
}

func nativeUsageComplete(decoded any, endpoint string) bool {
	payload, ok := decoded.(map[string]any)
	if !ok {
		return false
	}
	usage, ok := payload["usage"].(map[string]any)
	if !ok || !nativeUsageIntegerPresent(usage, "prompt_tokens", "input_tokens") {
		return false
	}
	if endpoint == "/v1/embeddings" {
		return true
	}
	return nativeUsageIntegerPresent(usage, "completion_tokens", "output_tokens")
}

func nativeUsageIntegerPresent(values map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch value := values[key].(type) {
		case int:
			return value >= 0
		case json.Number:
			number, err := value.Int64()
			return err == nil && number >= 0
		}
	}
	return false
}

type nativeResponseUsageDetails struct {
	cacheReadTokens int
	reasoningTokens int
	finishReason    string
}

func nativeResponseDetails(decoded any) nativeResponseUsageDetails {
	payload, _ := decoded.(map[string]any)
	usage, _ := payload["usage"].(map[string]any)
	promptDetails, _ := usage["prompt_tokens_details"].(map[string]any)
	completionDetails, _ := usage["completion_tokens_details"].(map[string]any)
	details := nativeResponseUsageDetails{
		cacheReadTokens: intValue(promptDetails, "cached_tokens"),
		reasoningTokens: intValue(completionDetails, "reasoning_tokens"),
		finishReason:    "stop",
	}
	choices, _ := payload["choices"].([]any)
	if len(choices) > 0 {
		choice, _ := choices[0].(map[string]any)
		if value, ok := choice["finish_reason"].(string); ok && value != "" {
			details.finishReason = value
		}
	}
	return details
}

func nativeVisibleBody(
	decoded any,
	requestedModel string,
	usage Usage,
	state nativeState,
	usageEstimated bool,
) any {
	payload, ok := decoded.(map[string]any)
	if !ok {
		return decoded
	}
	payload["model"] = requestedModel
	usageMap, _ := payload["usage"].(map[string]any)
	if usageMap == nil {
		usageMap = map[string]any{}
		payload["usage"] = usageMap
	}
	usageMap["prompt_tokens"] = usage.PromptTokens
	usageMap["completion_tokens"] = usage.CompletionTokens
	usageMap["total_tokens"] = usage.TotalTokens
	usageMap["cost_microdollars"] = usage.CostMicrodollars
	usageMap["total_cost_microdollars"] = usage.CostMicrodollars
	usageMap["cost"] = usage.Cost
	providerUsage := map[string]any{
		"router":                        "direct",
		"selected_model":                state.Model,
		"selected_provider":             firstNonEmpty(usage.Provider, state.Provider),
		"selected_endpoint":             state.EndpointID,
		"fallback_candidate_count":      1,
		"upstream_attempt_count":        1,
		"fallback_attempt_count":        0,
		"contains_prompt_or_completion": false,
		"generation_id":                 usage.GenerationID,
		"region":                        usage.Region,
		"usage_type":                    "Credits",
		"cost_microdollars":             usage.CostMicrodollars,
		"total_cost_microdollars":       usage.CostMicrodollars,
		"output_tokens":                 usage.CompletionTokens,
		"batch":                         true,
		"usage_estimated":               usageEstimated,
	}
	details := nativeResponseDetails(payload)
	if details.cacheReadTokens > 0 {
		usageMap["cache_read_input_tokens"] = details.cacheReadTokens
		providerUsage["cache_read_input_tokens"] = details.cacheReadTokens
	}
	uncached := usage.PromptTokens - details.cacheReadTokens
	if uncached < 0 {
		uncached = 0
	}
	if usage.PromptTokens > 0 {
		usageMap["uncached_input_tokens"] = uncached
		providerUsage["uncached_input_tokens"] = uncached
	}
	if details.reasoningTokens > 0 {
		providerUsage["reasoning_tokens"] = details.reasoningTokens
	}
	usageMap["provider_usage"] = providerUsage
	trustedRouter, _ := payload["trustedrouter"].(map[string]any)
	if trustedRouter == nil {
		trustedRouter = map[string]any{}
	}
	trustedRouter["routing"] = map[string]any{
		"selected_model":           providerUsage["selected_model"],
		"selected_provider":        providerUsage["selected_provider"],
		"selected_endpoint":        providerUsage["selected_endpoint"],
		"fallback_candidate_count": providerUsage["fallback_candidate_count"],
		"upstream_attempt_count":   providerUsage["upstream_attempt_count"],
		"fallback_attempt_count":   providerUsage["fallback_attempt_count"],
	}
	payload["trustedrouter"] = trustedRouter
	return payload
}

func (s *Service) storeItemCheckpoint(ctx context.Context, batchID string, index int, result Result) error {
	encoded, err := json.Marshal(itemCheckpoint{
		Result:           result,
		Usage:            result.Usage,
		CostMicrodollars: result.Usage.CostMicrodollars,
		GenerationID:     result.Usage.GenerationID,
		Provider:         result.Usage.Provider,
		Region:           result.Usage.Region,
	})
	if err == nil {
		encoded, err = s.protector.Seal(ctx, batchID, itemResultKind(index), encoded)
	}
	if err == nil {
		_, err = s.store.Put(ctx, itemResultName(batchID, index), encoded, PutCondition{Generation: 0})
	}
	if err == nil {
		err = s.storeItemStateCheckpoint(ctx, batchID, index, stateForResult(result))
	}
	return err
}

func (s *Service) storeItemStateCheckpoint(
	ctx context.Context,
	batchID string,
	index int,
	state itemState,
) error {
	encoded, err := json.Marshal(itemStateCheckpoint{
		Finished:         state.finished,
		Failed:           state.failed,
		Usage:            state.usage,
		CostMicrodollars: state.usage.CostMicrodollars,
		GenerationID:     state.usage.GenerationID,
		Provider:         state.usage.Provider,
		Region:           state.usage.Region,
	})
	if err == nil {
		encoded, err = s.protector.Seal(ctx, batchID, itemStateKind(index), encoded)
	}
	if err == nil {
		_, err = s.store.Put(ctx, itemStateName(batchID, index), encoded, PutCondition{Generation: 0})
	}
	if errors.Is(err, ErrPrecondition) {
		return nil
	}
	return err
}

const (
	nativeLedgerVersion  = 1
	nativeLedgerSettled  = "settled"
	nativeLedgerRefunded = "refunded"
)

type nativeLedgerCheckpoint struct {
	Version          int     `json:"version"`
	Action           string  `json:"action"`
	Usage            Usage   `json:"usage"`
	CostMicrodollars int     `json:"cost_microdollars"`
	GenerationID     string  `json:"generation_id,omitempty"`
	Provider         string  `json:"provider,omitempty"`
	Region           string  `json:"region,omitempty"`
	Result           *Result `json:"result,omitempty"`
}

func (checkpoint nativeLedgerCheckpoint) valid() bool {
	if checkpoint.Version != nativeLedgerVersion {
		return false
	}
	switch checkpoint.Action {
	case nativeLedgerSettled:
		return checkpoint.Result != nil && checkpoint.Result.ID != "" && checkpoint.Result.CustomID != ""
	case nativeLedgerRefunded:
		return checkpoint.Result == nil
	default:
		return false
	}
}

func (checkpoint nativeLedgerCheckpoint) restoredUsage() Usage {
	usage := checkpoint.Usage
	usage.CostMicrodollars = checkpoint.CostMicrodollars
	usage.Cost = float64(checkpoint.CostMicrodollars) / 1_000_000
	usage.GenerationID = checkpoint.GenerationID
	usage.Provider = checkpoint.Provider
	usage.Region = checkpoint.Region
	return usage
}

func (s *Service) settleNativeAuthorizationResultOnce(
	ctx context.Context,
	batchID string,
	index int,
	authorization NativeAuthorization,
	usage NativeUsage,
	buildResult func(Usage) Result,
) (Result, error) {
	checkpoint, found, err := s.loadNativeLedgerCheckpoint(ctx, batchID, index)
	if err != nil {
		return Result{}, err
	}
	if found {
		if checkpoint.Action != nativeLedgerSettled {
			return Result{}, ErrNativeAuthorizationRefunded
		}
		return checkpoint.restoredResult(), nil
	}
	settled, err := s.nativeAuthorizer.Settle(ctx, authorization, usage)
	if err != nil {
		return Result{}, err
	}
	result := buildResult(settled)
	checkpoint = nativeLedgerCheckpoint{
		Version:          nativeLedgerVersion,
		Action:           nativeLedgerSettled,
		Usage:            settled,
		CostMicrodollars: settled.CostMicrodollars,
		GenerationID:     settled.GenerationID,
		Provider:         settled.Provider,
		Region:           settled.Region,
		Result:           &result,
	}
	stored, err := s.storeNativeLedgerCheckpoint(ctx, batchID, index, checkpoint)
	if err != nil {
		return Result{}, err
	}
	return stored.restoredResult(), nil
}

func (checkpoint nativeLedgerCheckpoint) restoredResult() Result {
	result := *checkpoint.Result
	result.Usage = checkpoint.restoredUsage()
	return result
}

func (s *Service) restoreSettledNativeItem(ctx context.Context, batchID string, index int) (bool, error) {
	checkpoint, found, err := s.loadNativeLedgerCheckpoint(ctx, batchID, index)
	if err != nil || !found || checkpoint.Action != nativeLedgerSettled {
		return false, err
	}
	err = s.storeItemCheckpoint(ctx, batchID, index, checkpoint.restoredResult())
	if errors.Is(err, ErrPrecondition) {
		return true, nil
	}
	return err == nil, err
}

func (s *Service) refundNativeAuthorizationOnce(
	ctx context.Context,
	batchID string,
	index int,
	request Request,
	authorization NativeAuthorization,
	status int,
	reason string,
) error {
	_, err := s.refundNativeAuthorizationOnceDetailed(
		ctx, batchID, index, request, authorization, status, reason,
	)
	return err
}

func (s *Service) refundNativeAuthorizationOnceDetailed(
	ctx context.Context,
	batchID string,
	index int,
	request Request,
	authorization NativeAuthorization,
	status int,
	reason string,
) (bool, error) {
	checkpoint, found, err := s.loadNativeLedgerCheckpoint(ctx, batchID, index)
	if err != nil {
		return false, err
	}
	if found {
		if checkpoint.Action == nativeLedgerSettled {
			return true, s.restoreRecoveredNativeSettlement(ctx, batchID, index, checkpoint)
		}
		return false, nil
	}
	refunded, err := s.nativeAuthorizer.Refund(
		ctx, authorization, status, reason, time.Millisecond,
	)
	if err != nil {
		return false, err
	}
	if refunded.AlreadySettled {
		result := Result{
			ID:       resultID(batchID, request.CustomID),
			CustomID: request.CustomID,
			Error: map[string]any{
				"message": "provider-native batch settlement completed before its result checkpoint",
				"type":    "server_error",
				"code":    "native_batch_settlement_recovered",
			},
			Usage: refunded.SettledUsage,
		}
		checkpoint, err := s.storeNativeLedgerCheckpoint(ctx, batchID, index, nativeLedgerCheckpoint{
			Version:          nativeLedgerVersion,
			Action:           nativeLedgerSettled,
			Usage:            refunded.SettledUsage,
			CostMicrodollars: refunded.SettledUsage.CostMicrodollars,
			GenerationID:     refunded.SettledUsage.GenerationID,
			Provider:         refunded.SettledUsage.Provider,
			Region:           refunded.SettledUsage.Region,
			Result:           &result,
		})
		if err != nil {
			return false, err
		}
		return true, s.restoreRecoveredNativeSettlement(ctx, batchID, index, checkpoint)
	}
	_, err = s.storeNativeLedgerCheckpoint(ctx, batchID, index, nativeLedgerCheckpoint{
		Version: nativeLedgerVersion,
		Action:  nativeLedgerRefunded,
	})
	return false, err
}

func (s *Service) restoreRecoveredNativeSettlement(
	ctx context.Context,
	batchID string,
	index int,
	checkpoint nativeLedgerCheckpoint,
) error {
	if checkpoint.Action != nativeLedgerSettled || checkpoint.Result == nil {
		return fmt.Errorf("native batch settled checkpoint %d is incomplete", index)
	}
	err := s.storeItemCheckpoint(ctx, batchID, index, checkpoint.restoredResult())
	if errors.Is(err, ErrPrecondition) {
		return nil
	}
	return err
}

func (s *Service) loadNativeLedgerCheckpoint(
	ctx context.Context,
	batchID string,
	index int,
) (nativeLedgerCheckpoint, bool, error) {
	stored, err := s.store.Get(ctx, nativeLedgerName(batchID, index))
	if errors.Is(err, ErrNotFound) {
		return nativeLedgerCheckpoint{}, false, nil
	}
	if err != nil {
		return nativeLedgerCheckpoint{}, false, err
	}
	plaintext, err := s.protector.Open(ctx, batchID, nativeLedgerKind(index), stored.Data)
	if err != nil {
		return nativeLedgerCheckpoint{}, false, err
	}
	defer clear(plaintext)
	var checkpoint nativeLedgerCheckpoint
	if json.Unmarshal(plaintext, &checkpoint) != nil || !checkpoint.valid() {
		return nativeLedgerCheckpoint{}, false, fmt.Errorf("native batch ledger checkpoint is invalid")
	}
	return checkpoint, true, nil
}

func (s *Service) storeNativeLedgerCheckpoint(
	ctx context.Context,
	batchID string,
	index int,
	checkpoint nativeLedgerCheckpoint,
) (nativeLedgerCheckpoint, error) {
	encoded, err := json.Marshal(checkpoint)
	if err == nil {
		encoded, err = s.protector.Seal(ctx, batchID, nativeLedgerKind(index), encoded)
	}
	if err == nil {
		_, err = s.store.Put(ctx, nativeLedgerName(batchID, index), encoded, PutCondition{Generation: 0})
	}
	if errors.Is(err, ErrPrecondition) {
		existing, found, loadErr := s.loadNativeLedgerCheckpoint(ctx, batchID, index)
		if loadErr != nil {
			return nativeLedgerCheckpoint{}, loadErr
		}
		if !found || existing.Action != checkpoint.Action {
			return nativeLedgerCheckpoint{}, fmt.Errorf("native batch ledger action conflict")
		}
		return existing, nil
	}
	return checkpoint, err
}

func (s *Service) disableNative(
	ctx context.Context,
	job job,
	pending []int,
	requests []Request,
	state nativeState,
	generation int64,
	reason string,
) (nativeOutcome, error) {
	state.Stage = nativeStageDisabled
	state.NextPollAt = 0
	state.RetryAttempts = 0
	updatedGeneration, err := s.saveNativeState(ctx, job.ID, state, generation)
	if err != nil {
		return nativeNotHandled, err
	}
	outcome, err := s.finishNativeDisabled(ctx, job, pending, requests, state, updatedGeneration, reason)
	if err == nil && outcome == nativeManagedFallback {
		s.logf("batch.native_managed id=%q provider=%q reason=%q", job.ID, state.Provider, reason)
	}
	return outcome, err
}

func (s *Service) refundNativeAuthorizations(
	ctx context.Context,
	job job,
	indexes []int,
	requests []Request,
	reason string,
) error {
	if len(requests) != job.RequestCounts.Total {
		return fmt.Errorf("native batch input count changed")
	}
	present, err := s.listItemResultPresence(ctx, job.ID, job.RequestCounts.Total)
	if err != nil {
		return err
	}
	for _, index := range indexes {
		if present[index] {
			continue
		}
		if restored, err := s.restoreSettledNativeItem(ctx, job.ID, index); err != nil {
			return err
		} else if restored {
			continue
		}
		authorization, err := s.loadNativeAuthorization(ctx, job.ID, index)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err := s.refundNativeAuthorizationOnce(
			ctx, job.ID, index, requests[index], authorization, http.StatusServiceUnavailable, reason,
		); err != nil {
			return err
		}
	}
	return nil
}

// expireNative harvests every durable provider result before cancelling and
// refunding unresolved holds. Provider-native batches can finish at the edge of
// the 24-hour window; refunding first would discard paid work or race a settle.
// Any transient poll, cancel, settlement, refund, or cleanup failure leaves the
// public batch active so the worker can retry without leaking money or content.
func (s *Service) expireNative(ctx context.Context, job job) error {
	state, generation, found, err := s.loadNativeState(ctx, job.ID)
	if err != nil || !found || state.Stage == nativeStageComplete {
		return err
	}
	if s.nativeAuthorizer == nil {
		return fmt.Errorf("native batch authorizer unavailable during expiration")
	}
	payload, err := s.loadNativeInputPayload(ctx, job)
	if err != nil {
		return err
	}
	defer clearRequests(payload.Requests)
	pending, err := s.nativePendingIndexes(ctx, job)
	if err != nil {
		return err
	}
	var provider NativeProvider
	if provider = s.nativeProviders[strings.ToLower(state.Provider)]; provider != nil {
		if state.Stage != nativeStageCleanup && strings.TrimSpace(state.Submission.ID) == "" && state.SubmitUncertain {
			// A create response may have been lost before its provider job ID was
			// checkpointed. Make one final token lookup at expiry so a recovered
			// orphan can be cancelled instead of running after customer refund.
			recovered, recoverErr := provider.Recover(ctx, state.Token)
			switch {
			case recoverErr == nil && strings.TrimSpace(recovered.ID) != "":
				state.Submission = recovered
				state.Stage = nativeStageSubmitted
				state.SubmitUncertain = false
				generation, err = s.saveNativeState(ctx, job.ID, state, generation)
				if err != nil {
					return err
				}
			case recoverErr == nil:
				return fmt.Errorf("native batch provider %s recovered an invalid job", provider.Name())
			case !errors.Is(recoverErr, ErrNativeNotFound):
				return recoverErr
			}
		}
		if state.Stage != nativeStageCleanup && !state.ResultsHarvested && strings.TrimSpace(state.Submission.ID) != "" {
			poll, pollErr := provider.Poll(ctx, state.Submission)
			if pollErr != nil {
				if !nativeProviderObjectGone(pollErr) {
					return pollErr
				} else {
					s.logf("batch.native_expiry_object_gone id=%q provider=%q stage=%q", job.ID, state.Provider, "poll")
					poll = NativeProviderPoll{Status: NativeStatusFailed, Job: state.Submission}
				}
			}
			if poll.Job.ID != "" {
				state.Submission = poll.Job
			}
			if poll.Status == NativeStatusPending {
				if err := provider.Cancel(ctx, state.Submission); err != nil {
					return err
				} else {
					poll, pollErr = provider.Poll(ctx, state.Submission)
					if pollErr != nil {
						if !nativeProviderObjectGone(pollErr) {
							return pollErr
						} else {
							s.logf("batch.native_expiry_object_gone id=%q provider=%q stage=%q", job.ID, state.Provider, "poll_after_cancel")
						}
						poll = NativeProviderPoll{Status: NativeStatusFailed, Job: state.Submission}
					}
					if poll.Job.ID != "" {
						state.Submission = poll.Job
					}
				}
			}
			switch poll.Status {
			case NativeStatusComplete, NativeStatusFailed:
				if err := s.finishNativeResults(
					ctx, job, payload.APIKeyLookupHash, pending, payload.Requests,
					state, provider, false,
				); err != nil {
					if !nativeProviderObjectGone(err) && !errors.Is(err, ErrNativeInvalidResult) {
						return err
					} else {
						s.logf("batch.native_expiry_results_unavailable id=%q provider=%q", job.ID, state.Provider)
					}
				}
				state.ResultsHarvested = true
				generation, err = s.saveNativeState(ctx, job.ID, state, generation)
				if err != nil {
					return err
				}
			case NativeStatusPending:
				return fmt.Errorf("native batch provider %s cancellation is still pending", provider.Name())
			default:
				return fmt.Errorf("native batch provider %s returned invalid status", provider.Name())
			}
		}
	} else if nativeProviderJobNeedsCleanup(state.Submission) {
		return fmt.Errorf("native batch provider %s is unavailable for cleanup", state.Provider)
	}
	if state.Stage != nativeStageDisabled {
		state.Stage = nativeStageDisabled
		_, err = s.saveNativeState(ctx, job.ID, state, generation)
		if err != nil {
			return err
		}
	}
	pending, err = s.nativePendingIndexes(ctx, job)
	if err != nil {
		return err
	}
	for _, index := range pending {
		if restored, err := s.restoreSettledNativeItem(ctx, job.ID, index); err != nil {
			return err
		} else if restored {
			continue
		}
		authorization, err := s.loadNativeAuthorization(ctx, job.ID, index)
		if !errors.Is(err, ErrNotFound) {
			if err != nil {
				return err
			}
			if err := s.refundNativeAuthorizationOnce(
				ctx, job.ID, index, payload.Requests[index], authorization,
				http.StatusGatewayTimeout,
				"native_batch_expired",
			); err != nil {
				return err
			}
		}
		if err := s.storeNativeFailureResult(
			ctx, job, index, payload.Requests[index], "native_batch_expired",
		); err != nil {
			return err
		}
	}
	if provider != nil {
		if err := provider.Cleanup(ctx, state.Submission); err != nil {
			if job.ExpiryAttempts+1 < nativeCleanupMaxAttempts {
				return err
			}
			s.logf(
				"batch.native_expiry_cleanup_abandoned id=%q provider=%q attempts=%d",
				job.ID, state.Provider, job.ExpiryAttempts+1,
			)
		}
	}
	s.logf("batch.native_expired id=%q provider=%q", job.ID, state.Provider)
	return nil
}

func (s *Service) loadNativeInputPayload(ctx context.Context, job job) (encryptedPayload, error) {
	input, err := s.store.Get(ctx, job.InputObject)
	if err != nil {
		return encryptedPayload{}, err
	}
	plaintext, err := s.protector.Open(ctx, job.ID, "input", input.Data)
	if err != nil {
		return encryptedPayload{}, err
	}
	defer clear(plaintext)
	var payload encryptedPayload
	if json.Unmarshal(plaintext, &payload) != nil ||
		payload.APIKeyLookupHash != job.OwnerLookupHash ||
		len(payload.Requests) != job.RequestCounts.Total {
		clearRequests(payload.Requests)
		return encryptedPayload{}, fmt.Errorf("batch input metadata mismatch")
	}
	return payload, nil
}

func (s *Service) nativePendingIndexes(ctx context.Context, job job) ([]int, error) {
	present, err := s.listItemResultPresence(ctx, job.ID, job.RequestCounts.Total)
	if err != nil {
		return nil, err
	}
	pending := make([]int, 0, job.RequestCounts.Total)
	for index, exists := range present {
		if !exists {
			pending = append(pending, index)
		}
	}
	return pending, nil
}

func nativeProviderJobNeedsCleanup(job NativeProviderJob) bool {
	return strings.TrimSpace(job.ID) != "" ||
		strings.TrimSpace(job.InputFileID) != "" ||
		strings.TrimSpace(job.OutputFileID) != "" ||
		strings.TrimSpace(job.ErrorFileID) != ""
}

func (s *Service) loadOrAuthorizeNative(
	ctx context.Context,
	job job,
	apiKeyLookupHash string,
	index int,
	body []byte,
) (NativeAuthorization, error) {
	authorization, err := s.loadNativeAuthorization(ctx, job.ID, index)
	if err == nil {
		return authorization, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return NativeAuthorization{}, fmt.Errorf("%w: %v", errNativeAuthorizationCheckpoint, err)
	}
	authorization, err = s.nativeAuthorizer.Authorize(
		ctx,
		apiKeyLookupHash,
		job.Endpoint,
		body,
		fmt.Sprintf("tr-native-batch:%s:%d", job.ID, index),
	)
	if err != nil {
		return NativeAuthorization{}, err
	}
	encoded, err := json.Marshal(authorization)
	if err == nil {
		encoded, err = s.protector.Seal(ctx, job.ID, nativeAuthorizationKind(index), encoded)
	}
	if err == nil {
		_, err = s.store.Put(ctx, nativeAuthorizationName(job.ID, index), encoded, PutCondition{Generation: 0})
	}
	if errors.Is(err, ErrPrecondition) {
		return s.loadNativeAuthorization(ctx, job.ID, index)
	}
	if err != nil {
		// Keep the deterministic authorization live. A retry uses the same
		// idempotency key, receives the same hold, and checkpoints it once storage
		// recovers. Refunding here would make that replay terminal and impossible
		// to settle; the authorization TTL remains the bounded crash fallback.
		return NativeAuthorization{}, fmt.Errorf("%w: %v", errNativeAuthorizationCheckpoint, err)
	}
	return authorization, nil
}

func (s *Service) loadNativeAuthorization(
	ctx context.Context,
	batchID string,
	index int,
) (NativeAuthorization, error) {
	stored, err := s.store.Get(ctx, nativeAuthorizationName(batchID, index))
	if err != nil {
		return NativeAuthorization{}, err
	}
	plaintext, err := s.protector.Open(ctx, batchID, nativeAuthorizationKind(index), stored.Data)
	if err != nil {
		return NativeAuthorization{}, err
	}
	defer clear(plaintext)
	var authorization NativeAuthorization
	if err := json.Unmarshal(plaintext, &authorization); err != nil || len(authorization.Handle) == 0 {
		return NativeAuthorization{}, fmt.Errorf("native batch authorization is invalid")
	}
	return authorization, nil
}

func (s *Service) loadNativeState(
	ctx context.Context,
	batchID string,
) (nativeState, int64, bool, error) {
	stored, err := s.store.Get(ctx, nativeStateName(batchID))
	if errors.Is(err, ErrNotFound) {
		return nativeState{}, 0, false, nil
	}
	if err != nil {
		return nativeState{}, 0, false, err
	}
	plaintext, err := s.protector.Open(ctx, batchID, nativeStateKind, stored.Data)
	if err != nil {
		return nativeState{}, 0, false, err
	}
	defer clear(plaintext)
	var state nativeState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nativeState{}, 0, false, fmt.Errorf("native batch state is invalid")
	}
	if state.Version > 1 {
		return nativeState{}, stored.Generation, true, fmt.Errorf(
			"%w: version %d", errNativeStateNewerVersion, state.Version,
		)
	}
	if !state.valid() {
		return nativeState{}, 0, false, fmt.Errorf("native batch state is invalid")
	}
	return state, stored.Generation, true, nil
}

func (s *Service) saveNativeState(
	ctx context.Context,
	batchID string,
	state nativeState,
	generation int64,
) (int64, error) {
	encoded, err := json.Marshal(state)
	if err == nil {
		encoded, err = s.protector.Seal(ctx, batchID, nativeStateKind, encoded)
	}
	if err != nil {
		return generation, err
	}
	stored, err := s.store.Put(
		ctx, nativeStateName(batchID), encoded, PutCondition{Generation: generation},
	)
	if err != nil {
		return generation, err
	}
	return stored.Generation, nil
}

func (s *Service) createNativeState(
	ctx context.Context,
	batchID string,
	proposed nativeState,
) (nativeState, int64, error) {
	generation, err := s.saveNativeState(ctx, batchID, proposed, 0)
	if !errors.Is(err, ErrPrecondition) {
		return proposed, generation, err
	}
	current, currentGeneration, found, loadErr := s.loadNativeState(ctx, batchID)
	if loadErr != nil {
		return nativeState{}, 0, loadErr
	}
	if !found {
		return nativeState{}, 0, ErrPrecondition
	}
	return current, currentGeneration, nil
}

func nativeSubmissionToken(batchID string) string {
	sum := sha256.Sum256([]byte("trustedrouter-native-batch\x00" + batchID))
	return "tr_batch_" + hex.EncodeToString(sum[:16])
}

func nativeStateName(batchID string) string {
	return artifactPrefix + batchID + "/native/state.enc"
}

const nativeStateKind = "native-state"

func nativeAuthorizationName(batchID string, index int) string {
	return fmt.Sprintf("%s%s/native/authorizations/%08d.enc", artifactPrefix, batchID, index)
}

func nativeAuthorizationKind(index int) string {
	return fmt.Sprintf("native-authorization:%d", index)
}

func nativeLedgerName(batchID string, index int) string {
	return fmt.Sprintf("%s%s/native/ledger/%08d.enc", artifactPrefix, batchID, index)
}

func nativeLedgerKind(index int) string {
	return fmt.Sprintf("native-ledger:%d", index)
}

func clearRequests(requests []Request) {
	for index := range requests {
		clear(requests[index].Body)
	}
}
