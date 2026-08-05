package batch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	NativeStatusPending   = "pending"
	NativeStatusComplete  = "complete"
	NativeStatusFailed    = "failed"
	NativeUsageTypeCredit = "credits"

	nativeStagePreparing = "preparing"
	nativeStagePrepared  = "prepared"
	nativeStageSubmitted = "submitted"
	nativeStageCleanup   = "cleanup"
	nativeStageDisabled  = "disabled"
	nativeStageResolved  = "resolved"
	nativeStageComplete  = "complete"
)

var ErrNativeNotFound = errors.New("native batch job not found")

// ErrNativeInvalidResult means a completed provider result artifact is
// structurally invalid. Result files are immutable after provider completion,
// so retrying the same bytes cannot recover; the service must clean up and
// safely return unresolved items to the managed path.
var ErrNativeInvalidResult = errors.New("native batch provider result is invalid")

var errNativeRecoveryPending = errors.New("native batch submission recovery pending")
var errNativeRecoveryExhausted = errors.New("native batch submission could not be recovered")

// ErrNativeAuthorizationRefunded means a durable refund won the settlement race.
var ErrNativeAuthorizationRefunded = errors.New("native batch authorization was already refunded")

// ErrNativeSettlementRejected marks a non-retryable control-plane settlement
// rejection. The provider result must not be retried forever; the hold is
// refunded and the item returns to the managed path when that path is allowed.
var ErrNativeSettlementRejected = errors.New("native batch settlement was rejected")

// ErrNativeUsageMissing means the provider returned a successful result
// without authoritative token usage. Native Batch billing must never settle
// from a token estimate; the item is refunded and returned to the managed path.
var ErrNativeUsageMissing = errors.New("native batch provider usage is missing")

// ErrNativeSettlementPending means the control plane has claimed the
// authorization but its durable generation is not visible yet. It is unsafe
// to infer that the authorization was refunded and rerun the provider call;
// the worker must retry the same idempotent settlement instead.
var ErrNativeSettlementPending = errors.New("native batch settlement outcome is pending")

var errNativeSubmitExhausted = errors.New("native batch submission retry budget exhausted")

var errNativeAuthorizationCheckpoint = errors.New("native batch authorization checkpoint unavailable")

// ErrNativeAuthorizationRetryable marks an authorization whose outcome may
// already exist behind a lost response. The worker must retry the same
// deterministic idempotency key instead of switching to managed execution and
// leaving the first credit hold orphaned until its TTL.
var ErrNativeAuthorizationRetryable = errors.New("native batch authorization outcome is retryable")

var errNativeStateNewerVersion = errors.New("native batch state was written by a newer enclave")

// NativeRoute is the provider route frozen by the control plane when an item
// is authorized. Only routes present here may be selected for settlement.
type NativeRoute struct {
	Provider      string `json:"provider"`
	EndpointID    string `json:"endpoint_id"`
	Model         string `json:"model"`
	UpstreamModel string `json:"upstream_model"`
	UsageType     string `json:"usage_type"`
}

// NativeAuthorization is deliberately opaque to the batch package. Handle is
// encrypted before persistence and is interpreted only by the attested
// gateway authorizer that created it.
type NativeAuthorization struct {
	Handle              json.RawMessage `json:"handle"`
	Routes              []NativeRoute   `json:"routes"`
	NativeBatchEligible bool            `json:"native_batch_eligible"`
	CustomModel         bool            `json:"custom_model,omitempty"`
	ManagedPathOnly     bool            `json:"managed_path_only,omitempty"`
}

type NativeUsage struct {
	RequestID       string
	InputTokens     int
	OutputTokens    int
	CacheReadTokens int
	ReasoningTokens int
	FinishReason    string
	UsageEstimated  bool
	Elapsed         time.Duration
	Route           NativeRoute
}

// NativeRefund distinguishes an idempotent refund replay from a late refund
// that lost a race to settlement. The latter must never be checkpointed as a
// refund locally, because doing so would let a later worker rerun or refund
// provider work that was already charged.
type NativeRefund struct {
	AlreadySettled bool
	SettledUsage   Usage
}

// NativeAuthorizer keeps provider content out of the control plane. It sends
// only token estimates and route metadata, then settles/refunds the same
// durable ledger reservation after a provider-native job completes.
type NativeAuthorizer interface {
	Authorize(
		context.Context,
		string,
		string,
		[]byte,
		string,
	) (NativeAuthorization, error)
	Settle(context.Context, NativeAuthorization, NativeUsage) (Usage, error)
	Refund(context.Context, NativeAuthorization, int, string, time.Duration) (NativeRefund, error)
}

type NativeProviderRequest struct {
	Index    int
	CustomID string
	Body     json.RawMessage
}

type NativeProviderJob struct {
	Provider     string `json:"provider"`
	ID           string `json:"id,omitempty"`
	InputFileID  string `json:"input_file_id,omitempty"`
	OutputFileID string `json:"output_file_id,omitempty"`
	ErrorFileID  string `json:"error_file_id,omitempty"`
	Token        string `json:"token"`
}

type NativeProviderResult struct {
	Index      int
	StatusCode int
	RequestID  string
	Body       json.RawMessage
	Error      json.RawMessage
}

type NativeProviderPoll struct {
	Status string
	Job    NativeProviderJob
	Error  string
}

// NativeProvider is a provider-specific asynchronous Batch API adapter.
// Recover must find an earlier submission by Token so a network ambiguity
// after create cannot double-submit and double-charge a provider job.
type NativeProvider interface {
	Name() string
	Supports(endpoint string) bool
	Submit(
		context.Context,
		string,
		string,
		string,
		[]NativeProviderRequest,
		bool,
	) (NativeProviderJob, error)
	Recover(context.Context, string) (NativeProviderJob, error)
	Poll(context.Context, NativeProviderJob) (NativeProviderPoll, error)
	Results(context.Context, NativeProviderJob, func(NativeProviderResult) error) error
	Cancel(context.Context, NativeProviderJob) error
	Cleanup(context.Context, NativeProviderJob) error
}

type nativeState struct {
	Version           int               `json:"version"`
	Stage             string            `json:"stage"`
	Token             string            `json:"token"`
	Provider          string            `json:"provider,omitempty"`
	EndpointID        string            `json:"endpoint_id,omitempty"`
	Model             string            `json:"model,omitempty"`
	UpstreamModel     string            `json:"upstream_model,omitempty"`
	SubmitAttempts    int               `json:"submit_attempts,omitempty"`
	SubmitUncertain   bool              `json:"submit_uncertain,omitempty"`
	SubmitUncertainAt int64             `json:"submit_uncertain_at,omitempty"`
	RecoveryNotFound  int               `json:"recovery_not_found,omitempty"`
	RetryAttempts     int               `json:"retry_attempts,omitempty"`
	NextPollAt        int64             `json:"next_poll_at,omitempty"`
	ResultsHarvested  bool              `json:"results_harvested,omitempty"`
	Submission        NativeProviderJob `json:"submission"`
}

func (state nativeState) valid() bool {
	if state.Version != 1 || strings.TrimSpace(state.Token) == "" ||
		state.SubmitAttempts < 0 || state.RecoveryNotFound < 0 ||
		state.SubmitUncertainAt < 0 || state.RetryAttempts < 0 ||
		state.NextPollAt < 0 {
		return false
	}
	if state.Stage == nativeStageDisabled || state.Stage == nativeStageResolved {
		return true
	}
	if state.Stage == nativeStagePreparing {
		return strings.TrimSpace(state.Provider) == "" &&
			strings.TrimSpace(state.EndpointID) == "" &&
			strings.TrimSpace(state.Model) == "" &&
			strings.TrimSpace(state.UpstreamModel) == "" &&
			strings.TrimSpace(state.Submission.ID) == ""
	}
	if state.Stage != nativeStagePrepared && state.Stage != nativeStageSubmitted &&
		state.Stage != nativeStageCleanup && state.Stage != nativeStageComplete {
		return false
	}
	provider := strings.ToLower(strings.TrimSpace(state.Provider))
	if provider == "" || strings.TrimSpace(state.EndpointID) == "" ||
		strings.TrimSpace(state.Model) == "" || strings.TrimSpace(state.UpstreamModel) == "" ||
		strings.ToLower(strings.TrimSpace(state.Submission.Provider)) != provider ||
		state.Submission.Token != state.Token {
		return false
	}
	if state.Stage == nativeStageSubmitted || state.Stage == nativeStageCleanup || state.Stage == nativeStageComplete {
		return strings.TrimSpace(state.Submission.ID) != ""
	}
	return true
}
