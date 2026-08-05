package batch

import (
	"context"
	"encoding/json"
	"time"
)

const (
	ObjectType       = "batch"
	CompletionWindow = "24h"

	StatusValidating = "validating"
	StatusInProgress = "in_progress"
	StatusFinalizing = "finalizing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
	StatusExpired    = "expired"
	StatusCancelling = "cancelling"
	StatusCancelled  = "cancelled"
)

var supportedEndpoints = map[string]struct{}{
	"/v1/chat/completions": {},
	"/v1/responses":        {},
	"/v1/messages":         {},
	"/v1/embeddings":       {},
}

type Request struct {
	CustomID string          `json:"custom_id"`
	Body     json.RawMessage `json:"body"`
}

type CreateRequest struct {
	Endpoint string    `json:"endpoint"`
	Model    string    `json:"model"`
	Requests []Request `json:"requests"`
}

type RequestCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type Usage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	Cost             float64 `json:"cost"`
	IsBYOK           bool    `json:"is_byok"`
	CostMicrodollars int     `json:"-"`
	GenerationID     string  `json:"-"`
	Provider         string  `json:"-"`
	Region           string  `json:"-"`
}

type ResultResponse struct {
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id"`
	Body       any    `json:"body"`
}

type Result struct {
	ID       string          `json:"id"`
	CustomID string          `json:"custom_id"`
	Response *ResultResponse `json:"response"`
	Error    any             `json:"error"`
	Usage    Usage           `json:"-"`
}

// itemCheckpoint is encrypted and never returned to callers. Keep internal
// integer accounting beside the public result so a worker restart can rebuild
// aggregate usage without rerunning or double-charging completed items.
type itemCheckpoint struct {
	Result           Result `json:"result"`
	Usage            Usage  `json:"usage"`
	CostMicrodollars int    `json:"cost_microdollars"`
	GenerationID     string `json:"generation_id,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Region           string `json:"region,omitempty"`
}

// itemStateCheckpoint is the compact recovery index for an item result. The
// full result remains the source of truth; this companion object lets workers
// rebuild progress and aggregate billing without materializing response bodies.
type itemStateCheckpoint struct {
	Finished         bool   `json:"finished"`
	Failed           bool   `json:"failed"`
	Usage            Usage  `json:"usage"`
	CostMicrodollars int    `json:"cost_microdollars"`
	GenerationID     string `json:"generation_id,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Region           string `json:"region,omitempty"`
}

type Batch struct {
	ID               string        `json:"id"`
	Object           string        `json:"object"`
	Endpoint         string        `json:"endpoint"`
	Model            string        `json:"model"`
	CompletionWindow string        `json:"completion_window"`
	Status           string        `json:"status"`
	CreatedAt        int64         `json:"created_at"`
	FinalizedAt      *int64        `json:"finalized_at"`
	RequestCounts    RequestCounts `json:"request_counts"`
	Usage            *Usage        `json:"usage"`
	Results          []Result      `json:"results"`
	Error            any           `json:"error"`
}

// PreparedBatch is an authenticated batch read whose terminal results can be
// consumed incrementally. Callers must read Next in order and must not reuse a
// PreparedBatch concurrently.
type PreparedBatch struct {
	Batch     Batch
	ResultSet bool

	service *Service
	batchID string
	present []bool
	next    int
	legacy  []Result
}

// Next returns the next persisted result in request order.
func (p *PreparedBatch) Next(ctx context.Context) (Result, bool, error) {
	if p == nil || !p.ResultSet {
		return Result{}, false, nil
	}
	if len(p.legacy) > 0 {
		if p.next >= len(p.legacy) {
			return Result{}, false, nil
		}
		result := p.legacy[p.next]
		p.next++
		return result, true, nil
	}
	for p.next < len(p.present) {
		index := p.next
		p.next++
		if !p.present[index] {
			continue
		}
		stored, err := p.service.store.Get(ctx, itemResultName(p.batchID, index))
		if err != nil {
			return Result{}, false, err
		}
		result, err := p.service.openItemResult(ctx, p.batchID, index, stored.Data)
		if err != nil {
			return Result{}, false, err
		}
		return result, true, nil
	}
	return Result{}, false, nil
}

type encryptedPayload struct {
	APIKeyLookupHash string    `json:"api_key_lookup_hash"`
	Requests         []Request `json:"requests"`
}

type job struct {
	Batch
	OwnerLookupHash string `json:"owner_lookup_hash"`
	InputObject     string `json:"input_object"`
	ResultsObject   string `json:"results_object,omitempty"`
	LeaseOwner      string `json:"lease_owner,omitempty"`
	LeaseUntil      int64  `json:"lease_until,omitempty"`
	NextAttemptAt   int64  `json:"next_attempt_at,omitempty"`
	ExpiryAttempts  int    `json:"expiry_attempts,omitempty"`
	ExpiresAt       int64  `json:"expires_at"`
}

type jobMetadata = job

func (j *job) terminal() bool {
	switch j.Status {
	case StatusCompleted, StatusFailed, StatusExpired, StatusCancelled:
		return true
	default:
		return false
	}
}

func newJob(id, ownerHash string, req CreateRequest, now time.Time) job {
	return job{
		Batch: Batch{
			ID:               id,
			Object:           ObjectType,
			Endpoint:         req.Endpoint,
			Model:            req.Model,
			CompletionWindow: CompletionWindow,
			Status:           StatusValidating,
			CreatedAt:        now.Unix(),
			RequestCounts:    RequestCounts{Total: len(req.Requests)},
		},
		OwnerLookupHash: ownerHash,
		InputObject:     inputObjectName(id),
		ExpiresAt:       now.Add(24 * time.Hour).Unix(),
	}
}

type APIError struct {
	Status  int
	Message string
	Type    string
	Code    string
	Param   string
}

func (e *APIError) Error() string { return e.Message }
