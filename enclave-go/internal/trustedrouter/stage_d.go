package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

const (
	HeartbeatPath = "/internal/gateway/heartbeat"

	DispositionFinalized        = "finalized"
	DispositionIntentDurable    = "intent_durable"
	DispositionAlreadyFinalized = "already_finalized"
	DispositionReapedSnapshot   = "reaped_snapshot"
)

// StageDEligibility is the router's authoritative cohort decision. The
// enclave deliberately does not attempt to reproduce this decision locally.
type StageDEligibility struct {
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason"`
}

// CandidatePrice is one endpoint program from the router's immutable pricing
// document. All rates are integer micro-dollars per million tokens.
type CandidatePrice struct {
	EndpointID          string      `json:"endpoint_id"`
	PriceHistoryVersion int         `json:"price_history_version"`
	Rates               PriceRates  `json:"rates"`
	Tiers               []PriceTier `json:"tiers"`
	RequestFeeMicro     int64       `json:"request_fee_micro"`
	Rounding            string      `json:"rounding"`
}

type PriceRates struct {
	InputMicroPerMillion         int64 `json:"input_micro_per_million"`
	OutputMicroPerMillion        int64 `json:"output_micro_per_million"`
	CachedInputMicroPerMillion   int64 `json:"cached_input_micro_per_million"`
	CacheCreationMicroPerMillion int64 `json:"cache_creation_micro_per_million"`
}

type PriceTier struct {
	MaxPromptTokens *int64     `json:"max_prompt_tokens"`
	Rates           PriceRates `json:"rates"`
}

// RatesForPrompt applies the first pricing-tier upper bound containing the
// prompt. A final null upper bound is represented by a nil pointer.
func (p CandidatePrice) RatesForPrompt(promptTokens int) PriceRates {
	for _, tier := range p.Tiers {
		if tier.MaxPromptTokens == nil || int64(promptTokens) <= *tier.MaxPromptTokens {
			return tier.Rates
		}
	}
	return p.Rates
}

func (a *Authorization) CandidatePrice(endpointID string) (CandidatePrice, bool) {
	if a == nil {
		return CandidatePrice{}, false
	}
	for _, candidate := range a.CandidatePrices {
		if candidate.EndpointID == endpointID {
			return candidate, true
		}
	}
	return CandidatePrice{}, false
}

type HeartbeatUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	PriceTierInputTokens     int `json:"price_tier_input_tokens"`
	ReasoningTokens          int `json:"reasoning_tokens"`
}

type HeartbeatRequest struct {
	AuthorizationID    string         `json:"authorization_id"`
	Seq                int64          `json:"seq"`
	StartedAtMS        int64          `json:"started_at_ms"`
	SelectedEndpointID string         `json:"selected_endpoint_id"`
	Usage              HeartbeatUsage `json:"usage"`
	ElapsedMS          int64          `json:"elapsed_ms"`
	Stream             bool           `json:"stream"`
}

type HeartbeatResponse struct {
	Accepted     bool  `json:"accepted"`
	Seq          int64 `json:"seq"`
	ExpiresAtMS  int64 `json:"expires_at_ms"`
	CapMicro     int64 `json:"cap_micro"`
	RunningMicro int64 `json:"running_micro"`
}

type HeartbeatRejectionReason string

const (
	HeartbeatUnknownAuthorization HeartbeatRejectionReason = "unknown_authorization"
	HeartbeatAlreadyTerminal      HeartbeatRejectionReason = "already_terminal"
	HeartbeatOutOfCohort          HeartbeatRejectionReason = "out_of_cohort"
	HeartbeatBootNotAccepted      HeartbeatRejectionReason = "boot_not_accepted"
	HeartbeatStaleSeq             HeartbeatRejectionReason = "stale_seq"
	HeartbeatEndpointMismatch     HeartbeatRejectionReason = "endpoint_mismatch"
	HeartbeatUsageRegression      HeartbeatRejectionReason = "usage_regression"
	HeartbeatUsageExceedsCap      HeartbeatRejectionReason = "usage_exceeds_cap"
)

var heartbeatRejectionReasons = map[HeartbeatRejectionReason]struct{}{
	HeartbeatUnknownAuthorization: {}, HeartbeatAlreadyTerminal: {},
	HeartbeatOutOfCohort: {}, HeartbeatBootNotAccepted: {},
	HeartbeatStaleSeq: {}, HeartbeatEndpointMismatch: {},
	HeartbeatUsageRegression: {}, HeartbeatUsageExceedsCap: {},
}

type HeartbeatRejectedError struct {
	Reason HeartbeatRejectionReason
	Cause  *ControlPlaneError
}

func (e *HeartbeatRejectedError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("trustedrouter: heartbeat rejected: %s", e.Reason)
}

func (e *HeartbeatRejectedError) Unwrap() error { return e.Cause }

func HeartbeatRejection(err error) (HeartbeatRejectionReason, bool) {
	var rejected *HeartbeatRejectedError
	if !errors.As(err, &rejected) {
		return "", false
	}
	return rejected.Reason, true
}

// Heartbeat marshals once, signs those exact bytes with the boot signer, and
// reuses both the byte slice and signature for every transport retry.
func (c *Client) Heartbeat(ctx context.Context, auth *Authorization, request HeartbeatRequest) (*HeartbeatResponse, error) {
	if auth == nil {
		return nil, fmt.Errorf("trustedrouter: nil authorization")
	}
	if request.AuthorizationID == "" {
		request.AuthorizationID = auth.AuthorizationID
	} else if request.AuthorizationID != auth.AuthorizationID {
		return nil, fmt.Errorf("trustedrouter: heartbeat authorization mismatch")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	return c.heartbeatBytes(ctx, auth, body)
}

// heartbeatBytes is kept as a narrow seam so tests can prove duplicate
// retries reuse the router-pinned literal request bytes.
func (c *Client) heartbeatBytes(ctx context.Context, auth *Authorization, body []byte) (*HeartbeatResponse, error) {
	signer := c.stageDBootDigestSigner()
	if signer == nil {
		return nil, fmt.Errorf("trustedrouter: heartbeat boot signer is unavailable")
	}
	bootAuth, err := spendlease.SignAuthorize(signer, http.MethodPost, HeartbeatPath, body)
	if err != nil {
		return nil, err
	}
	var decoded HeartbeatResponse
	_, err = c.postJSONBytesWithRetryFromEndpoint(
		ctx, HeartbeatPath, append([]byte(nil), body...), &decoded, c.authorizeRetry,
		auth.pinnedControlPlaneEndpoint(), bootAuth.HeaderValue(),
	)
	if err != nil {
		var controlErr *ControlPlaneError
		if errors.As(err, &controlErr) {
			reason := HeartbeatRejectionReason(controlErr.Reason)
			if controlErr.Type == "heartbeat_rejected" {
				if _, ok := heartbeatRejectionReasons[reason]; ok {
					return nil, &HeartbeatRejectedError{Reason: reason, Cause: controlErr}
				}
			}
		}
		return nil, err
	}
	return &decoded, nil
}

type DispositionResult struct {
	AuthorizationID string `json:"authorization_id"`
	Disposition     string `json:"disposition"`
}

func (c *Client) Disposition(ctx context.Context, auth *Authorization) (*DispositionResult, error) {
	if auth == nil {
		return nil, fmt.Errorf("trustedrouter: nil authorization")
	}
	path := "/internal/gateway/authorizations/" + url.PathEscape(auth.AuthorizationID) + "/disposition"
	signer := c.stageDBootDigestSigner()
	if signer == nil {
		return nil, fmt.Errorf("trustedrouter: disposition boot signer is unavailable")
	}
	bootAuth, err := spendlease.SignAuthorize(signer, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	resp, _, err := c.getFromControlPlaneWithBootAuth(ctx, path, auth.pinnedControlPlaneEndpoint(), bootAuth.HeaderValue())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, decodeControlPlaneError(path, resp)
	}
	var envelope struct {
		Data DispositionResult `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return &envelope.Data, nil
}

func (c *Client) getFromControlPlaneWithBootAuth(ctx context.Context, path string, pinnedEndpoint int, bootAuthHeader string) (*http.Response, int, error) {
	if c != nil && c.configurationError != nil {
		return nil, -1, c.configurationError
	}
	if c == nil || len(c.baseURLs) == 0 {
		return nil, -1, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
	}
	start, end := 0, len(c.baseURLs)
	if pinnedEndpoint >= 0 {
		if pinnedEndpoint >= len(c.baseURLs) {
			return nil, -1, fmt.Errorf("trustedrouter: invalid control-plane endpoint index %d", pinnedEndpoint)
		}
		start, end = pinnedEndpoint, pinnedEndpoint+1
	}
	for index := start; index < end; index++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURLs[index]+path, bytes.NewReader(nil))
		if err != nil {
			return nil, -1, err
		}
		req.Header.Set(internalTokenHeader, c.internalToken)
		req.Header.Set(spendlease.BootAuthHeader, bootAuthHeader)
		resp, err := c.httpc.Do(req)
		if err == nil {
			return resp, index, nil
		}
		if pinnedEndpoint >= 0 || !isDialFailure(err) || index == end-1 {
			return nil, -1, fmt.Errorf("trustedrouter: get %s: %w", path, err)
		}
	}
	return nil, -1, fmt.Errorf("trustedrouter: get %s: no endpoint dialable", path)
}

func decodeControlPlaneError(path string, resp *http.Response) error {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return fmt.Errorf("trustedrouter: read %s error body: %w", path, readErr)
	}
	result := &ControlPlaneError{Path: path, StatusCode: resp.StatusCode, Body: string(body), RetryAfter: sanitizeRetryAfter(resp.Header.Get("Retry-After"))}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Reason  string `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil {
		result.Message = strings.TrimSpace(envelope.Error.Message)
		result.Type = strings.TrimSpace(envelope.Error.Type)
		result.Reason = strings.TrimSpace(envelope.Error.Reason)
	}
	return result
}
