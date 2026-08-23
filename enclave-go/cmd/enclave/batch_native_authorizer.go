package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	nativeBatchChatRoute       = "batch.native.chat.completions"
	nativeBatchEmbeddingsRoute = "batch.native.embeddings"
)

type batchNativeAuthorizer struct {
	gateway *trustedrouter.Client
}

type batchNativeAuthorizationHandle struct {
	AuthorizationID         string         `json:"authorization_id"`
	Model                   string         `json:"model"`
	EndpointID              string         `json:"endpoint_id"`
	EstimatedInputTokens    int            `json:"estimated_input_tokens"`
	RouteType               string         `json:"route_type"`
	User                    string         `json:"user,omitempty"`
	SessionID               string         `json:"session_id,omitempty"`
	Trace                   map[string]any `json:"trace,omitempty"`
	Metadata                map[string]any `json:"metadata,omitempty"`
	ControlPlaneEndpoint    int            `json:"control_plane_endpoint,omitempty"`
	ControlPlaneEndpointSet bool           `json:"control_plane_endpoint_set,omitempty"`
}

type batchNativeAttribution struct {
	User      string
	SessionID string
	Trace     map[string]any
	Metadata  map[string]any
}

func (a *batchNativeAuthorizer) Authorize(
	ctx context.Context,
	apiKeyLookupHash string,
	endpoint string,
	body []byte,
	idempotencyKey string,
) (batchapi.NativeAuthorization, error) {
	if a == nil || a.gateway == nil || !a.gateway.Enabled() {
		return batchapi.NativeAuthorization{}, fmt.Errorf("native batch authorization unavailable")
	}
	ctx, err := trustedrouter.WithAPIKeyLookupHash(ctx, apiKeyLookupHash)
	if err != nil {
		return batchapi.NativeAuthorization{}, err
	}
	var authorization *trustedrouter.Authorization
	var estimatedInput int
	var routeType string
	var attribution batchNativeAttribution
	switch endpoint {
	case "/v1/chat/completions":
		var request qtypes.OpenAIChatRequest
		if err := json.Unmarshal(body, &request); err != nil {
			return batchapi.NativeAuthorization{}, fmt.Errorf("native batch chat request is invalid")
		}
		request.NormalizeMaxTokens()
		request.IdempotencyKey = idempotencyKey
		estimatedInput = trustedrouter.EstimateInputTokens(&request)
		attribution = batchNativeAttribution{
			User: request.User, SessionID: request.SessionID,
			Trace: request.Trace, Metadata: request.Metadata,
		}
		routeType = nativeBatchChatRoute
		authorization, err = a.gateway.AuthorizeWithRoute(
			ctx, batchInternalBearer, &request, routeType,
		)
	case "/v1/embeddings":
		var request qtypes.EmbeddingRequest
		if err := json.Unmarshal(body, &request); err != nil {
			return batchapi.NativeAuthorization{}, fmt.Errorf("native batch embeddings request is invalid")
		}
		request.IdempotencyKey = idempotencyKey
		estimatedInput = qtypes.EstimateEmbeddingInputTokens(request.Inputs())
		attribution = batchNativeAttribution{
			User: request.User, SessionID: request.SessionID,
			Trace: request.Trace, Metadata: request.Metadata,
		}
		routeType = nativeBatchEmbeddingsRoute
		authorization, err = a.gateway.AuthorizeEmbeddingsWithRoute(
			ctx, batchInternalBearer, &request, estimatedInput, routeType,
		)
	default:
		return batchapi.NativeAuthorization{}, fmt.Errorf("native batch endpoint is unsupported")
	}
	if err != nil {
		var controlErr *trustedrouter.ControlPlaneError
		if errors.As(err, &controlErr) {
			if controlErr.StatusCode == http.StatusConflict ||
				(controlErr.StatusCode >= 400 && controlErr.StatusCode < 500 &&
					!nativeBatchRetryableControlPlaneStatus(controlErr.StatusCode)) {
				return batchapi.NativeAuthorization{}, err
			}
		}
		return batchapi.NativeAuthorization{}, fmt.Errorf(
			"%w: %v", batchapi.ErrNativeAuthorizationRetryable, err,
		)
	}
	handle, err := encodeBatchNativeHandle(
		authorization, estimatedInput, routeType, attribution,
	)
	if err != nil {
		_ = a.gateway.Refund(ctx, authorization, 503, "native_batch_handle_failed", 0.001, nil)
		return batchapi.NativeAuthorization{}, err
	}
	routes := nativeRoutes(authorization)
	managedOnly := authorization.CustomModel != nil || len(authorization.BroadcastDestinations) > 0
	return batchapi.NativeAuthorization{
		Handle:              handle,
		Routes:              routes,
		NativeBatchEligible: authorization.NativeBatchEligible,
		CustomModel:         authorization.CustomModel != nil,
		ManagedPathOnly:     managedOnly,
	}, nil
}

func nativeRoutes(authorization *trustedrouter.Authorization) []batchapi.NativeRoute {
	if authorization == nil {
		return nil
	}
	candidates := authorization.RouteCandidates
	if len(candidates) == 0 {
		candidates = []trustedrouter.RouteCandidate{{
			EndpointID:    authorization.EndpointID,
			Model:         authorization.Model,
			UpstreamModel: authorization.UpstreamModel,
			Provider:      authorization.Provider,
			UsageType:     authorization.UsageType,
		}}
	}
	routes := make([]batchapi.NativeRoute, 0, len(candidates))
	for _, candidate := range candidates {
		provider := strings.TrimSpace(candidate.Provider)
		model := strings.TrimSpace(candidate.Model)
		routes = append(routes, batchapi.NativeRoute{
			Provider:   provider,
			EndpointID: strings.TrimSpace(candidate.EndpointID),
			Model:      model,
			UpstreamModel: llm.DirectModelID(
				provider,
				model,
				strings.TrimSpace(candidate.UpstreamModel),
			),
			UsageType: strings.TrimSpace(candidate.UsageType),
		})
	}
	return routes
}

func (a *batchNativeAuthorizer) Settle(
	ctx context.Context,
	authorization batchapi.NativeAuthorization,
	usage batchapi.NativeUsage,
) (batchapi.Usage, error) {
	handle, err := decodeBatchNativeHandle(authorization)
	if err != nil {
		return batchapi.Usage{}, err
	}
	inputTokens := usage.InputTokens
	if inputTokens <= 0 {
		inputTokens = handle.EstimatedInputTokens
	}
	outputTokens := usage.OutputTokens
	if outputTokens < 0 {
		outputTokens = 0
	}
	frozen := handle.authorization()
	result, err := a.gateway.Settle(ctx, &frozen, trustedrouter.Usage{
		RequestID:            usage.RequestID,
		InputTokens:          inputTokens,
		OutputTokens:         outputTokens,
		ElapsedSeconds:       max(usage.Elapsed.Seconds(), 0.001),
		ReasoningTokens:      usage.ReasoningTokens,
		CacheReadInputTokens: usage.CacheReadTokens,
		UsageEstimated:       usage.UsageEstimated,
		FinishReason:         usage.FinishReason,
		RouteType:            handle.RouteType,
		SelectedModel:        usage.Route.Model,
		SelectedEndpoint:     usage.Route.EndpointID,
		User:                 handle.User,
		SessionID:            handle.SessionID,
		Trace:                handle.Trace,
		Metadata:             handle.Metadata,
		App:                  "TrustedRouter Batch",
	})
	if err != nil {
		var controlErr *trustedrouter.ControlPlaneError
		if errors.As(err, &controlErr) && controlErr.StatusCode >= 400 &&
			controlErr.StatusCode < 500 && !nativeBatchRetryableControlPlaneStatus(controlErr.StatusCode) {
			return batchapi.Usage{}, fmt.Errorf("%w: %v", batchapi.ErrNativeSettlementRejected, err)
		}
		return batchapi.Usage{}, err
	}
	if result.AlreadySettled {
		switch strings.ToLower(strings.TrimSpace(result.FinalizationOutcome)) {
		case "settled":
			// The control-plane billing record is authoritative even when its
			// optional generation/activity mirror is not yet visible.
			if result.InputTokens > 0 || result.OutputTokens > 0 {
				inputTokens = result.InputTokens
				outputTokens = result.OutputTokens
			}
		case "refunded":
			return batchapi.Usage{}, batchapi.ErrNativeAuthorizationRefunded
		default:
			return batchapi.Usage{}, batchapi.ErrNativeSettlementPending
		}
	}
	return batchapi.Usage{
		PromptTokens:     inputTokens,
		CompletionTokens: outputTokens,
		TotalTokens:      inputTokens + outputTokens,
		CostMicrodollars: result.CostMicrodollars,
		Cost:             float64(result.CostMicrodollars) / 1_000_000,
		IsBYOK:           false,
		GenerationID:     result.GenerationID,
		Provider:         result.Provider,
		Region:           result.Region,
	}, nil
}

func nativeBatchRetryableControlPlaneStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func (a *batchNativeAuthorizer) Refund(
	ctx context.Context,
	authorization batchapi.NativeAuthorization,
	status int,
	reason string,
	elapsed time.Duration,
) (batchapi.NativeRefund, error) {
	handle, err := decodeBatchNativeHandle(authorization)
	if err != nil {
		return batchapi.NativeRefund{}, err
	}
	frozen := handle.authorization()
	metadata := make(map[string]any, len(handle.Metadata)+1)
	for key, value := range handle.Metadata {
		metadata[key] = value
	}
	metadata["batch_native"] = true
	result, err := a.gateway.RefundDetailedAttributed(
		ctx,
		&frozen,
		status,
		reason,
		max(elapsed.Seconds(), 0.001),
		metadata,
		trustedrouter.RefundAttribution{
			User: handle.User, SessionID: handle.SessionID, Trace: handle.Trace,
		},
	)
	if err != nil {
		return batchapi.NativeRefund{}, err
	}
	settlementWon := false
	if result.AlreadySettled {
		switch strings.ToLower(strings.TrimSpace(result.FinalizationOutcome)) {
		case "settled":
			settlementWon = true
		case "refunded":
			settlementWon = false
		default:
			return batchapi.NativeRefund{}, batchapi.ErrNativeSettlementPending
		}
	}
	refunded := batchapi.NativeRefund{AlreadySettled: settlementWon}
	if settlementWon {
		refunded.SettledUsage = batchapi.Usage{
			PromptTokens:     result.InputTokens,
			CompletionTokens: result.OutputTokens,
			TotalTokens:      result.InputTokens + result.OutputTokens,
			CostMicrodollars: result.CostMicrodollars,
			Cost:             float64(result.CostMicrodollars) / 1_000_000,
			IsBYOK:           strings.EqualFold(result.UsageType, "byok"),
			GenerationID:     result.GenerationID,
			Provider:         result.Provider,
			Region:           result.Region,
		}
	}
	return refunded, nil
}

func decodeBatchNativeHandle(
	authorization batchapi.NativeAuthorization,
) (batchNativeAuthorizationHandle, error) {
	var handle batchNativeAuthorizationHandle
	if len(authorization.Handle) == 0 || json.Unmarshal(authorization.Handle, &handle) != nil ||
		strings.TrimSpace(handle.AuthorizationID) == "" ||
		strings.TrimSpace(handle.Model) == "" ||
		strings.TrimSpace(handle.EndpointID) == "" ||
		strings.TrimSpace(handle.RouteType) == "" {
		return handle, fmt.Errorf("native batch authorization handle is invalid")
	}
	return handle, nil
}

func encodeBatchNativeHandle(
	authorization *trustedrouter.Authorization,
	estimatedInputTokens int,
	routeType string,
	attribution batchNativeAttribution,
) ([]byte, error) {
	if authorization == nil {
		return nil, fmt.Errorf("native batch authorization is nil")
	}
	return json.Marshal(batchNativeAuthorizationHandle{
		AuthorizationID:         authorization.AuthorizationID,
		Model:                   authorization.Model,
		EndpointID:              authorization.EndpointID,
		EstimatedInputTokens:    estimatedInputTokens,
		RouteType:               routeType,
		User:                    attribution.User,
		SessionID:               attribution.SessionID,
		Trace:                   attribution.Trace,
		Metadata:                attribution.Metadata,
		ControlPlaneEndpoint:    authorization.ControlPlaneEndpoint,
		ControlPlaneEndpointSet: authorization.ControlPlaneEndpointSet,
	})
}

func (h batchNativeAuthorizationHandle) authorization() trustedrouter.Authorization {
	return trustedrouter.Authorization{
		AuthorizationID:         h.AuthorizationID,
		Model:                   h.Model,
		EndpointID:              h.EndpointID,
		RouteType:               h.RouteType,
		ControlPlaneEndpoint:    h.ControlPlaneEndpoint,
		ControlPlaneEndpointSet: h.ControlPlaneEndpointSet,
	}
}
