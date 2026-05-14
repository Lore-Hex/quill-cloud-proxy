package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/broadcast"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var contentBroadcasts = broadcast.NewQueueFromEnv()

func settleAndBroadcast(
	ctx context.Context,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	usage trustedrouter.Usage,
	req *types.OpenAIChatRequest,
	originalInput any,
	output string,
) (*trustedrouter.SettleResult, error) {
	if trGateway == nil || !trGateway.Enabled() || authorization == nil {
		return nil, nil
	}
	result, err := trGateway.Settle(ctx, authorization, usage)
	if err != nil {
		return nil, err
	}
	contentBroadcasts.Enqueue(broadcast.Job{
		Cache:        secretCache,
		Destinations: authorization.BroadcastDestinations,
		Generation: broadcast.Generation{
			ID:                result.GenerationID,
			WorkspaceID:       authorization.WorkspaceID,
			APIKeyHash:        authorization.APIKeyHash,
			Model:             result.Model,
			Provider:          result.Provider,
			Region:            result.Region,
			RouteType:         usage.RouteType,
			RequestID:         usage.RequestID,
			InputTokens:       usage.InputTokens,
			OutputTokens:      usage.OutputTokens,
			ElapsedSeconds:    usage.ElapsedSeconds,
			FirstTokenSeconds: usage.FirstTokenSeconds,
			Streamed:          usage.Streamed,
			FinishReason:      usage.FinishReason,
			CostMicrodollars:  result.CostMicrodollars,
			User:              req.User,
			SessionID:         req.SessionID,
			Trace:             req.Trace,
			Metadata:          req.Metadata,
		},
		Input:  originalInput,
		Output: output,
	})
	return result, nil
}

func invokeOptionsForAuthorization(
	ctx context.Context,
	cache *byokcache.Cache,
	authorization *trustedrouter.Authorization,
) ([]llm.InvokeOptions, error) {
	if authorization == nil {
		return nil, nil
	}
	candidates := authorization.RouteCandidates
	if len(candidates) == 0 {
		candidates = []trustedrouter.RouteCandidate{{
			EndpointID:          authorization.EndpointID,
			Model:               authorization.Model,
			UpstreamModel:       authorization.UpstreamModel,
			Provider:            authorization.Provider,
			UsageType:           authorization.UsageType,
			BYOKSecretRef:       authorization.BYOKSecretRef,
			BYOKEncryptedSecret: authorization.BYOKEncryptedSecret,
			BYOKCacheKey:        authorization.BYOKCacheKey,
		}}
	}
	options := make([]llm.InvokeOptions, 0, len(candidates))
	var unavailable []string
	for _, candidate := range candidates {
		if candidate.Model == "" {
			candidate.Model = authorization.Model
		}
		if candidate.UpstreamModel == "" {
			candidate.UpstreamModel = candidate.Model
		}
		if candidate.EndpointID == "" {
			candidate.EndpointID = authorization.EndpointID
		}
		if candidate.Provider == "" {
			candidate.Provider = authorization.Provider
		}
		if candidate.UsageType == "" {
			candidate.UsageType = authorization.UsageType
		}
		providerKey, err := providerAPIKeyForRoute(ctx, cache, authorization.WorkspaceID, candidate)
		if err != nil {
			unavailable = append(unavailable, fmt.Sprintf("%s: %v", candidate.EndpointID, err))
			continue
		}
		options = append(options, llm.InvokeOptions{
			Model:          candidate.Model,
			UpstreamModel:  candidate.UpstreamModel,
			ProviderAPIKey: providerKey,
			Provider:       candidate.Provider,
			EndpointID:     candidate.EndpointID,
			UsageType:      candidate.UsageType,
		})
	}
	if len(options) == 0 && len(unavailable) > 0 {
		return nil, fmt.Errorf("no authorized route candidate has an available provider key: %s", strings.Join(unavailable, "; "))
	}
	return options, nil
}

func providerAPIKeyForRoute(
	ctx context.Context,
	cache *byokcache.Cache,
	workspaceID string,
	candidate trustedrouter.RouteCandidate,
) (string, error) {
	if !strings.EqualFold(candidate.UsageType, "BYOK") {
		return "", nil
	}
	if candidate.BYOKEncryptedSecret != nil {
		if cache == nil {
			return "", fmt.Errorf("byok cache is not configured")
		}
		secret, _, err := cache.Resolve(
			ctx,
			workspaceID,
			candidate.Provider,
			candidate.BYOKCacheKey,
			*candidate.BYOKEncryptedSecret,
		)
		return secret, err
	}
	if strings.HasPrefix(candidate.BYOKSecretRef, "env://") {
		name := strings.TrimPrefix(candidate.BYOKSecretRef, "env://")
		if value := os.Getenv(name); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("BYOK env ref %s is unset", name)
	}
	if strings.HasPrefix(candidate.BYOKSecretRef, "byok://") {
		return "", fmt.Errorf("BYOK envelope is missing for %s", candidate.BYOKSecretRef)
	}
	return "", fmt.Errorf("BYOK provider key reference is missing")
}

func statusFromControlPlaneError(err error) int {
	message := err.Error()
	for _, status := range []int{400, 401, 402, 403, 404, 429} {
		if strings.Contains(message, fmt.Sprintf("http %d", status)) {
			return status
		}
	}
	return 502
}
