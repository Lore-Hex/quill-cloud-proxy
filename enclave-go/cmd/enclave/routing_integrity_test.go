package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestValidateAuthorizationRoutingRejectsFallbackCandidatesWhenDisabled(t *testing.T) {
	allow := false
	req := &types.OpenAIChatRequest{
		Model:    "openai/gpt-oss-20b",
		Provider: &types.ProviderRouting{AllowFallbacks: &allow},
	}
	authorization := &trustedrouter.Authorization{
		Model: "openai/gpt-oss-20b",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "openai/gpt-oss-20b", Provider: "deepinfra"},
			{Model: "google/gemini-2.0-flash-lite", Provider: "google-ai-studio"},
		},
	}

	if err := validateAuthorizationRouting(req, authorization); err == nil {
		t.Fatal("multiple candidates must fail when fallbacks are disabled")
	}
}

func TestValidateAuthorizationRoutingRejectsWrongExplicitModelWhenDisabled(t *testing.T) {
	allow := false
	req := &types.OpenAIChatRequest{
		Model:    "openai/gpt-oss-20b",
		Provider: &types.ProviderRouting{AllowFallbacks: &allow},
	}
	authorization := &trustedrouter.Authorization{
		Model: "google/gemini-2.0-flash-lite",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "google/gemini-2.0-flash-lite", Provider: "google-ai-studio"},
		},
	}

	if err := validateAuthorizationRouting(req, authorization); err == nil {
		t.Fatal("wrong-model authorization must fail closed")
	}
}

func TestValidateAuthorizationRoutingAcceptsExactModelWhenDisabled(t *testing.T) {
	allow := false
	req := &types.OpenAIChatRequest{
		Model:    "openai/gpt-oss-20b",
		Provider: &types.ProviderRouting{AllowFallbacks: &allow},
	}
	authorization := &trustedrouter.Authorization{
		Model: "openai/gpt-oss-20b",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "openai/gpt-oss-20b", Provider: "deepinfra"},
		},
	}

	if err := validateAuthorizationRouting(req, authorization); err != nil {
		t.Fatalf("exact-model authorization rejected: %v", err)
	}
}

func TestValidateAuthorizationRoutingAllowsUnderlyingModelForRouterAlias(t *testing.T) {
	allow := false
	req := &types.OpenAIChatRequest{
		Model:    "trustedrouter/auto",
		Provider: &types.ProviderRouting{AllowFallbacks: &allow},
	}
	authorization := &trustedrouter.Authorization{
		Model: "openai/gpt-oss-20b",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "openai/gpt-oss-20b", Provider: "deepinfra"},
		},
	}

	if err := validateAuthorizationRouting(req, authorization); err != nil {
		t.Fatalf("router alias authorization rejected: %v", err)
	}
}

func TestValidateAuthorizationRoutingAllowsCanonicalOpenAISnapshot(t *testing.T) {
	allow := false
	for _, requested := range []string{
		"gpt-4.1-2025-04-14",
		"openai/gpt-4.1-2025-04-14",
		"openai/gpt-4.1:nitro",
	} {
		req := &types.OpenAIChatRequest{
			Model:    requested,
			Provider: &types.ProviderRouting{AllowFallbacks: &allow},
		}
		authorization := &trustedrouter.Authorization{
			Model: "openai/gpt-4.1",
			RouteCandidates: []trustedrouter.RouteCandidate{
				{Model: "openai/gpt-4.1", Provider: "openai"},
			},
		}

		if err := validateAuthorizationRouting(req, authorization); err != nil {
			t.Fatalf("canonical model for %q rejected: %v", requested, err)
		}
	}
}
