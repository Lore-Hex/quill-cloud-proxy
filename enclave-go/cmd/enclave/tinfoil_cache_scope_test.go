package main

import (
	"context"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestProviderCacheScopeIsStableOpaqueAndWorkspaceIsolated(t *testing.T) {
	first := providerCacheScope("workspace-123")
	if first == "" || first == "workspace-123" {
		t.Fatalf("scope must be non-empty and opaque: %q", first)
	}
	if got := providerCacheScope("workspace-123"); got != first {
		t.Fatalf("scope changed between calls: %q != %q", got, first)
	}
	if got := providerCacheScope("workspace-456"); got == first {
		t.Fatalf("different workspaces share scope %q", got)
	}
	if got := providerCacheScope(" "); got != "" {
		t.Fatalf("empty workspace scope = %q", got)
	}
}

func TestInvokeOptionsCarryWorkspaceCacheScope(t *testing.T) {
	authorization := &trustedrouter.Authorization{
		WorkspaceID: "workspace-123",
		Model:       "z-ai/glm-5.2",
		EndpointID:  "z-ai/glm-5.2@tinfoil/prepaid",
		Provider:    "tinfoil",
		UsageType:   "Credits",
	}
	options, err := invokeOptionsForAuthorization(context.Background(), nil, authorization)
	if err != nil {
		t.Fatalf("invokeOptionsForAuthorization: %v", err)
	}
	if len(options) != 1 {
		t.Fatalf("options = %d, want 1", len(options))
	}
	if got, want := options[0].ProviderCacheScope, providerCacheScope(authorization.WorkspaceID); got != want {
		t.Fatalf("cache scope = %q, want %q", got, want)
	}
}

func TestInvokeOptionsCarryWaferZDRPolicy(t *testing.T) {
	authorization := &trustedrouter.Authorization{
		WorkspaceID: "workspace-123",
		Model:       "moonshotai/kimi-k3",
		EndpointID:  "moonshotai/kimi-k3@wafer/prepaid",
		Provider:    "wafer",
		UsageType:   "Credits",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{
				Model:            "moonshotai/kimi-k3",
				UpstreamModel:    "Kimi-K3",
				EndpointID:       "moonshotai/kimi-k3@wafer/prepaid",
				Provider:         "wafer",
				UsageType:        "Credits",
				WaferZDRRequired: true,
			},
		},
	}

	options, err := invokeOptionsForAuthorization(context.Background(), nil, authorization)
	if err != nil {
		t.Fatalf("invokeOptionsForAuthorization: %v", err)
	}
	if len(options) != 1 {
		t.Fatalf("options = %d, want 1", len(options))
	}
	if !options[0].WaferZDRRequired {
		t.Fatal("WaferZDRRequired was not propagated to the provider invocation")
	}
}
